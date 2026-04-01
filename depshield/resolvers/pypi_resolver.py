"""PyPI dependency resolver.

Reads a requirements.txt file, queries the public PyPI JSON API,
parses ``requires_dist`` for transitive dependencies, and builds
the full dependency tree reusing the same DependencyNode model as
the npm resolver.
"""

import re
import time
from pathlib import Path

import requests

from depshield.resolvers.npm_resolver import DependencyNode


# ---------------------------------------------------------------------------
# requirements.txt parser
# ---------------------------------------------------------------------------

_REQ_LINE_RE = re.compile(
    r"""
    ^
    \s*
    (?P<name>[A-Za-z0-9_][A-Za-z0-9._-]*)   # package name
    \s*
    (?:
        (?P<op>~=|==|!=|>=|<=|>|<)           # version operator
        \s*
        (?P<version>[^\s;#,]+)               # version string
    )?
    """,
    re.VERBOSE,
)


def read_requirements_txt(path: str | Path) -> dict[str, str]:
    """Parse a requirements.txt and return ``{name: version_spec}``.

    Supported formats per line:
      - ``requests``            → name only (latest)
      - ``requests==2.31.0``    → pinned
      - ``requests>=2.20``      → minimum
      - ``requests~=2.31``      → compatible release
      - Lines starting with ``#`` or ``-`` are ignored.
    """
    path = Path(path)
    deps: dict[str, str] = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        match = _REQ_LINE_RE.match(line)
        if match:
            name = match.group("name")
            op = match.group("op") or ""
            version = match.group("version") or ""
            deps[name] = f"{op}{version}" if op else ""

    return deps


# ---------------------------------------------------------------------------
# requires_dist parser
# ---------------------------------------------------------------------------

_REQUIRES_DIST_RE = re.compile(
    r"""
    ^
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)    # package name
    \s*
    (?:
        \((?P<version_paren>[^)]*)\)         # (>=1.0, <2.0)  – with parens
        |
        (?P<version_bare>(?:[<>=!~]+[^;,\s]+(?:\s*,\s*[<>=!~]+[^;,\s]+)*))  # >=1.0,<2.0 – no parens
    )?
    (?:\s*;\s*(?P<marker>.*))?               # optional ; extra == "..."
    $
    """,
    re.VERBOSE,
)


def _parse_requires_dist(requires_dist: list[str]) -> dict[str, str]:
    """Extract unconditional dependencies from ``requires_dist``.

    Entries with environment markers containing ``extra ==`` are skipped
    because those are optional dependencies not installed by default.
    """
    deps: dict[str, str] = {}

    for entry in requires_dist:
        match = _REQUIRES_DIST_RE.match(entry.strip())
        if not match:
            continue

        marker = match.group("marker") or ""
        # Skip optional / extra dependencies
        if "extra" in marker:
            continue

        name = match.group("name")
        version_spec = match.group("version_paren") or match.group("version_bare") or ""
        deps[name] = version_spec

    return deps


# ---------------------------------------------------------------------------
# PyPI registry client (with rate limiting)
# ---------------------------------------------------------------------------

_PYPI_BASE = "https://pypi.org/pypi"
_last_request_time: float = 0.0


def _rate_limit() -> None:
    """Ensure at least 1 second between consecutive HTTP requests."""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < 1.0:
        time.sleep(1.0 - elapsed)
    _last_request_time = time.time()


def _fetch_package_metadata(package_name: str, version: str = "") -> dict:
    """Query the PyPI JSON API for package metadata.

    - ``GET https://pypi.org/pypi/{name}/json``
    - ``GET https://pypi.org/pypi/{name}/{version}/json``
    """
    _rate_limit()
    if version:
        url = f"{_PYPI_BASE}/{package_name}/{version}/json"
    else:
        url = f"{_PYPI_BASE}/{package_name}/json"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()


# ---------------------------------------------------------------------------
# Version resolution helpers
# ---------------------------------------------------------------------------

def _parse_version_tuple(version_str: str) -> tuple[int, ...]:
    """Parse ``1.2.3`` into ``(1, 2, 3)``."""
    parts: list[int] = []
    for segment in version_str.split("."):
        m = re.match(r"(\d+)", segment)
        if m:
            parts.append(int(m.group(1)))
        else:
            break
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _is_prerelease(version: str) -> bool:
    """Return True if version contains pre-release markers (a, b, rc, dev)."""
    return bool(re.search(r"(a|b|rc|dev|alpha|beta)\d*", version, re.IGNORECASE))


def _resolve_version(available_versions: list[str], spec: str) -> str | None:
    """Pick the best version from *available_versions* matching *spec*.

    Supported specs:
      - ``""``  or empty → latest stable
      - ``==X.Y.Z``      → exact
      - ``>=X.Y.Z``      → minimum
      - ``~=X.Y``        → compatible release (>=X.Y, ==X.*)
      - ``<=X.Y.Z``      → maximum
      - ``!=X.Y.Z``      → exclude specific version
    """
    # Filter out pre-releases
    stable = [v for v in available_versions if not _is_prerelease(v)]
    if not stable:
        stable = available_versions

    spec = spec.strip()

    # No spec → latest
    if not spec:
        return max(stable, key=_parse_version_tuple, default=None)

    # Handle comma-separated compound specifiers: >=1.0,<2.0
    if "," in spec:
        candidates = list(stable)
        for part in spec.split(","):
            part = part.strip()
            sub_result = set()
            for v in candidates:
                if _version_matches_single(v, part):
                    sub_result.add(v)
            candidates = [v for v in candidates if v in sub_result]
        return max(candidates, key=_parse_version_tuple, default=None)

    # Single specifier
    candidates = [v for v in stable if _version_matches_single(v, spec)]
    return max(candidates, key=_parse_version_tuple, default=None)


def _version_matches_single(version: str, spec: str) -> bool:
    """Check if a single version matches a single spec like ``>=1.0``."""
    spec = spec.strip()
    v = _parse_version_tuple(version)

    if spec.startswith("=="):
        return v == _parse_version_tuple(spec[2:].strip())
    if spec.startswith("!="):
        return v != _parse_version_tuple(spec[2:].strip())
    if spec.startswith(">="):
        return v >= _parse_version_tuple(spec[2:].strip())
    if spec.startswith("<="):
        return v <= _parse_version_tuple(spec[2:].strip())
    if spec.startswith(">") and not spec.startswith(">="):
        return v > _parse_version_tuple(spec[1:].strip())
    if spec.startswith("<") and not spec.startswith("<="):
        return v < _parse_version_tuple(spec[1:].strip())
    if spec.startswith("~="):
        # Compatible release: ~=X.Y means >=X.Y, ==X.*
        s = _parse_version_tuple(spec[2:].strip())
        return v[0] == s[0] and v >= s
    # Treat as exact
    return v == _parse_version_tuple(spec)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_tree(
    deps: dict[str, str],
    *,
    max_depth: int = 5,
    _visited: set[str] | None = None,
    _depth: int = 0,
    _is_direct: bool = True,
) -> list[DependencyNode]:
    """Recursively resolve the PyPI dependency tree.

    Parameters
    ----------
    deps:
        Mapping of ``{package_name: version_spec}``.
    max_depth:
        Maximum recursion depth (default 5 for PyPI).
    _visited:
        Internal set of ``name@version`` for cycle detection.
    _depth:
        Current recursion depth.
    _is_direct:
        Whether current level consists of direct dependencies.

    Returns
    -------
    list[DependencyNode]
        Root-level nodes with children populated recursively.
    """
    if _visited is None:
        _visited = set()

    nodes: list[DependencyNode] = []

    for name, spec in deps.items():
        try:
            metadata = _fetch_package_metadata(name)
        except requests.RequestException:
            continue

        available_versions = list(metadata.get("releases", {}).keys())
        resolved_version = _resolve_version(available_versions, spec)

        if resolved_version is None:
            continue

        key = f"{name}@{resolved_version}"
        if key in _visited:
            nodes.append(
                DependencyNode(name=name, version=resolved_version, is_direct=_is_direct)
            )
            continue

        _visited.add(key)

        node = DependencyNode(name=name, version=resolved_version, is_direct=_is_direct)

        # Resolve transitive dependencies if depth allows
        if _depth < max_depth:
            try:
                version_meta = _fetch_package_metadata(name, resolved_version)
            except requests.RequestException:
                nodes.append(node)
                continue

            requires_dist = version_meta.get("info", {}).get("requires_dist") or []
            child_deps = _parse_requires_dist(requires_dist)

            if child_deps:
                node.children = resolve_tree(
                    child_deps,
                    max_depth=max_depth,
                    _visited=_visited,
                    _depth=_depth + 1,
                    _is_direct=False,
                )

        nodes.append(node)

    return nodes


def resolve_from_requirements_txt(
    path: str | Path,
    *,
    max_depth: int = 5,
) -> list[DependencyNode]:
    """High-level helper: read requirements.txt → resolve full tree."""
    deps = read_requirements_txt(path)
    return resolve_tree(deps, max_depth=max_depth)
