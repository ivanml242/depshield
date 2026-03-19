"""npm dependency resolver.

Reads a package.json file, queries the public npm registry API,
resolves semver constraints, and builds the full transitive dependency tree.
"""

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DependencyNode:
    """Represents a single package in the dependency tree."""

    name: str
    version: str
    is_direct: bool = False
    children: list["DependencyNode"] = field(default_factory=list)

    def flatten(self) -> list["DependencyNode"]:
        """Return a flat list of this node plus all descendants."""
        result = [self]
        for child in self.children:
            result.extend(child.flatten())
        return result

    def __repr__(self) -> str:
        child_count = len(self.children)
        return f"DependencyNode({self.name}@{self.version}, children={child_count})"


# ---------------------------------------------------------------------------
# Semver helpers  (basic: exact, ^caret, ~tilde, >=, ranges with ||)
# ---------------------------------------------------------------------------

def _parse_version_tuple(version_str: str) -> tuple[int, ...]:
    """Parse '1.2.3' into (1, 2, 3). Non-numeric parts are ignored."""
    parts: list[int] = []
    for segment in version_str.split("."):
        match = re.match(r"(\d+)", segment)
        if match:
            parts.append(int(match.group(1)))
        else:
            break
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _matches_caret(version: str, spec_version: str) -> bool:
    """^1.2.3 allows changes that do not modify the left-most non-zero digit."""
    v = _parse_version_tuple(version)
    s = _parse_version_tuple(spec_version)
    if s[0] != 0:
        return v[0] == s[0] and v >= s
    if s[1] != 0:
        return v[0] == s[0] and v[1] == s[1] and v >= s
    return v == s


def _matches_tilde(version: str, spec_version: str) -> bool:
    """~1.2.3 allows patch-level changes (>=1.2.3, <1.3.0)."""
    v = _parse_version_tuple(version)
    s = _parse_version_tuple(spec_version)
    return v[0] == s[0] and v[1] == s[1] and v >= s


def _matches_gte(version: str, spec_version: str) -> bool:
    """>= comparison."""
    return _parse_version_tuple(version) >= _parse_version_tuple(spec_version)


def _is_prerelease(version: str) -> bool:
    """Return True if the version string contains a pre-release tag."""
    return bool(re.search(r"[-]", version.split("+")[0].split(".")[-1] if "." in version else version))


def _best_match(versions: list[str], spec: str) -> str | None:
    """Return the best (highest) version from *versions* that satisfies *spec*.

    Supported spec formats:
      - exact   ``1.2.3``
      - caret   ``^1.2.3``
      - tilde   ``~1.2.3``
      - gte     ``>=1.2.3``
      - star    ``*``
      - latest  ``latest``
      - ranges  ``>=1.0.0 <2.0.0`` (simple two-part ranges)
      - or      ``^1 || ^2`` (picks first branch that matches)
    """
    spec = spec.strip()

    # Filter out pre-release versions by default
    stable_versions = [v for v in versions if not _is_prerelease(v)]
    if not stable_versions:
        stable_versions = versions

    # Handle OR operator – pick first branch that yields a match
    if "||" in spec:
        for branch in spec.split("||"):
            result = _best_match(stable_versions, branch.strip())
            if result:
                return result
        return None

    # Star / latest → newest stable
    if spec in ("*", "latest", ""):
        return max(stable_versions, key=_parse_version_tuple, default=None)

    # Caret
    if spec.startswith("^"):
        spec_ver = spec[1:].strip()
        candidates = [v for v in stable_versions if _matches_caret(v, spec_ver)]
        return max(candidates, key=_parse_version_tuple, default=None)

    # Tilde
    if spec.startswith("~"):
        spec_ver = spec[1:].strip()
        candidates = [v for v in stable_versions if _matches_tilde(v, spec_ver)]
        return max(candidates, key=_parse_version_tuple, default=None)

    # >=x.y.z <a.b.c  (simple range)
    range_match = re.match(r">=\s*([\d.]+)\s+<\s*([\d.]+)", spec)
    if range_match:
        lo, hi = range_match.group(1), range_match.group(2)
        candidates = [
            v for v in stable_versions
            if _parse_version_tuple(v) >= _parse_version_tuple(lo)
            and _parse_version_tuple(v) < _parse_version_tuple(hi)
        ]
        return max(candidates, key=_parse_version_tuple, default=None)

    # >=
    if spec.startswith(">="):
        spec_ver = spec[2:].strip()
        candidates = [v for v in stable_versions if _matches_gte(v, spec_ver)]
        return max(candidates, key=_parse_version_tuple, default=None)

    # Exact
    clean = spec.lstrip("=").strip()
    if clean in versions:
        return clean

    return None


# ---------------------------------------------------------------------------
# npm registry client (with rate limiting)
# ---------------------------------------------------------------------------

_NPM_REGISTRY = "https://registry.npmjs.org"
_last_request_time: float = 0.0


def _rate_limit() -> None:
    """Ensure at least 1 second between consecutive HTTP requests."""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < 1.0:
        time.sleep(1.0 - elapsed)
    _last_request_time = time.time()


def _fetch_package_metadata(package_name: str) -> dict:
    """GET https://registry.npmjs.org/{package_name} and return the JSON."""
    _rate_limit()
    url = f"{_NPM_REGISTRY}/{package_name}"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def read_package_json(path: str | Path) -> dict[str, str]:
    """Read a package.json and return merged dependencies + devDependencies."""
    path = Path(path)
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies"):
        if key in data:
            deps.update(data[key])
    return deps


def resolve_tree(
    deps: dict[str, str],
    *,
    max_depth: int = 3,
    _visited: set[str] | None = None,
    _depth: int = 0,
    _is_direct: bool = True,
) -> list[DependencyNode]:
    """Recursively resolve the dependency tree.

    Parameters
    ----------
    deps:
        Mapping of ``{package_name: semver_spec}``.
    max_depth:
        Maximum recursion depth to prevent very deep trees.
    _visited:
        Internal set of ``name@version`` strings already resolved (cycle guard).
    _depth:
        Current recursion depth.
    _is_direct:
        Whether the current level consists of direct dependencies.

    Returns
    -------
    list[DependencyNode]
        Root-level nodes with their children populated recursively.
    """
    if _visited is None:
        _visited = set()

    nodes: list[DependencyNode] = []

    for name, spec in deps.items():
        try:
            metadata = _fetch_package_metadata(name)
        except requests.RequestException:
            # Package not found or network error – skip gracefully
            continue

        available_versions = list(metadata.get("versions", {}).keys())
        resolved_version = _best_match(available_versions, spec)

        if resolved_version is None:
            continue

        key = f"{name}@{resolved_version}"
        if key in _visited:
            # Cycle detected – add a leaf node without children
            nodes.append(DependencyNode(name=name, version=resolved_version, is_direct=_is_direct))
            continue

        _visited.add(key)

        node = DependencyNode(name=name, version=resolved_version, is_direct=_is_direct)

        # Resolve transitive dependencies if depth allows
        if _depth < max_depth:
            version_meta = metadata["versions"].get(resolved_version, {})
            child_deps: dict[str, str] = version_meta.get("dependencies", {})
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


def resolve_from_package_json(
    path: str | Path,
    *,
    max_depth: int = 3,
) -> list[DependencyNode]:
    """High-level helper: read package.json → resolve full tree."""
    deps = read_package_json(path)
    return resolve_tree(deps, max_depth=max_depth)
