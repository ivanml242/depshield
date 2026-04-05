"""Main orchestrator for depshield.

Ties together resolvers, downloader, analyzers, scorer and report
into a single ``scan_project()`` entry point.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from depshield.analyzers.js_analyzer import Finding
from depshield.analyzers.js_analyzer import analyze_directory as js_analyze_dir
from depshield.analyzers.py_analyzer import analyze_directory as py_analyze_dir
from depshield.analyzers.metadata_analyzer import (
    analyze_metadata,
    fetch_npm_metadata,
    fetch_pypi_metadata,
)
from depshield.downloaders.package_downloader import PackageDownloader
from depshield.resolvers.npm_resolver import resolve_tree as npm_resolve
from depshield.resolvers.pypi_resolver import resolve_tree as pypi_resolve
from depshield.scoring.scorer import score_all, PackageScore
from depshield.scoring.report import print_report, save_json, to_json

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

_CACHE_DIR = Path.home() / ".depshield" / "cache"
_CACHE_VERSION = "1"  # bump when heuristics change


def _cache_key(name: str, version: str) -> str:
    """Deterministic cache key for a package+version."""
    raw = f"{name}@{version}@v{_CACHE_VERSION}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _load_cached(name: str, version: str) -> list[Finding] | None:
    """Load cached findings, or None if miss."""
    key = _cache_key(name, version)
    path = _CACHE_DIR / f"{key}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return [
            Finding(
                signal_type=f["signal_type"],
                severity=f["severity"],
                file=f["file"],
                line=f["line"],
                snippet=f["snippet"],
            )
            for f in data
        ]
    except Exception:
        return None


def _save_cache(name: str, version: str, findings: list[Finding]) -> None:
    """Persist findings to the cache."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = _cache_key(name, version)
    path = _CACHE_DIR / f"{key}.json"
    data = [
        {
            "signal_type": f.signal_type,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "snippet": f.snippet,
        }
        for f in findings
    ]
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


# ---------------------------------------------------------------------------
# Ecosystem detection
# ---------------------------------------------------------------------------

def detect_ecosystems(project_dir: Path) -> list[str]:
    """Auto-detect which ecosystems are present in a project directory."""
    ecosystems: list[str] = []
    if (project_dir / "package.json").exists():
        ecosystems.append("npm")
    if (project_dir / "requirements.txt").exists():
        ecosystems.append("pypi")
    return ecosystems


# ---------------------------------------------------------------------------
# Dependency parsing helpers
# ---------------------------------------------------------------------------

def _read_npm_deps(project_dir: Path) -> dict[str, str]:
    """Read dependencies from package.json."""
    pkg_json = project_dir / "package.json"
    data = json.loads(pkg_json.read_text(encoding="utf-8"))
    deps: dict[str, str] = {}
    deps.update(data.get("dependencies", {}))
    deps.update(data.get("devDependencies", {}))
    return deps


def _read_pypi_deps(project_dir: Path) -> dict[str, str]:
    """Read dependencies from requirements.txt."""
    req_txt = project_dir / "requirements.txt"
    deps: dict[str, str] = {}
    for line in req_txt.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Handle: package==version, package>=version, package
        for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
            if sep in line:
                name, _, ver = line.partition(sep)
                deps[name.strip()] = f"{sep}{ver.strip()}"
                break
        else:
            deps[line] = ""
    return deps


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def scan_project(
    project_dir: str | Path,
    *,
    ecosystem: str = "auto",
    use_cache: bool = True,
    max_depth: int = 3,
    only_direct: bool = False,
    output_format: str = "table",
    console: Console | None = None,
) -> list[PackageScore]:
    """Scan a project for malicious dependencies.

    Parameters
    ----------
    project_dir:
        Path to the project directory containing package.json and/or
        requirements.txt.
    ecosystem:
        Which ecosystem to scan: "npm", "pypi", or "auto" (detect both).
    use_cache:
        Whether to use the result cache (~/.depshield/cache/).
    max_depth:
        Maximum depth for dependency tree resolution.
    only_direct:
        If True, only analyze direct dependencies (depth=1).
    output_format:
        "table" for rich terminal output, "json" for JSON.
    console:
        Optional Rich console (for testing / output redirection).

    Returns
    -------
    list[PackageScore]
        Scored results for all packages found.
    """
    console = console or Console()
    project_dir = Path(project_dir).resolve()

    # Detect ecosystems
    if ecosystem == "auto":
        ecosystems = detect_ecosystems(project_dir)
    else:
        ecosystems = [ecosystem]

    if not ecosystems:
        console.print(
            "[bold red]No package.json or requirements.txt found.[/bold red]"
        )
        return []

    effective_depth = 1 if only_direct else max_depth

    # Collect all packages to analyze
    all_packages: list[tuple[str, str, list[Finding], bool]] = []

    with PackageDownloader() as downloader:
        for eco in ecosystems:
            console.print(
                f"\n[bold blue]Scanning {eco} dependencies...[/bold blue]"
            )

            # 1. Resolve dependency tree
            try:
                if eco == "npm":
                    deps = _read_npm_deps(project_dir)
                    tree = npm_resolve(deps, max_depth=effective_depth)
                else:
                    deps = _read_pypi_deps(project_dir)
                    tree = pypi_resolve(deps, max_depth=effective_depth)
            except Exception as e:
                console.print(f"[red]Error resolving {eco} deps: {e}[/red]")
                continue

            # Flatten tree
            flat = []
            for node in tree:
                flat.extend(node.flatten())

            # Deduplicate by name+version
            seen: set[str] = set()
            unique_nodes = []
            for node in flat:
                key = f"{node.name}@{node.version}"
                if key not in seen:
                    seen.add(key)
                    unique_nodes.append(node)

            # Determine which are direct deps
            direct_names = set(deps.keys())

            console.print(
                f"  Found [cyan]{len(unique_nodes)}[/cyan] packages "
                f"({len(direct_names)} direct)"
            )

            # 2. Analyze each package
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Analyzing...", total=len(unique_nodes))

                for node in unique_nodes:
                    progress.update(
                        task,
                        description=f"Analyzing {node.name}@{node.version}...",
                    )

                    is_direct = node.name in direct_names
                    findings: list[Finding] = []

                    # Check cache
                    if use_cache:
                        cached = _load_cached(node.name, node.version)
                        if cached is not None:
                            all_packages.append(
                                (node.name, node.version, cached, is_direct)
                            )
                            progress.advance(task)
                            continue

                    # 2a. Download & analyze source code
                    try:
                        src_dir = downloader.download(
                            node.name, node.version, ecosystem=eco
                        )
                        if eco == "npm":
                            findings.extend(js_analyze_dir(src_dir))
                        else:
                            findings.extend(py_analyze_dir(src_dir))
                    except Exception as e:
                        log.debug(
                            "Download/analyze failed for %s@%s: %s",
                            node.name, node.version, e,
                        )

                    # 2b. Fetch & analyze metadata
                    try:
                        if eco == "npm":
                            meta = fetch_npm_metadata(node.name)
                        else:
                            meta = fetch_pypi_metadata(node.name)
                        findings.extend(analyze_metadata(meta, node.name))
                    except Exception as e:
                        log.debug(
                            "Metadata fetch failed for %s: %s",
                            node.name, e,
                        )

                    # Cache results
                    if use_cache:
                        _save_cache(node.name, node.version, findings)

                    all_packages.append(
                        (node.name, node.version, findings, is_direct)
                    )
                    progress.advance(task)

    # 3. Score all packages
    scores = score_all(all_packages)

    # 4. Output
    if output_format == "json":
        console.print_json(json.dumps(to_json(scores), ensure_ascii=False))
    else:
        print_report(scores, console=console)

    return scores
