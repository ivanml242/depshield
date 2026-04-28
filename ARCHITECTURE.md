# Architecture — depshield

This document describes the internal architecture of depshield, including the
data flow, module responsibilities, and key design decisions.

## High-Level Architecture

```
                    ┌──────────────────────────┐
                    │        USER INPUT         │
                    │  package.json             │
                    │  requirements.txt         │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │      CLI (cli.py)         │
                    │  Click command parser     │
                    │  --format --ecosystem     │
                    │  --max-depth --no-cache   │
                    └────────────┬─────────────┘
                                 │
                                 ▼
              ┌──────────────────────────────────────┐
              │     SCANNER (core/scanner.py)         │
              │     Main orchestrator                 │
              │                                       │
              │  1. Detect ecosystems                 │
              │  2. Read manifest files               │
              │  3. For each ecosystem:               │
              │     ┌─────────────────────────────┐   │
              │     │  RESOLVER                    │   │
              │     │  npm_resolver / pypi_resolver│   │
              │     │  → DependencyNode tree       │   │
              │     └──────────┬──────────────────┘   │
              │                │                       │
              │     ┌──────────▼──────────────────┐   │
              │     │  DOWNLOADER                  │   │
              │     │  package_downloader.py       │   │
              │     │  → Source code in temp dir   │   │
              │     └──────────┬──────────────────┘   │
              │                │                       │
              │     ┌──────────▼──────────────────┐   │
              │     │  ANALYZERS (parallel)        │   │
              │     │  ┌──────────┐ ┌────────────┐│   │
              │     │  │JS/Python │ │  Metadata   ││   │
              │     │  │ AST scan │ │  API check  ││   │
              │     │  └────┬─────┘ └──────┬─────┘│   │
              │     │       └──────┬───────┘       │   │
              │     │              ▼               │   │
              │     │     list[Finding]            │   │
              │     └──────────────────────────────┘   │
              │                │                       │
              │     ┌──────────▼──────────────────┐   │
              │     │  SCORER                      │   │
              │     │  scorer.py                   │   │
              │     │  → PackageScore (0-100)      │   │
              │     └──────────────────────────────┘   │
              │                                       │
              │  4. Collect all PackageScores          │
              └──────────────────┬────────────────────┘
                                 │
                                 ▼
              ┌──────────────────────────────────────┐
              │     REPORT (scoring/report.py)        │
              │                                       │
              │  ┌──────────────┐ ┌────────────────┐ │
              │  │ Rich table   │ │  JSON export   │ │
              │  │ (terminal)   │ │  (CI/CD file)  │ │
              │  └──────────────┘ └────────────────┘ │
              └──────────────────────────────────────┘
```

## Module Responsibilities

### `depshield/cli.py` — Command-Line Interface

- Entry point: `depshield scan [PATH]`
- Parses CLI options using Click
- Invokes `scan_project()` from the scanner
- Handles exit codes (1 if HIGH_RISK found)

### `depshield/core/scanner.py` — Orchestrator

The central module that ties everything together:

1. **Ecosystem detection** — checks for `package.json` and `requirements.txt`
2. **Dependency reading** — parses manifest files into `{name: version_spec}` dicts
3. **Tree resolution** — calls npm/pypi resolvers to build the dependency tree
4. **Flattening & deduplication** — converts tree to unique list of packages
5. **Per-package analysis loop:**
   - Check cache → use cached findings if available
   - Download source code → `PackageDownloader`
   - Run static analyzer → `js_analyze_dir()` or `py_analyze_dir()`
   - Fetch & analyze metadata → `fetch_*_metadata()` + `analyze_metadata()`
   - Save to cache
6. **Scoring** — `score_all()` computes scores and sorts results
7. **Reporting** — `print_report()` or `to_json()` based on format

### `depshield/resolvers/npm_resolver.py` — npm Dependency Resolver

- Queries `registry.npmjs.org` to fetch package metadata
- Resolves semver constraints (^, ~, >=, *, ||, ranges)
- Builds recursive dependency tree with cycle protection
- Rate limited (1 req/sec)
- Returns `list[DependencyNode]`

### `depshield/resolvers/pypi_resolver.py` — PyPI Dependency Resolver

- Queries `pypi.org/pypi/{name}/json` for package metadata
- Parses `requires_dist` field (with/without parentheses, filtering extras)
- Resolves PEP 440 version specifiers (==, >=, <=, ~=, !=, >, <, compound)
- Builds recursive dependency tree with cycle protection
- Rate limited (1 req/sec)
- Returns `list[DependencyNode]` (shared data model with npm resolver)

### `depshield/downloaders/package_downloader.py` — Source Code Downloader

- Downloads npm tarballs (`.tgz`) from `dist.tarball` URL
- Downloads PyPI sdists (`.tar.gz`) with fallback to `.zip` and `.whl`
- Secure extraction: filters path traversal (`..`, absolute paths)
- Uses `filter="data"` on Python 3.12+ for native safe extraction
- Context manager for automatic cleanup of temp directories

### `depshield/analyzers/js_analyzer.py` — JavaScript Static Analyzer

- Parses JS files with esprima (AST-based analysis)
- Falls back to regex when esprima fails (JSX, TypeScript, modern JS)
- Detects 6 signal types: NETWORK_CALLS, ENV_ACCESS, FILE_SENSITIVE, CODE_EXECUTION, OBFUSCATION, INSTALL_SCRIPTS
- Checks `package.json` for dangerous lifecycle scripts (preinstall/postinstall)
- Defines the shared `Finding` dataclass used by all analyzers

### `depshield/analyzers/py_analyzer.py` — Python Static Analyzer

- Parses Python files with the built-in `ast` module
- Uses `ast.NodeVisitor` to walk the AST efficiently
- Detects 6 signal types: NETWORK_CALLS, ENV_ACCESS, FILE_SENSITIVE, CODE_EXECUTION, OBFUSCATION, INSTALL_HOOKS
- Specifically checks `setup.py` for `cmdclass` overrides (classic attack vector)

### `depshield/analyzers/metadata_analyzer.py` — Metadata Analyzer

- Fetches live metadata from npm/PyPI APIs
- Evaluates 8 signals: YOUNG_PACKAGE, LOW_DOWNLOADS, NO_REPOSITORY, SINGLE_MAINTAINER, VERSION_ANOMALY, TYPOSQUATTING, NO_LICENSE, DESCRIPTION_MISMATCH
- Includes Levenshtein distance algorithm for typosquatting detection
- Hardcoded lists of top-100 npm and PyPI packages for comparison

### `depshield/scoring/scorer.py` — Risk Scorer

- Assigns weights: HIGH=25, MEDIUM=10, LOW=3 points per finding
- Caps score at 100
- Classifies: SAFE (0-10), LOW_RISK (11-30), MEDIUM_RISK (31-60), HIGH_RISK (61-100)
- Sorts results: direct dependencies first, then by score descending

### `depshield/scoring/report.py` — Report Generator

- **Terminal mode**: Rich tables with colors, emojis, summary panel, detailed findings
- **JSON mode**: Structured output with summary + per-package details
- `save_json()` for file export

## Data Flow

```
package.json / requirements.txt
        │
        ▼
  ┌─────────────┐    ┌─────────────┐
  │ npm_resolver │    │pypi_resolver│
  └──────┬──────┘    └──────┬──────┘
         │                   │
         ▼                   ▼
    DependencyNode tree (name, version, children)
         │
         ▼
    Flatten + deduplicate → unique list
         │
         ▼ (for each package)
    ┌────────────────┐
    │  Cache check   │──→ HIT: use cached findings
    └───────┬────────┘
            │ MISS
            ▼
    ┌────────────────┐
    │  Downloader    │──→ temp directory with source code
    └───────┬────────┘
            │
    ┌───────▼────────┐    ┌──────────────────┐
    │ JS/Py Analyzer │    │ Metadata Analyzer │
    │ (AST → Finding)│    │ (API → Finding)   │
    └───────┬────────┘    └────────┬──────────┘
            │                      │
            └──────────┬───────────┘
                       │
                       ▼
              list[Finding]
                       │
                       ▼
              ┌────────────────┐
              │    Scorer      │
              │ Finding → score│
              │ → PackageScore │
              └───────┬────────┘
                      │
                      ▼
              ┌────────────────┐
              │    Report      │
              │ table / JSON   │
              └────────────────┘
```

## Key Data Models

### `DependencyNode` (resolvers)

```python
@dataclass
class DependencyNode:
    name: str                            # Package name
    version: str                         # Resolved version
    is_direct: bool = False              # Direct vs transitive
    children: list[DependencyNode] = []  # Transitive dependencies
```

### `Finding` (analyzers)

```python
@dataclass
class Finding:
    signal_type: str   # e.g. "NETWORK_CALLS", "TYPOSQUATTING"
    severity: str      # "HIGH", "MEDIUM", "LOW"
    file: str          # File path where finding was detected
    line: int          # Line number (0 if unknown)
    snippet: str       # Code fragment (max 100 chars)
```

### `PackageScore` (scorer)

```python
@dataclass
class PackageScore:
    name: str              # Package name
    version: str           # Version
    score: int             # 0–100
    classification: str    # SAFE / LOW_RISK / MEDIUM_RISK / HIGH_RISK
    findings: list[Finding]  # Sorted by severity
    is_direct: bool        # Direct dependency flag
```

## Cache System

- Location: `~/.depshield/cache/`
- Key: SHA-256 of `{name}@{version}@v{CACHE_VERSION}` (truncated to 16 chars)
- Format: JSON array of serialized findings
- Invalidation: bump `_CACHE_VERSION` when heuristics change

## Design Decisions

1. **AST-first, regex fallback**: esprima provides semantic accuracy; regex ensures coverage for modern JS/JSX that esprima can't parse.
2. **No semgrep dependency**: Unlike GuardDog, we use built-in AST modules (Python `ast`, esprima for JS), keeping the installation lightweight (~5 MB vs ~200+ MB).
3. **Ecosystem-agnostic scoring**: The `Finding` and `PackageScore` models are independent of npm/PyPI, making it easy to add new ecosystems.
4. **Secure-by-default extraction**: Path traversal protection and Python 3.12+ `filter="data"` prevent malicious tarballs from escaping the temp directory.
5. **Shared `DependencyNode`**: Both resolvers use the same tree structure, enabling uniform processing downstream.
