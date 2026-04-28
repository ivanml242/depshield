# depshield

**Detect malicious dependencies before installation.**

depshield is a command-line tool that analyzes `package.json` and/or `requirements.txt` files, resolves the full transitive dependency tree, downloads package source code, and performs static analysis to detect malicious behaviors — all *before* running `npm install` or `pip install`.

## Problem

Supply chain attacks on open-source software have doubled in 2025. Attackers publish malicious packages on npm and PyPI using techniques like typosquatting, dependency confusion, and compromised maintainer accounts. Existing tools have significant gaps:

- **npm audit / pip-audit**: Only detect known CVEs. Cannot detect zero-day malicious packages.
- **GuardDog (Datadog)**: Analyzes individual packages with Semgrep rules, but doesn't resolve the full transitive tree and can be evaded with basic obfuscation.
- **Packj**: Audits packages one by one, not the full project. Requires Linux.
- **Socket.dev**: Commercial and closed-source.

**depshield** combines: (1) full transitive dependency tree resolution, (2) behavioral static analysis of source code, (3) suspicious metadata analysis, and (4) a multi-signal risk scoring model.

## Features

- 🌳 **Full transitive dependency tree** resolution for npm and PyPI
- 🔍 **Static analysis** of JavaScript (esprima AST + regex fallback) and Python (ast module)
- 📊 **Metadata analysis** — 8 signals: package age, downloads, typosquatting (Levenshtein), repository, license, maintainers, version anomalies, description quality
- 🎯 **Multi-signal risk scoring** (0–100) with classification: SAFE / LOW_RISK / MEDIUM_RISK / HIGH_RISK
- 📋 **Rich terminal reports** (colored tables with emojis) + JSON export for CI/CD
- 💾 **Result caching** in `~/.depshield/cache/` to avoid re-analyzing packages
- 🔒 **Secure extraction** — path traversal protection when unpacking tarballs

## Installation

```bash
# Clone the repository
git clone https://github.com/ivanml242/depshield.git
cd depshield

# Create virtual environment and install
python -m venv .venv
.venv\Scripts\activate       # Windows
# source .venv/bin/activate  # Linux/macOS

pip install -e .
```

For development (includes pytest, pytest-cov, guarddog):

```bash
pip install -e ".[dev]"
```

## Usage

### Basic scan

```bash
# Scan the current directory (auto-detects ecosystem)
depshield scan

# Scan a specific project directory
depshield scan /path/to/project
```

### Options

| Option | Description | Default |
|---|---|---|
| `PATH` | Project directory to scan | `.` (current) |
| `--format` | Output format: `table` or `json` | `table` |
| `--ecosystem` | Ecosystem: `npm`, `pypi`, or `auto` | `auto` |
| `--no-cache` | Disable result caching | `false` |
| `--max-depth N` | Maximum dependency tree depth | `3` |
| `--only-direct` | Only scan direct dependencies | `false` |
| `--output FILE` | Save JSON report to file | — |

### Examples

```bash
# Scan with JSON output
depshield scan . --format json

# Only direct dependencies, no cache
depshield scan . --only-direct --no-cache

# Scan npm only, limit depth to 2
depshield scan . --ecosystem npm --max-depth 2

# Save report to file while showing table in terminal
depshield scan . --output report.json

# Force PyPI ecosystem
depshield scan . --ecosystem pypi
```

### Example output

```
depshield v0.1.0

Scanning npm dependencies...
  Found 15 packages (3 direct)

┌─────────────────────────────────────────────────────────────────┐
│                   depshield scan results                        │
│                                                                 │
│  📦 15 packages scanned                                        │
│  🔴 1 HIGH RISK                                                │
│  🟠 2 MEDIUM RISK                                              │
│  ⚠️  3 LOW RISK                                                 │
│  ✅ 9 SAFE                                                     │
└─────────────────────────────────────────────────────────────────┘

┌──────────────┬─────────┬────────┬───────┬────────────┬──────────────┐
│ Package      │ Version │ Type   │ Score │ Risk       │ Findings     │
├──────────────┼─────────┼────────┼───────┼────────────┼──────────────┤
│ evil-pkg     │ 1.0.0   │ direct │    75 │ 🔴 HIGH    │ 🔴 3 HIGH    │
│ shady-lib    │ 2.1.0   │ trans. │    45 │ 🟠 MEDIUM  │ 🟡 2 MED     │
│ lodash       │ 4.17.21 │ direct │     0 │ ✅ SAFE    │ —            │
└──────────────┴─────────┴────────┴───────┴────────────┴──────────────┘
```

### CI/CD Integration

depshield returns **exit code 1** if any HIGH_RISK package is found, making it easy to integrate in CI/CD pipelines:

```yaml
# GitHub Actions
- name: Security audit
  run: |
    pip install depshield
    depshield scan . --format json --output report.json
  # Step fails automatically if any HIGH_RISK package is detected
```

## Running Tests

```bash
# Unit tests only (fast, no network)
pytest -v --ignore=tests/integration --ignore=tests/benchmarks

# Integration tests (real API calls, slow)
pytest -m integration -v

# Benchmark: depshield vs GuardDog
pytest -m benchmark -v -s

# All tests
pytest -v
```

## Scoring System

Each finding from the analyzers contributes to the risk score:

| Severity | Points | Examples |
|---|---|---|
| HIGH | +25 | `eval()`, `child_process.exec()`, network exfiltration, typosquatting |
| MEDIUM | +10 | URL literals, `atob()`, young package, no repository |
| LOW | +3 | No license, short description, single maintainer |

**Maximum score: 100** (capped).

| Score | Classification | Meaning |
|---|---|---|
| 0–10 | ✅ SAFE | No significant risks detected |
| 11–30 | ⚠️ LOW_RISK | Minor signals, likely benign |
| 31–60 | 🟠 MEDIUM_RISK | Suspicious patterns, review recommended |
| 61–100 | 🔴 HIGH_RISK | Strong malicious indicators, do not install |

## Detection Signals

### Source code analysis (JavaScript)
- `NETWORK_CALLS` — fetch, axios, http.request, URL literals
- `ENV_ACCESS` — process.env, process.argv
- `FILE_SENSITIVE` — .ssh, .npmrc, .aws, /etc/passwd
- `CODE_EXECUTION` — eval(), Function(), child_process.exec/spawn
- `OBFUSCATION` — Buffer.from(base64), atob(), hex strings, String.fromCharCode
- `INSTALL_SCRIPTS` — preinstall/postinstall in package.json

### Source code analysis (Python)
- `NETWORK_CALLS` — urllib, requests, http.client, socket, httpx
- `ENV_ACCESS` — os.environ, os.getenv()
- `FILE_SENSITIVE` — ~/.ssh, ~/.aws, /etc/passwd
- `CODE_EXECUTION` — eval(), exec(), os.system(), subprocess
- `OBFUSCATION` — base64.b64decode, codecs.decode, marshal.loads
- `INSTALL_HOOKS` — setup.py cmdclass overrides (install/develop)

### Metadata analysis
- `YOUNG_PACKAGE` — First published < 30 days ago
- `LOW_DOWNLOADS` — Weekly downloads < 100 (npm) or < 50 (PyPI)
- `NO_REPOSITORY` — No repository/homepage URL
- `SINGLE_MAINTAINER` — Only one maintainer
- `VERSION_ANOMALY` — > 5 versions published in 24 hours
- `TYPOSQUATTING` — Name within Levenshtein distance ≤ 2 of a top-100 package
- `NO_LICENSE` — No license defined
- `DESCRIPTION_MISMATCH` — No description or very short (< 10 chars)

## Requirements

- Python ≥ 3.11
- Dependencies: requests, click, rich, esprima

## License

MIT
