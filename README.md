# depshield

**Detect malicious dependencies before installation.**

depshield is a CLI tool that analyzes `package.json` and/or `requirements.txt` files, resolves the full transitive dependency tree, downloads package source code, and performs static analysis to detect malicious behaviors — all *before* running `npm install` or `pip install`.

## Features

- 🌳 Full transitive dependency tree resolution (npm + PyPI)
- 🔍 Static analysis of JavaScript (esprima AST) and Python (ast) source code
- 📊 Package metadata analysis (typosquatting, age, downloads, etc.)
- 🎯 Multi-signal risk scoring (SAFE / LOW / MEDIUM / HIGH)
- 📋 Terminal reports (rich tables) + JSON export

## Installation

```bash
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
```

## Usage

```bash
depshield scan /path/to/project
```

### Options

| Option | Description | Default |
|---|---|---|
| `--format` | Output format: `table` or `json` | `table` |
| `--ecosystem` | Ecosystem: `npm`, `pypi`, or `auto` | `auto` |
| `--no-cache` | Disable result caching | `false` |
| `--max-depth N` | Max dependency tree depth | `3` |
| `--only-direct` | Only scan direct dependencies | `false` |

## Development

Run tests:

```bash
pytest -v
```

## License

MIT
