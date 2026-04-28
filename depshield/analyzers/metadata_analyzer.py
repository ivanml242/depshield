"""Metadata analyzer for npm and PyPI packages.

Checks package metadata (age, downloads, repo, maintainers, etc.)
for signals that may indicate a suspicious or untrustworthy package.
This runs independently of source code analysis.

Detected signals: YOUNG_PACKAGE, LOW_DOWNLOADS, NO_REPOSITORY,
SINGLE_MAINTAINER, VERSION_ANOMALY, TYPOSQUATTING, NO_LICENSE,
DESCRIPTION_MISMATCH.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

import requests

from depshield.analyzers.js_analyzer import Finding


# Popular packages (used for typosquatting detection)

_POPULAR_NPM = {
    "lodash", "chalk", "react", "express", "commander", "moment", "debug",
    "request", "async", "bluebird", "glob", "mkdirp", "underscore", "colors",
    "minimist", "uuid", "yargs", "semver", "rimraf", "axios", "webpack",
    "body-parser", "through2", "inquirer", "path", "fs-extra", "graceful-fs",
    "minimatch", "readable-stream", "cheerio", "chokidar", "eslint", "gulp",
    "rxjs", "ws", "qs", "prop-types", "mocha", "tslib", "joi", "dotenv",
    "classnames", "core-js", "babel-core", "yallist", "lru-cache", "source-map",
    "kind-of", "once", "wrappy", "inflight", "inherits", "isarray", "isobject",
    "strip-ansi", "ansi-regex", "ansi-styles", "supports-color", "color-convert",
    "color-name", "has-flag", "ms", "safe-buffer", "string_decoder", "string-width",
    "which", "cross-spawn", "execa", "signal-exit", "get-stream", "is-stream",
    "npm-run-path", "path-key", "shebang-command", "shebang-regex",
    "typescript", "prettier", "jest", "next", "vue", "svelte", "angular",
    "jquery", "d3", "three", "socket.io", "mongoose", "sequelize", "knex",
    "passport", "jsonwebtoken", "bcrypt", "cors", "helmet", "morgan",
    "nodemon", "pm2", "redis", "pg", "mysql", "sqlite3", "mongodb",
    "puppeteer", "playwright", "electron", "tailwindcss", "postcss",
    "autoprefixer", "sass", "less", "styled-components", "emotion",
    "formik", "yup", "zod", "immer", "date-fns",
}

_POPULAR_PYPI = {
    "requests", "setuptools", "pip", "urllib3", "certifi", "idna", "charset-normalizer",
    "numpy", "six", "python-dateutil", "pyyaml", "packaging", "boto3", "botocore",
    "typing-extensions", "s3transfer", "cryptography", "jmespath", "colorama",
    "pyasn1", "cffi", "wheel", "attrs", "click", "markupsafe", "importlib-metadata",
    "jinja2", "pycparser", "pyparsing", "pytz", "rsa", "awscli", "docutils",
    "tomli", "platformdirs", "filelock", "protobuf", "pillow", "scipy",
    "pandas", "matplotlib", "grpcio", "google-api-core", "google-auth",
    "google-cloud-storage", "google-cloud-core", "google-resumable-media",
    "google-api-python-client", "google-auth-httplib2", "httplib2",
    "flask", "django", "fastapi", "uvicorn", "gunicorn", "celery",
    "sqlalchemy", "alembic", "psycopg2", "psycopg2-binary", "pymongo",
    "redis", "pydantic", "aiohttp", "httpx", "beautifulsoup4", "lxml",
    "scrapy", "selenium", "pytest", "tox", "coverage", "black", "flake8",
    "mypy", "isort", "pylint", "bandit", "sphinx", "mkdocs",
    "scikit-learn", "tensorflow", "torch", "keras", "xgboost", "lightgbm",
    "transformers", "tokenizers", "datasets", "opencv-python",
    "Pillow", "rich", "typer", "tqdm", "tabulate", "arrow",
    "paramiko", "fabric", "ansible", "docker", "kubernetes",
    "pygments", "decorator", "wrapt", "frozenlist", "multidict",
}


# Levenshtein distance (for typosquatting)

def _levenshtein(a: str, b: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(
                curr[j] + 1,        # insert
                prev[j + 1] + 1,    # delete
                prev[j] + cost,     # substitute
            ))
        prev = curr
    return prev[-1]


# Individual signal checks

def _check_young_package(metadata: dict[str, Any], pkg_name: str) -> list[Finding]:
    """YOUNG_PACKAGE: first published < 30 days ago."""
    findings: list[Finding] = []
    created = metadata.get("created")
    if not created:
        return findings

    try:
        if isinstance(created, str):
            # npm format: "2024-01-15T12:00:00.000Z"
            created_dt = _dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
        elif isinstance(created, _dt.datetime):
            created_dt = created
        else:
            return findings

        now = _dt.datetime.now(_dt.timezone.utc)
        age_days = (now - created_dt).days
        if age_days < 30:
            findings.append(Finding(
                "YOUNG_PACKAGE", "MEDIUM", pkg_name, 0,
                f"Package first published {age_days} days ago",
            ))
    except (ValueError, TypeError):
        pass
    return findings


def _check_low_downloads(metadata: dict[str, Any], pkg_name: str) -> list[Finding]:
    """LOW_DOWNLOADS: weekly downloads < 100 (npm) or < 50 (PyPI)."""
    findings: list[Finding] = []
    downloads = metadata.get("weekly_downloads")
    ecosystem = metadata.get("ecosystem", "npm")

    if downloads is None:
        return findings

    threshold = 100 if ecosystem == "npm" else 50
    if isinstance(downloads, (int, float)) and downloads < threshold:
        findings.append(Finding(
            "LOW_DOWNLOADS", "LOW", pkg_name, 0,
            f"{int(downloads)} weekly downloads (threshold: {threshold})",
        ))
    return findings


def _check_no_repository(metadata: dict[str, Any], pkg_name: str) -> list[Finding]:
    """NO_REPOSITORY: missing or empty repository/homepage URL."""
    findings: list[Finding] = []
    repo = metadata.get("repository") or metadata.get("homepage") or ""
    if not repo.strip():
        findings.append(Finding(
            "NO_REPOSITORY", "MEDIUM", pkg_name, 0,
            "No repository or homepage URL",
        ))
    return findings


def _check_single_maintainer(metadata: dict[str, Any], pkg_name: str) -> list[Finding]:
    """SINGLE_MAINTAINER: only one maintainer."""
    findings: list[Finding] = []
    maintainers = metadata.get("maintainers", [])
    if isinstance(maintainers, list) and len(maintainers) == 1:
        findings.append(Finding(
            "SINGLE_MAINTAINER", "LOW", pkg_name, 0,
            f"Only 1 maintainer: {maintainers[0] if maintainers else 'unknown'}",
        ))
    return findings


def _check_version_anomaly(metadata: dict[str, Any], pkg_name: str) -> list[Finding]:
    """VERSION_ANOMALY: >5 versions published within 24 h."""
    findings: list[Finding] = []
    versions_times = metadata.get("version_timestamps")
    if not versions_times or not isinstance(versions_times, list):
        return findings

    # Parse timestamps and sort
    timestamps: list[_dt.datetime] = []
    for ts in versions_times:
        try:
            if isinstance(ts, str):
                timestamps.append(_dt.datetime.fromisoformat(ts.replace("Z", "+00:00")))
            elif isinstance(ts, _dt.datetime):
                timestamps.append(ts)
        except (ValueError, TypeError):
            continue

    timestamps.sort()

    # Sliding window: count versions within any 24h window
    window = _dt.timedelta(hours=24)
    for i in range(len(timestamps)):
        count = 0
        for j in range(i, len(timestamps)):
            if timestamps[j] - timestamps[i] <= window:
                count += 1
            else:
                break
        if count > 5:
            findings.append(Finding(
                "VERSION_ANOMALY", "HIGH", pkg_name, 0,
                f"{count} versions published within 24h",
            ))
            break  # One finding is enough

    return findings


def _check_typosquatting(
    metadata: dict[str, Any],
    pkg_name: str,
) -> list[Finding]:
    """TYPOSQUATTING: name within Levenshtein distance ≤ 2 of a popular package."""
    findings: list[Finding] = []
    ecosystem = metadata.get("ecosystem", "npm")
    popular = _POPULAR_NPM if ecosystem == "npm" else _POPULAR_PYPI
    name_lower = pkg_name.lower()

    for popular_name in popular:
        if name_lower == popular_name.lower():
            break  # Exact match = it IS the popular package, skip
    else:
        # Check distance against all popular names
        for popular_name in popular:
            dist = _levenshtein(name_lower, popular_name.lower())
            if 0 < dist <= 2:
                findings.append(Finding(
                    "TYPOSQUATTING", "HIGH", pkg_name, 0,
                    f"Name similar to popular package '{popular_name}' "
                    f"(distance: {dist})",
                ))
                break  # Report only the closest match

    return findings


def _check_no_license(metadata: dict[str, Any], pkg_name: str) -> list[Finding]:
    """NO_LICENSE: no license defined."""
    findings: list[Finding] = []
    license_val = metadata.get("license") or ""
    if not license_val.strip():
        findings.append(Finding(
            "NO_LICENSE", "LOW", pkg_name, 0,
            "No license defined",
        ))
    return findings


def _check_description_mismatch(metadata: dict[str, Any], pkg_name: str) -> list[Finding]:
    """DESCRIPTION_MISMATCH: no description or very short (< 10 chars)."""
    findings: list[Finding] = []
    desc = metadata.get("description") or ""
    if len(desc.strip()) < 10:
        findings.append(Finding(
            "DESCRIPTION_MISMATCH", "LOW", pkg_name, 0,
            f"Description too short ({len(desc.strip())} chars)"
            if desc.strip() else "No description",
        ))
    return findings


# Registry fetchers

def fetch_npm_metadata(name: str) -> dict[str, Any]:
    """Fetch metadata for an npm package from the registry.

    Returns a normalized dict with keys used by the signal checkers.
    """
    # Basic metadata
    url = f"https://registry.npmjs.org/{name}"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    time_info = data.get("time", {})
    latest = data.get("dist-tags", {}).get("latest", "")
    latest_meta = data.get("versions", {}).get(latest, {})

    # Downloads (separate API)
    weekly_downloads = None
    try:
        dl_url = f"https://api.npmjs.org/downloads/point/last-week/{name}"
        dl_resp = requests.get(dl_url, timeout=10)
        if dl_resp.ok:
            weekly_downloads = dl_resp.json().get("downloads")
    except Exception:
        pass

    # Version timestamps
    version_timestamps = [
        v for k, v in time_info.items()
        if k not in ("created", "modified")
    ]

    repo = latest_meta.get("repository", {})
    repo_url = repo.get("url", "") if isinstance(repo, dict) else str(repo)

    return {
        "ecosystem": "npm",
        "created": time_info.get("created"),
        "weekly_downloads": weekly_downloads,
        "repository": repo_url,
        "homepage": latest_meta.get("homepage", ""),
        "maintainers": [
            m.get("name", "") for m in data.get("maintainers", [])
        ],
        "version_timestamps": version_timestamps,
        "license": latest_meta.get("license", ""),
        "description": data.get("description", ""),
    }


def fetch_pypi_metadata(name: str) -> dict[str, Any]:
    """Fetch metadata for a PyPI package.

    Returns a normalized dict with keys used by the signal checkers.
    """
    url = f"https://pypi.org/pypi/{name}/json"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    info = data.get("info", {})
    releases = data.get("releases", {})

    # Version timestamps from release uploads
    version_timestamps: list[str] = []
    for _version, files in releases.items():
        if files:
            version_timestamps.append(files[0].get("upload_time_iso_8601", ""))

    # Find creation date (earliest upload)
    created = None
    if version_timestamps:
        valid = [t for t in version_timestamps if t]
        if valid:
            created = min(valid)

    return {
        "ecosystem": "pypi",
        "created": created,
        "weekly_downloads": None,  # PyPI doesn't expose this easily
        "repository": info.get("project_urls", {}).get("Source", "")
                      or info.get("project_urls", {}).get("Homepage", "")
                      or info.get("home_page", ""),
        "homepage": info.get("home_page", ""),
        "maintainers": [info.get("author", "")] if info.get("author") else [],
        "version_timestamps": version_timestamps,
        "license": info.get("license", ""),
        "description": info.get("summary", ""),
    }


# Public API

def analyze_metadata(
    metadata: dict[str, Any],
    pkg_name: str,
) -> list[Finding]:
    """Analyze package metadata for suspicious signals.

    Parameters
    ----------
    metadata:
        Normalized metadata dict (from ``fetch_npm_metadata`` or
        ``fetch_pypi_metadata``).
    pkg_name:
        Package name string.

    Returns
    -------
    list[Finding]
        List of findings with signal types, severities, and descriptions.
    """
    findings: list[Finding] = []
    findings.extend(_check_young_package(metadata, pkg_name))
    findings.extend(_check_low_downloads(metadata, pkg_name))
    findings.extend(_check_no_repository(metadata, pkg_name))
    findings.extend(_check_single_maintainer(metadata, pkg_name))
    findings.extend(_check_version_anomaly(metadata, pkg_name))
    findings.extend(_check_typosquatting(metadata, pkg_name))
    findings.extend(_check_no_license(metadata, pkg_name))
    findings.extend(_check_description_mismatch(metadata, pkg_name))
    return findings
