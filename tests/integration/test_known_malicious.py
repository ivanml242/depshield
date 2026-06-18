"""Integration tests against known malicious and legitimate packages.

These tests make REAL HTTP calls to npm/PyPI registries and the OpenSSF
malicious-packages dataset.  They are intentionally slow and require
network access.

Run with:
    pytest -m integration -v

Do NOT run as part of the regular test suite.

Metrics generated:
  - True  Positives (TP): malicious packages detected as >= MEDIUM_RISK
  - False Negatives (FN): malicious packages that slipped through as SAFE/LOW_RISK
  - True  Negatives (TN): legitimate packages detected as SAFE/LOW_RISK
  - False Positives (FP): legitimate packages flagged as >= MEDIUM_RISK
  - Precision, Recall, F1-Score

Results are saved to tests/integration/results.json after each run.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import requests
from rich.console import Console

from depshield.analyzers.js_analyzer import Finding
from depshield.analyzers.metadata_analyzer import (
    analyze_metadata,
    fetch_npm_metadata,
    fetch_pypi_metadata,
)
from depshield.analyzers.js_analyzer import analyze_directory as js_analyze_dir
from depshield.analyzers.py_analyzer import analyze_directory as py_analyze_dir
from depshield.downloaders.package_downloader import PackageDownloader
from depshield.scoring.scorer import score_package, PackageScore

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
_FIXTURES_DIR = _HERE.parent / "fixtures" / "osv_reports"
_RESULTS_FILE = _HERE / "results.json"

# ---------------------------------------------------------------------------
# Helper: load OSV reports from fixtures
# ---------------------------------------------------------------------------


def _load_osv_reports() -> list[dict[str, Any]]:
    """Load all OSV JSON fixture files."""
    reports: list[dict[str, Any]] = []
    if not _FIXTURES_DIR.exists():
        return reports
    for path in sorted(_FIXTURES_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            reports.append(data)
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Skipping %s: %s", path.name, exc)
    return reports


def _extract_package_info(osv: dict) -> tuple[str, str, str]:
    """Extract (ecosystem, name, version) from an OSV report.

    Returns the first affected package.  Version defaults to the first
    entry in ``versions`` or ``"latest"`` when unspecified.
    """
    affected = osv.get("affected", [{}])[0]
    pkg = affected.get("package", {})
    ecosystem = pkg.get("ecosystem", "").lower()
    name = pkg.get("name", "")
    versions = affected.get("versions", [])
    version = versions[0] if versions else "latest"
    return ecosystem, name, version


# ---------------------------------------------------------------------------
# Helper: check if a package still exists on the registry
# ---------------------------------------------------------------------------


def _package_exists_npm(name: str) -> bool | str:
    """Return True if the package is still published on npm.

    Returns the string ``'security_placeholder'`` when npm has replaced
    the malicious package with an empty security stub (version
    ``0.0.1-security``).  Returns False if the package has been fully
    removed.
    """
    try:
        r = requests.get(
            f"https://registry.npmjs.org/{name}",
            timeout=15,
        )
        if r.status_code == 404:
            return False
        data = r.json()
        # Some removed packages return {"error": "Not found"}
        if "error" in data:
            return False
        # Detect security placeholders: npm replaces malicious packages
        # with a single version "0.0.1-security" containing no code.
        latest = data.get("dist-tags", {}).get("latest", "")
        if "security" in latest.lower():
            return "security_placeholder"
        return True
    except Exception:
        return False


def _package_exists_pypi(name: str) -> bool:
    """Return True if the package is still published on PyPI."""
    try:
        r = requests.get(
            f"https://pypi.org/pypi/{name}/json",
            timeout=15,
        )
        return r.status_code == 200
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Helper: analyze a single package end-to-end
# ---------------------------------------------------------------------------


def _analyze_package(
    name: str,
    version: str,
    ecosystem: str,
) -> PackageScore | None:
    """Download, analyze and score a single package.

    Returns None if the package cannot be downloaded (e.g. removed from
    the registry).
    """
    findings: list[Finding] = []

    with PackageDownloader() as dl:
        # 1. Download source code
        try:
            if version == "latest":
                # Resolve latest version from registry
                if ecosystem == "npm":
                    meta = requests.get(
                        f"https://registry.npmjs.org/{name}",
                        timeout=15,
                    ).json()
                    version = meta.get("dist-tags", {}).get("latest", "0.0.0")
                else:
                    meta = requests.get(
                        f"https://pypi.org/pypi/{name}/json",
                        timeout=15,
                    ).json()
                    version = meta.get("info", {}).get("version", "0.0.0")

            src_dir = dl.download(name, version, ecosystem=ecosystem)
        except Exception as exc:
            log.warning("Download failed for %s@%s: %s", name, version, exc)
            return None

        # 2. Static analysis
        try:
            if ecosystem == "npm":
                findings.extend(js_analyze_dir(src_dir))
            else:
                findings.extend(py_analyze_dir(src_dir))
        except Exception as exc:
            log.warning("Analysis failed for %s@%s: %s", name, version, exc)

    # 3. Metadata analysis
    try:
        if ecosystem == "npm":
            meta = fetch_npm_metadata(name)
        else:
            meta = fetch_pypi_metadata(name)
        findings.extend(analyze_metadata(meta, name))
    except Exception as exc:
        log.warning("Metadata failed for %s: %s", name, exc)

    # 4. Score
    return score_package(name, version, findings, is_direct=True)


# ---------------------------------------------------------------------------
# Known malicious packages (from OSV fixture files)
# ---------------------------------------------------------------------------

# These are loaded from tests/fixtures/osv_reports/*.json at collection time.
_osv_reports = _load_osv_reports()

# Map: (ecosystem, name, version) for each OSV report
_MALICIOUS_PACKAGES = [_extract_package_info(r) for r in _osv_reports]

# ---------------------------------------------------------------------------
# Known legitimate packages (should NOT be flagged)
# ---------------------------------------------------------------------------

_LEGITIMATE_PACKAGES = [
    # npm
    ("npm", "is-odd", "3.0.1"),
    ("npm", "minimist", "1.2.8"),
    # PyPI
    ("pypi", "six", "1.16.0"),
    ("pypi", "charset-normalizer", "3.3.2"),
]

# ---------------------------------------------------------------------------
# Metrics accumulator
# ---------------------------------------------------------------------------


@dataclass
class _Metrics:
    """Accumulator for TP/FP/TN/FN across all tests."""

    tp: int = 0  # malicious correctly flagged
    fn: int = 0  # malicious missed
    tn: int = 0  # legitimate correctly passed
    fp: int = 0  # legitimate incorrectly flagged

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "true_positives": self.tp,
            "false_negatives": self.fn,
            "true_negatives": self.tn,
            "false_positives": self.fp,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1, 4),
        }


# Module-level metrics instance (shared across tests in the session)
_metrics = _Metrics()
_detailed_results: list[dict[str, Any]] = []


def _save_results() -> None:
    """Persist metrics and detailed results to results.json."""
    output = {
        "metrics": _metrics.to_dict(),
        "details": _detailed_results,
    }
    _RESULTS_FILE.write_text(
        json.dumps(output, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Tests: known malicious packages
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestKnownMalicious:
    """Test depshield against known malicious packages from the OpenSSF dataset.

    For each OSV report in fixtures/osv_reports/:
      1. Extract package name, ecosystem, and version.
      2. Check if the package still exists on the registry.
      3. If it does, download + analyze + score it.
      4. Assert that the score is >= 31 (MEDIUM_RISK or higher).
    """

    @pytest.fixture(autouse=True)
    def _rate_limit(self):
        """Sleep between tests to respect API rate limits."""
        yield
        time.sleep(1.5)

    @pytest.mark.parametrize(
        "ecosystem,name,version",
        _MALICIOUS_PACKAGES,
        ids=[f"{e}/{n}@{v}" for e, n, v in _MALICIOUS_PACKAGES],
    )
    def test_malicious_detected(self, ecosystem, name, version):
        """A known-malicious package should get score >= 31 (MEDIUM_RISK+)."""
        # Check if the package is still on the registry
        if ecosystem == "npm":
            exists = _package_exists_npm(name)
        elif ecosystem == "pypi":
            exists = _package_exists_pypi(name)
        else:
            pytest.skip(f"Unsupported ecosystem: {ecosystem}")
            return

        if not exists:
            pytest.skip(f"{name} has been removed from {ecosystem} registry")
            return

        # npm replaces malicious packages with security placeholders
        if exists == "security_placeholder":
            pytest.skip(
                f"{name} replaced by npm with security placeholder "
                f"(malicious code removed from registry)"
            )
            return

        score = _analyze_package(name, version, ecosystem)

        if score is None:
            pytest.skip(f"Could not download {name}@{version}")
            return

        # Record result
        is_detected = score.score >= 31
        _detailed_results.append({
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "expected": "malicious",
            "score": score.score,
            "classification": score.classification,
            "detected": is_detected,
            "findings_count": len(score.findings),
        })

        if is_detected:
            _metrics.tp += 1
        else:
            _metrics.fn += 1

        _save_results()

        assert score.score >= 31, (
            f"Expected {name}@{version} to be MEDIUM_RISK+ (score >= 31), "
            f"but got {score.classification} (score={score.score}). "
            f"Findings: {len(score.findings)}"
        )


# ---------------------------------------------------------------------------
# Tests: known legitimate packages (false positive check)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestKnownLegitimate:
    """Test depshield against known legitimate packages to measure false positives.

    For each legitimate package:
      1. Download + analyze + score.
      2. Assert that the score is <= 30 (SAFE or LOW_RISK).
    """

    @pytest.fixture(autouse=True)
    def _rate_limit(self):
        """Sleep between tests to respect API rate limits."""
        yield
        time.sleep(1.5)

    @pytest.mark.parametrize(
        "ecosystem,name,version",
        _LEGITIMATE_PACKAGES,
        ids=[f"{e}/{n}@{v}" for e, n, v in _LEGITIMATE_PACKAGES],
    )
    def test_legitimate_not_flagged(self, ecosystem, name, version):
        """A known-legitimate package should get score <= 30 (SAFE/LOW_RISK)."""
        score = _analyze_package(name, version, ecosystem)

        if score is None:
            pytest.skip(f"Could not download {name}@{version}")
            return

        # Record result
        is_false_positive = score.score >= 31
        _detailed_results.append({
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "expected": "legitimate",
            "score": score.score,
            "classification": score.classification,
            "detected": is_false_positive,
            "findings_count": len(score.findings),
        })

        if is_false_positive:
            _metrics.fp += 1
        else:
            _metrics.tn += 1

        _save_results()

        assert score.score <= 30, (
            f"Expected {name}@{version} to be SAFE/LOW_RISK (score <= 30), "
            f"but got {score.classification} (score={score.score}). "
            f"Findings: {[f.signal_type for f in score.findings]}"
        )


# ---------------------------------------------------------------------------
# Summary test – saves final metrics
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSummary:
    """Generate and validate the final metrics report."""

    def test_save_final_results(self):
        """Save accumulated TP/FP/TN/FN and metrics to results.json."""
        _save_results()

        assert _RESULTS_FILE.exists(), "results.json should have been created"

        data = json.loads(_RESULTS_FILE.read_text(encoding="utf-8"))
        metrics = data["metrics"]

        # Log summary
        print(f"\n{'='*60}")
        print(f"  depshield Integration Test Results")
        print(f"{'='*60}")
        print(f"  True Positives  (TP): {metrics['true_positives']}")
        print(f"  False Negatives (FN): {metrics['false_negatives']}")
        print(f"  True Negatives  (TN): {metrics['true_negatives']}")
        print(f"  False Positives (FP): {metrics['false_positives']}")
        print(f"  ---")
        print(f"  Precision: {metrics['precision']:.2%}")
        print(f"  Recall:    {metrics['recall']:.2%}")
        print(f"  F1-Score:  {metrics['f1_score']:.2%}")
        print(f"{'='*60}\n")
