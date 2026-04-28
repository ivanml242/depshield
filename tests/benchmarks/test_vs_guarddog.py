"""Benchmark: depshield vs GuardDog.

Compares depshield against GuardDog (Datadog) using the same set of
packages to measure detection accuracy and performance.

Dataset:
  - 10 known-malicious packages (from OpenSSF malicious-packages)
  - 10 known-legitimate packages

For each package, both tools are executed and the results compared:
  - Recall: who detects more malicious packages?
  - Precision: who has fewer false positives?
  - Time: how fast is each tool?

Results are saved to tests/benchmarks/comparison_results.md

Run with:
    pytest -m benchmark -v -s

Do NOT run as part of the regular test suite.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import requests

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
_RESULTS_MD = _HERE / "comparison_results.md"
_RESULTS_JSON = _HERE / "comparison_results.json"

# ---------------------------------------------------------------------------
# Benchmark dataset — 20 packages
# ---------------------------------------------------------------------------

# 10 malicious packages (from OpenSSF dataset)
# Format: (ecosystem, name, version, osv_id)
_MALICIOUS_PACKAGES: list[tuple[str, str, str, str]] = [
    ("npm", "029testnpm", "1.0.0", "MAL-2025-1"),
    ("npm", "0maptrea", "latest", "MAL-2022-12"),
    ("npm", "0supportscolor", "latest", "MAL-2022-13"),
    ("npm", "--hiljson", "latest", "MAL-2022-2"),
    ("npm", "0x-fee-wrapper-contract", "latest", "MAL-2022-14"),
    ("npm", "0-dns", "latest", "MAL-2022-9"),
    ("npm", "0-shadowenv", "latest", "MAL-2022-10"),
    ("pypi", "littest", "0.1.0", "MAL-2023-8429"),
    ("npm", "ab-request", "latest", "MAL-2022-80"),
    ("npm", "abc-to-copy", "latest", "MAL-2022-82"),
]

# 10 legitimate packages (well-known, widely used)
# Format: (ecosystem, name, version)
_LEGITIMATE_PACKAGES: list[tuple[str, str, str]] = [
    ("npm", "is-odd", "3.0.1"),
    ("npm", "minimist", "1.2.8"),
    ("npm", "color-name", "1.1.4"),
    ("npm", "ms", "2.1.3"),
    ("npm", "escape-string-regexp", "4.0.0"),
    ("pypi", "six", "1.16.0"),
    ("pypi", "click", "8.1.7"),
    ("pypi", "idna", "3.7"),
    ("pypi", "certifi", "2024.2.2"),
    ("pypi", "charset-normalizer", "3.3.2"),
]


# ---------------------------------------------------------------------------
# Helper: check if package still exists on registry
# ---------------------------------------------------------------------------


def _package_exists(name: str, ecosystem: str) -> bool:
    """Return True if the package is still published on the registry."""
    try:
        if ecosystem == "npm":
            r = requests.get(
                f"https://registry.npmjs.org/{name}", timeout=15
            )
            if r.status_code == 404:
                return False
            data = r.json()
            return "error" not in data
        else:
            r = requests.get(
                f"https://pypi.org/pypi/{name}/json", timeout=15
            )
            return r.status_code == 200
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Helper: analyze with depshield
# ---------------------------------------------------------------------------


def _run_depshield(
    name: str, version: str, ecosystem: str
) -> tuple[PackageScore | None, float]:
    """Run depshield analysis on a single package.

    Returns (PackageScore or None, elapsed_seconds).
    """
    start = time.time()
    findings: list[Finding] = []

    with PackageDownloader() as dl:
        try:
            if version == "latest":
                if ecosystem == "npm":
                    meta = requests.get(
                        f"https://registry.npmjs.org/{name}", timeout=15
                    ).json()
                    version = meta.get("dist-tags", {}).get("latest", "0.0.0")
                else:
                    meta = requests.get(
                        f"https://pypi.org/pypi/{name}/json", timeout=15
                    ).json()
                    version = meta.get("info", {}).get("version", "0.0.0")

            src_dir = dl.download(name, version, ecosystem=ecosystem)
        except Exception as exc:
            log.warning("depshield download failed for %s@%s: %s", name, version, exc)
            return None, time.time() - start

        try:
            if ecosystem == "npm":
                findings.extend(js_analyze_dir(src_dir))
            else:
                findings.extend(py_analyze_dir(src_dir))
        except Exception as exc:
            log.warning("depshield analysis failed for %s: %s", name, exc)

    try:
        if ecosystem == "npm":
            meta = fetch_npm_metadata(name)
        else:
            meta = fetch_pypi_metadata(name)
        findings.extend(analyze_metadata(meta, name))
    except Exception as exc:
        log.warning("depshield metadata failed for %s: %s", name, exc)

    elapsed = time.time() - start
    score = score_package(name, version, findings, is_direct=True)
    return score, elapsed


# ---------------------------------------------------------------------------
# Helper: analyze with GuardDog
# ---------------------------------------------------------------------------


def _run_guarddog(
    name: str, ecosystem: str
) -> tuple[bool, int, float]:
    """Run GuardDog scan on a single package via subprocess.

    Returns (flagged: bool, num_issues: int, elapsed_seconds: float).
    ``flagged`` is True if GuardDog reports any issues.
    """
    eco_arg = "pypi" if ecosystem == "pypi" else "npm"
    cmd = [
        sys.executable, "-m", "guarddog",
        eco_arg, "scan", name,
    ]

    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        elapsed = time.time() - start

        output = result.stdout + result.stderr

        # GuardDog outputs JSON or text with issue counts
        # Try to parse JSON output first
        try:
            data = json.loads(result.stdout)
            # GuardDog JSON format: {"issues": N, ...} or list of issues
            if isinstance(data, dict):
                num_issues = data.get("issues", 0)
                if isinstance(num_issues, list):
                    num_issues = len(num_issues)
                elif isinstance(num_issues, dict):
                    num_issues = sum(len(v) if isinstance(v, list) else 1
                                     for v in num_issues.values())
            else:
                num_issues = len(data) if data else 0
            flagged = num_issues > 0
        except (json.JSONDecodeError, TypeError):
            # Fallback: check for keywords in text output
            output_lower = output.lower()
            flagged = any(
                kw in output_lower
                for kw in ["found", "issue", "malicious", "suspicious", "warning"]
            )
            # Try to extract number of issues from text
            import re
            match = re.search(r"(\d+)\s+issue", output_lower)
            num_issues = int(match.group(1)) if match else (1 if flagged else 0)

        return flagged, num_issues, elapsed

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        log.warning("GuardDog timed out for %s after %ds", name, elapsed)
        return False, 0, elapsed
    except FileNotFoundError:
        log.warning("GuardDog not installed or not found in PATH")
        return False, 0, 0.0
    except Exception as exc:
        elapsed = time.time() - start
        log.warning("GuardDog failed for %s: %s", name, exc)
        return False, 0, elapsed


# ---------------------------------------------------------------------------
# Result accumulator
# ---------------------------------------------------------------------------


@dataclass
class _ToolResult:
    """Results for one tool across all packages."""

    name: str
    tp: int = 0
    fn: int = 0
    tn: int = 0
    fp: int = 0
    total_time: float = 0.0
    details: list[dict[str, Any]] = field(default_factory=list)

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def avg_time(self) -> float:
        n = len(self.details)
        return self.total_time / n if n else 0.0


# Module-level accumulators
_depshield_results = _ToolResult(name="depshield")
_guarddog_results = _ToolResult(name="guarddog")


# ---------------------------------------------------------------------------
# Generate comparison report
# ---------------------------------------------------------------------------


def _generate_report() -> None:
    """Generate comparison_results.md and comparison_results.json."""

    ds = _depshield_results
    gd = _guarddog_results

    # --- Markdown report ---
    lines = [
        "# Benchmark: depshield vs GuardDog",
        "",
        "> **Auto-generated file** — do not edit manually.",
        "> Re-run with: `pytest -m benchmark -v -s`",
        "",
        "## Summary",
        "",
        "| Metric | depshield | GuardDog |",
        "|---|---|---|",
        f"| True Positives (TP) | {ds.tp} | {gd.tp} |",
        f"| False Negatives (FN) | {ds.fn} | {gd.fn} |",
        f"| True Negatives (TN) | {ds.tn} | {gd.tn} |",
        f"| False Positives (FP) | {ds.fp} | {gd.fp} |",
        f"| **Precision** | **{ds.precision:.2%}** | **{gd.precision:.2%}** |",
        f"| **Recall** | **{ds.recall:.2%}** | **{gd.recall:.2%}** |",
        f"| **F1-Score** | **{ds.f1:.2%}** | **{gd.f1:.2%}** |",
        f"| Avg time/package | {ds.avg_time:.2f}s | {gd.avg_time:.2f}s |",
        f"| Total time | {ds.total_time:.2f}s | {gd.total_time:.2f}s |",
        "",
        "## Detailed results — Malicious packages",
        "",
        "| Package | Ecosystem | depshield score | depshield | GuardDog issues | GuardDog |",
        "|---|---|---|---|---|---|",
    ]

    for detail in ds.details:
        if detail["expected"] != "malicious":
            continue
        name = detail["name"]
        eco = detail["ecosystem"]
        ds_score = detail.get("depshield_score", "N/A")
        ds_class = detail.get("depshield_class", "SKIP")
        ds_flag = "✅" if detail.get("depshield_flagged") else "❌"

        # Find matching guarddog detail
        gd_detail = next(
            (d for d in gd.details if d["name"] == name and d["expected"] == "malicious"),
            {},
        )
        gd_issues = gd_detail.get("guarddog_issues", "N/A")
        gd_flag = "✅" if gd_detail.get("guarddog_flagged") else "❌"

        lines.append(
            f"| {name} | {eco} | {ds_score} ({ds_class}) | {ds_flag} | {gd_issues} | {gd_flag} |"
        )

    lines.extend([
        "",
        "## Detailed results — Legitimate packages",
        "",
        "| Package | Ecosystem | depshield score | depshield | GuardDog issues | GuardDog |",
        "|---|---|---|---|---|---|",
    ])

    for detail in ds.details:
        if detail["expected"] != "legitimate":
            continue
        name = detail["name"]
        eco = detail["ecosystem"]
        ds_score = detail.get("depshield_score", "N/A")
        ds_class = detail.get("depshield_class", "SAFE")
        ds_ok = "✅" if not detail.get("depshield_flagged") else "❌ FP"

        gd_detail = next(
            (d for d in gd.details if d["name"] == name and d["expected"] == "legitimate"),
            {},
        )
        gd_issues = gd_detail.get("guarddog_issues", 0)
        gd_ok = "✅" if not gd_detail.get("guarddog_flagged") else "❌ FP"

        lines.append(
            f"| {name} | {eco} | {ds_score} ({ds_class}) | {ds_ok} | {gd_issues} | {gd_ok} |"
        )

    lines.extend([
        "",
        "## Interpretation",
        "",
        "- **Precision**: Of the packages flagged as malicious, how many were actually malicious?",
        "- **Recall**: Of the actually malicious packages, how many were detected?",
        "- **F1-Score**: Harmonic mean of Precision and Recall (overall balance).",
        "- ✅ = correct result, ❌ = incorrect result, ❌ FP = false positive.",
        "",
        "## Notes",
        "",
        "- Many malicious packages are removed from registries after being reported.",
        "  Packages that could not be downloaded are excluded from the comparison.",
        "- GuardDog is invoked via `python -m guarddog {ecosystem} scan {name}`.",
        "- depshield analyzes both source code (AST) and metadata; GuardDog uses Semgrep rules.",
        "- Times include network latency (download + API calls).",
        "",
    ])

    _RESULTS_MD.write_text("\n".join(lines), encoding="utf-8")

    # --- JSON report ---
    json_data = {
        "depshield": {
            "tp": ds.tp, "fn": ds.fn, "tn": ds.tn, "fp": ds.fp,
            "precision": round(ds.precision, 4),
            "recall": round(ds.recall, 4),
            "f1_score": round(ds.f1, 4),
            "total_time_s": round(ds.total_time, 2),
            "avg_time_s": round(ds.avg_time, 2),
        },
        "guarddog": {
            "tp": gd.tp, "fn": gd.fn, "tn": gd.tn, "fp": gd.fp,
            "precision": round(gd.precision, 4),
            "recall": round(gd.recall, 4),
            "f1_score": round(gd.f1, 4),
            "total_time_s": round(gd.total_time, 2),
            "avg_time_s": round(gd.avg_time, 2),
        },
        "details": ds.details,
    }
    _RESULTS_JSON.write_text(
        json.dumps(json_data, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Tests: malicious packages
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
class TestBenchmarkMalicious:
    """Compare depshield vs GuardDog on known-malicious packages."""

    @pytest.fixture(autouse=True)
    def _rate_limit(self):
        """Sleep between tests to respect API rate limits."""
        yield
        time.sleep(2.0)

    @pytest.mark.parametrize(
        "ecosystem,name,version,osv_id",
        _MALICIOUS_PACKAGES,
        ids=[f"{e}/{n}" for e, n, _, _ in _MALICIOUS_PACKAGES],
    )
    def test_malicious(self, ecosystem, name, version, osv_id):
        """Run both tools on a known-malicious package and record results."""
        # Check availability
        if not _package_exists(name, ecosystem):
            detail = {
                "name": name,
                "ecosystem": ecosystem,
                "expected": "malicious",
                "osv_id": osv_id,
                "skipped": True,
                "reason": "removed from registry",
            }
            _depshield_results.details.append(detail)
            _guarddog_results.details.append(detail)
            pytest.skip(f"{name} removed from {ecosystem} registry")
            return

        # --- depshield ---
        ds_score, ds_time = _run_depshield(name, version, ecosystem)
        _depshield_results.total_time += ds_time

        if ds_score is None:
            ds_flagged = False
            ds_score_val = 0
            ds_class = "SKIP"
        else:
            ds_flagged = ds_score.score >= 31
            ds_score_val = ds_score.score
            ds_class = ds_score.classification

        if ds_flagged:
            _depshield_results.tp += 1
        else:
            _depshield_results.fn += 1

        # --- GuardDog ---
        gd_flagged, gd_issues, gd_time = _run_guarddog(name, ecosystem)
        _guarddog_results.total_time += gd_time

        if gd_flagged:
            _guarddog_results.tp += 1
        else:
            _guarddog_results.fn += 1

        # Record details
        detail = {
            "name": name,
            "ecosystem": ecosystem,
            "expected": "malicious",
            "osv_id": osv_id,
            "skipped": False,
            "depshield_score": ds_score_val,
            "depshield_class": ds_class,
            "depshield_flagged": ds_flagged,
            "depshield_time_s": round(ds_time, 2),
            "guarddog_flagged": gd_flagged,
            "guarddog_issues": gd_issues,
            "guarddog_time_s": round(gd_time, 2),
        }
        _depshield_results.details.append(detail)
        _guarddog_results.details.append(detail)

        # Save incremental results
        _generate_report()

        # Log progress
        print(
            f"\n  {name} ({ecosystem}): "
            f"depshield={ds_score_val} ({ds_class}) [{ds_time:.1f}s] | "
            f"guarddog={'FLAGGED' if gd_flagged else 'CLEAN'} "
            f"({gd_issues} issues) [{gd_time:.1f}s]"
        )


# ---------------------------------------------------------------------------
# Tests: legitimate packages
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
class TestBenchmarkLegitimate:
    """Compare depshield vs GuardDog on known-legitimate packages."""

    @pytest.fixture(autouse=True)
    def _rate_limit(self):
        """Sleep between tests to respect API rate limits."""
        yield
        time.sleep(2.0)

    @pytest.mark.parametrize(
        "ecosystem,name,version",
        _LEGITIMATE_PACKAGES,
        ids=[f"{e}/{n}" for e, n, _ in _LEGITIMATE_PACKAGES],
    )
    def test_legitimate(self, ecosystem, name, version):
        """Run both tools on a known-legitimate package and record results."""
        # --- depshield ---
        ds_score, ds_time = _run_depshield(name, version, ecosystem)
        _depshield_results.total_time += ds_time

        if ds_score is None:
            ds_flagged = False
            ds_score_val = 0
            ds_class = "SKIP"
        else:
            ds_flagged = ds_score.score >= 31
            ds_score_val = ds_score.score
            ds_class = ds_score.classification

        if ds_flagged:
            _depshield_results.fp += 1
        else:
            _depshield_results.tn += 1

        # --- GuardDog ---
        gd_flagged, gd_issues, gd_time = _run_guarddog(name, ecosystem)
        _guarddog_results.total_time += gd_time

        if gd_flagged:
            _guarddog_results.fp += 1
        else:
            _guarddog_results.tn += 1

        # Record details
        detail = {
            "name": name,
            "ecosystem": ecosystem,
            "expected": "legitimate",
            "skipped": False,
            "depshield_score": ds_score_val,
            "depshield_class": ds_class,
            "depshield_flagged": ds_flagged,
            "depshield_time_s": round(ds_time, 2),
            "guarddog_flagged": gd_flagged,
            "guarddog_issues": gd_issues,
            "guarddog_time_s": round(gd_time, 2),
        }
        _depshield_results.details.append(detail)
        _guarddog_results.details.append(detail)

        # Save incremental results
        _generate_report()

        # Log progress
        print(
            f"\n  {name} ({ecosystem}): "
            f"depshield={ds_score_val} ({ds_class}) [{ds_time:.1f}s] | "
            f"guarddog={'FLAGGED' if gd_flagged else 'CLEAN'} "
            f"({gd_issues} issues) [{gd_time:.1f}s]"
        )


# ---------------------------------------------------------------------------
# Summary — generate final comparison report
# ---------------------------------------------------------------------------


@pytest.mark.benchmark
class TestBenchmarkSummary:
    """Generate the final comparison report."""

    def test_generate_comparison_report(self):
        """Save comparison_results.md and comparison_results.json."""
        _generate_report()

        assert _RESULTS_MD.exists(), "comparison_results.md should exist"
        assert _RESULTS_JSON.exists(), "comparison_results.json should exist"

        ds = _depshield_results
        gd = _guarddog_results

        print(f"\n{'='*70}")
        print(f"  BENCHMARK: depshield vs GuardDog")
        print(f"{'='*70}")
        print(f"  {'':30s} {'depshield':>12s} {'GuardDog':>12s}")
        print(f"  {'-'*54}")
        print(f"  {'True Positives (TP)':30s} {ds.tp:>12d} {gd.tp:>12d}")
        print(f"  {'False Negatives (FN)':30s} {ds.fn:>12d} {gd.fn:>12d}")
        print(f"  {'True Negatives (TN)':30s} {ds.tn:>12d} {gd.tn:>12d}")
        print(f"  {'False Positives (FP)':30s} {ds.fp:>12d} {gd.fp:>12d}")
        print(f"  {'-'*54}")
        print(f"  {'Precision':30s} {ds.precision:>11.2%} {gd.precision:>11.2%}")
        print(f"  {'Recall':30s} {ds.recall:>11.2%} {gd.recall:>11.2%}")
        print(f"  {'F1-Score':30s} {ds.f1:>11.2%} {gd.f1:>11.2%}")
        print(f"  {'-'*54}")
        print(f"  {'Avg time/package':30s} {ds.avg_time:>10.2f}s {gd.avg_time:>10.2f}s")
        print(f"  {'Total time':30s} {ds.total_time:>10.2f}s {gd.total_time:>10.2f}s")
        print(f"{'='*70}")
        print(f"\n  Report saved to: {_RESULTS_MD}")
        print(f"  JSON saved to:   {_RESULTS_JSON}\n")
