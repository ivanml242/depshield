"""Demonstration tests: PASSED vs FAILED.

Contains tests designed to fail on purpose, to show how pytest
reports errors and how to read its output.

Not part of the regular test suite -- used for TFG documentation only.

Run with:
    pytest tests/test_demo_failures.py -v --tb=long
"""

import json
from pathlib import Path

import pytest

from depshield.analyzers.js_analyzer import Finding
from depshield.analyzers.py_analyzer import analyze_file as py_analyze_file
from depshield.analyzers.metadata_analyzer import analyze_metadata, _levenshtein
from depshield.scoring.scorer import score_package, _classify


# Tests that PASS (baseline for comparison)


class TestRefPassed:
    """These tests pass correctly as a baseline."""

    def test_classify_safe(self):
        """Score 0 should classify as SAFE."""
        assert _classify(0) == "SAFE"

    def test_score_empty_findings(self):
        """No findings should give a score of 0."""
        result = score_package("pkg", "1.0.0", [])
        assert result.score == 0


# Tests that FAIL on purpose (for demonstration)


class TestDemoFailures:
    """These tests are deliberately wrong to show pytest failure output."""

    # --- FAIL 1: Wrong expected value ---
    def test_fail_wrong_classification(self):
        """FAILS: expects 'DANGEROUS' but the function returns 'HIGH_RISK'.

        Simulates a developer writing the wrong classification name.
        _classify(61) returns 'HIGH_RISK', not 'DANGEROUS'.
        """
        result = _classify(61)
        # WRONG: "DANGEROUS" is not a valid classification
        # should be: assert result == "HIGH_RISK"
        assert result == "DANGEROUS", (
            f"Se esperaba 'DANGEROUS' pero se obtuvo '{result}'"
        )

    # --- FAIL 2: Wrong score value ---
    def test_fail_wrong_score_calculation(self):
        """FAILS: expects 2 HIGH findings to sum 40, but they sum 50.

        Simulates a developer assuming HIGH = 20 points, when it's
        actually 25. So 2 x 25 = 50, not 40.
        """
        findings = [
            Finding("CODE_EXECUTION", "HIGH", "a.js", 1, "eval(x)"),
            Finding("NETWORK_CALLS", "HIGH", "a.js", 2, "fetch(url)"),
        ]
        result = score_package("test-pkg", "1.0.0", findings)
        # WRONG: 2 x HIGH(25) = 50, not 40
        assert result.score == 40, (
            f"Se esperaba score=40 pero se obtuvo score={result.score}. "
            f"(2 findings HIGH × 25 = 50, no 40)"
        )

    # --- FAIL 3: Wrong data type ---
    def test_fail_findings_type(self):
        """FAILS: expects findings to be a dict, but it's a list.

        Simulates a developer confusing PackageScore.findings (list)
        with findings_by_severity (dict).
        """
        result = score_package("pkg", "1.0.0", [
            Finding("CODE_EXECUTION", "HIGH", "a.py", 1, "eval(x)"),
        ])
        # WRONG: findings is list[Finding], not dict
        assert isinstance(result.findings, dict), (
            f"Se esperaba dict pero se obtuvo {type(result.findings).__name__}. "
            f"Nota: findings_by_severity sí retorna dict."
        )

    # --- FAIL 4: False negative ---
    def test_fail_undetected_obfuscation(self, tmp_path):
        """FAILS: expects print() to be flagged as obfuscation, but it's not.

        Simulates a developer expecting print() to be suspicious, when
        actually the analyzer correctly ignores standard functions.
        """
        py_file = tmp_path / "normal.py"
        py_file.write_text("print('hello world')\n", encoding="utf-8")
        findings = py_analyze_file(str(py_file))
        # WRONG: print() is not obfuscation
        obfuscation = [f for f in findings if f.signal_type == "OBFUSCATION"]
        assert len(obfuscation) >= 1, (
            "Se esperaba que print() generara un finding de OBFUSCATION, "
            "pero el analizador correctamente no lo detecta como sospechoso."
        )

    # --- FAIL 5: Algorithm misunderstanding ---
    def test_fail_levenshtein_wrong_distance(self):
        """FAILS: assumes the distance between 'lodash' and 'lodasj' is 2.

        One substitution (h -> j) costs 1 edit in Levenshtein, not 2.
        """
        dist = _levenshtein("lodash", "lodasj")
        # WRONG: one substitution = distance 1, not 2
        assert dist == 2, (
            f"Se esperaba distancia=2 pero se obtuvo distancia={dist}. "
            f"Una sustitución ('h'→'j') cuenta como 1 operación, no 2."
        )
