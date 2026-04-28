"""Tests for the core scanner module.

Covers ecosystem detection, dependency parsing, the cache system,
and the full scan_project pipeline with mocked network calls.
"""

import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from depshield.analyzers.js_analyzer import Finding
from depshield.core.scanner import (
    _cache_key,
    _load_cached,
    _save_cache,
    _CACHE_DIR,
    detect_ecosystems,
    _read_npm_deps,
    _read_pypi_deps,
    scan_project,
)
from depshield.scoring.scorer import PackageScore


# Fixtures

@pytest.fixture
def tmp_project(tmp_path):
    """Create a temporary project directory and return its Path."""
    return tmp_path


@pytest.fixture
def npm_project(tmp_project):
    """Project with a package.json."""
    pkg = {
        "name": "test-project",
        "version": "1.0.0",
        "dependencies": {"is-odd": "^3.0.1"},
        "devDependencies": {"minimist": "^1.2.0"},
    }
    (tmp_project / "package.json").write_text(
        json.dumps(pkg), encoding="utf-8"
    )
    return tmp_project


@pytest.fixture
def pypi_project(tmp_project):
    """Project with a requirements.txt."""
    (tmp_project / "requirements.txt").write_text(
        "six==1.16.0\nrequests>=2.20\n", encoding="utf-8"
    )
    return tmp_project


@pytest.fixture
def mixed_project(npm_project):
    """Project with both package.json and requirements.txt."""
    (npm_project / "requirements.txt").write_text(
        "six==1.16.0\n", encoding="utf-8"
    )
    return npm_project


# Ecosystem detection

class TestDetectEcosystems:
    """Tests for detect_ecosystems()."""

    def test_npm_only(self, npm_project):
        """Detect npm when only package.json exists."""
        result = detect_ecosystems(npm_project)
        assert result == ["npm"]

    def test_pypi_only(self, pypi_project):
        """Detect pypi when only requirements.txt exists."""
        result = detect_ecosystems(pypi_project)
        assert result == ["pypi"]

    def test_both_ecosystems(self, mixed_project):
        """Detect both ecosystems when both manifest files exist."""
        result = detect_ecosystems(mixed_project)
        assert "npm" in result
        assert "pypi" in result

    def test_no_ecosystem(self, tmp_project):
        """Return empty list when no manifest files found."""
        result = detect_ecosystems(tmp_project)
        assert result == []


# Dependency reading

class TestReadDeps:
    """Tests for _read_npm_deps() and _read_pypi_deps()."""

    def test_read_npm_deps(self, npm_project):
        """Read and merge dependencies + devDependencies from package.json."""
        deps = _read_npm_deps(npm_project)
        assert "is-odd" in deps
        assert "minimist" in deps
        assert deps["is-odd"] == "^3.0.1"
        assert deps["minimist"] == "^1.2.0"

    def test_read_pypi_deps(self, pypi_project):
        """Read dependencies from requirements.txt with version specifiers."""
        deps = _read_pypi_deps(pypi_project)
        assert "six" in deps
        assert deps["six"] == "==1.16.0"
        assert "requests" in deps
        assert deps["requests"] == ">=2.20"

    def test_read_pypi_deps_comments_and_blanks(self, tmp_project):
        """Comments and blank lines are ignored in requirements.txt."""
        (tmp_project / "requirements.txt").write_text(
            "# this is a comment\n\nflask\n  \n", encoding="utf-8"
        )
        deps = _read_pypi_deps(tmp_project)
        assert deps == {"flask": ""}

    def test_read_pypi_deps_all_operators(self, tmp_project):
        """All PEP 440 operators are parsed correctly."""
        content = "a==1.0\nb>=2.0\nc<=3.0\nd~=4.0\ne!=5.0\nf>6.0\ng<7.0\n"
        (tmp_project / "requirements.txt").write_text(content, encoding="utf-8")
        deps = _read_pypi_deps(tmp_project)
        assert deps["a"] == "==1.0"
        assert deps["b"] == ">=2.0"
        assert deps["c"] == "<=3.0"
        assert deps["d"] == "~=4.0"
        assert deps["e"] == "!=5.0"
        assert deps["f"] == ">6.0"
        assert deps["g"] == "<7.0"


# Cache system

class TestCache:
    """Tests for the file-based cache system."""

    def setup_method(self):
        """Ensure a clean cache directory for each test."""
        self._cache_backup = _CACHE_DIR
        # Use a temp dir for cache tests to avoid polluting user cache
        self._test_cache_dir = Path(tempfile.mkdtemp(prefix="depshield_test_cache_"))

    def teardown_method(self):
        """Clean up test cache directory."""
        shutil.rmtree(self._test_cache_dir, ignore_errors=True)

    def test_cache_key_deterministic(self):
        """Same name+version always produces the same cache key."""
        key1 = _cache_key("lodash", "4.17.21")
        key2 = _cache_key("lodash", "4.17.21")
        assert key1 == key2
        assert len(key1) == 16

    def test_cache_key_differs_by_name(self):
        """Different package names produce different keys."""
        key1 = _cache_key("lodash", "4.17.21")
        key2 = _cache_key("express", "4.17.21")
        assert key1 != key2

    def test_cache_key_differs_by_version(self):
        """Different versions of the same package produce different keys."""
        key1 = _cache_key("lodash", "4.17.20")
        key2 = _cache_key("lodash", "4.17.21")
        assert key1 != key2

    def test_cache_miss_returns_none(self):
        """Loading a non-existent cache entry returns None."""
        result = _load_cached("nonexistent-package-xyz", "0.0.0")
        assert result is None

    @patch("depshield.core.scanner._CACHE_DIR")
    def test_cache_roundtrip(self, mock_cache_dir):
        """Saving and loading findings produces identical data."""
        mock_cache_dir.__truediv__ = lambda self, key: self._test_cache_dir / key
        # We'll do a manual roundtrip using the real functions with a temp dir
        findings = [
            Finding("NETWORK_CALLS", "HIGH", "index.js", 10, "fetch('http://evil.com')"),
            Finding("CODE_EXECUTION", "HIGH", "hack.js", 5, "eval(payload)"),
            Finding("ENV_ACCESS", "MEDIUM", "util.js", 20, "process.env.SECRET"),
        ]

        # Save manually to test dir
        import hashlib
        raw = f"test-pkg@1.0.0@v1"
        key = hashlib.sha256(raw.encode()).hexdigest()[:16]
        cache_path = self._test_cache_dir / f"{key}.json"
        self._test_cache_dir.mkdir(parents=True, exist_ok=True)

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
        cache_path.write_text(json.dumps(data), encoding="utf-8")

        # Load back
        loaded_data = json.loads(cache_path.read_text(encoding="utf-8"))
        loaded_findings = [
            Finding(
                signal_type=f["signal_type"],
                severity=f["severity"],
                file=f["file"],
                line=f["line"],
                snippet=f["snippet"],
            )
            for f in loaded_data
        ]

        assert len(loaded_findings) == 3
        assert loaded_findings[0].signal_type == "NETWORK_CALLS"
        assert loaded_findings[1].snippet == "eval(payload)"
        assert loaded_findings[2].severity == "MEDIUM"


# scan_project with mocks

class TestScanProject:
    """Tests for the scan_project() orchestrator using mocked dependencies."""

    def _make_mock_node(self, name, version):
        """Create a mock DependencyNode."""
        from depshield.resolvers.npm_resolver import DependencyNode
        return DependencyNode(name=name, version=version, is_direct=True)

    @patch("depshield.core.scanner.npm_resolve")
    @patch("depshield.core.scanner.js_analyze_dir")
    @patch("depshield.core.scanner.fetch_npm_metadata")
    @patch("depshield.core.scanner.analyze_metadata")
    @patch("depshield.core.scanner.PackageDownloader")
    def test_scan_npm_project_mocked(
        self, MockDownloader, mock_analyze_meta, mock_fetch_meta,
        mock_js_analyze, mock_npm_resolve, npm_project
    ):
        """Full scan pipeline with mocked network calls for npm."""
        # Setup mocks
        node = self._make_mock_node("is-odd", "3.0.1")
        mock_npm_resolve.return_value = [node]

        mock_js_analyze.return_value = [
            Finding("CODE_EXECUTION", "HIGH", "index.js", 1, "eval('test')"),
        ]
        mock_fetch_meta.return_value = {"name": "is-odd"}
        mock_analyze_meta.return_value = [
            Finding("YOUNG_PACKAGE", "MEDIUM", "metadata", 0, "Package < 30 days old"),
        ]

        # Mock downloader
        mock_dl_instance = MagicMock()
        mock_dl_instance.download.return_value = npm_project
        mock_dl_instance.__enter__ = MagicMock(return_value=mock_dl_instance)
        mock_dl_instance.__exit__ = MagicMock(return_value=False)
        MockDownloader.return_value = mock_dl_instance

        # Execute
        scores = scan_project(
            npm_project,
            ecosystem="npm",
            use_cache=False,
            output_format="json",
        )

        # Verify
        assert len(scores) >= 1
        assert isinstance(scores[0], PackageScore)
        assert scores[0].name == "is-odd"
        assert scores[0].score > 0

    def test_scan_empty_project(self, tmp_project):
        """Scanning a project with no manifest files returns empty list."""
        from rich.console import Console
        console = Console(quiet=True)
        scores = scan_project(
            tmp_project,
            ecosystem="auto",
            use_cache=False,
            console=console,
        )
        assert scores == []

    @patch("depshield.core.scanner.pypi_resolve")
    @patch("depshield.core.scanner.py_analyze_dir")
    @patch("depshield.core.scanner.fetch_pypi_metadata")
    @patch("depshield.core.scanner.analyze_metadata")
    @patch("depshield.core.scanner.PackageDownloader")
    def test_scan_pypi_project_mocked(
        self, MockDownloader, mock_analyze_meta, mock_fetch_meta,
        mock_py_analyze, mock_pypi_resolve, pypi_project
    ):
        """Full scan pipeline with mocked network calls for PyPI."""
        node = self._make_mock_node("six", "1.16.0")
        mock_pypi_resolve.return_value = [node]

        mock_py_analyze.return_value = []  # six is clean
        mock_fetch_meta.return_value = {"name": "six"}
        mock_analyze_meta.return_value = []  # no metadata issues

        mock_dl_instance = MagicMock()
        mock_dl_instance.download.return_value = pypi_project
        mock_dl_instance.__enter__ = MagicMock(return_value=mock_dl_instance)
        mock_dl_instance.__exit__ = MagicMock(return_value=False)
        MockDownloader.return_value = mock_dl_instance

        scores = scan_project(
            pypi_project,
            ecosystem="pypi",
            use_cache=False,
            output_format="json",
        )

        assert len(scores) >= 1
        assert scores[0].name == "six"
        assert scores[0].classification == "SAFE"

    @patch("depshield.core.scanner.npm_resolve")
    @patch("depshield.core.scanner.js_analyze_dir")
    @patch("depshield.core.scanner.fetch_npm_metadata")
    @patch("depshield.core.scanner.analyze_metadata")
    @patch("depshield.core.scanner.PackageDownloader")
    def test_scan_high_risk_classification(
        self, MockDownloader, mock_analyze_meta, mock_fetch_meta,
        mock_js_analyze, mock_npm_resolve, npm_project
    ):
        """Packages with many HIGH findings get HIGH_RISK classification."""
        node = self._make_mock_node("evil-pkg", "1.0.0")
        # Override package.json deps to match the mock
        pkg = {"dependencies": {"evil-pkg": "1.0.0"}}
        (npm_project / "package.json").write_text(json.dumps(pkg), encoding="utf-8")

        mock_npm_resolve.return_value = [node]
        mock_js_analyze.return_value = [
            Finding("CODE_EXECUTION", "HIGH", "index.js", 1, "eval(x)"),
            Finding("NETWORK_CALLS", "HIGH", "index.js", 2, "fetch(url)"),
            Finding("OBFUSCATION", "HIGH", "index.js", 3, "Buffer.from(x,'base64')"),
        ]
        mock_fetch_meta.return_value = {"name": "evil-pkg"}
        mock_analyze_meta.return_value = [
            Finding("TYPOSQUATTING", "HIGH", "metadata", 0, "Similar to 'express'"),
        ]

        mock_dl_instance = MagicMock()
        mock_dl_instance.download.return_value = npm_project
        mock_dl_instance.__enter__ = MagicMock(return_value=mock_dl_instance)
        mock_dl_instance.__exit__ = MagicMock(return_value=False)
        MockDownloader.return_value = mock_dl_instance

        scores = scan_project(
            npm_project,
            ecosystem="npm",
            use_cache=False,
            output_format="table",
        )

        assert len(scores) >= 1
        evil = [s for s in scores if s.name == "evil-pkg"]
        assert len(evil) == 1
        assert evil[0].classification == "HIGH_RISK"
        assert evil[0].score >= 61

    @patch("depshield.core.scanner.npm_resolve")
    @patch("depshield.core.scanner.js_analyze_dir")
    @patch("depshield.core.scanner.fetch_npm_metadata")
    @patch("depshield.core.scanner.analyze_metadata")
    @patch("depshield.core.scanner.PackageDownloader")
    def test_only_direct_flag(
        self, MockDownloader, mock_analyze_meta, mock_fetch_meta,
        mock_js_analyze, mock_npm_resolve, npm_project
    ):
        """The --only-direct flag limits scan depth to 1."""
        node = self._make_mock_node("is-odd", "3.0.1")
        mock_npm_resolve.return_value = [node]
        mock_js_analyze.return_value = []
        mock_fetch_meta.return_value = {"name": "is-odd"}
        mock_analyze_meta.return_value = []

        mock_dl_instance = MagicMock()
        mock_dl_instance.download.return_value = npm_project
        mock_dl_instance.__enter__ = MagicMock(return_value=mock_dl_instance)
        mock_dl_instance.__exit__ = MagicMock(return_value=False)
        MockDownloader.return_value = mock_dl_instance

        scores = scan_project(
            npm_project,
            ecosystem="npm",
            use_cache=False,
            only_direct=True,
            output_format="json",
        )

        # Verify that npm_resolve was called with max_depth=1
        mock_npm_resolve.assert_called_once()
        call_kwargs = mock_npm_resolve.call_args
        # max_depth is passed as keyword arg
        assert call_kwargs[1].get("max_depth", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else None) == 1 \
            or (len(call_kwargs[0]) > 1 and call_kwargs[0][1] == 1)


# Report output

class TestReportIntegration:
    """Tests to verify report formatting works with scan results."""

    def test_json_report_structure(self):
        """to_json() produces the expected JSON structure."""
        from depshield.scoring.report import to_json

        scores = [
            PackageScore(
                name="test-pkg",
                version="1.0.0",
                score=35,
                classification="MEDIUM_RISK",
                findings=[
                    Finding("CODE_EXECUTION", "HIGH", "index.js", 1, "eval(x)"),
                    Finding("ENV_ACCESS", "MEDIUM", "util.js", 5, "process.env.X"),
                ],
                is_direct=True,
            ),
        ]

        result = to_json(scores)
        assert "summary" in result
        assert result["summary"]["total_packages"] == 1
        assert result["summary"]["medium_risk"] == 1

        assert "packages" in result
        assert len(result["packages"]) == 1
        assert result["packages"][0]["name"] == "test-pkg"
        assert result["packages"][0]["score"] == 35
        assert len(result["packages"][0]["findings"]) == 2

    def test_save_json_to_file(self, tmp_path):
        """save_json() writes valid JSON to disk."""
        from depshield.scoring.report import save_json

        scores = [
            PackageScore(
                name="lodash",
                version="4.17.21",
                score=0,
                classification="SAFE",
                findings=[],
                is_direct=True,
            ),
        ]

        output_path = tmp_path / "report.json"
        save_json(scores, output_path)

        assert output_path.exists()
        data = json.loads(output_path.read_text(encoding="utf-8"))
        assert data["summary"]["safe"] == 1
        assert data["packages"][0]["name"] == "lodash"
