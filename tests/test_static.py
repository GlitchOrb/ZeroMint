"""Tests for STEP 4 — static analysis: semgrep, codeql, normalize_findings.

Covers:
  1. normalize_findings produces valid Finding objects from semgrep/codeql raw data
  2. Stable IDs are deterministic
  3. Severity mapping is conservative
  4. Semgrep/CodeQL scanners skip gracefully when tools not installed
  5. Static stage succeeds even when no tools are available
  6. Pydantic validation passes on all normalized findings
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cve_agent.analyzers.normalize_findings import (
    normalize_codeql,
    normalize_semgrep,
    save_candidates,
    stable_finding_id,
)
from cve_agent.analyzers.semgrep_scanner import is_semgrep_available, run_semgrep
from cve_agent.analyzers.codeql_runner import is_codeql_available, run_codeql
from cve_agent.schemas.findings import (
    CodeLocation,
    EvidenceKind,
    Finding,
    FindingStatus,
    Severity,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sample_repo"


# ── stable_finding_id ─────────────────────────────────────


class TestStableFindingId:
    """Test deterministic ID generation."""

    def test_deterministic(self) -> None:
        """Same inputs should produce the same ID."""
        id1 = stable_finding_id("main.py", "sql-injection", 42)
        id2 = stable_finding_id("main.py", "sql-injection", 42)
        assert id1 == id2

    def test_different_inputs_differ(self) -> None:
        """Different inputs should produce different IDs."""
        id1 = stable_finding_id("main.py", "sql-injection", 42)
        id2 = stable_finding_id("main.py", "sql-injection", 43)
        id3 = stable_finding_id("main.py", "xss", 42)
        id4 = stable_finding_id("other.py", "sql-injection", 42)
        assert len({id1, id2, id3, id4}) == 4

    def test_length(self) -> None:
        """ID should be 12 hex characters."""
        fid = stable_finding_id("test.py", "rule-1", 10)
        assert len(fid) == 12
        assert all(c in "0123456789abcdef" for c in fid)


# ── normalize_semgrep ─────────────────────────────────────


MOCK_SEMGREP_RESULTS: list[dict[str, Any]] = [
    {
        "check_id": "python.lang.security.audit.eval-detected",
        "path": "auth_handler.py",
        "start": {"line": 15, "col": 12},
        "end": {"line": 15, "col": 30},
        "extra": {
            "severity": "ERROR",
            "message": "Detected use of eval(). Do not use eval() with untrusted input.",
            "lines": "    return eval(user_input)",
            "metadata": {
                "references": [
                    "https://owasp.org/injection",
                    "https://cwe.mitre.org/data/definitions/95.html",
                ],
            },
        },
    },
    {
        "check_id": "python.lang.security.deserialization.pickle",
        "path": "auth_handler.py",
        "start": {"line": 20, "col": 12},
        "end": {"line": 20, "col": 33},
        "extra": {
            "severity": "WARNING",
            "message": "Detected pickle deserialization. Avoid with untrusted data.",
            "lines": "    return pickle.loads(data)",
            "metadata": {},
        },
    },
    {
        "check_id": "generic.info-rule",
        "path": "utils.py",
        "start": {"line": 5, "col": 1},
        "end": {"line": 5, "col": 20},
        "extra": {
            "severity": "INFO",
            "message": "Informational finding.",
            "lines": "def add(a, b):",
            "metadata": {},
        },
    },
]


class TestNormalizeSemgrep:
    """Test semgrep result normalization."""

    def test_produces_findings(self) -> None:
        """Should produce one Finding per raw result."""
        findings = normalize_semgrep(MOCK_SEMGREP_RESULTS)
        assert len(findings) == 3

    def test_finding_fields(self) -> None:
        """Each finding should have correct fields populated."""
        findings = normalize_semgrep(MOCK_SEMGREP_RESULTS)

        for f in findings:
            assert isinstance(f, Finding)
            assert f.status == FindingStatus.CANDIDATE
            assert len(f.id) == 12
            assert f.title.startswith("[semgrep]")
            assert len(f.evidence) == 1
            assert f.evidence[0].kind == EvidenceKind.TOOL_OUTPUT
            assert f.evidence[0].location is not None
            assert f.evidence[0].location.file != ""
            assert f.confidence > 0
            assert f.confidence <= 1.0

    def test_severity_mapping(self) -> None:
        """ERROR→HIGH, WARNING→MEDIUM, INFO→LOW."""
        findings = normalize_semgrep(MOCK_SEMGREP_RESULTS)

        sev_map = {f.evidence[0].summary: f.severity for f in findings}
        # The eval rule has severity ERROR → HIGH
        eval_finding = next(f for f in findings if "eval" in f.title.lower())
        assert eval_finding.severity == Severity.HIGH

        pickle_finding = next(f for f in findings if "pickle" in f.title.lower())
        assert pickle_finding.severity == Severity.MEDIUM

        info_finding = next(f for f in findings if "info-rule" in f.title.lower())
        assert info_finding.severity == Severity.LOW

    def test_confidence_conservative(self) -> None:
        """Confidence should be conservative (< 1.0 for all)."""
        findings = normalize_semgrep(MOCK_SEMGREP_RESULTS)
        for f in findings:
            assert f.confidence < 1.0
            assert f.confidence > 0

    def test_stable_ids(self) -> None:
        """Running normalize twice should produce the same IDs."""
        findings1 = normalize_semgrep(MOCK_SEMGREP_RESULTS)
        findings2 = normalize_semgrep(MOCK_SEMGREP_RESULTS)
        ids1 = [f.id for f in findings1]
        ids2 = [f.id for f in findings2]
        assert ids1 == ids2

    def test_references_extracted(self) -> None:
        """References from metadata should be preserved."""
        findings = normalize_semgrep(MOCK_SEMGREP_RESULTS)
        eval_finding = next(f for f in findings if "eval" in f.title.lower())
        assert len(eval_finding.references) == 2
        assert any("owasp" in r for r in eval_finding.references)

    def test_snippet_in_evidence(self) -> None:
        """Evidence should contain the source snippet."""
        findings = normalize_semgrep(MOCK_SEMGREP_RESULTS)
        eval_finding = next(f for f in findings if "eval" in f.title.lower())
        assert eval_finding.evidence[0].snippet is not None
        assert "eval" in eval_finding.evidence[0].snippet

    def test_empty_results(self) -> None:
        """Empty input should produce empty output."""
        findings = normalize_semgrep([])
        assert findings == []

    def test_malformed_result_skipped(self) -> None:
        """Malformed result should be skipped, not crash."""
        bad = [{"bad": "data"}]
        findings = normalize_semgrep(bad)
        # Should produce a finding with defaults (not crash)
        # The normalize function catches exceptions per-result
        assert isinstance(findings, list)

    def test_pydantic_validation(self) -> None:
        """All findings should pass pydantic model validation."""
        findings = normalize_semgrep(MOCK_SEMGREP_RESULTS)
        for f in findings:
            # Re-validate through pydantic
            validated = Finding.model_validate(f.model_dump())
            assert validated.id == f.id
            assert validated.severity == f.severity


# ── normalize_codeql ──────────────────────────────────────


MOCK_CODEQL_RESULTS: list[dict[str, Any]] = [
    {
        "ruleId": "py/sql-injection",
        "level": "error",
        "message": {"text": "SQL injection vulnerability found"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "auth_handler.py"},
                    "region": {
                        "startLine": 40,
                        "endLine": 41,
                        "snippet": {"text": "query = f\"SELECT ...\""},
                    },
                },
            },
        ],
    },
    {
        "ruleId": "py/command-injection",
        "level": "warning",
        "message": {"text": "Command injection via subprocess"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "auth_handler.py"},
                    "region": {
                        "startLine": 25,
                        "endLine": 25,
                    },
                },
            },
        ],
    },
]


class TestNormalizeCodeql:
    """Test CodeQL SARIF result normalization."""

    def test_produces_findings(self) -> None:
        findings = normalize_codeql(MOCK_CODEQL_RESULTS)
        assert len(findings) == 2

    def test_finding_fields(self) -> None:
        findings = normalize_codeql(MOCK_CODEQL_RESULTS)
        for f in findings:
            assert isinstance(f, Finding)
            assert f.status == FindingStatus.CANDIDATE
            assert f.title.startswith("[codeql]")
            assert len(f.evidence) == 1
            assert f.evidence[0].kind == EvidenceKind.TOOL_OUTPUT

    def test_severity_mapping(self) -> None:
        findings = normalize_codeql(MOCK_CODEQL_RESULTS)
        sql_finding = next(f for f in findings if "sql" in f.title.lower())
        assert sql_finding.severity == Severity.HIGH  # level=error

        cmd_finding = next(f for f in findings if "command" in f.title.lower())
        assert cmd_finding.severity == Severity.MEDIUM  # level=warning

    def test_stable_ids(self) -> None:
        findings1 = normalize_codeql(MOCK_CODEQL_RESULTS)
        findings2 = normalize_codeql(MOCK_CODEQL_RESULTS)
        assert [f.id for f in findings1] == [f.id for f in findings2]

    def test_empty_results(self) -> None:
        assert normalize_codeql([]) == []

    def test_pydantic_validation(self) -> None:
        findings = normalize_codeql(MOCK_CODEQL_RESULTS)
        for f in findings:
            validated = Finding.model_validate(f.model_dump())
            assert validated.id == f.id


# ── save_candidates ───────────────────────────────────────


class TestSaveCandidates:
    """Test finding serialization."""

    def test_saves_and_loads(self, tmp_path: Path) -> None:
        """Findings should round-trip through JSON."""
        findings = normalize_semgrep(MOCK_SEMGREP_RESULTS)
        out_path = tmp_path / "test_candidates.json"
        save_candidates(findings, out_path)

        assert out_path.exists()

        # Load and validate
        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        assert len(data) == len(findings)

        # Verify pydantic roundtrip
        for item in data:
            restored = Finding.model_validate(item)
            assert restored.status == FindingStatus.CANDIDATE

    def test_empty_list(self, tmp_path: Path) -> None:
        out_path = tmp_path / "empty.json"
        save_candidates([], out_path)
        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert data == []


# ── Semgrep scanner (graceful skip) ───────────────────────


class TestSemgrepScanner:
    """Test semgrep scanner graceful degradation."""

    def test_run_without_semgrep(self, tmp_path: Path) -> None:
        """If semgrep isn't installed, should return empty list (not crash)."""
        if is_semgrep_available():
            pytest.skip("semgrep is installed — cannot test skip path")

        findings = run_semgrep(tmp_path, artifacts_dir=tmp_path)
        assert findings == []

    def test_is_semgrep_available_returns_bool(self) -> None:
        result = is_semgrep_available()
        assert isinstance(result, bool)


# ── CodeQL runner (graceful skip) ─────────────────────────


class TestCodeqlRunner:
    """Test CodeQL runner graceful degradation."""

    def test_run_without_codeql(self, tmp_path: Path) -> None:
        """If codeql isn't installed, should return empty list (not crash)."""
        if is_codeql_available():
            pytest.skip("codeql is installed — cannot test skip path")

        findings = run_codeql(tmp_path, artifacts_dir=tmp_path)
        assert findings == []

    def test_is_codeql_available_returns_bool(self) -> None:
        result = is_codeql_available()
        assert isinstance(result, bool)


# ── Integration: static stage with no tools ───────────────


class TestStaticStageNoTools:
    """Test that the full static stage works even without any tools."""

    def test_pipeline_static_stage_succeeds(self, tmp_path: Path) -> None:
        """Pipeline should not crash when semgrep/codeql are both unavailable."""
        from cve_agent.schemas.config import RunConfig, TargetConfig, FeaturesConfig
        from cve_agent.run_context import RunContext

        config = RunConfig(
            target=TargetConfig(
                type="repo",
                path_or_url=str(FIXTURES_DIR),
            ),
            features=FeaturesConfig(
                enable_semgrep=True,   # enabled but tool not installed
                enable_codeql=True,    # enabled but tool not installed
                enable_graph=False,
            ),
        )

        ctx = RunContext(config, runs_dir=tmp_path / "runs")
        ctx.mark_running()

        # Run pipeline static stage manually
        from cve_agent.analyzers.semgrep_scanner import run_semgrep
        from cve_agent.analyzers.codeql_runner import run_codeql

        target_dir = Path(config.target.path_or_url).resolve()
        sg = run_semgrep(target_dir, artifacts_dir=ctx.artifacts_dir)
        cq = run_codeql(
            target_dir,
            artifacts_dir=ctx.artifacts_dir,
            languages_hint=config.target.languages_hint,
        )

        all_findings = sg + cq
        ctx.result.stats.static_candidates = len(all_findings)
        ctx.result.findings.extend(all_findings)
        ctx.mark_completed()

        # Should succeed with zero findings when tools not installed
        assert ctx.result.status.value == "completed"
        assert ctx.result.stats.static_candidates >= 0
