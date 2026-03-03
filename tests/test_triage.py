"""Tests for STEP 8 — Triage Agent.

Covers:
  1. Crash outcome → confirmed
  2. Sanitizer crash → confirmed with high confidence
  3. Environment error → false_positive
  4. Unknown vuln_type + all pass → false_positive
  5. Timeout → potential
  6. Success with high-confidence hypothesis → potential
  7. No validation outcome → candidate (no change)
  8. Dry-run / skipped → candidate (no change)
  9. Mixed pass/fail → potential
  10. Confidence adjustments
  11. TriageReport / TriageVerdict schemas
  12. Save / load roundtrip
  13. Integration: full pipeline dry-run → triage.json + findings.json
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cve_agent.triage.triage_agent import (
    TriageReport,
    TriageVerdict,
    run_triage,
    save_final_findings,
    save_triage_report,
    triage_finding,
)
from cve_agent.analyzers.execution import ValidationOutcome, ValidationResults
from cve_agent.schemas.findings import (
    Finding,
    FindingStatus,
    Hypothesis,
    Severity,
)


# ── Helpers ───────────────────────────────────────────────


def _make_finding(
    fid: str = "abc123",
    vuln_type: str = "code_injection",
    confidence: float = 0.4,
    status: str = "candidate",
) -> Finding:
    return Finding(
        id=fid,
        title=f"[test] {vuln_type}",
        severity=Severity.HIGH,
        confidence=confidence,
        status=FindingStatus(status),
        hypothesis=Hypothesis(
            vuln_type=vuln_type,
            attack_surface="test",
            exploit_idea="test",
            confidence=confidence,
            self_critique="test",
        ),
    )


def _make_outcome(
    fid: str = "abc123",
    status: str = "success",
    exit_code: int = 0,
    passed: int = 5,
    failed: int = 0,
    errors: list[str] | None = None,
    sanitizer: str = "",
) -> ValidationOutcome:
    return ValidationOutcome(
        finding_id=fid,
        test_file="test_abc.py",
        status=status,
        exit_code=exit_code,
        passed_count=passed,
        failed_count=failed,
        errors=errors or [],
        sanitizer_output=sanitizer,
    )


# ── Crash → confirmed ────────────────────────────────────


class TestCrashConfirmed:
    """Crash outcomes should become confirmed."""

    def test_crash_status(self) -> None:
        finding = _make_finding()
        outcome = _make_outcome(status="crash", exit_code=-11)
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "confirmed"

    def test_negative_exit_code(self) -> None:
        finding = _make_finding()
        outcome = _make_outcome(status="failure", exit_code=-6)
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "confirmed"

    def test_crash_with_sanitizer(self) -> None:
        finding = _make_finding()
        outcome = _make_outcome(
            status="crash",
            exit_code=-11,
            sanitizer="AddressSanitizer: heap-buffer-overflow",
        )
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "confirmed"
        assert verdict.sanitizer_relevant is True
        assert verdict.confidence_adjustment > 0.2

    def test_crash_boosts_confidence(self) -> None:
        finding = _make_finding(confidence=0.3)
        outcome = _make_outcome(status="crash", exit_code=-1)
        verdict = triage_finding(finding, outcome)
        assert verdict.confidence_adjustment > 0


# ── Environment error → false_positive ────────────────────


class TestEnvErrorFalsePositive:
    """Environment errors should be marked false_positive."""

    def test_import_error(self) -> None:
        finding = _make_finding()
        outcome = _make_outcome(
            status="failure",
            errors=["ModuleNotFoundError: No module named 'foo'"],
        )
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "false_positive"

    def test_file_not_found(self) -> None:
        finding = _make_finding()
        outcome = _make_outcome(
            status="failure",
            errors=["FileNotFoundError: something missing"],
        )
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "false_positive"

    def test_docker_not_available(self) -> None:
        finding = _make_finding()
        outcome = _make_outcome(
            status="failure",
            errors=["Docker not available"],
        )
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "false_positive"

    def test_env_error_lowers_confidence(self) -> None:
        finding = _make_finding(confidence=0.5)
        outcome = _make_outcome(
            status="failure",
            errors=["ImportError: cannot import name 'x'"],
        )
        verdict = triage_finding(finding, outcome)
        assert verdict.confidence_adjustment < 0


# ── Unknown vuln_type → false_positive ────────────────────


class TestUnknownFalsePositive:
    """Unknown vuln_type with all-pass should be false_positive."""

    def test_unknown_all_pass(self) -> None:
        finding = _make_finding(vuln_type="unknown")
        outcome = _make_outcome(status="success", passed=5, failed=0)
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "false_positive"


# ── Timeout → potential ───────────────────────────────────


class TestTimeout:
    """Timeout should be marked potential (resource exhaustion risk)."""

    def test_timeout_is_potential(self) -> None:
        finding = _make_finding()
        outcome = _make_outcome(status="timeout")
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "potential"

    def test_timeout_has_next_steps(self) -> None:
        finding = _make_finding()
        outcome = _make_outcome(status="timeout")
        verdict = triage_finding(finding, outcome)
        assert len(verdict.next_steps) > 0


# ── Success + high confidence hypothesis → potential ──────


class TestSuccessPotential:
    """All-pass with good hypothesis → potential."""

    def test_high_confidence_hypothesis(self) -> None:
        finding = _make_finding(confidence=0.5)
        outcome = _make_outcome(status="success", passed=5, failed=0)
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "potential"

    def test_low_confidence_all_pass(self) -> None:
        """Low confidence + all pass → false_positive."""
        finding = _make_finding(confidence=0.2)
        outcome = _make_outcome(status="success", passed=5, failed=0)
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "false_positive"


# ── No outcome / skipped / dry_run → candidate ────────────


class TestNoChange:
    """No data should leave status as candidate."""

    def test_no_outcome(self) -> None:
        finding = _make_finding()
        verdict = triage_finding(finding, None)
        assert verdict.new_status == "candidate"

    def test_skipped(self) -> None:
        finding = _make_finding()
        outcome = _make_outcome(status="skipped")
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "candidate"

    def test_dry_run(self) -> None:
        finding = _make_finding()
        outcome = _make_outcome(status="dry_run")
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "candidate"


# ── Mixed pass/fail → potential ───────────────────────────


class TestMixedResults:
    """Mixed results should be potential."""

    def test_some_pass_some_fail(self) -> None:
        finding = _make_finding()
        outcome = _make_outcome(status="failure", passed=3, failed=2)
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "potential"

    def test_all_fail(self) -> None:
        finding = _make_finding()
        outcome = _make_outcome(status="failure", passed=0, failed=5)
        verdict = triage_finding(finding, outcome)
        assert verdict.new_status == "potential"


# ── Rationale is always present ───────────────────────────


class TestRationale:
    """Every verdict should have a non-empty rationale."""

    @pytest.mark.parametrize("status,exit_code,passed,failed", [
        ("success", 0, 5, 0),
        ("failure", 1, 3, 2),
        ("crash", -11, 0, 0),
        ("timeout", -1, 0, 0),
        ("skipped", 0, 0, 0),
        ("dry_run", 0, 0, 0),
    ])
    def test_rationale_present(self, status, exit_code, passed, failed) -> None:
        finding = _make_finding()
        outcome = _make_outcome(
            status=status, exit_code=exit_code, passed=passed, failed=failed,
        )
        verdict = triage_finding(finding, outcome)
        assert verdict.rationale != ""
        assert len(verdict.rationale) >= 10


# ── Schema tests ──────────────────────────────────────────


class TestSchemas:
    """Test triage schemas."""

    def test_verdict_roundtrip(self) -> None:
        v = TriageVerdict(
            finding_id="x",
            new_status="confirmed",
            rationale="Crash detected",
            next_steps=["Investigate"],
        )
        data = v.model_dump()
        restored = TriageVerdict.model_validate(data)
        assert restored.new_status == "confirmed"

    def test_report_roundtrip(self) -> None:
        r = TriageReport(
            total=3, confirmed=1, potential=1, false_positive=1,
            verdicts=[
                TriageVerdict(finding_id="a", new_status="confirmed"),
                TriageVerdict(finding_id="b", new_status="potential"),
                TriageVerdict(finding_id="c", new_status="false_positive"),
            ],
        )
        json_str = r.model_dump_json()
        restored = TriageReport.model_validate_json(json_str)
        assert restored.total == 3
        assert len(restored.verdicts) == 3


# ── Save / load roundtrip ────────────────────────────────


class TestSave:
    """Test artifact saving."""

    def test_save_triage_report(self, tmp_path: Path) -> None:
        report = TriageReport(
            total=1, confirmed=1,
            verdicts=[TriageVerdict(finding_id="a", new_status="confirmed")],
        )
        path = save_triage_report(report, tmp_path)
        assert path.exists()
        loaded = TriageReport.model_validate_json(path.read_text(encoding="utf-8"))
        assert loaded.confirmed == 1

    def test_save_final_findings(self, tmp_path: Path) -> None:
        findings = [_make_finding(fid="f1"), _make_finding(fid="f2")]
        path = save_final_findings(findings, tmp_path)
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data) == 2


# ── Integration ───────────────────────────────────────────


class TestIntegration:
    """Integration: run_triage with fake artifacts."""

    def test_run_triage_with_crash(self, tmp_path: Path) -> None:
        """Crash outcome → confirmed in triage.json."""
        from pydantic import TypeAdapter

        # Create hypotheses
        findings = [_make_finding(fid="crash_001")]
        adapter = TypeAdapter(list[Finding])
        (tmp_path / "hypotheses.json").write_text(
            adapter.dump_json(findings, indent=2).decode(), encoding="utf-8",
        )

        # Create validation results with crash
        val = ValidationResults(
            total=1, crash=1,
            outcomes=[_make_outcome(
                fid="crash_001", status="crash", exit_code=-11,
                sanitizer="AddressSanitizer: heap-buffer-overflow",
            )],
        )
        (tmp_path / "validation_results.json").write_text(
            val.model_dump_json(indent=2), encoding="utf-8",
        )

        # Run triage
        report, triaged = run_triage(tmp_path)

        assert report.confirmed == 1
        assert report.potential == 0
        assert report.false_positive == 0
        assert triaged[0].status == FindingStatus.CONFIRMED

    def test_run_triage_with_dry_run(self, tmp_path: Path) -> None:
        """Dry-run outcomes → candidate (no change)."""
        from pydantic import TypeAdapter

        findings = [_make_finding(fid="dry_001")]
        adapter = TypeAdapter(list[Finding])
        (tmp_path / "hypotheses.json").write_text(
            adapter.dump_json(findings, indent=2).decode(), encoding="utf-8",
        )

        val = ValidationResults(
            total=1, skipped=1,
            outcomes=[_make_outcome(fid="dry_001", status="dry_run")],
        )
        (tmp_path / "validation_results.json").write_text(
            val.model_dump_json(indent=2), encoding="utf-8",
        )

        report, triaged = run_triage(tmp_path)
        assert report.candidate == 1
        assert triaged[0].status == FindingStatus.CANDIDATE

    def test_run_triage_saves_artifacts(self, tmp_path: Path) -> None:
        """Triage should save both triage.json and findings.json."""
        from pydantic import TypeAdapter

        findings = [
            _make_finding(fid="t1", vuln_type="unknown"),
            _make_finding(fid="t2"),
        ]
        adapter = TypeAdapter(list[Finding])
        (tmp_path / "hypotheses.json").write_text(
            adapter.dump_json(findings, indent=2).decode(), encoding="utf-8",
        )

        val = ValidationResults(
            total=2,
            outcomes=[
                _make_outcome(fid="t1", status="success", passed=5, failed=0),
                _make_outcome(fid="t2", status="timeout"),
            ],
        )
        (tmp_path / "validation_results.json").write_text(
            val.model_dump_json(indent=2), encoding="utf-8",
        )

        report, triaged = run_triage(tmp_path)
        save_triage_report(report, tmp_path)
        save_final_findings(triaged, tmp_path)

        assert (tmp_path / "triage.json").exists()
        assert (tmp_path / "findings.json").exists()

        # t1 (unknown + all pass) → false_positive
        # t2 (timeout) → potential
        assert report.false_positive == 1
        assert report.potential == 1

    def test_no_hypotheses(self, tmp_path: Path) -> None:
        """No hypotheses.json → empty report."""
        report, findings = run_triage(tmp_path)
        assert report.total == 0
        assert findings == []

    def test_no_validation_results(self, tmp_path: Path) -> None:
        """No validation_results.json → all candidates."""
        from pydantic import TypeAdapter

        findings = [_make_finding(fid="nv_001")]
        adapter = TypeAdapter(list[Finding])
        (tmp_path / "hypotheses.json").write_text(
            adapter.dump_json(findings, indent=2).decode(), encoding="utf-8",
        )

        report, triaged = run_triage(tmp_path)
        assert report.candidate == 1
        assert triaged[0].status == FindingStatus.CANDIDATE
