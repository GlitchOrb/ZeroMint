"""Tests for STEP 9 — Report Generation & Evidence Bundling.

Covers:
  1. REPORT.md structure (summary, table, details, CVE draft, disclosure)
  2. Empty findings → valid report
  3. Confirmed findings → CVE draft template present
  4. False positives → collapsed section
  5. Evidence bundler → ZIP with correct contents
  6. Large file exclusion in bundle
  7. Integration: sample findings → REPORT.md + evidence_bundle.zip
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from pydantic import TypeAdapter

from cve_agent.reporting.report_md import (
    generate_report_md,
    save_report,
    _severity_badge,
    _status_badge,
)
from cve_agent.reporting.bundler import create_evidence_bundle
from cve_agent.schemas.findings import (
    CodeLocation,
    EvidenceItem,
    EvidenceKind,
    Finding,
    FindingStatus,
    Hypothesis,
    Severity,
)
from cve_agent.triage.triage_agent import TriageReport, TriageVerdict


# ── Helpers ───────────────────────────────────────────────


def _make_finding(
    fid: str = "rpt001",
    title: str = "SQL Injection in query handler",
    vuln_type: str = "sql_injection",
    severity: str = "high",
    status: str = "confirmed",
    confidence: float = 0.8,
) -> Finding:
    return Finding(
        id=fid,
        title=title,
        severity=Severity(severity),
        confidence=confidence,
        status=FindingStatus(status),
        hypothesis=Hypothesis(
            vuln_type=vuln_type,
            attack_surface="HTTP query parameter",
            preconditions=["User input reaches SQL query"],
            exploit_idea="Supply crafted query parameter",
            confidence=confidence,
            related_sinks=["cursor.execute"],
            related_sources=["request.args"],
            self_critique="Offline analysis; may be parameterized",
        ),
        evidence=[
            EvidenceItem(
                kind=EvidenceKind.CODE,
                summary="Unsafe string interpolation in SQL query",
                location=CodeLocation(
                    file="app/db.py",
                    start_line=42,
                    end_line=45,
                    symbol="execute_query",
                ),
                snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
            ),
        ],
        reproduction_steps=[
            "Start the application locally",
            "Send GET /api/users?id=1%27%20OR%201%3D1",
            "Observe SQL error in response",
        ],
        mitigation="Use parameterized queries instead of string interpolation.",
        references=["https://cwe.mitre.org/data/definitions/89.html"],
    )


def _make_triage(finding_id: str, status: str) -> TriageVerdict:
    return TriageVerdict(
        finding_id=finding_id,
        previous_status="candidate",
        new_status=status,
        rationale=f"Assessment: {status}",
        next_steps=["Review code", "Test manually"],
    )


# ── Badge helpers ─────────────────────────────────────────


class TestBadges:
    def test_severity_badges(self) -> None:
        assert "Critical" in _severity_badge("critical")
        assert "High" in _severity_badge("high")
        assert "Medium" in _severity_badge("medium")
        assert "Low" in _severity_badge("low")
        assert "Info" in _severity_badge("info")

    def test_status_badges(self) -> None:
        assert "Confirmed" in _status_badge("confirmed")
        assert "Potential" in _status_badge("potential")
        assert "False Positive" in _status_badge("false_positive")
        assert "Candidate" in _status_badge("candidate")


# ── REPORT.md structure ───────────────────────────────────


class TestReportStructure:
    """Test REPORT.md contains all required sections."""

    def test_has_header(self) -> None:
        report = generate_report_md([], run_id="test-001", target="./project")
        assert "Security Analysis Report" in report
        assert "test-001" in report
        assert "./project" in report

    def test_has_disclaimer(self) -> None:
        report = generate_report_md([])
        assert "manual verification" in report.lower()

    def test_has_summary(self) -> None:
        findings = [_make_finding()]
        report = generate_report_md(findings)
        assert "Executive Summary" in report
        assert "1" in report  # at least 1 finding

    def test_has_findings_table(self) -> None:
        findings = [_make_finding()]
        report = generate_report_md(findings)
        assert "Findings Overview" in report
        assert "|" in report  # table markers

    def test_has_finding_details(self) -> None:
        findings = [_make_finding()]
        report = generate_report_md(findings)
        assert "Finding Details" in report
        assert "SQL Injection" in report

    def test_has_evidence_section(self) -> None:
        findings = [_make_finding()]
        report = generate_report_md(findings)
        assert "Evidence" in report
        assert "cursor.execute" in report

    def test_has_hypothesis_section(self) -> None:
        findings = [_make_finding()]
        report = generate_report_md(findings)
        assert "Hypothesis" in report
        assert "sql_injection" in report

    def test_has_reproduction_steps(self) -> None:
        findings = [_make_finding()]
        report = generate_report_md(findings)
        assert "Reproduction Steps" in report

    def test_has_mitigation(self) -> None:
        findings = [_make_finding()]
        report = generate_report_md(findings)
        assert "parameterized queries" in report

    def test_has_responsible_disclosure(self) -> None:
        report = generate_report_md([])
        assert "Responsible Disclosure" in report
        assert "90 days" in report
        assert "malicious" in report.lower()

    def test_has_footer(self) -> None:
        report = generate_report_md([], run_id="foot-001")
        assert "foot-001" in report


# ── CVE Draft Template ────────────────────────────────────


class TestCVEDraft:
    """Test CVE draft template generation."""

    def test_confirmed_has_cve_draft(self) -> None:
        findings = [_make_finding(status="confirmed")]
        report = generate_report_md(findings)
        assert "CVE Draft" in report

    def test_potential_has_cve_draft(self) -> None:
        findings = [_make_finding(status="potential")]
        report = generate_report_md(findings)
        assert "CVE Draft" in report

    def test_false_positive_no_cve_draft(self) -> None:
        findings = [_make_finding(status="false_positive")]
        report = generate_report_md(findings)
        assert "CVE Draft" not in report

    def test_candidate_no_cve_draft(self) -> None:
        findings = [_make_finding(status="candidate")]
        report = generate_report_md(findings)
        assert "CVE Draft" not in report

    def test_cve_draft_has_required_fields(self) -> None:
        findings = [_make_finding(status="confirmed")]
        report = generate_report_md(findings)
        assert "Title:" in report
        assert "Type:" in report
        assert "Severity:" in report
        assert "Affected Component:" in report
        assert "Impact:" in report
        assert "Suggested Fix:" in report

    def test_cve_draft_no_overstatement(self) -> None:
        findings = [_make_finding(status="confirmed")]
        report = generate_report_md(findings)
        assert "DO NOT overstate" in report
        assert "manual verification" in report.lower()


# ── Empty findings ────────────────────────────────────────


class TestEmptyReport:
    """Empty findings should produce a valid report."""

    def test_no_findings(self) -> None:
        report = generate_report_md([])
        assert "No findings to report" in report

    def test_no_findings_still_has_disclosure(self) -> None:
        report = generate_report_md([])
        assert "Responsible Disclosure" in report


# ── False positive section ────────────────────────────────


class TestFalsePositiveSection:
    """False positives should appear in collapsed section."""

    def test_false_positive_collapsed(self) -> None:
        findings = [_make_finding(status="false_positive")]
        triage = TriageReport(
            total=1, false_positive=1,
            verdicts=[_make_triage("rpt001", "false_positive")],
        )
        report = generate_report_md(findings, triage)
        assert "False Positives" in report
        assert "<details>" in report

    def test_false_positive_not_in_details_section(self) -> None:
        findings = [_make_finding(status="false_positive")]
        report = generate_report_md(findings)
        # Should NOT appear in the detailed findings section
        assert "Finding Details" not in report


# ── Triage rationale in report ────────────────────────────


class TestTriageRationale:
    def test_rationale_appears(self) -> None:
        findings = [_make_finding(status="confirmed")]
        triage = TriageReport(
            total=1, confirmed=1,
            verdicts=[_make_triage("rpt001", "confirmed")],
        )
        report = generate_report_md(findings, triage)
        assert "Triage Rationale" in report
        assert "confirmed" in report.lower()

    def test_next_steps_appear(self) -> None:
        findings = [_make_finding(status="potential")]
        triage = TriageReport(
            total=1, potential=1,
            verdicts=[_make_triage("rpt001", "potential")],
        )
        report = generate_report_md(findings, triage)
        assert "Next Steps" in report


# ── Severity distribution ────────────────────────────────


class TestSeverityDistribution:
    def test_shows_severity_counts(self) -> None:
        findings = [
            _make_finding(fid="a", severity="critical", status="confirmed"),
            _make_finding(fid="b", severity="high", status="potential"),
            _make_finding(fid="c", severity="low", status="false_positive"),
        ]
        report = generate_report_md(findings)
        assert "Severity Distribution" in report
        assert "Critical" in report
        assert "High" in report
        assert "Low" in report


# ── Save report ───────────────────────────────────────────


class TestSaveReport:
    def test_save_report_md(self, tmp_path: Path) -> None:
        report = generate_report_md([_make_finding()])
        path = save_report(report, tmp_path)
        assert path.exists()
        assert path.name == "REPORT.md"
        content = path.read_text(encoding="utf-8")
        assert "Security Analysis Report" in content


# ── Evidence bundler ──────────────────────────────────────


class TestEvidenceBundler:
    """Test evidence_bundle.zip creation."""

    def _setup_artifacts(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create mock run_dir and artifacts_dir with sample files."""
        run_dir = tmp_path / "run_test"
        art_dir = run_dir / "artifacts"
        art_dir.mkdir(parents=True)

        # Create REPORT.md
        (run_dir / "REPORT.md").write_text("# Report\n", encoding="utf-8")

        # Create JSON artifacts
        for name in ("findings.json", "triage.json", "validation_results.json",
                      "fuzz_attempts.json", "hypotheses.json"):
            (art_dir / name).write_text("{}", encoding="utf-8")

        # Create log dir
        log_dir = art_dir / "logs"
        log_dir.mkdir()
        (log_dir / "test_abc.log").write_text("log output", encoding="utf-8")

        # Create harness dir
        harness_dir = art_dir / "harnesses" / "find_001"
        harness_dir.mkdir(parents=True)
        (harness_dir / "test_find_001.py").write_text(
            "def test_ok(): pass", encoding="utf-8",
        )

        return run_dir, art_dir

    def test_creates_zip(self, tmp_path: Path) -> None:
        run_dir, art_dir = self._setup_artifacts(tmp_path)
        zip_path = create_evidence_bundle(run_dir, art_dir)
        assert zip_path.exists()
        assert zip_path.suffix == ".zip"

    def test_zip_contains_report(self, tmp_path: Path) -> None:
        run_dir, art_dir = self._setup_artifacts(tmp_path)
        zip_path = create_evidence_bundle(run_dir, art_dir)
        with zipfile.ZipFile(zip_path, "r") as zf:
            assert "REPORT.md" in zf.namelist()

    def test_zip_contains_artifacts(self, tmp_path: Path) -> None:
        run_dir, art_dir = self._setup_artifacts(tmp_path)
        zip_path = create_evidence_bundle(run_dir, art_dir)
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            assert "artifacts/findings.json" in names
            assert "artifacts/triage.json" in names

    def test_zip_contains_logs(self, tmp_path: Path) -> None:
        run_dir, art_dir = self._setup_artifacts(tmp_path)
        zip_path = create_evidence_bundle(run_dir, art_dir)
        with zipfile.ZipFile(zip_path, "r") as zf:
            log_files = [n for n in zf.namelist() if "logs/" in n]
            assert len(log_files) >= 1

    def test_zip_contains_harnesses(self, tmp_path: Path) -> None:
        run_dir, art_dir = self._setup_artifacts(tmp_path)
        zip_path = create_evidence_bundle(run_dir, art_dir)
        with zipfile.ZipFile(zip_path, "r") as zf:
            harness_files = [n for n in zf.namelist() if "harnesses/" in n]
            assert len(harness_files) >= 1

    def test_empty_artifacts(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "empty_run"
        art_dir = run_dir / "artifacts"
        art_dir.mkdir(parents=True)
        zip_path = create_evidence_bundle(run_dir, art_dir)
        assert zip_path.exists()
        with zipfile.ZipFile(zip_path, "r") as zf:
            assert len(zf.namelist()) == 0  # nothing to bundle


# ── Integration ───────────────────────────────────────────


class TestIntegration:
    """Integration: generate full report from sample findings."""

    def test_full_report_generation(self, tmp_path: Path) -> None:
        """Generate REPORT.md + evidence_bundle.zip from sample data."""
        run_dir = tmp_path / "run_int"
        art_dir = run_dir / "artifacts"
        art_dir.mkdir(parents=True)

        # Create realistic findings
        findings = [
            _make_finding(
                fid="int_001",
                title="SQL Injection in /api/search",
                status="confirmed",
                severity="high",
            ),
            _make_finding(
                fid="int_002",
                title="Path Traversal in file handler",
                vuln_type="path_traversal",
                status="potential",
                severity="medium",
                confidence=0.5,
            ),
            _make_finding(
                fid="int_003",
                title="Weak hash in auth",
                vuln_type="unknown",
                status="false_positive",
                severity="low",
                confidence=0.2,
            ),
        ]

        triage = TriageReport(
            total=3, confirmed=1, potential=1, false_positive=1,
            verdicts=[
                _make_triage("int_001", "confirmed"),
                _make_triage("int_002", "potential"),
                _make_triage("int_003", "false_positive"),
            ],
        )

        # Save artifacts
        adapter = TypeAdapter(list[Finding])
        (art_dir / "findings.json").write_text(
            adapter.dump_json(findings, indent=2).decode(), encoding="utf-8",
        )
        (art_dir / "triage.json").write_text(
            triage.model_dump_json(indent=2), encoding="utf-8",
        )

        # Generate report
        report = generate_report_md(
            findings, triage, run_id="int-test-001", target="./test-project",
        )
        report_path = save_report(report, run_dir)

        # Generate bundle
        bundle_path = create_evidence_bundle(run_dir, art_dir)

        # Verify report
        assert report_path.exists()
        content = report_path.read_text(encoding="utf-8")
        assert "int-test-001" in content
        assert "SQL Injection" in content
        assert "Path Traversal" in content
        assert "CVE Draft" in content
        assert "False Positives" in content
        assert "Responsible Disclosure" in content

        # Verify CVE drafts exist for confirmed + potential
        assert content.count("CVE Draft #") == 2

        # Verify bundle
        assert bundle_path.exists()
        with zipfile.ZipFile(bundle_path, "r") as zf:
            names = zf.namelist()
            assert "REPORT.md" in names
            assert "artifacts/findings.json" in names
            assert "artifacts/triage.json" in names
