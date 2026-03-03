"""Triage Agent — conservative vulnerability assessment.

Philosophy: NEVER overstate.  The rules are:

  1. confirmed  — ONLY when dynamic evidence exists:
       - Crash (exit code < 0, sanitizer trigger, signal 11/6)
       - Clear policy violation reproduced in the sandbox
       - Same failure reproduced ≥ 2 times (if available)
  2. potential  — security-relevant hypothesis + tests pass (no
       dynamic negative proof), but no crash / violation witnessed.
       This is the "we think it's real but need more investigation"
       bucket.  DO NOT call this "confirmed".
  3. false_positive — one of:
       - Environment error only (import failure, config issue)
       - All boundary tests pass without exception (indicates the
         code handles edge cases properly)
       - Hypothesis vuln_type is "unknown"
  4. candidate — insufficient data to decide (no validation ran)

Inputs:
  - hypotheses.json   (Finding[] with hypothesis)
  - validation_results.json  (ValidationResults with outcomes)
  - sanitizer logs    (optional, from artifacts/logs/)

Outputs:
  - triage.json       (per-finding verdict + rationale + next_steps)
  - findings.json     (updated Finding[] with status changes)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, TypeAdapter

from cve_agent.analyzers.execution import ValidationOutcome, ValidationResults
from cve_agent.schemas.findings import (
    EvidenceItem,
    EvidenceKind,
    Finding,
    FindingStatus,
)

logger = logging.getLogger("cve_agent.triage.triage_agent")


# ── Triage verdict schema ────────────────────────────────


class TriageVerdict(BaseModel):
    """Per-finding triage decision with rationale."""
    finding_id: str
    previous_status: str = "candidate"
    new_status: str = "candidate"
    rationale: str = ""
    confidence_adjustment: float = 0.0  # delta applied to confidence
    next_steps: list[str] = Field(default_factory=list)
    sanitizer_relevant: bool = False
    reproduced_count: int = 0


class TriageReport(BaseModel):
    """Collection of triage verdicts."""
    total: int = 0
    confirmed: int = 0
    potential: int = 0
    false_positive: int = 0
    candidate: int = 0  # unchanged
    verdicts: list[TriageVerdict] = Field(default_factory=list)


# ── Evidence markers for crash / policy violations ────────

_CRASH_INDICATORS = [
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "LeakSanitizer",
    "SEGV",
    "SIGABRT",
    "signal 11",
    "signal 6",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "double-free",
    "null dereference",
    "Traceback (most recent call last)",
    "core dumped",
]

_ENV_ERROR_INDICATORS = [
    "ModuleNotFoundError",
    "ImportError",
    "FileNotFoundError",
    "PermissionError",
    "Docker not available",
    "pytest not found",
    "No such file or directory",
]


# ── Core triage logic ─────────────────────────────────────


def triage_finding(
    finding: Finding,
    outcome: ValidationOutcome | None,
) -> TriageVerdict:
    """Assess a single finding conservatively.

    Decision tree (in order):
      1. No outcome → candidate (no data)
      2. Outcome skipped / dry_run → candidate (not executed)
      3. Environment error → false_positive
      4. Crash + sanitizer → confirmed (dynamic proof)
      5. Crash (exit < 0 or status=crash) → confirmed
      6. Tests pass with failures → potential
      7. All tests pass, no exceptions → depends on hypothesis quality
      8. Unknown vuln_type → false_positive
    """
    verdict = TriageVerdict(
        finding_id=finding.id,
        previous_status=finding.status.value,
    )

    # No validation outcome → keep as candidate
    if outcome is None:
        verdict.new_status = "candidate"
        verdict.rationale = "No validation data available. Cannot assess."
        verdict.next_steps = ["Run validation tests", "Manual code review"]
        return verdict

    # Not executed
    if outcome.status in ("skipped", "dry_run"):
        verdict.new_status = "candidate"
        verdict.rationale = (
            f"Validation was {outcome.status}. "
            f"No dynamic evidence to assess."
        )
        verdict.next_steps = [
            "Execute tests in sandbox",
            "Enable Docker for isolated execution",
        ]
        return verdict

    # Check for environment errors (→ false_positive for the test, not the vuln)
    errors_text = " ".join(outcome.errors)
    if _is_environment_error(errors_text):
        verdict.new_status = "false_positive"
        verdict.rationale = (
            "Test failures are due to environment/configuration issues, "
            "not a security vulnerability. "
            f"Errors: {errors_text[:200]}"
        )
        verdict.confidence_adjustment = -0.3
        verdict.next_steps = [
            "Fix test environment",
            "Re-run after resolving imports/dependencies",
        ]
        return verdict

    # Check sanitizer output
    has_sanitizer = bool(outcome.sanitizer_output)
    if has_sanitizer:
        verdict.sanitizer_relevant = True

    # CRASH — dynamic proof exists
    if outcome.status == "crash" or outcome.exit_code < 0:
        if has_sanitizer:
            verdict.new_status = "confirmed"
            verdict.rationale = (
                "CONFIRMED: Sanitizer detected a memory safety violation. "
                "This is dynamic proof of a vulnerability. "
                f"Sanitizer: {outcome.sanitizer_output[:200]}"
            )
            verdict.confidence_adjustment = +0.3
            verdict.next_steps = [
                "Determine exploitability",
                "Check if crash is reachable from external input",
                "Assess severity based on crash type",
            ]
        else:
            verdict.new_status = "confirmed"
            verdict.rationale = (
                "CONFIRMED: Process crashed (exit code "
                f"{outcome.exit_code}). This indicates a reproducible "
                "fault. Further investigation needed to assess "
                "security impact."
            )
            verdict.confidence_adjustment = +0.2
            verdict.next_steps = [
                "Reproduce crash manually",
                "Check if crash is exploitable",
                "Determine root cause",
            ]
        return verdict

    # TIMEOUT — may indicate infinite loop / resource exhaustion
    if outcome.status == "timeout":
        verdict.new_status = "potential"
        verdict.rationale = (
            "Test timed out — may indicate resource exhaustion "
            "or infinite loop triggered by crafted input. "
            "This is potentially security-relevant but not confirmed."
        )
        verdict.confidence_adjustment = +0.05
        verdict.next_steps = [
            "Increase timeout and re-run",
            "Profile the target function for resource usage",
            "Check if DoS is a valid threat model",
        ]
        return verdict

    # Tests ran — check pass/fail
    if outcome.status == "success":
        # All passed — the target handled all boundary inputs correctly?
        if outcome.passed_count > 0 and outcome.failed_count == 0:
            hyp = finding.hypothesis
            if hyp and hyp.vuln_type == "unknown":
                verdict.new_status = "false_positive"
                verdict.rationale = (
                    "No specific vulnerability type identified, and all "
                    "boundary tests passed without exception."
                )
                verdict.confidence_adjustment = -0.3
            elif hyp and hyp.confidence >= 0.4:
                verdict.new_status = "potential"
                verdict.rationale = (
                    "All boundary tests passed (no crashes or exceptions). "
                    "The hypothesis suggests a vulnerability but "
                    "dynamic testing did not trigger it. "
                    "This may require more targeted testing or the "
                    "vulnerability may be mitigated by upstream validation."
                )
                verdict.next_steps = [
                    "Manual code review of the flagged code path",
                    "Add more targeted test inputs",
                    "Check for upstream sanitisation",
                ]
            else:
                verdict.new_status = "false_positive"
                verdict.rationale = (
                    "Low-confidence hypothesis, and all boundary tests "
                    "passed without triggering any issues. "
                    "Likely a false positive."
                )
                verdict.confidence_adjustment = -0.2
        else:
            # Mixed — default to candidate
            verdict.new_status = "candidate"
            verdict.rationale = "Inconclusive: no tests failed or passed."
        return verdict

    if outcome.status == "failure":
        # Some tests failed — but WHY?
        if _is_environment_error(errors_text):
            verdict.new_status = "false_positive"
            verdict.rationale = (
                "Test failures are environment-related, not security findings."
            )
            verdict.confidence_adjustment = -0.2
        elif outcome.failed_count > 0 and outcome.passed_count > 0:
            verdict.new_status = "potential"
            verdict.rationale = (
                f"Mixed results: {outcome.passed_count} passed, "
                f"{outcome.failed_count} failed. "
                "Failures may indicate the hypothesis is partially valid. "
                "Further investigation needed — DO NOT treat as confirmed "
                "without dynamic crash evidence."
            )
            verdict.confidence_adjustment = +0.1
            verdict.next_steps = [
                "Review failing test cases",
                "Check if failures are security-relevant or benign",
                "Add more targeted test inputs",
            ]
        elif outcome.failed_count > 0:
            verdict.new_status = "potential"
            verdict.rationale = (
                f"All {outcome.failed_count} tests failed. "
                "This may indicate the hypothesis is correct, but "
                "could also be a test environment issue. "
                "Manual review required."
            )
            verdict.confidence_adjustment = +0.05
            verdict.next_steps = [
                "Review failure logs",
                "Check if failures indicate security impact",
            ]
        else:
            verdict.new_status = "candidate"
            verdict.rationale = "Inconclusive failure — no pass/fail counts."

        return verdict

    # Fallback
    verdict.new_status = "candidate"
    verdict.rationale = f"Unknown outcome status: {outcome.status}"
    return verdict


def _is_environment_error(text: str) -> bool:
    """Check if error text indicates environment issues, not security bugs."""
    text_lower = text.lower()
    for indicator in _ENV_ERROR_INDICATORS:
        if indicator.lower() in text_lower:
            return True
    return False


# ── Main triage runner ────────────────────────────────────


def run_triage(
    artifacts_dir: Path,
) -> tuple[TriageReport, list[Finding]]:
    """Run triage on all findings using validation results.

    Args:
        artifacts_dir: Path to artifacts/ directory.

    Returns:
        (TriageReport, updated_findings)
    """
    # Load hypotheses (findings)
    findings: list[Finding] = []
    hyp_path = artifacts_dir / "hypotheses.json"
    if hyp_path.exists():
        try:
            adapter = TypeAdapter(list[Finding])
            findings = adapter.validate_json(hyp_path.read_text(encoding="utf-8"))
            logger.info("[triage] Loaded %d findings from hypotheses.json", len(findings))
        except Exception as exc:
            logger.error("[triage] Failed to load hypotheses.json: %s", exc)

    if not findings:
        logger.warning("[triage] No findings to triage")
        return TriageReport(), []

    # Load validation results
    outcomes_map: dict[str, ValidationOutcome] = {}
    val_path = artifacts_dir / "validation_results.json"
    if val_path.exists():
        try:
            val_results = ValidationResults.model_validate_json(
                val_path.read_text(encoding="utf-8")
            )
            outcomes_map = {o.finding_id: o for o in val_results.outcomes}
            logger.info(
                "[triage] Loaded %d validation outcomes", len(outcomes_map),
            )
        except Exception as exc:
            logger.warning("[triage] Failed to load validation_results.json: %s", exc)

    # Load sanitizer logs (optional enrichment)
    _enrich_with_sanitizer_logs(outcomes_map, artifacts_dir / "logs")

    # Triage each finding
    report = TriageReport()
    for finding in findings:
        outcome = outcomes_map.get(finding.id)
        verdict = triage_finding(finding, outcome)

        # Apply status change
        try:
            finding.status = FindingStatus(verdict.new_status)
        except ValueError:
            finding.status = FindingStatus.CANDIDATE

        # Apply confidence adjustment
        new_conf = finding.confidence + verdict.confidence_adjustment
        finding.confidence = max(0.0, min(1.0, new_conf))

        # Add triage evidence
        triage_evidence = EvidenceItem(
            kind=EvidenceKind.TOOL_OUTPUT,
            summary=f"Triage: {verdict.new_status} — {verdict.rationale[:100]}",
        )
        finding.evidence.append(triage_evidence)

        report.verdicts.append(verdict)

        # Count
        if verdict.new_status == "confirmed":
            report.confirmed += 1
        elif verdict.new_status == "potential":
            report.potential += 1
        elif verdict.new_status == "false_positive":
            report.false_positive += 1
        else:
            report.candidate += 1

    report.total = len(report.verdicts)

    logger.info(
        "[triage] %d findings: %d confirmed, %d potential, "
        "%d false_positive, %d candidate",
        report.total, report.confirmed, report.potential,
        report.false_positive, report.candidate,
    )

    return report, findings


def _enrich_with_sanitizer_logs(
    outcomes_map: dict[str, ValidationOutcome],
    logs_dir: Path,
) -> None:
    """Enrich outcomes with any sanitizer log files found."""
    if not logs_dir.exists():
        return

    for log_file in logs_dir.glob("*.log"):
        try:
            content = log_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Look for sanitizer output
        from cve_agent.analyzers.execution import parse_sanitizer_output
        sanitizer_out = parse_sanitizer_output(content)
        if not sanitizer_out:
            continue

        # Try to match to a finding ID
        for fid, outcome in outcomes_map.items():
            if fid in log_file.stem and not outcome.sanitizer_output:
                outcome.sanitizer_output = sanitizer_out
                logger.debug("[triage] Enriched %s with sanitizer log", fid)


# ── Save artifacts ────────────────────────────────────────


def save_triage_report(
    report: TriageReport,
    artifacts_dir: Path,
) -> Path:
    """Save triage.json artifact."""
    out_path = artifacts_dir / "triage.json"
    out_path.write_text(
        report.model_dump_json(indent=2),
        encoding="utf-8",
    )
    logger.info("Saved triage report: %s", out_path)
    return out_path


def save_final_findings(
    findings: list[Finding],
    artifacts_dir: Path,
) -> Path:
    """Save updated findings.json artifact."""
    out_path = artifacts_dir / "findings.json"
    adapter = TypeAdapter(list[Finding])
    out_path.write_text(
        adapter.dump_json(findings, indent=2).decode(),
        encoding="utf-8",
    )
    logger.info("Saved %d final findings: %s", len(findings), out_path)
    return out_path
