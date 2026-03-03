"""Normalize raw static analysis results into Finding candidates.

Takes raw JSON output from Semgrep / CodeQL and produces a list
of Finding objects with stable IDs, evidence, and conservative
severity/confidence mapping.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

from cve_agent.schemas.findings import (
    CodeLocation,
    EvidenceItem,
    EvidenceKind,
    Finding,
    FindingStatus,
    Severity,
)

logger = logging.getLogger("cve_agent.analyzers.normalize_findings")

# ── Stable ID ─────────────────────────────────────────────


def stable_finding_id(file: str, rule: str, line: int) -> str:
    """Generate a deterministic 12-char hex ID from file+rule+line.

    This ensures the same finding always gets the same ID across runs.
    """
    raw = f"{file}|{rule}|{line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


# ── Severity mapping ─────────────────────────────────────

_SEMGREP_SEVERITY: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

_CODEQL_SEVERITY: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "recommendation": Severity.INFO,
}

# Conservative confidence values for static tools
_SEMGREP_CONFIDENCE: dict[str, float] = {
    "ERROR": 0.6,
    "WARNING": 0.4,
    "INFO": 0.2,
}

_CODEQL_CONFIDENCE: dict[str, float] = {
    "error": 0.7,
    "warning": 0.5,
    "note": 0.3,
    "recommendation": 0.2,
}


# ── Semgrep normalisation ─────────────────────────────────


def normalize_semgrep(raw_results: list[dict[str, Any]]) -> list[Finding]:
    """Convert Semgrep JSON results into Finding candidates.

    Args:
        raw_results: List of result dicts from semgrep --json output['results'].

    Returns:
        List of Finding objects with status=CANDIDATE.
    """
    findings: list[Finding] = []

    for result in raw_results:
        try:
            check_id = result.get("check_id", "unknown-rule")
            severity_raw = result.get("extra", {}).get("severity", "WARNING")
            message = result.get("extra", {}).get("message", check_id)
            path = result.get("path", "unknown")
            start_line = result.get("start", {}).get("line", 1)
            end_line = result.get("end", {}).get("line", start_line)
            snippet = result.get("extra", {}).get("lines", "")
            metadata = result.get("extra", {}).get("metadata", {})

            # Stable ID
            fid = stable_finding_id(path, check_id, start_line)

            # Map severity conservatively
            severity = _SEMGREP_SEVERITY.get(severity_raw, Severity.MEDIUM)
            confidence = _SEMGREP_CONFIDENCE.get(severity_raw, 0.4)

            location = CodeLocation(
                file=path,
                start_line=max(1, start_line),
                end_line=max(1, end_line),
            )

            evidence = EvidenceItem(
                kind=EvidenceKind.TOOL_OUTPUT,
                summary=f"Semgrep [{check_id}]: {message}",
                location=location,
                snippet=snippet[:500] if snippet else None,
                artifact_path="semgrep_raw.json",
            )

            references: list[str] = []
            if metadata.get("references"):
                refs = metadata["references"]
                if isinstance(refs, list):
                    references.extend(str(r) for r in refs[:5])
                elif isinstance(refs, str):
                    references.append(refs)

            finding = Finding(
                id=fid,
                title=f"[semgrep] {check_id}: {message[:100]}",
                severity=severity,
                confidence=confidence,
                status=FindingStatus.CANDIDATE,
                evidence=[evidence],
                references=references,
            )
            findings.append(finding)

        except Exception as exc:
            logger.warning("Failed to normalize semgrep result: %s", exc)
            continue

    logger.info("Normalized %d semgrep results into findings", len(findings))
    return findings


# ── CodeQL normalisation ──────────────────────────────────


def normalize_codeql(sarif_results: list[dict[str, Any]]) -> list[Finding]:
    """Convert CodeQL SARIF results into Finding candidates.

    Args:
        sarif_results: List of result dicts from SARIF runs[].results[].

    Returns:
        List of Finding objects with status=CANDIDATE.
    """
    findings: list[Finding] = []

    for result in sarif_results:
        try:
            rule_id = result.get("ruleId", "unknown-query")
            level = result.get("level", "warning")
            message_obj = result.get("message", {})
            message = message_obj.get("text", rule_id) if isinstance(message_obj, dict) else str(message_obj)

            # Extract location from first location in result
            locations = result.get("locations", [])
            path = "unknown"
            start_line = 1
            end_line = 1
            snippet = ""

            if locations:
                phys_loc = locations[0].get("physicalLocation", {})
                artifact = phys_loc.get("artifactLocation", {})
                path = artifact.get("uri", "unknown")
                region = phys_loc.get("region", {})
                start_line = region.get("startLine", 1)
                end_line = region.get("endLine", start_line)
                snippet_obj = region.get("snippet", {})
                snippet = snippet_obj.get("text", "") if isinstance(snippet_obj, dict) else ""

            # Stable ID
            fid = stable_finding_id(path, rule_id, start_line)

            severity = _CODEQL_SEVERITY.get(level, Severity.MEDIUM)
            confidence = _CODEQL_CONFIDENCE.get(level, 0.5)

            location = CodeLocation(
                file=path,
                start_line=max(1, start_line),
                end_line=max(1, end_line),
            )

            evidence = EvidenceItem(
                kind=EvidenceKind.TOOL_OUTPUT,
                summary=f"CodeQL [{rule_id}]: {message}",
                location=location,
                snippet=snippet[:500] if snippet else None,
                artifact_path="codeql_raw.json",
            )

            finding = Finding(
                id=fid,
                title=f"[codeql] {rule_id}: {message[:100]}",
                severity=severity,
                confidence=confidence,
                status=FindingStatus.CANDIDATE,
                evidence=[evidence],
            )
            findings.append(finding)

        except Exception as exc:
            logger.warning("Failed to normalize codeql result: %s", exc)
            continue

    logger.info("Normalized %d codeql results into findings", len(findings))
    return findings


def save_candidates(
    findings: list[Finding],
    output_path: Path,
) -> Path:
    """Serialize a list of Finding candidates to JSON.

    Returns:
        The output path.
    """
    from pydantic import TypeAdapter
    adapter = TypeAdapter(list[Finding])
    output_path.write_text(
        adapter.dump_json(findings, indent=2).decode(),
        encoding="utf-8",
    )
    logger.info("Saved %d candidates to %s", len(findings), output_path)
    return output_path
