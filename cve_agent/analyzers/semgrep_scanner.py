"""Semgrep scanner — run semgrep and collect raw JSON results.

Gracefully skips if semgrep is not installed.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from cve_agent.analyzers.normalize_findings import (
    normalize_semgrep,
    save_candidates,
)
from cve_agent.schemas.findings import Finding

logger = logging.getLogger("cve_agent.analyzers.semgrep_scanner")


def is_semgrep_available() -> bool:
    """Check if semgrep CLI is installed and accessible."""
    return shutil.which("semgrep") is not None


def run_semgrep(
    target_dir: Path,
    *,
    artifacts_dir: Path,
    languages: list[str] | None = None,
    timeout: int = 300,
) -> list[Finding]:
    """Run semgrep against target_dir and return normalized findings.

    If semgrep is not installed, logs a warning and returns an empty list.

    Args:
        target_dir: Directory to scan.
        artifacts_dir: Where to save raw and candidate JSON artifacts.
        languages: Optional language hints (unused by semgrep but logged).
        timeout: Max seconds for semgrep execution.

    Returns:
        List of Finding candidates.

    Artifacts written:
        artifacts/semgrep_raw.json      — full semgrep --json output
        artifacts/semgrep_candidates.json — normalized Finding[] JSON
    """
    if not is_semgrep_available():
        logger.warning(
            "[semgrep] semgrep not installed — skipping. "
            "Install: pip install semgrep  or  brew install semgrep"
        )
        return []

    logger.info("[semgrep] Scanning: %s", target_dir)

    # Build command
    cmd = [
        "semgrep",
        "--json",
        "--config", "auto",       # use recommended rules
        "--no-git-ignore",        # scan regardless of .gitignore
        "--metrics", "off",       # no telemetry
        "--timeout", str(timeout),
        str(target_dir),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30,  # extra buffer
            cwd=str(target_dir),
        )
    except subprocess.TimeoutExpired:
        logger.error("[semgrep] Timed out after %ds", timeout)
        return []
    except FileNotFoundError:
        logger.warning("[semgrep] Command not found despite which() check")
        return []
    except Exception as exc:
        logger.error("[semgrep] Execution error: %s", exc)
        return []

    # Parse JSON output
    raw_output: dict[str, Any] = {}
    try:
        raw_output = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        logger.warning("[semgrep] Failed to parse JSON output")
        # Save raw stdout for debugging
        raw_path = artifacts_dir / "semgrep_raw.json"
        raw_path.write_text(result.stdout or "{}", encoding="utf-8")
        return []

    # Save raw output
    raw_path = artifacts_dir / "semgrep_raw.json"
    raw_path.write_text(
        json.dumps(raw_output, indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("[semgrep] Raw output saved: %s", raw_path)

    # Extract results
    results_list = raw_output.get("results", [])
    errors = raw_output.get("errors", [])

    if errors:
        logger.warning("[semgrep] %d errors reported", len(errors))
        for err in errors[:5]:
            logger.debug("[semgrep] Error: %s", err.get("message", str(err)))

    logger.info("[semgrep] Found %d raw results", len(results_list))

    if not results_list:
        # Still save empty candidates
        candidates_path = artifacts_dir / "semgrep_candidates.json"
        save_candidates([], candidates_path)
        return []

    # Normalize to findings
    findings = normalize_semgrep(results_list)

    # Save candidates
    candidates_path = artifacts_dir / "semgrep_candidates.json"
    save_candidates(findings, candidates_path)

    return findings
