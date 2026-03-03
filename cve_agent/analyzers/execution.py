"""Execution / validation runner — run harnesses and tests, collect results.

Reads fuzz_attempts.json, executes each test/harness via the sandbox
(or locally), and produces validation_results.json with per-finding
outcomes (success / failure / crash / timeout).

Each result links back to the Finding via EvidenceItem with log paths.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from cve_agent.sandbox.docker_runner import (
    SandboxResult,
    is_docker_available,
    run_in_sandbox,
    run_local_pytest,
    run_pytest_in_sandbox,
)
from cve_agent.schemas.config import FeaturesConfig, SandboxConfig
from cve_agent.schemas.findings import (
    CodeLocation,
    EvidenceItem,
    EvidenceKind,
    Finding,
    FindingStatus,
)

logger = logging.getLogger("cve_agent.analyzers.execution")


# ── Validation result schema ─────────────────────────────


class ValidationOutcome(BaseModel):
    """Result of executing a single test/harness."""
    finding_id: str
    test_file: str = ""
    status: str = "pending"  # success | failure | crash | timeout | skipped | dry_run
    exit_code: int = 0
    duration_sec: float = 0.0
    passed_count: int = 0
    failed_count: int = 0
    log_path: str = ""
    errors: list[str] = Field(default_factory=list)
    sanitizer_output: str = ""


class ValidationResults(BaseModel):
    """Collection of all validation outcomes."""
    total: int = 0
    success: int = 0
    failure: int = 0
    crash: int = 0
    timeout: int = 0
    skipped: int = 0
    outcomes: list[ValidationOutcome] = Field(default_factory=list)


# ── Sanitizer helpers ─────────────────────────────────────


def inject_sanitizer_flags(
    build_content: str,
    *,
    asan: bool = True,
    ubsan: bool = True,
) -> str:
    """Inject ASan/UBSan flags into a Makefile or CMakeLists.txt.

    Only applies if the flags aren't already present.
    """
    flags: list[str] = []
    if asan and "-fsanitize=address" not in build_content:
        flags.append("-fsanitize=address")
    if ubsan and "-fsanitize=undefined" not in build_content:
        flags.append("-fsanitize=undefined")

    if not flags:
        return build_content  # already has them

    flag_str = " ".join(flags)

    # For Makefile: append to CFLAGS
    if "CFLAGS" in build_content:
        build_content = build_content.replace(
            "CFLAGS =", f"CFLAGS = {flag_str}", 1,
        )
    # For CMake: append compile options
    elif "target_compile_options" in build_content:
        build_content = build_content.replace(
            "-fsanitize=fuzzer",
            f"-fsanitize=fuzzer {flag_str}",
        )

    return build_content


def parse_sanitizer_output(output: str) -> str:
    """Extract sanitizer-relevant lines from stderr/stdout."""
    sanitizer_markers = [
        "AddressSanitizer",
        "UndefinedBehaviorSanitizer",
        "LeakSanitizer",
        "MemorySanitizer",
        "ThreadSanitizer",
        "ERROR: ",
        "SUMMARY: ",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "use-after-free",
        "double-free",
        "null dereference",
        "signed integer overflow",
    ]

    lines = output.split("\n")
    relevant: list[str] = []

    for line in lines:
        if any(marker in line for marker in sanitizer_markers):
            relevant.append(line.strip())

    return "\n".join(relevant[:30])  # limit


# ── Parse pytest output ───────────────────────────────────


def _count_pytest_results(output: str) -> tuple[int, int]:
    """Extract passed/failed counts from pytest output."""
    import re
    passed = 0
    failed = 0

    m_passed = re.search(r"(\d+)\s+passed", output)
    if m_passed:
        passed = int(m_passed.group(1))

    m_failed = re.search(r"(\d+)\s+failed", output)
    if m_failed:
        failed = int(m_failed.group(1))

    return passed, failed


# ── Main execution runner ─────────────────────────────────


def execute_validations(
    artifacts_dir: Path,
    *,
    sandbox_cfg: SandboxConfig,
    features_cfg: FeaturesConfig,
    repo_dir: Path | None = None,
    dry_run: bool = False,
) -> ValidationResults:
    """Execute all generated tests/harnesses and collect results.

    Reads fuzz_attempts.json, runs each test file via sandbox or
    locally, and produces validation_results.json.

    Args:
        artifacts_dir: Path to artifacts/ directory.
        sandbox_cfg: Sandbox configuration.
        features_cfg: Feature flags (sanitizers, etc).
        repo_dir: Repository root for read-only mount.
        dry_run: Skip actual execution.

    Returns:
        ValidationResults with all outcomes.
    """
    results = ValidationResults()

    # Load fuzz attempts
    attempts_path = artifacts_dir / "fuzz_attempts.json"
    if not attempts_path.exists():
        logger.warning("[execute] No fuzz_attempts.json found — nothing to execute")
        return results

    try:
        attempts = json.loads(attempts_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("[execute] Failed to load fuzz_attempts.json: %s", exc)
        return results

    log_dir = artifacts_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    docker_ok = is_docker_available() and not dry_run
    use_docker = docker_ok and sandbox_cfg.enabled

    logger.info(
        "[execute] %d attempts, docker=%s, dry_run=%s",
        len(attempts), use_docker, dry_run,
    )

    for attempt in attempts:
        finding_id = attempt.get("finding_id", "unknown")
        test_file = attempt.get("test_file", "")
        harness_file = attempt.get("harness_file", "")
        language = attempt.get("language", "python")

        # Determine which file to execute
        target_file = test_file or harness_file
        if not target_file:
            outcome = ValidationOutcome(
                finding_id=finding_id,
                status="skipped",
                errors=["No test or harness file"],
            )
            results.outcomes.append(outcome)
            results.skipped += 1
            continue

        full_path = artifacts_dir / target_file
        if not full_path.exists():
            outcome = ValidationOutcome(
                finding_id=finding_id,
                test_file=target_file,
                status="skipped",
                errors=["File not found"],
            )
            results.outcomes.append(outcome)
            results.skipped += 1
            continue

        # Inject sanitizers for C/C++
        if language == "c_cpp" and features_cfg.enable_sanitizers:
            _inject_sanitizers_for_harness(full_path.parent)

        # Execute
        if dry_run:
            sandbox_result = SandboxResult(status="dry_run")
        elif language == "python":
            if use_docker:
                sandbox_result = run_pytest_in_sandbox(
                    full_path,
                    sandbox_cfg=sandbox_cfg,
                    repo_dir=repo_dir,
                    log_dir=log_dir,
                    dry_run=False,
                )
            else:
                sandbox_result = run_local_pytest(
                    full_path,
                    timeout=sandbox_cfg.timeout_sec,
                    log_dir=log_dir,
                    label=f"test_{finding_id}",
                )
        elif language == "c_cpp":
            # For C/C++ we'd need to compile + run
            # For now, just record as skipped if no Docker
            sandbox_result = SandboxResult(
                status="skipped",
                errors=["C/C++ execution requires Docker + clang"],
            )
        else:
            sandbox_result = SandboxResult(
                status="skipped",
                errors=[f"Unsupported language: {language}"],
            )

        # Parse results
        passed, failed = 0, 0
        if language == "python" and sandbox_result.stdout:
            passed, failed = _count_pytest_results(sandbox_result.stdout)

        # Check for sanitizer output
        sanitizer_out = ""
        if features_cfg.enable_sanitizers:
            sanitizer_out = parse_sanitizer_output(
                sandbox_result.stderr + sandbox_result.stdout
            )

        outcome = ValidationOutcome(
            finding_id=finding_id,
            test_file=target_file,
            status=sandbox_result.status,
            exit_code=sandbox_result.exit_code,
            duration_sec=sandbox_result.duration_sec,
            passed_count=passed,
            failed_count=failed,
            log_path=sandbox_result.log_path or "",
            errors=sandbox_result.errors,
            sanitizer_output=sanitizer_out,
        )
        results.outcomes.append(outcome)

        # Count by status
        if sandbox_result.status == "success":
            results.success += 1
        elif sandbox_result.status == "failure":
            results.failure += 1
        elif sandbox_result.status == "crash":
            results.crash += 1
        elif sandbox_result.status == "timeout":
            results.timeout += 1
        else:
            results.skipped += 1

        logger.info(
            "[execute] %s — %s (passed=%d, failed=%d, %.1fs)",
            finding_id, sandbox_result.status,
            passed, failed, sandbox_result.duration_sec,
        )

    results.total = len(results.outcomes)
    return results


def _inject_sanitizers_for_harness(harness_dir: Path) -> None:
    """Inject sanitizer flags into build files in a harness directory."""
    for build_file in ("Makefile", "CMakeLists.txt"):
        path = harness_dir / build_file
        if path.exists():
            content = path.read_text(encoding="utf-8")
            updated = inject_sanitizer_flags(content)
            if updated != content:
                path.write_text(updated, encoding="utf-8")
                logger.info("[execute] Injected sanitizer flags: %s", path)


def create_evidence_from_outcome(
    outcome: ValidationOutcome,
) -> EvidenceItem:
    """Convert a validation outcome into an EvidenceItem."""
    summary_parts = [f"Execution: {outcome.status}"]
    if outcome.passed_count or outcome.failed_count:
        summary_parts.append(f"passed={outcome.passed_count}, failed={outcome.failed_count}")
    if outcome.duration_sec:
        summary_parts.append(f"duration={outcome.duration_sec}s")
    if outcome.sanitizer_output:
        summary_parts.append("SANITIZER FINDINGS DETECTED")

    return EvidenceItem(
        kind=EvidenceKind.TOOL_OUTPUT,
        summary=" | ".join(summary_parts),
        artifact_path=outcome.log_path or None,
        snippet=outcome.sanitizer_output[:500] if outcome.sanitizer_output else None,
    )


def save_validation_results(
    results: ValidationResults,
    artifacts_dir: Path,
) -> Path:
    """Save validation_results.json artifact."""
    out_path = artifacts_dir / "validation_results.json"
    out_path.write_text(
        results.model_dump_json(indent=2),
        encoding="utf-8",
    )
    logger.info(
        "Saved validation results: %d total (%d success, %d failure, %d crash, %d timeout)",
        results.total, results.success, results.failure,
        results.crash, results.timeout,
    )
    return out_path
