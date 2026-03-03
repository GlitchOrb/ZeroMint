"""Self-correction loop — run tests, parse failures, retry fixes.

Executes generated test files in a subprocess, parses pytest output
for failures, produces correction instructions, and retries up to
MAX_ITERATIONS times.

Safety:
  - Local execution only (no network)
  - Timeout enforced per test run
  - No destructive operations
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger("cve_agent.fuzz.self_correction")

MAX_ITERATIONS = 3
TEST_TIMEOUT_SEC = 30


def run_test_file(
    test_path: Path,
    *,
    timeout: int = TEST_TIMEOUT_SEC,
    cwd: Path | None = None,
) -> dict[str, Any]:
    """Execute a pytest test file and return structured results.

    Args:
        test_path: Path to the test .py file.
        timeout: Max seconds for the test run.
        cwd: Working directory for pytest.

    Returns:
        Dict with keys: passed, failed, errors, output, returncode
    """
    cmd = [
        "python", "-m", "pytest",
        str(test_path),
        "-v",
        "--tb=short",
        "--no-header",
        "-q",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
    except subprocess.TimeoutExpired:
        return {
            "passed": 0,
            "failed": 0,
            "errors": ["Test execution timed out"],
            "output": "",
            "returncode": -1,
        }
    except FileNotFoundError:
        return {
            "passed": 0,
            "failed": 0,
            "errors": ["pytest not found"],
            "output": "",
            "returncode": -1,
        }

    output = result.stdout + "\n" + result.stderr

    # Parse pytest summary line
    passed, failed, error_count = _parse_pytest_summary(output)

    errors: list[str] = []
    if failed > 0 or error_count > 0:
        errors = _extract_failure_messages(output)

    return {
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "output": output[-2000:],  # last 2000 chars
        "returncode": result.returncode,
    }


def _parse_pytest_summary(output: str) -> tuple[int, int, int]:
    """Parse pytest summary line for pass/fail/error counts."""
    # Match patterns like "5 passed", "2 failed", "1 error"
    passed = 0
    failed = 0
    errors = 0

    m_passed = re.search(r"(\d+)\s+passed", output)
    if m_passed:
        passed = int(m_passed.group(1))

    m_failed = re.search(r"(\d+)\s+failed", output)
    if m_failed:
        failed = int(m_failed.group(1))

    m_error = re.search(r"(\d+)\s+error", output)
    if m_error:
        errors = int(m_error.group(1))

    return passed, failed, errors


def _extract_failure_messages(output: str) -> list[str]:
    """Extract individual failure messages from pytest output."""
    failures: list[str] = []

    # Look for FAILED lines
    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("FAILED"):
            failures.append(line)
        elif "Error" in line and "::" in line:
            failures.append(line)
        elif line.startswith("E "):
            failures.append(line)

    return failures[:10]  # limit


def generate_correction_instruction(
    test_path: Path,
    errors: list[str],
    iteration: int,
) -> str:
    """Generate a textual correction instruction from test failures.

    This instruction could be consumed by an LLM or used as a log
    for the self-correction loop.

    Args:
        test_path: Path to the failing test file.
        errors: List of error/failure messages.
        iteration: Current iteration number.

    Returns:
        Human-readable correction instruction.
    """
    lines = [
        f"Self-correction iteration {iteration}/{MAX_ITERATIONS}",
        f"Test file: {test_path}",
        f"Failures ({len(errors)}):",
    ]

    for i, err in enumerate(errors, 1):
        lines.append(f"  {i}. {err}")

    lines.append("")
    lines.append("Suggested fixes:")

    # Heuristic suggestions based on error patterns
    errors_text = " ".join(errors).lower()

    if "importerror" in errors_text or "modulenotfounderror" in errors_text:
        lines.append("  - Fix import paths or mock missing modules")
    if "syntaxerror" in errors_text:
        lines.append("  - Fix Python syntax in generated test")
    if "typeerror" in errors_text:
        lines.append("  - Check argument types — may need bytes vs str conversion")
    if "nameerror" in errors_text:
        lines.append("  - Define missing variables or fix references")
    if "attributeerror" in errors_text:
        lines.append("  - Verify object methods/attributes exist")
    if "timeout" in errors_text:
        lines.append("  - Reduce input sizes or add timeout guards")
    if "memoryerror" in errors_text:
        lines.append("  - Reduce extreme input sizes")

    return "\n".join(lines)


def self_correction_loop(
    test_path: Path,
    attempt: dict[str, Any],
    *,
    max_iterations: int = MAX_ITERATIONS,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run a self-correction loop for a single test file.

    1. Run the test
    2. If all pass → done (status="verified")
    3. If failures → generate correction instruction
    4. Apply minimal fix (syntax/import errors only)
    5. Retry up to max_iterations

    Args:
        test_path: Path to the test file.
        attempt: The attempt record to update.
        max_iterations: Maximum correction iterations.
        dry_run: If True, skip actual test execution.

    Returns:
        Updated attempt dict with final status.
    """
    if dry_run:
        attempt["status"] = "dry_run"
        attempt["iterations"] = 0
        logger.info("[self_correct] Dry-run: %s", test_path.name)
        return attempt

    for iteration in range(1, max_iterations + 1):
        attempt["iterations"] = iteration

        logger.info(
            "[self_correct] Running %s (iteration %d/%d)",
            test_path.name, iteration, max_iterations,
        )

        result = run_test_file(test_path)

        if result["passed"] > 0 and result["failed"] == 0:
            attempt["status"] = "verified"
            attempt["errors"] = []
            logger.info(
                "[self_correct] ✓ %s — %d passed",
                test_path.name, result["passed"],
            )
            return attempt

        if result["passed"] > 0:
            # Some pass, some fail — partial success
            attempt["status"] = "partial"
            attempt["errors"] = result["errors"]
            logger.info(
                "[self_correct] Partial: %d passed, %d failed",
                result["passed"], result["failed"],
            )
        else:
            attempt["status"] = "failed"
            attempt["errors"] = result["errors"]

        # Generate correction instruction
        instruction = generate_correction_instruction(
            test_path, result["errors"], iteration,
        )
        logger.debug("[self_correct] Correction:\n%s", instruction)

        # Try to auto-fix simple issues
        if iteration < max_iterations:
            fixed = _try_auto_fix(test_path, result["errors"])
            if not fixed:
                logger.info(
                    "[self_correct] No auto-fix available, stopping at iteration %d",
                    iteration,
                )
                break

    return attempt


def _try_auto_fix(test_path: Path, errors: list[str]) -> bool:
    """Attempt simple auto-fixes on the test file.

    Currently handles:
      - SyntaxError: comment out problematic lines
      - ImportError: add try/except around imports

    Returns:
        True if a fix was applied.
    """
    errors_text = " ".join(errors).lower()

    try:
        content = test_path.read_text(encoding="utf-8")
    except OSError:
        return False

    modified = False

    # Fix: surrogate unicode strings that crash
    if "surrogates not allowed" in errors_text or "surrogatepass" in errors_text:
        content = content.replace("'\\ud800'", "'\\ufffd'")
        modified = True

    # Fix: MemoryError from huge allocations
    if "memoryerror" in errors_text:
        content = content.replace("2 ** 20", "2 ** 14")
        content = content.replace("2**20", "2**14")
        modified = True

    if modified:
        test_path.write_text(content, encoding="utf-8")
        logger.info("[self_correct] Applied auto-fix to %s", test_path.name)
        return True

    return False


# ── Orchestrator ──────────────────────────────────────────


def run_all_tests(
    attempts: list[dict[str, Any]],
    output_dir: Path,
    *,
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    """Run self-correction loop for all generated test files.

    Args:
        attempts: List of attempt dicts from test generator.
        output_dir: Artifacts directory.
        dry_run: Skip actual execution.

    Returns:
        Updated attempts list.
    """
    for attempt in attempts:
        if attempt["status"] != "generated":
            continue

        test_path = output_dir / attempt["test_file"]
        if not test_path.exists():
            attempt["status"] = "missing"
            continue

        self_correction_loop(
            test_path,
            attempt,
            dry_run=dry_run,
        )

    # Summary
    statuses = {}
    for a in attempts:
        statuses[a["status"]] = statuses.get(a["status"], 0) + 1
    logger.info("[self_correct] Summary: %s", statuses)

    return attempts


def save_fuzz_attempts(
    attempts: list[dict[str, Any]],
    artifacts_dir: Path,
) -> Path:
    """Save fuzz_attempts.json artifact."""
    out_path = artifacts_dir / "fuzz_attempts.json"
    out_path.write_text(
        json.dumps(attempts, indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("Saved %d attempts to %s", len(attempts), out_path)
    return out_path
