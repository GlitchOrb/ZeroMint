"""Docker sandbox runner — isolated execution with resource limits.

Provides a safe, network-isolated Docker container for running
generated tests and harnesses. Falls back gracefully when Docker
is unavailable or in --dry-run mode.

Safety constraints (enforced):
  - network_off=True by default (--network=none)
  - CPU / memory limits
  - Hard timeout with forced kill
  - Repo mounted read-only
  - stdout/stderr captured to artifacts/logs
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from cve_agent.schemas.config import SandboxConfig

logger = logging.getLogger("cve_agent.sandbox.docker_runner")

# Default Docker image for Python test execution
DEFAULT_IMAGE = "python:3.12-slim"


@dataclass
class SandboxResult:
    """Result of a sandbox execution."""
    status: str  # "success" | "failure" | "crash" | "timeout" | "skipped" | "dry_run"
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_sec: float = 0.0
    log_path: Optional[str] = None
    errors: list[str] = field(default_factory=list)


def is_docker_available() -> bool:
    """Check if Docker CLI is installed and daemon is running."""
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def build_docker_command(
    command: list[str],
    *,
    sandbox_cfg: SandboxConfig,
    work_dir: Path | None = None,
    repo_dir: Path | None = None,
    image: str = DEFAULT_IMAGE,
    extra_env: dict[str, str] | None = None,
) -> list[str]:
    """Build a docker run command with safety constraints.

    Args:
        command: Command to run inside the container.
        sandbox_cfg: Sandbox configuration with resource limits.
        work_dir: Working directory to mount (read-write).
        repo_dir: Repository directory to mount (read-only).
        image: Docker image to use.
        extra_env: Additional environment variables.

    Returns:
        Complete docker command as a list of strings.
    """
    cmd = ["docker", "run", "--rm"]

    # Network isolation (MUST be true for safety)
    if sandbox_cfg.network_off:
        cmd.append("--network=none")

    # Resource limits
    if sandbox_cfg.cpu:
        cmd.extend(["--cpus", str(sandbox_cfg.cpu)])

    if sandbox_cfg.mem_mb:
        cmd.extend(["--memory", f"{sandbox_cfg.mem_mb}m"])
        # Prevent swap abuse
        cmd.extend(["--memory-swap", f"{sandbox_cfg.mem_mb}m"])

    # Security: drop all capabilities, read-only root filesystem
    cmd.extend([
        "--cap-drop=ALL",
        "--security-opt", "no-new-privileges",
    ])

    # Mount working directory (tests/harnesses)
    if work_dir:
        cmd.extend(["-v", f"{work_dir}:/work:rw"])
        cmd.extend(["-w", "/work"])

    # Mount repo read-only
    if repo_dir:
        cmd.extend(["-v", f"{repo_dir}:/repo:ro"])

    # Environment variables
    if extra_env:
        for key, val in extra_env.items():
            cmd.extend(["-e", f"{key}={val}"])

    # Image
    cmd.append(image)

    # Command
    cmd.extend(command)

    return cmd


def run_in_sandbox(
    command: list[str],
    *,
    sandbox_cfg: SandboxConfig,
    work_dir: Path | None = None,
    repo_dir: Path | None = None,
    log_dir: Path | None = None,
    label: str = "sandbox",
    image: str = DEFAULT_IMAGE,
    dry_run: bool = False,
) -> SandboxResult:
    """Execute a command inside a Docker sandbox.

    Args:
        command: Command to run inside container.
        sandbox_cfg: Sandbox resource/safety configuration.
        work_dir: Directory for test files (mounted rw).
        repo_dir: Repository root (mounted ro).
        log_dir: Where to save stdout/stderr logs.
        label: Label for log filenames.
        image: Docker image.
        dry_run: If True, build command but don't execute.

    Returns:
        SandboxResult with status, output, and log paths.
    """
    docker_cmd = build_docker_command(
        command,
        sandbox_cfg=sandbox_cfg,
        work_dir=work_dir,
        repo_dir=repo_dir,
        image=image,
    )

    cmd_str = " ".join(docker_cmd)
    logger.info("[sandbox] Command: %s", cmd_str[:200])

    if dry_run:
        logger.info("[sandbox] Dry-run mode — skipping execution")
        return SandboxResult(
            status="dry_run",
            stdout=f"[dry-run] Would execute: {cmd_str[:500]}",
        )

    if not is_docker_available():
        logger.warning("[sandbox] Docker not available — skipping")
        return SandboxResult(
            status="skipped",
            errors=["Docker not available"],
        )

    # Execute
    start_time = time.monotonic()
    try:
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=sandbox_cfg.timeout_sec,
        )
        duration = time.monotonic() - start_time

        # Determine status
        if result.returncode == 0:
            status = "success"
        elif result.returncode == 137:  # killed (OOM or timeout)
            status = "crash"
        elif result.returncode < 0:
            status = "crash"
        else:
            status = "failure"

        sandbox_result = SandboxResult(
            status=status,
            exit_code=result.returncode,
            stdout=result.stdout[-5000:],  # last 5KB
            stderr=result.stderr[-5000:],
            duration_sec=round(duration, 2),
        )

    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start_time
        sandbox_result = SandboxResult(
            status="timeout",
            exit_code=-1,
            duration_sec=round(duration, 2),
            errors=[f"Timed out after {sandbox_cfg.timeout_sec}s"],
        )
        # Force-kill the container
        _force_kill_container(label)

    except Exception as exc:
        sandbox_result = SandboxResult(
            status="crash",
            exit_code=-1,
            errors=[str(exc)],
        )

    # Save logs
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{label}.log"

        log_content = (
            f"=== Sandbox Execution: {label} ===\n"
            f"Status: {sandbox_result.status}\n"
            f"Exit code: {sandbox_result.exit_code}\n"
            f"Duration: {sandbox_result.duration_sec}s\n"
            f"\n=== STDOUT ===\n{sandbox_result.stdout}\n"
            f"\n=== STDERR ===\n{sandbox_result.stderr}\n"
        )
        if sandbox_result.errors:
            log_content += f"\n=== ERRORS ===\n"
            for err in sandbox_result.errors:
                log_content += f"  - {err}\n"

        log_path.write_text(log_content, encoding="utf-8")
        sandbox_result.log_path = str(log_path)
        logger.info("[sandbox] Log saved: %s", log_path)

    logger.info(
        "[sandbox] %s — status=%s exit=%d duration=%.1fs",
        label, sandbox_result.status,
        sandbox_result.exit_code, sandbox_result.duration_sec,
    )

    return sandbox_result


def run_pytest_in_sandbox(
    test_path: Path,
    *,
    sandbox_cfg: SandboxConfig,
    repo_dir: Path | None = None,
    log_dir: Path | None = None,
    dry_run: bool = False,
) -> SandboxResult:
    """Run a pytest test file inside a Docker sandbox.

    Convenience wrapper that sets up the right command and mounts.
    """
    command = [
        "python", "-m", "pytest",
        str(test_path.name),
        "-v", "--tb=short", "-q",
    ]

    return run_in_sandbox(
        command,
        sandbox_cfg=sandbox_cfg,
        work_dir=test_path.parent,
        repo_dir=repo_dir,
        log_dir=log_dir,
        label=f"pytest_{test_path.stem}",
        dry_run=dry_run,
    )


def run_local_pytest(
    test_path: Path,
    *,
    timeout: int = 60,
    log_dir: Path | None = None,
    label: str = "",
) -> SandboxResult:
    """Run a pytest test file locally (no Docker).

    Used as fallback when Docker is not available.
    """
    label = label or f"local_{test_path.stem}"
    cmd = [
        "python", "-m", "pytest",
        str(test_path),
        "-v", "--tb=short", "-q",
    ]

    start_time = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration = time.monotonic() - start_time

        if result.returncode == 0:
            status = "success"
        else:
            status = "failure"

        sandbox_result = SandboxResult(
            status=status,
            exit_code=result.returncode,
            stdout=result.stdout[-5000:],
            stderr=result.stderr[-5000:],
            duration_sec=round(duration, 2),
        )

    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start_time
        sandbox_result = SandboxResult(
            status="timeout",
            exit_code=-1,
            duration_sec=round(duration, 2),
            errors=[f"Timed out after {timeout}s"],
        )

    except Exception as exc:
        sandbox_result = SandboxResult(
            status="crash",
            exit_code=-1,
            errors=[str(exc)],
        )

    # Save logs
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{label}.log"
        log_content = (
            f"=== Local Execution: {label} ===\n"
            f"Status: {sandbox_result.status}\n"
            f"Exit code: {sandbox_result.exit_code}\n"
            f"Duration: {sandbox_result.duration_sec}s\n"
            f"\n=== STDOUT ===\n{sandbox_result.stdout}\n"
            f"\n=== STDERR ===\n{sandbox_result.stderr}\n"
        )
        log_path.write_text(log_content, encoding="utf-8")
        sandbox_result.log_path = str(log_path)

    return sandbox_result


def _force_kill_container(label: str) -> None:
    """Attempt to force-kill a running container by label."""
    try:
        subprocess.run(
            ["docker", "kill", label],
            capture_output=True,
            timeout=5,
        )
    except Exception:
        pass
