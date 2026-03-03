"""Run context — creates run_id, sets up directory structure and logging."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cve_agent.logging import setup_logging
from cve_agent.schemas.config import RunConfig
from cve_agent.schemas.run import RunResult, RunStatus

logger = logging.getLogger("cve_agent.run_context")

RUNS_DIR = Path("runs")


def generate_run_id() -> str:
    """Generate a unique run identifier: timestamp + short UUID."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    short = uuid.uuid4().hex[:8]
    return f"{ts}_{short}"


class RunContext:
    """Manages the lifecycle of a single pipeline run.

    Responsibilities:
      - Create runs/<run_id>/ directory structure
      - Initialise structured logging (console + run.log)
      - Hold the RunResult state object
      - Provide paths for artifacts
    """

    def __init__(
        self,
        config: RunConfig,
        *,
        run_id: Optional[str] = None,
        runs_dir: Optional[Path] = None,
        verbose: bool = False,
    ):
        self.config = config
        self.run_id = run_id or generate_run_id()
        self.runs_dir = runs_dir or RUNS_DIR
        self.verbose = verbose

        # Directory structure
        self.run_dir = self.runs_dir / self.run_id
        self.artifacts_dir = self.run_dir / "artifacts"
        self.log_file = self.run_dir / "run.log"

        # Create directories
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

        # Setup logging
        self.logger = setup_logging(
            log_file=self.log_file,
            verbose=verbose,
        )

        # Initialise result object
        self.result = RunResult(
            run_id=self.run_id,
            status=RunStatus.INITIALIZED,
        )

        logger.info(f"Run context created: {self.run_id}")
        logger.info(f"  Run dir:      {self.run_dir.resolve()}")
        logger.info(f"  Artifacts:    {self.artifacts_dir.resolve()}")
        logger.info(f"  Log file:     {self.log_file.resolve()}")

    def artifact_path(self, filename: str) -> Path:
        """Return full path for an artifact file."""
        return self.artifacts_dir / filename

    def mark_running(self) -> None:
        """Transition to RUNNING status."""
        self.result.status = RunStatus.RUNNING
        logger.info("Pipeline status -> RUNNING")

    def mark_completed(self) -> None:
        """Transition to COMPLETED status."""
        self.result.status = RunStatus.COMPLETED
        self.result.finished_at = datetime.now(timezone.utc)
        logger.info(
            f"Pipeline status -> COMPLETED "
            f"(findings: {len(self.result.findings)}, "
            f"confirmed: {self.result.stats.findings_confirmed})"
        )

    def mark_failed(self, error: str = "") -> None:
        """Transition to FAILED status."""
        self.result.status = RunStatus.FAILED
        self.result.finished_at = datetime.now(timezone.utc)
        logger.error(f"Pipeline status -> FAILED: {error}")
