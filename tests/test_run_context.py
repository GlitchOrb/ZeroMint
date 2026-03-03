"""Test 3: Run context — run_id generation and directory creation."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from cve_agent.run_context import RunContext, generate_run_id
from cve_agent.schemas.config import RunConfig


class TestRunIdGeneration:
    """Tests for run_id format and uniqueness."""

    def test_format(self) -> None:
        """run_id should be timestamp_uuid format."""
        rid = generate_run_id()
        # Format: YYYYMMDD_HHMMSS_<8hex>
        assert re.match(r"^\d{8}_\d{6}_[0-9a-f]{8}$", rid), f"Bad format: {rid}"

    def test_uniqueness(self) -> None:
        """Successive run_ids should be unique."""
        ids = {generate_run_id() for _ in range(20)}
        assert len(ids) == 20


class TestRunContext:
    """Tests for RunContext directory setup."""

    def test_creates_run_directory(self, tmp_dir: Path) -> None:
        """RunContext should create runs/<run_id>/ with artifacts/ and run.log."""
        config = RunConfig()
        ctx = RunContext(
            config,
            run_id="test-run-001",
            runs_dir=tmp_dir / "runs",
        )

        assert ctx.run_dir.exists()
        assert ctx.artifacts_dir.exists()
        assert ctx.log_file.parent.exists()
        assert ctx.run_id == "test-run-001"
        assert (tmp_dir / "runs" / "test-run-001").exists()
        assert (tmp_dir / "runs" / "test-run-001" / "artifacts").exists()

    def test_auto_generates_run_id(self, tmp_dir: Path) -> None:
        """RunContext should auto-generate run_id if not provided."""
        config = RunConfig()
        ctx = RunContext(config, runs_dir=tmp_dir / "runs")

        assert ctx.run_id is not None
        assert len(ctx.run_id) > 0
        assert ctx.run_dir.exists()

    def test_artifact_path(self, tmp_dir: Path) -> None:
        """artifact_path should return correct full path."""
        config = RunConfig()
        ctx = RunContext(config, run_id="art-test", runs_dir=tmp_dir / "runs")

        path = ctx.artifact_path("code_graph.json")
        assert path == tmp_dir / "runs" / "art-test" / "artifacts" / "code_graph.json"

    def test_lifecycle_transitions(self, tmp_dir: Path) -> None:
        """RunContext should transition through status states."""
        config = RunConfig()
        ctx = RunContext(config, run_id="lifecycle-test", runs_dir=tmp_dir / "runs")

        assert ctx.result.status.value == "initialized"

        ctx.mark_running()
        assert ctx.result.status.value == "running"

        ctx.mark_completed()
        assert ctx.result.status.value == "completed"
        assert ctx.result.finished_at is not None

    def test_mark_failed(self, tmp_dir: Path) -> None:
        """mark_failed should set status and finished_at."""
        config = RunConfig()
        ctx = RunContext(config, run_id="fail-test", runs_dir=tmp_dir / "runs")

        ctx.mark_running()
        ctx.mark_failed("something broke")

        assert ctx.result.status.value == "failed"
        assert ctx.result.finished_at is not None

    def test_log_file_created(self, tmp_dir: Path) -> None:
        """Logging should write to run.log file."""
        import logging

        config = RunConfig()
        ctx = RunContext(
            config,
            run_id="log-test",
            runs_dir=tmp_dir / "runs",
            verbose=True,
        )

        # Force a log entry
        logger = logging.getLogger("cve_agent.run_context")
        logger.info("Test log entry for verification")

        # Flush handlers
        for handler in logging.getLogger("cve_agent").handlers:
            handler.flush()

        # Check file exists and has content
        assert ctx.log_file.exists()
        content = ctx.log_file.read_text(encoding="utf-8")
        assert len(content) > 0
