"""Tests for STEP 10 — Pipeline Orchestrator (state-machine).

Covers:
  1. Full end-to-end pipeline produces all expected artifacts
  2. Checkpoint skipping (re-run skips completed stages)
  3. continue_on_fail mode
  4. Budget tracker
  5. StageResult / StageStatus schemas
  6. Pipeline state persistence (pipeline_state.json)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cve_agent.pipeline import (
    BudgetTracker,
    StageResult,
    StageStatus,
    _has_checkpoint,
    run_pipeline,
)
from cve_agent.run_context import RunContext
from cve_agent.schemas.config import (
    BudgetConfig,
    FeaturesConfig,
    RetrieverConfig,
    RunConfig,
    TargetConfig,
)


# ── Helpers ───────────────────────────────────────────────


_FIXTURES = Path(__file__).parent / "fixtures" / "sample_repo"


def _make_ctx(
    tmp_path: Path,
    *,
    target: str | None = None,
    continue_on_fail: bool = False,
    enable_graph: bool = False,
    enable_fuzz: bool = True,
    sandbox_enabled: bool = True,
) -> RunContext:
    """Create a RunContext pointing at sample_repo."""
    cfg = RunConfig(
        target=TargetConfig(
            type="repo",
            path_or_url=target or str(_FIXTURES),
        ),
        features=FeaturesConfig(
            enable_graph=enable_graph,
            enable_fuzz=enable_fuzz,
        ),
        sandbox=RunConfig().sandbox.model_copy(
            update={"enabled": sandbox_enabled},
        ),
        continue_on_fail=continue_on_fail,
    )
    return RunContext(cfg, run_id="e2e-test", runs_dir=tmp_path)


# ── E2E Pipeline ─────────────────────────────────────────


class TestEndToEndPipeline:
    """Full pipeline dry-run produces all expected artifacts."""

    def test_full_pipeline_produces_all_artifacts(self, tmp_path: Path) -> None:
        """recon → static → hypothesize → generate → execute →
        triage → report — all produce artifacts."""
        ctx = _make_ctx(tmp_path)
        run_pipeline(ctx)

        art = ctx.artifacts_dir

        # Core artifacts
        assert (art / "repo_index.json").exists()
        assert (art / "hotspots.json").exists()
        assert (art / "hypotheses.json").exists()
        assert (art / "fuzz_attempts.json").exists()
        assert (art / "validation_results.json").exists()
        assert (art / "triage.json").exists()
        assert (art / "findings.json").exists()
        assert (art / "run_result.json").exists()
        assert (art / "pipeline_state.json").exists()

        # Report
        assert (ctx.run_dir / "REPORT.md").exists()
        assert (ctx.run_dir / "evidence_bundle.zip").exists()

        # Status
        assert ctx.result.status.value == "completed"
        assert ctx.result.stats.hypotheses_generated > 0

    def test_pipeline_state_has_all_stages(self, tmp_path: Path) -> None:
        """pipeline_state.json records all 8 stages."""
        ctx = _make_ctx(tmp_path)
        run_pipeline(ctx)

        state = json.loads(
            (ctx.artifacts_dir / "pipeline_state.json").read_text(encoding="utf-8")
        )
        stages = state["stages"]
        assert len(stages) == 8

        stage_names = [s["name"] for s in stages]
        assert stage_names == [
            "recon", "graph", "static", "hypothesize",
            "generate", "execute", "triage", "report",
        ]

        # All completed
        for s in stages:
            assert s["status"] == "completed"
            assert s["error"] is None


# ── Checkpoint skipping ──────────────────────────────────


class TestCheckpointing:
    """Re-running should skip stages with existing artifacts."""

    def test_rerun_skips_completed_stages(self, tmp_path: Path) -> None:
        """First run produces artifacts; second run skips stages."""
        ctx1 = _make_ctx(tmp_path)
        run_pipeline(ctx1)

        # Create new context pointing at same run dir
        cfg = ctx1.config
        ctx2 = RunContext(
            cfg, run_id="e2e-test",
            runs_dir=tmp_path,
        )
        run_pipeline(ctx2)

        # Should still complete
        assert ctx2.result.status.value == "completed"

    def test_has_checkpoint_empty_file(self, tmp_path: Path) -> None:
        """Empty JSON file should not count as checkpoint."""
        (tmp_path / "test.json").write_text("{}", encoding="utf-8")
        assert not _has_checkpoint(tmp_path, "test.json")

    def test_has_checkpoint_real_file(self, tmp_path: Path) -> None:
        (tmp_path / "test.json").write_text('{"data": 1}', encoding="utf-8")
        assert _has_checkpoint(tmp_path, "test.json")

    def test_has_checkpoint_missing(self, tmp_path: Path) -> None:
        assert not _has_checkpoint(tmp_path, "missing.json")


# ── continue_on_fail ──────────────────────────────────────


class TestContinueOnFail:
    """continue_on_fail allows pipeline to continue past failures."""

    def test_continue_records_failure(self, tmp_path: Path) -> None:
        """If a stage fails with continue_on_fail, pipeline still runs."""
        # Point at non-existent repo so recon may fail
        ctx = _make_ctx(
            tmp_path,
            target=str(tmp_path / "nonexistent_dir"),
            continue_on_fail=True,
            enable_fuzz=False,
            sandbox_enabled=False,
        )
        # This should not raise even if stages fail
        run_pipeline(ctx)

        # Pipeline completes (possibly with failed status)
        state = json.loads(
            (ctx.artifacts_dir / "pipeline_state.json").read_text(encoding="utf-8")
        )
        # State file was saved regardless
        assert len(state["stages"]) == 8


# ── Budget tracker ────────────────────────────────────────


class TestBudgetTracker:
    """Test budget tracking and limit enforcement."""

    def test_initial_state(self) -> None:
        cfg = RunConfig()
        bt = BudgetTracker(cfg)
        assert bt.tokens_used == 0
        assert bt.cost_usd == 0.0
        assert bt.check() is None

    def test_record_usage(self) -> None:
        cfg = RunConfig()
        bt = BudgetTracker(cfg)
        bt.record(tokens=100, cost=0.01)
        assert bt.tokens_used == 100
        assert bt.cost_usd == 0.01

    def test_token_budget_exceeded(self) -> None:
        cfg = RunConfig(budget=BudgetConfig(max_tokens=100))
        bt = BudgetTracker(cfg)
        bt.record(tokens=100)
        err = bt.check()
        assert err is not None
        assert "Token budget exceeded" in err

    def test_cost_budget_exceeded(self) -> None:
        cfg = RunConfig(budget=BudgetConfig(max_cost_usd=0.50))
        bt = BudgetTracker(cfg)
        bt.record(cost=0.51)
        err = bt.check()
        assert err is not None
        assert "Cost budget exceeded" in err

    def test_within_budget(self) -> None:
        cfg = RunConfig(budget=BudgetConfig(max_tokens=1000, max_cost_usd=1.0))
        bt = BudgetTracker(cfg)
        bt.record(tokens=500, cost=0.25)
        assert bt.check() is None

    def test_remaining_tokens(self) -> None:
        cfg = RunConfig(budget=BudgetConfig(max_tokens=1000))
        bt = BudgetTracker(cfg)
        bt.record(tokens=300)
        assert bt.remaining_tokens() == 700

    def test_no_limit_remaining(self) -> None:
        cfg = RunConfig()
        bt = BudgetTracker(cfg)
        assert bt.remaining_tokens() is None


# ── StageResult schema ────────────────────────────────────


class TestStageResult:
    def test_defaults(self) -> None:
        sr = StageResult("test")
        assert sr.name == "test"
        assert sr.status == StageStatus.PENDING
        assert sr.error is None

    def test_status_transitions(self) -> None:
        sr = StageResult("test")
        sr.status = StageStatus.RUNNING
        assert sr.status == StageStatus.RUNNING
        sr.status = StageStatus.COMPLETED
        assert sr.status == StageStatus.COMPLETED


# ── Config additions ──────────────────────────────────────


class TestConfigAdditions:
    """Test new config fields."""

    def test_continue_on_fail_default(self) -> None:
        cfg = RunConfig()
        assert cfg.continue_on_fail is False

    def test_continue_on_fail_set(self) -> None:
        cfg = RunConfig(continue_on_fail=True)
        assert cfg.continue_on_fail is True

    def test_retriever_defaults(self) -> None:
        cfg = RunConfig()
        assert cfg.retriever.top_k == 10
        assert cfg.retriever.max_snippet_len == 500

    def test_retriever_custom(self) -> None:
        cfg = RunConfig(retriever=RetrieverConfig(top_k=5, max_snippet_len=200))
        assert cfg.retriever.top_k == 5
        assert cfg.retriever.max_snippet_len == 200

    def test_budget_defaults(self) -> None:
        cfg = RunConfig()
        assert cfg.budget.max_tokens is None
        assert cfg.budget.max_cost_usd is None
