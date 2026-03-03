"""Pipeline — state-machine orchestrator.

Stages (in order):
  1. recon       — Index repo, score hotspots
  2. graph       — Build call graph (optional)
  3. static      — Semgrep / CodeQL scanning
  4. hypothesize — Generate vulnerability hypotheses
  5. generate    — Create verification tests / harnesses
  6. execute     — Run tests in sandbox
  7. triage      — Conservative assessment
  8. report      — REPORT.md + evidence bundle

Architecture:
  - Each stage is a discrete function with a **checkpoint**: if the
    expected artifact already exists, the stage is skipped.
  - `continue_on_fail` controls whether a stage failure aborts the
    pipeline (default) or records the error and continues.
  - Budget guard checks LLM token / cost limits before stages that
    may call the LLM.
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from cve_agent.run_context import RunContext
from cve_agent.schemas.config import RunConfig

logger = logging.getLogger("cve_agent.pipeline")


# ── Stage definitions ─────────────────────────────────────


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


class StageResult:
    """Outcome of a single pipeline stage."""
    __slots__ = ("name", "status", "error", "skipped_reason")

    def __init__(self, name: str) -> None:
        self.name = name
        self.status = StageStatus.PENDING
        self.error: str | None = None
        self.skipped_reason: str | None = None


# ── Budget guard ──────────────────────────────────────────


class BudgetTracker:
    """Tracks LLM token usage and cost against configured limits."""

    def __init__(self, cfg: RunConfig) -> None:
        self.max_tokens = cfg.budget.max_tokens
        self.max_cost_usd = cfg.budget.max_cost_usd
        self.tokens_used = 0
        self.cost_usd = 0.0

    def check(self) -> str | None:
        """Return error string if budget exceeded, else None."""
        if self.max_tokens and self.tokens_used >= self.max_tokens:
            return (
                f"Token budget exceeded: {self.tokens_used}/{self.max_tokens}"
            )
        if self.max_cost_usd is not None and self.cost_usd >= self.max_cost_usd:
            return (
                f"Cost budget exceeded: ${self.cost_usd:.4f}/${self.max_cost_usd:.4f}"
            )
        return None

    def record(self, tokens: int = 0, cost: float = 0.0) -> None:
        self.tokens_used += tokens
        self.cost_usd += cost

    def remaining_tokens(self) -> int | None:
        if self.max_tokens is None:
            return None
        return max(0, self.max_tokens - self.tokens_used)


# ── Checkpoint helpers ────────────────────────────────────


def _has_checkpoint(artifacts_dir: Path, filename: str) -> bool:
    """Return True if the checkpoint artifact exists and is non-empty."""
    path = artifacts_dir / filename
    return path.exists() and path.stat().st_size > 2  # > "{}"


# ── Individual stage functions ────────────────────────────


def _stage_recon(ctx: RunContext, cfg: RunConfig) -> None:
    """Stage 1: Repo indexing + hotspot scoring."""
    if _has_checkpoint(ctx.artifacts_dir, "repo_index.json"):
        logger.info("[stage:recon] Checkpoint found — skipping")
        return

    logger.info("[stage:recon] Target: %s (%s)", cfg.target.path_or_url, cfg.target.type.value)

    if cfg.target.type.value == "repo":
        from cve_agent.analyzers.repo_indexer import index_repo, save_artifacts
        repo_index, hotspot_index = index_repo(cfg)
        save_artifacts(repo_index, hotspot_index, ctx.artifacts_dir)

        ctx.result.stats.indexed_files = repo_index.summary.total_files
        ctx.result.stats.languages = repo_index.summary.language_counts
        ctx.result.stats.hotspot_top5 = [h.path for h in hotspot_index.items[:5]]
        logger.info(
            "[stage:recon] Indexed %d files, %d hotspots",
            repo_index.summary.total_files, len(hotspot_index.items),
        )
    else:
        logger.info("[stage:recon] Non-repo target — skipping indexer")


def _stage_graph(ctx: RunContext, cfg: RunConfig) -> None:
    """Stage 2: Call graph construction (optional)."""
    if not cfg.features.enable_graph:
        logger.info("[stage:graph] Disabled — skipping")
        return

    if cfg.target.type.value != "repo":
        logger.info("[stage:graph] Graph requires target.type=repo — skipping")
        return

    if _has_checkpoint(ctx.artifacts_dir, "call_graph.json"):
        logger.info("[stage:graph] Checkpoint found — skipping")
        return

    from cve_agent.graph.call_graph import build_graph, save_graph_artifacts
    logger.info("[stage:graph] Building code graph...")
    units_art, graph_art = build_graph(cfg)
    save_graph_artifacts(units_art, graph_art, ctx.artifacts_dir)

    ctx.result.stats.nodes_parsed = len(units_art.units)
    ctx.result.stats.edges_built = len(graph_art.edges)
    logger.info(
        "[stage:graph] %d units, %d edges",
        len(units_art.units), len(graph_art.edges),
    )


def _stage_static(ctx: RunContext, cfg: RunConfig) -> None:
    """Stage 3: Static analysis (Semgrep / CodeQL)."""
    if _has_checkpoint(ctx.artifacts_dir, "candidates.json"):
        logger.info("[stage:static] Checkpoint found — skipping")
        return

    static_findings: list = []
    target_dir = Path(cfg.target.path_or_url).resolve()

    if cfg.features.enable_semgrep:
        from cve_agent.analyzers.semgrep_scanner import run_semgrep
        logger.info("[stage:static] Running Semgrep...")
        sg_findings = run_semgrep(
            target_dir, artifacts_dir=ctx.artifacts_dir,
            languages=cfg.target.languages_hint,
        )
        static_findings.extend(sg_findings)
        logger.info("[stage:static] Semgrep: %d candidates", len(sg_findings))

    if cfg.features.enable_codeql:
        from cve_agent.analyzers.codeql_runner import run_codeql
        logger.info("[stage:static] Running CodeQL...")
        cq_findings = run_codeql(
            target_dir, artifacts_dir=ctx.artifacts_dir,
            languages_hint=cfg.target.languages_hint,
        )
        static_findings.extend(cq_findings)
        logger.info("[stage:static] CodeQL: %d candidates", len(cq_findings))

    if not cfg.features.enable_semgrep and not cfg.features.enable_codeql:
        logger.info("[stage:static] No static tools enabled — skipping")

    ctx.result.stats.static_candidates = len(static_findings)
    ctx.result.findings.extend(static_findings)
    logger.info("[stage:static] Total static candidates: %d", len(static_findings))


def _stage_hypothesize(
    ctx: RunContext, cfg: RunConfig, budget: BudgetTracker,
) -> None:
    """Stage 4: Vulnerability hypothesis generation."""
    if _has_checkpoint(ctx.artifacts_dir, "hypotheses.json"):
        logger.info("[stage:hypothesize] Checkpoint found — skipping")
        return

    # Budget gate
    if cfg.llm.enabled:
        budget_err = budget.check()
        if budget_err:
            logger.warning("[stage:hypothesize] %s — using offline only", budget_err)
            cfg.llm.enabled = False  # fall back to offline

    from cve_agent.agents.hypothesis_agent import generate_hypotheses, save_hypotheses

    llm_client = None
    if cfg.llm.enabled:
        if cfg.llm.provider == "dummy":
            from cve_agent.agents.llm_clients.dummy import DummyLLMClient
            llm_client = DummyLLMClient()
        else:
            logger.info(
                "[stage:hypothesize] LLM provider '%s' not implemented — using offline",
                cfg.llm.provider,
            )

    hyp_findings = generate_hypotheses(cfg, ctx.artifacts_dir, llm_client=llm_client)
    save_hypotheses(hyp_findings, ctx.artifacts_dir)

    # Record dummy token usage for budget tracking
    if llm_client:
        estimated_tokens = len(hyp_findings) * 200  # rough estimate
        budget.record(tokens=estimated_tokens, cost=estimated_tokens * 0.00001)

    ctx.result.stats.hypotheses_generated = len(hyp_findings)

    # Merge into findings
    existing_ids = {f.id for f in ctx.result.findings}
    for hf in hyp_findings:
        if hf.id not in existing_ids:
            ctx.result.findings.append(hf)
            existing_ids.add(hf.id)
        else:
            for f in ctx.result.findings:
                if f.id == hf.id and hf.hypothesis:
                    f.hypothesis = hf.hypothesis
                    break

    logger.info("[stage:hypothesize] %d hypotheses generated", len(hyp_findings))


def _stage_generate(ctx: RunContext, cfg: RunConfig) -> None:
    """Stage 5: Test / harness generation."""
    if not cfg.features.enable_fuzz:
        logger.info("[stage:generate] Fuzz disabled — skipping")
        return

    if _has_checkpoint(ctx.artifacts_dir, "fuzz_attempts.json"):
        logger.info("[stage:generate] Checkpoint found — skipping")
        return

    from cve_agent.fuzz.test_generator import generate_tests_for_findings
    from cve_agent.fuzz.harness_generator import generate_harness_for_finding
    from cve_agent.fuzz.self_correction import run_all_tests, save_fuzz_attempts

    # Load hypotheses
    from pydantic import TypeAdapter
    from cve_agent.schemas.findings import Finding

    hyp_path = ctx.artifacts_dir / "hypotheses.json"
    if not hyp_path.exists():
        logger.warning("[stage:generate] No hypotheses.json — skipping")
        return

    adapter = TypeAdapter(list[Finding])
    hyp_findings = adapter.validate_json(hyp_path.read_text(encoding="utf-8"))

    logger.info("[stage:generate] Generating tests/harnesses...")
    attempts = generate_tests_for_findings(hyp_findings, ctx.artifacts_dir)

    for hf in hyp_findings:
        c_attempt = generate_harness_for_finding(hf, ctx.artifacts_dir)
        if c_attempt:
            attempts.append(c_attempt)

    ctx.result.stats.harnesses_created = len(attempts)

    # Self-correction loop
    attempts = run_all_tests(
        attempts, ctx.artifacts_dir, dry_run=not cfg.sandbox.enabled,
    )
    ctx.result.stats.executions_run = sum(
        a.get("iterations", 0) for a in attempts
    )

    save_fuzz_attempts(attempts, ctx.artifacts_dir)
    logger.info(
        "[stage:generate] %d harnesses, %d correction iterations",
        len(attempts), ctx.result.stats.executions_run,
    )


def _stage_execute(ctx: RunContext, cfg: RunConfig) -> None:
    """Stage 6: Sandbox execution."""
    if not cfg.sandbox.enabled:
        logger.info("[stage:execute] Sandbox disabled — skipping")
        return

    if _has_checkpoint(ctx.artifacts_dir, "validation_results.json"):
        logger.info("[stage:execute] Checkpoint found — skipping")
        return

    from cve_agent.analyzers.execution import (
        execute_validations, save_validation_results,
        create_evidence_from_outcome,
    )

    logger.info(
        "[stage:execute] network_off=%s, cpu=%s, mem=%sMB, timeout=%ss",
        cfg.sandbox.network_off, cfg.sandbox.cpu,
        cfg.sandbox.mem_mb, cfg.sandbox.timeout_sec,
    )

    target_dir = Path(cfg.target.path_or_url).resolve()
    validation = execute_validations(
        ctx.artifacts_dir,
        sandbox_cfg=cfg.sandbox,
        features_cfg=cfg.features,
        repo_dir=target_dir if target_dir.is_dir() else None,
        dry_run=False,
    )
    save_validation_results(validation, ctx.artifacts_dir)

    ctx.result.stats.executions_run = validation.total
    ctx.result.stats.findings_confirmed = validation.success

    outcome_map = {o.finding_id: o for o in validation.outcomes}
    for f in ctx.result.findings:
        if f.id in outcome_map:
            ev = create_evidence_from_outcome(outcome_map[f.id])
            f.evidence.append(ev)

    logger.info(
        "[stage:execute] %d executed, %d success, %d failure, %d crash",
        validation.total, validation.success,
        validation.failure, validation.crash,
    )


def _stage_triage(ctx: RunContext, cfg: RunConfig) -> None:
    """Stage 7: Conservative triage assessment."""
    if _has_checkpoint(ctx.artifacts_dir, "triage.json"):
        logger.info("[stage:triage] Checkpoint found — skipping")
        return

    from cve_agent.triage.triage_agent import (
        run_triage, save_triage_report, save_final_findings,
    )

    triage_report, triaged_findings = run_triage(ctx.artifacts_dir)
    save_triage_report(triage_report, ctx.artifacts_dir)
    save_final_findings(triaged_findings, ctx.artifacts_dir)

    ctx.result.stats.findings_confirmed = triage_report.confirmed

    # Replace findings with triaged versions
    if triaged_findings:
        finding_map = {f.id: f for f in triaged_findings}
        for i, f in enumerate(ctx.result.findings):
            if f.id in finding_map:
                ctx.result.findings[i] = finding_map[f.id]

    logger.info(
        "[stage:triage] %d confirmed, %d potential, %d false_positive",
        triage_report.confirmed, triage_report.potential,
        triage_report.false_positive,
    )


def _stage_report(ctx: RunContext, cfg: RunConfig) -> None:
    """Stage 8: Report generation + evidence bundle."""
    from cve_agent.reporting.report_md import generate_report_md, save_report
    from cve_agent.reporting.bundler import create_evidence_bundle
    from cve_agent.triage.triage_agent import TriageReport

    # Load triage report if available
    triage_report = None
    triage_path = ctx.artifacts_dir / "triage.json"
    if triage_path.exists():
        try:
            triage_report = TriageReport.model_validate_json(
                triage_path.read_text(encoding="utf-8")
            )
        except Exception:
            pass

    # Load final findings
    from pydantic import TypeAdapter
    from cve_agent.schemas.findings import Finding

    findings = ctx.result.findings
    findings_path = ctx.artifacts_dir / "findings.json"
    if findings_path.exists():
        try:
            adapter = TypeAdapter(list[Finding])
            findings = adapter.validate_json(
                findings_path.read_text(encoding="utf-8")
            )
        except Exception:
            pass

    report_md = generate_report_md(
        findings,
        triage_report,
        run_id=ctx.run_id,
        target=cfg.target.path_or_url,
    )
    save_report(report_md, ctx.run_dir)

    create_evidence_bundle(ctx.run_dir, ctx.artifacts_dir)
    logger.info("[stage:report] REPORT.md + evidence bundle created")


# ── Pipeline stages registry ─────────────────────────────


_STAGES: list[tuple[str, str, Callable]] = [
    # (name, checkpoint_file, function)
    ("recon",       "repo_index.json",          _stage_recon),
    ("graph",       "call_graph.json",          _stage_graph),
    ("static",      "candidates.json",          _stage_static),
    ("hypothesize", "hypotheses.json",          _stage_hypothesize),
    ("generate",    "fuzz_attempts.json",       _stage_generate),
    ("execute",     "validation_results.json",  _stage_execute),
    ("triage",      "triage.json",              _stage_triage),
    ("report",      "",                         _stage_report),
]


# ── Main orchestrator ─────────────────────────────────────


def run_pipeline(ctx: RunContext) -> None:
    """Execute the full analysis pipeline as a state machine.

    Each stage is run in order. If `continue_on_fail` is True, a
    stage failure is recorded and the pipeline continues. Otherwise,
    the pipeline aborts on the first failure.

    Checkpointing: if a stage's checkpoint artifact already exists,
    the stage is skipped (allows resuming interrupted runs).
    """
    ctx.mark_running()
    cfg = ctx.config
    budget = BudgetTracker(cfg)

    stage_results: list[StageResult] = []
    failed_stages: list[str] = []

    logger.info(
        "Pipeline starting: %d stages, continue_on_fail=%s",
        len(_STAGES), cfg.continue_on_fail,
    )

    if cfg.llm.enabled:
        logger.info(
            "Budget: max_tokens=%s, max_cost=$%s, retriever top_k=%d, max_snippet=%d",
            cfg.budget.max_tokens, cfg.budget.max_cost_usd,
            cfg.retriever.top_k, cfg.retriever.max_snippet_len,
        )

    for stage_name, checkpoint, stage_fn in _STAGES:
        sr = StageResult(stage_name)
        stage_results.append(sr)

        # Budget check before LLM-heavy stages
        if stage_name in ("hypothesize",) and cfg.llm.enabled:
            budget_err = budget.check()
            if budget_err:
                logger.warning("[stage:%s] Budget exceeded: %s", stage_name, budget_err)

        sr.status = StageStatus.RUNNING
        logger.info("[stage:%s] Starting...", stage_name)

        try:
            # Stages that need budget tracker
            if stage_name == "hypothesize":
                stage_fn(ctx, cfg, budget)
            else:
                stage_fn(ctx, cfg)
            sr.status = StageStatus.COMPLETED
            logger.info("[stage:%s] Completed", stage_name)
        except Exception as exc:
            sr.status = StageStatus.FAILED
            sr.error = str(exc)
            failed_stages.append(stage_name)
            logger.error("[stage:%s] FAILED: %s", stage_name, exc)

            if cfg.continue_on_fail:
                logger.warning(
                    "[stage:%s] continue_on_fail=True — proceeding to next stage",
                    stage_name,
                )
            else:
                # Record budget usage before aborting
                ctx.result.stats.llm_tokens_used = budget.tokens_used
                ctx.result.stats.llm_cost_usd = budget.cost_usd
                ctx.mark_failed(f"Stage '{stage_name}' failed: {exc}")
                _save_pipeline_state(ctx, stage_results)
                raise

    # Record final budget usage
    ctx.result.stats.llm_tokens_used = budget.tokens_used
    ctx.result.stats.llm_cost_usd = budget.cost_usd

    # Save run result
    _save_pipeline_state(ctx, stage_results)

    if failed_stages:
        ctx.mark_failed(f"Stages failed: {', '.join(failed_stages)}")
    else:
        ctx.mark_completed()


def _save_pipeline_state(
    ctx: RunContext,
    stage_results: list[StageResult],
) -> None:
    """Persist run_result.json and pipeline_state.json."""
    # Save run_result
    result_path = ctx.artifact_path("run_result.json")
    result_path.write_text(
        ctx.result.model_dump_json(indent=2), encoding="utf-8",
    )

    # Save pipeline state
    state = {
        "stages": [
            {
                "name": sr.name,
                "status": sr.status.value,
                "error": sr.error,
                "skipped_reason": sr.skipped_reason,
            }
            for sr in stage_results
        ],
    }
    state_path = ctx.artifact_path("pipeline_state.json")
    state_path.write_text(
        json.dumps(state, indent=2), encoding="utf-8",
    )
    logger.info("Pipeline state saved: %s", state_path)
