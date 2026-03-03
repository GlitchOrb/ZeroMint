"""Pydantic v2 schemas — Run result."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from cve_agent.schemas.findings import Finding


class RunStatus(str, Enum):
    INITIALIZED = "initialized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RunStats(BaseModel):
    """Aggregate statistics for a pipeline run."""
    files_indexed: int = 0
    nodes_parsed: int = 0
    edges_built: int = 0
    static_candidates: int = 0
    hypotheses_generated: int = 0
    harnesses_created: int = 0
    executions_run: int = 0
    findings_confirmed: int = 0
    llm_tokens_used: int = 0
    llm_cost_usd: float = 0.0
    # Recon stage additions
    indexed_files: int = 0
    languages: dict[str, int] = Field(default_factory=dict)
    hotspot_top5: list[str] = Field(default_factory=list)


class RunResult(BaseModel):
    """Final output of a complete pipeline run."""
    run_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    status: RunStatus = RunStatus.INITIALIZED
    stats: RunStats = Field(default_factory=RunStats)
    findings: list[Finding] = Field(default_factory=list)
