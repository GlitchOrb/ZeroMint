"""Pydantic v2 schemas — Findings, Hypotheses, Evidence."""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Enums ──────────────────────────────────────────────────


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    POTENTIAL = "potential"       # security-relevant but no dynamic proof yet
    CONFIRMED = "confirmed"      # dynamic evidence: crash, policy violation
    FALSE_POSITIVE = "false_positive"


class EvidenceKind(str, Enum):
    CODE = "code"
    LOG = "log"
    TOOL_OUTPUT = "tool_output"


# ── Data Models ────────────────────────────────────────────


class CodeLocation(BaseModel):
    """Points to a specific location in source code."""
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    symbol: Optional[str] = Field(
        default=None,
        description="Function / class / variable name (optional)",
    )


class EvidenceItem(BaseModel):
    """A single piece of evidence supporting a finding."""
    kind: EvidenceKind
    summary: str
    location: Optional[CodeLocation] = None
    snippet: Optional[str] = Field(
        default=None,
        description="Relevant code or log snippet",
    )
    artifact_path: Optional[str] = Field(
        default=None,
        description="Path to artifact file inside runs/<run_id>/artifacts/",
    )


class Hypothesis(BaseModel):
    """LLM-generated vulnerability hypothesis."""
    vuln_type: str = Field(description="e.g. injection, buffer_overflow, path_traversal")
    attack_surface: str = Field(description="Entry point / exposed interface")
    preconditions: list[str] = Field(default_factory=list)
    exploit_idea: str = Field(
        description="Non-destructive proof-of-concept idea (crash, exception, auth-check failure)",
    )
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    related_sinks: list[str] = Field(
        default_factory=list,
        description="Dangerous functions / sinks reached",
    )
    related_sources: list[str] = Field(
        default_factory=list,
        description="Tainted data sources",
    )
    self_critique: str = Field(
        default="",
        description="Agent's own assessment of potential false-positive reasons",
    )


class Finding(BaseModel):
    """A single vulnerability finding (candidate or confirmed)."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str
    severity: Severity = Severity.MEDIUM
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    status: FindingStatus = FindingStatus.CANDIDATE
    hypothesis: Optional[Hypothesis] = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    reproduction_steps: list[str] = Field(default_factory=list)
    mitigation: str = ""
    references: list[str] = Field(default_factory=list)
