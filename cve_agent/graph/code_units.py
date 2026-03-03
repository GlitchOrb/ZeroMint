"""Pydantic models for code units and call graph artifacts."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from cve_agent.schemas.findings import CodeLocation


# ── Code Unit ─────────────────────────────────────────────


class CodeUnit(BaseModel):
    """A single extractable code entity (function, method, class)."""

    unit_id: str = Field(description="Unique identifier: file::symbol")
    language: str = Field(description="Source language (python, javascript, ...)")
    location: CodeLocation
    signature: str = Field(description="Function/class signature line")
    text: str = Field(description="Full source text of the unit")
    tokens_estimate: int = Field(
        default=0,
        ge=0,
        description="Rough token count (chars / 4)",
    )


class CodeUnitsArtifact(BaseModel):
    """Serialised artifact for code_units.json."""

    units: list[CodeUnit] = Field(default_factory=list)


# ── Call Graph ────────────────────────────────────────────


class GraphNode(BaseModel):
    """A node in the call graph (corresponds to a CodeUnit)."""

    unit_id: str
    signature: str
    location: CodeLocation


class GraphEdge(BaseModel):
    """A directed edge: from_unit_id calls to_symbol."""

    from_unit_id: str
    to_symbol: str = Field(description="Callee function/method name (unresolved)")


class CallGraphArtifact(BaseModel):
    """Serialised artifact for call_graph.json."""

    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
