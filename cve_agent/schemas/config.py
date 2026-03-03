"""Pydantic v2 schemas — Config section."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class TargetType(str, Enum):
    """Supported target types."""
    REPO = "repo"
    API = "api"
    BINARY = "binary"


# Built-in ignore list (always combined with user's ignore_patterns)
_DEFAULT_IGNORE: list[str] = [
    ".git", "node_modules", "dist", "build", "venv", ".venv",
    "__pycache__", ".tox", ".idea", ".pytest_cache", ".mypy_cache",
    ".eggs", "*.egg-info", ".hg", ".svn",
]


class TargetConfig(BaseModel):
    """What to analyse."""
    type: TargetType = TargetType.REPO
    path_or_url: str = Field(
        default=".",
        description="Local path or URL to the target",
    )
    languages_hint: list[str] = Field(
        default_factory=lambda: ["python"],
        description="Hint for expected source languages",
    )
    ignore_patterns: list[str] = Field(
        default_factory=list,
        description="Additional glob patterns to ignore during indexing",
    )

    @property
    def all_ignores(self) -> list[str]:
        """Merge built-in ignores with user-specified patterns."""
        return _DEFAULT_IGNORE + self.ignore_patterns


class FeaturesConfig(BaseModel):
    """Feature toggles for the pipeline."""
    enable_graph: bool = True
    enable_semgrep: bool = False
    enable_codeql: bool = False
    enable_fuzz: bool = True
    enable_sanitizers: bool = False


class SandboxConfig(BaseModel):
    """Sandbox execution constraints."""
    enabled: bool = True
    network_off: bool = Field(
        default=True,
        description="Disable network inside sandbox (MUST be true for safety)",
    )
    cpu: Optional[float] = Field(default=1.0, description="CPU limit (cores)")
    mem_mb: Optional[int] = Field(default=512, description="Memory limit (MB)")
    timeout_sec: int = Field(default=60, ge=5, le=600, description="Hard timeout (seconds)")


class LLMConfig(BaseModel):
    """LLM backend configuration."""
    enabled: bool = False
    provider: Optional[str] = Field(
        default=None,
        description="LLM provider: openai | anthropic | local | dummy",
    )
    model: Optional[str] = Field(default=None, description="Model identifier")


class BudgetConfig(BaseModel):
    """Cost / usage budgets."""
    max_tokens: Optional[int] = Field(default=None, ge=1, description="Max total tokens")
    max_cost_usd: Optional[float] = Field(default=None, ge=0.0, description="Max cost in USD")


class RetrieverConfig(BaseModel):
    """Retriever constraints for LLM context."""
    top_k: int = Field(default=10, ge=1, le=100, description="Max code snippets to retrieve")
    max_snippet_len: int = Field(default=500, ge=50, le=5000, description="Max chars per snippet")


class RunConfig(BaseModel):
    """Top-level run configuration — validated from YAML + .env."""
    target: TargetConfig = Field(default_factory=TargetConfig)
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    retriever: RetrieverConfig = Field(default_factory=RetrieverConfig)
    continue_on_fail: bool = Field(
        default=False,
        description="If true, continue to next stage on failure instead of aborting",
    )
