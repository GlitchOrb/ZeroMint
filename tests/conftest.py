"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from cve_agent.logging import reset_logging


@pytest.fixture(autouse=True)
def _clean_logging() -> None:
    """Reset logging between tests to prevent handler accumulation."""
    reset_logging()
    yield  # type: ignore[misc]
    reset_logging()


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """Shorthand for temporary directory."""
    return tmp_path


@pytest.fixture
def sample_config_yaml(tmp_dir: Path) -> Path:
    """Create a minimal valid config.yaml for testing."""
    cfg = tmp_dir / "config.yaml"
    cfg.write_text(
        """\
target:
  type: repo
  path_or_url: ./test_target
  languages_hint: [python]

features:
  enable_graph: true
  enable_semgrep: false
  enable_codeql: false
  enable_fuzz: false
  enable_sanitizers: false

sandbox:
  enabled: false
  network_off: true
  cpu: 0.5
  mem_mb: 256
  timeout_sec: 30

llm:
  enabled: false
  provider: null
  model: null

budget:
  max_tokens: null
  max_cost_usd: null
""",
        encoding="utf-8",
    )
    return cfg
