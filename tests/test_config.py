"""Test 1: Config loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from cve_agent.config import load_config, load_yaml, apply_env_overrides
from cve_agent.schemas.config import RunConfig, TargetType


class TestConfigLoad:
    """Tests for YAML config loading and pydantic validation."""

    def test_load_valid_config(self, sample_config_yaml: Path) -> None:
        """Load a valid config and verify all fields are parsed correctly."""
        cfg = load_config(sample_config_yaml)

        assert isinstance(cfg, RunConfig)
        assert cfg.target.type == TargetType.REPO
        assert cfg.target.path_or_url == "./test_target"
        assert cfg.target.languages_hint == ["python"]
        assert cfg.features.enable_graph is True
        assert cfg.features.enable_semgrep is False
        assert cfg.sandbox.enabled is False
        assert cfg.sandbox.network_off is True
        assert cfg.sandbox.cpu == 0.5
        assert cfg.sandbox.mem_mb == 256
        assert cfg.sandbox.timeout_sec == 30
        assert cfg.llm.enabled is False
        assert cfg.llm.provider is None
        assert cfg.budget.max_tokens is None

    def test_load_missing_file_raises(self) -> None:
        """Config loading should raise FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError):
            load_config(Path("/nonexistent/config.yaml"))

    def test_defaults(self) -> None:
        """RunConfig should have sensible defaults even with no input."""
        cfg = RunConfig()
        assert cfg.target.type == TargetType.REPO
        assert cfg.sandbox.network_off is True
        assert cfg.sandbox.timeout_sec == 60
        assert cfg.features.enable_graph is True

    def test_invalid_target_type(self, tmp_dir: Path) -> None:
        """Invalid target type should raise validation error."""
        bad_cfg = tmp_dir / "bad.yaml"
        bad_cfg.write_text("target:\n  type: invalid_type\n", encoding="utf-8")
        with pytest.raises(Exception):  # pydantic ValidationError
            load_config(bad_cfg)

    def test_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Environment variables should override config values."""
        monkeypatch.setenv("CVE_AGENT_SANDBOX__NETWORK_OFF", "false")
        monkeypatch.setenv("CVE_AGENT_LLM__ENABLED", "true")

        data: dict = {"sandbox": {"network_off": True}, "llm": {"enabled": False}}
        result = apply_env_overrides(data)

        assert result["sandbox"]["network_off"] is False
        assert result["llm"]["enabled"] is True

    def test_load_empty_yaml(self, tmp_dir: Path) -> None:
        """Empty YAML should produce default RunConfig."""
        empty = tmp_dir / "empty.yaml"
        empty.write_text("", encoding="utf-8")
        cfg = load_config(empty)
        assert isinstance(cfg, RunConfig)
        assert cfg.target.type == TargetType.REPO

    def test_partial_config(self, tmp_dir: Path) -> None:
        """Partial YAML should fill in defaults for missing sections."""
        partial = tmp_dir / "partial.yaml"
        partial.write_text("target:\n  type: api\n  path_or_url: https://example.com/api\n", encoding="utf-8")
        cfg = load_config(partial)
        assert cfg.target.type == TargetType.API
        assert cfg.target.path_or_url == "https://example.com/api"
        # Defaults for missing sections
        assert cfg.sandbox.enabled is True
        assert cfg.llm.enabled is False
