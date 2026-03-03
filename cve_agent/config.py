"""Config loader — merges YAML file + .env overrides → validated RunConfig."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from cve_agent.schemas.config import RunConfig


def load_yaml(path: Path) -> dict[str, Any]:
    """Load and return raw YAML dict. Returns {} if file is empty."""
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    return data if isinstance(data, dict) else {}


def apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Apply CVE_AGENT_* environment variables as overrides.

    Convention:  CVE_AGENT_<SECTION>__<KEY>=value
    Example:     CVE_AGENT_SANDBOX__NETWORK_OFF=true  →  sandbox.network_off = true
    """
    prefix = "CVE_AGENT_"
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        parts = key[len(prefix):].lower().split("__")
        if len(parts) == 2:
            section, field = parts
            data.setdefault(section, {})[field] = _coerce(value)
        elif len(parts) == 1:
            data[parts[0]] = _coerce(value)
    return data


def _coerce(value: str) -> Any:
    """Best-effort coerce string env values to Python types."""
    if value.lower() in ("true", "1", "yes"):
        return True
    if value.lower() in ("false", "0", "no"):
        return False
    if value.lower() in ("null", "none", ""):
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def load_config(
    config_path: Path,
    env_path: Path | None = None,
) -> RunConfig:
    """Load config from YAML file + optional .env, validate with pydantic.

    Args:
        config_path: Path to the YAML config file.
        env_path: Path to .env file (defaults to .env in same dir).

    Returns:
        Validated RunConfig instance.

    Raises:
        FileNotFoundError: If config_path does not exist.
        pydantic.ValidationError: If config values are invalid.
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    # Load .env
    if env_path is None:
        env_path = config_path.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=True)

    # YAML → dict
    raw = load_yaml(config_path)

    # Env overrides
    raw = apply_env_overrides(raw)

    # Validate
    return RunConfig.model_validate(raw)
