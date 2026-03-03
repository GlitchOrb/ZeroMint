"""Structured logging — dual output to console (Rich) and run.log file."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

_LOG_FORMAT = "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
_LOG_DATE_FMT = "%Y-%m-%d %H:%M:%S"

_configured = False


def setup_logging(
    *,
    log_file: Optional[Path] = None,
    verbose: bool = False,
    console: Optional[Console] = None,
) -> logging.Logger:
    """Configure the root logger with console + optional file output.

    Args:
        log_file: Path to run.log file.  If None, console-only.
        verbose: If True, set DEBUG level; else INFO.
        console: Rich Console instance (created if None).

    Returns:
        The configured root logger for the cve_agent namespace.
    """
    global _configured

    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("cve_agent")
    logger.setLevel(level)

    # Prevent duplicate handlers on repeated calls
    if _configured:
        return logger
    _configured = True

    # ── Console handler (Rich) ─────────────────────────────
    if console is None:
        console = Console(stderr=True)
    console_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        markup=True,
        level=level,
    )
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console_handler)

    # ── File handler ───────────────────────────────────────
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)  # Always verbose in file
        file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE_FMT))
        logger.addHandler(file_handler)

    # Quiet noisy libraries
    for noisy in ("urllib3", "docker", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    return logger


def reset_logging() -> None:
    """Remove all handlers (for tests)."""
    global _configured
    logger = logging.getLogger("cve_agent")
    logger.handlers.clear()
    _configured = False
