"""Filesystem utility helpers."""

from __future__ import annotations

import shutil
from pathlib import Path


def ensure_dir(path: Path) -> Path:
    """Create directory (and parents) if it doesn't exist. Return the path."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def copy_file(src: Path, dst: Path, *, overwrite: bool = False) -> Path:
    """Copy a file. Raises FileExistsError if dst exists and overwrite is False."""
    if dst.exists() and not overwrite:
        raise FileExistsError(f"Destination already exists: {dst}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return dst


def safe_read_text(path: Path, default: str = "") -> str:
    """Read text file, return default if not found."""
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return default
