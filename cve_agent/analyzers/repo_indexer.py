"""Repo indexer — walk a local repository, catalogue files, score hotspots.

Produces two artifacts:
  artifacts/repo_index.json  — file catalogue + summary statistics
  artifacts/hotspots.json    — top-50 security-relevant hotspot candidates
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from cve_agent.schemas.config import RunConfig

logger = logging.getLogger("cve_agent.analyzers.repo_indexer")

# ── Language detection ────────────────────────────────────

_EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".cs": "csharp",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".m": "objective-c",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".sql": "sql",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "ini",
    ".md": "markdown",
    ".rst": "rst",
    ".tf": "terraform",
    ".hcl": "hcl",
    ".dockerfile": "dockerfile",
    ".r": "r",
    ".lua": "lua",
    ".pl": "perl",
    ".pm": "perl",
    ".ex": "elixir",
    ".exs": "elixir",
}

# Dockerfile without extension
_FILENAME_TO_LANG: dict[str, str] = {
    "Dockerfile": "dockerfile",
    "Makefile": "makefile",
    "Rakefile": "ruby",
    "Gemfile": "ruby",
    "Vagrantfile": "ruby",
    "CMakeLists.txt": "cmake",
}

# ── Hotspot keywords & weights ────────────────────────────

# Each keyword group maps to a weight.  Source snippets matching
# any term in the group get that score added to their hotspot total.

HOTSPOT_KEYWORDS: dict[str, float] = {
    # Injection / code execution
    "eval": 5.0,
    "exec": 5.0,
    "compile": 3.0,
    "subprocess": 4.0,
    "shell": 4.0,
    "popen": 4.0,
    "os.system": 5.0,
    "system(": 4.0,
    "execve": 5.0,
    "spawn": 3.0,
    "ProcessBuilder": 4.0,
    "Runtime.exec": 4.0,
    # Deserialization
    "pickle": 5.0,
    "unpickle": 5.0,
    "yaml.load": 4.0,
    "yaml.unsafe_load": 5.0,
    "Marshal.load": 4.0,
    "deserialize": 4.0,
    "unserialize": 4.0,
    "readObject": 4.0,
    "ObjectInputStream": 4.0,
    "json.loads": 1.0,
    # Auth / session
    "auth": 3.0,
    "authenticate": 3.0,
    "login": 3.0,
    "password": 3.0,
    "passwd": 3.0,
    "jwt": 4.0,
    "token": 3.0,
    "session": 2.0,
    "cookie": 2.0,
    "oauth": 3.0,
    "api_key": 3.0,
    "secret": 3.0,
    # Crypto
    "crypto": 3.0,
    "cipher": 3.0,
    "encrypt": 3.0,
    "decrypt": 3.0,
    "hash": 2.0,
    "md5": 3.0,
    "sha1": 2.0,
    "hmac": 2.0,
    "random": 2.0,
    # SQL
    "sql": 3.0,
    "query": 2.0,
    "execute(": 3.0,
    "cursor": 2.0,
    "SELECT": 2.0,
    "INSERT": 2.0,
    "UPDATE": 2.0,
    "DELETE": 2.0,
    "DROP": 3.0,
    # Path / file
    "path": 2.0,
    "traversal": 4.0,
    "..": 3.0,
    "open(": 2.0,
    "readfile": 3.0,
    "file_get_contents": 3.0,
    "upload": 3.0,
    "download": 2.0,
    "tempfile": 2.0,
    # Web / redirect
    "redirect": 3.0,
    "url": 2.0,
    "href": 1.0,
    "innerHTML": 3.0,
    "document.write": 3.0,
    "template": 2.0,
    "render": 2.0,
    "jinja": 2.0,
    "format_string": 3.0,
    "f-string": 2.0,
    # Memory / native
    "malloc": 3.0,
    "free(": 3.0,
    "realloc": 3.0,
    "strcpy": 4.0,
    "strcat": 4.0,
    "sprintf": 4.0,
    "gets(": 5.0,
    "memcpy": 3.0,
    "buffer": 2.0,
    "overflow": 3.0,
    "unsafe": 3.0,
}

# ── Name-based signals (file / directory name) ────────────

NAME_SIGNALS: dict[str, float] = {
    "auth": 3.0,
    "login": 3.0,
    "admin": 3.0,
    "user": 2.0,
    "crypto": 3.0,
    "security": 3.0,
    "token": 3.0,
    "jwt": 4.0,
    "session": 2.0,
    "password": 3.0,
    "upload": 3.0,
    "api": 2.0,
    "middleware": 2.0,
    "handler": 2.0,
    "controller": 2.0,
    "deserialize": 4.0,
    "serialize": 2.0,
    "template": 2.0,
    "eval": 4.0,
    "exec": 4.0,
    "shell": 3.0,
    "sql": 3.0,
    "db": 2.0,
    "database": 2.0,
    "query": 2.0,
    "config": 2.0,
    "secret": 3.0,
    "key": 2.0,
    "permission": 3.0,
    "acl": 3.0,
    "sandbox": 2.0,
    "unsafe": 4.0,
}

# Parseable source extensions (we only read content for these)
_SOURCE_EXTS = set(_EXT_TO_LANG.keys()) | {".txt", ".conf", ".env"}

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB — skip huge files
MAX_HOTSPOTS = 50


# ── Output schemas ────────────────────────────────────────


class FileEntry(BaseModel):
    """One indexed file."""
    path: str
    size: int
    ext: str
    language_guess: str


class IndexSummary(BaseModel):
    """Aggregate stats about the indexed repo."""
    total_files: int = 0
    total_bytes: int = 0
    language_counts: dict[str, int] = Field(default_factory=dict)
    suspicious_keyword_hits: int = 0


class RepoIndex(BaseModel):
    """Complete repo index artifact."""
    files: list[FileEntry] = Field(default_factory=list)
    summary: IndexSummary = Field(default_factory=IndexSummary)


class HotspotItem(BaseModel):
    """One hotspot candidate."""
    path: str
    symbol: str | None = None
    score: float
    reasons: list[str] = Field(default_factory=list)
    top_matches: list[str] = Field(default_factory=list)


class HotspotIndex(BaseModel):
    """Top-N hotspot candidates artifact."""
    items: list[HotspotItem] = Field(default_factory=list)


# ── Core logic ────────────────────────────────────────────


def _should_ignore(rel_path: Path, ignores: list[str]) -> bool:
    """Check if any component of rel_path matches an ignore pattern."""
    parts = rel_path.parts
    for part in parts:
        for pattern in ignores:
            if fnmatch.fnmatch(part, pattern):
                return True
    return False


def _guess_language(file_path: Path) -> str:
    """Guess language from extension or filename."""
    name = file_path.name
    if name in _FILENAME_TO_LANG:
        return _FILENAME_TO_LANG[name]
    ext = file_path.suffix.lower()
    return _EXT_TO_LANG.get(ext, "unknown")


def _is_source_file(file_path: Path) -> bool:
    """Check if file is a parseable source file."""
    name = file_path.name
    if name in _FILENAME_TO_LANG:
        return True
    ext = file_path.suffix.lower()
    return ext in _SOURCE_EXTS


def _score_filename(rel_path: str) -> tuple[float, list[str]]:
    """Score a file path based on security-relevant name signals."""
    score = 0.0
    reasons: list[str] = []
    name_lower = rel_path.lower()

    for keyword, weight in NAME_SIGNALS.items():
        if keyword in name_lower:
            score += weight
            reasons.append(f"name:{keyword}")

    return score, reasons


def _score_content(content: str, max_matches: int = 10) -> tuple[float, list[str], list[str]]:
    """Score file content against hotspot keywords.

    Returns (score, reason_list, top_match_snippets).
    """
    score = 0.0
    reasons: list[str] = []
    matches: list[str] = []
    content_lower = content.lower()

    seen_keywords: set[str] = set()

    for keyword, weight in HOTSPOT_KEYWORDS.items():
        kw_lower = keyword.lower()
        if kw_lower in content_lower and kw_lower not in seen_keywords:
            score += weight
            reasons.append(f"code:{keyword}")
            seen_keywords.add(kw_lower)

            # Extract a short snippet around the first match
            idx = content_lower.index(kw_lower)
            start = max(0, idx - 30)
            end = min(len(content), idx + len(keyword) + 30)
            snippet = content[start:end].strip().replace("\n", " ")
            if len(matches) < max_matches:
                matches.append(snippet)

    return score, reasons, matches


def index_repo(
    config: RunConfig,
    *,
    base_dir: Path | None = None,
) -> tuple[RepoIndex, HotspotIndex]:
    """Index a local repository and produce hotspot candidates.

    Args:
        config: Validated RunConfig.
        base_dir: Override base directory (for tests); defaults to
                  config.target.path_or_url resolved.

    Returns:
        (RepoIndex, HotspotIndex) ready to be serialised as JSON artifacts.
    """
    target_dir = base_dir or Path(config.target.path_or_url).resolve()
    ignores = config.target.all_ignores

    logger.info("Indexing repo: %s", target_dir)
    logger.info("Ignore patterns (%d): %s", len(ignores), ignores[:10])

    files: list[FileEntry] = []
    lang_counter: Counter[str] = Counter()
    total_bytes = 0
    total_keyword_hits = 0

    # Raw hotspot accumulator: path → (score, reasons, matches)
    hotspot_map: dict[str, tuple[float, list[str], list[str]]] = {}

    if not target_dir.exists():
        logger.warning("Target directory does not exist: %s", target_dir)
        return RepoIndex(), HotspotIndex()

    for root, dirs, filenames in os.walk(target_dir):
        root_path = Path(root)
        rel_root = root_path.relative_to(target_dir)

        # Prune ignored directories in-place
        dirs[:] = [
            d for d in dirs
            if not _should_ignore(rel_root / d, ignores)
        ]

        for fname in filenames:
            file_path = root_path / fname
            rel_path = file_path.relative_to(target_dir)

            if _should_ignore(rel_path, ignores):
                continue

            try:
                stat = file_path.stat()
            except OSError:
                continue

            size = stat.st_size
            ext = file_path.suffix.lower()
            lang = _guess_language(file_path)

            files.append(FileEntry(
                path=str(rel_path),
                size=size,
                ext=ext,
                language_guess=lang,
            ))

            lang_counter[lang] += 1
            total_bytes += size

            # ── Hotspot scoring ────────────────────────────
            rel_str = str(rel_path)
            name_score, name_reasons = _score_filename(rel_str)
            content_score = 0.0
            content_reasons: list[str] = []
            content_matches: list[str] = []

            # Only read source files within size limit
            if _is_source_file(file_path) and size <= MAX_FILE_SIZE_BYTES and size > 0:
                try:
                    content = file_path.read_text(encoding="utf-8", errors="replace")
                    content_score, content_reasons, content_matches = _score_content(content)
                    total_keyword_hits += len(content_reasons)
                except Exception:
                    pass  # Skip unreadable files

            total_score = name_score + content_score
            if total_score > 0:
                hotspot_map[rel_str] = (
                    total_score,
                    name_reasons + content_reasons,
                    content_matches,
                )

    # ── Build RepoIndex ────────────────────────────────────
    summary = IndexSummary(
        total_files=len(files),
        total_bytes=total_bytes,
        language_counts=dict(lang_counter.most_common()),
        suspicious_keyword_hits=total_keyword_hits,
    )
    repo_index = RepoIndex(files=files, summary=summary)

    logger.info(
        "Indexed %d files (%d bytes) across %d languages",
        summary.total_files,
        summary.total_bytes,
        len(summary.language_counts),
    )

    # ── Build HotspotIndex (top N) ─────────────────────────
    sorted_hotspots = sorted(
        hotspot_map.items(),
        key=lambda kv: kv[1][0],
        reverse=True,
    )[:MAX_HOTSPOTS]

    items = [
        HotspotItem(
            path=path,
            score=score,
            reasons=reasons,
            top_matches=matches[:5],
        )
        for path, (score, reasons, matches) in sorted_hotspots
    ]
    hotspot_index = HotspotIndex(items=items)

    logger.info(
        "Found %d hotspot candidates (showing top %d)",
        len(hotspot_map),
        len(items),
    )
    for item in items[:5]:
        logger.info(
            "  [%.1f] %s — %s",
            item.score,
            item.path,
            ", ".join(item.reasons[:5]),
        )

    return repo_index, hotspot_index


def save_artifacts(
    repo_index: RepoIndex,
    hotspot_index: HotspotIndex,
    artifacts_dir: Path,
) -> tuple[Path, Path]:
    """Serialise both artifacts to JSON files.

    Returns:
        (repo_index_path, hotspots_path)
    """
    repo_path = artifacts_dir / "repo_index.json"
    hotspot_path = artifacts_dir / "hotspots.json"

    repo_path.write_text(
        repo_index.model_dump_json(indent=2),
        encoding="utf-8",
    )
    hotspot_path.write_text(
        hotspot_index.model_dump_json(indent=2),
        encoding="utf-8",
    )

    logger.info("Saved: %s (%d files)", repo_path, len(repo_index.files))
    logger.info("Saved: %s (%d hotspots)", hotspot_path, len(hotspot_index.items))

    return repo_path, hotspot_path
