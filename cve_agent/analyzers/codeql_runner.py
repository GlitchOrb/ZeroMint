"""CodeQL runner — create database, run queries, collect SARIF results.

Gracefully skips if codeql CLI is not installed.
CodeQL requires:
  1. codeql CLI on PATH
  2. A language-specific extractor (auto-downloaded by codeql)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from cve_agent.analyzers.normalize_findings import (
    normalize_codeql,
    save_candidates,
)
from cve_agent.schemas.findings import Finding

logger = logging.getLogger("cve_agent.analyzers.codeql_runner")

# Language → CodeQL language identifier
_CODEQL_LANGS: dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",  # same extractor
    "java": "java",
    "csharp": "csharp",
    "cpp": "cpp",
    "c": "cpp",
    "go": "go",
    "ruby": "ruby",
}


def is_codeql_available() -> bool:
    """Check if codeql CLI is installed and accessible."""
    return shutil.which("codeql") is not None


def _detect_codeql_language(languages_hint: list[str]) -> str | None:
    """Map user language hints to a CodeQL language identifier."""
    for lang in languages_hint:
        cql_lang = _CODEQL_LANGS.get(lang.lower())
        if cql_lang:
            return cql_lang
    return None


def run_codeql(
    target_dir: Path,
    *,
    artifacts_dir: Path,
    languages_hint: list[str] | None = None,
    timeout: int = 600,
) -> list[Finding]:
    """Run CodeQL analysis and return normalized findings.

    Steps:
      1. Create a CodeQL database (codeql database create)
      2. Run the default query suite (codeql database analyze)
      3. Parse SARIF output
      4. Normalize to Finding candidates

    If codeql is not installed, logs a warning and returns [].

    Args:
        target_dir: Directory to scan.
        artifacts_dir: Where to save raw and candidate JSON artifacts.
        languages_hint: Language hints from config.
        timeout: Max seconds per codeql command.

    Returns:
        List of Finding candidates.

    Artifacts written:
        artifacts/codeql_raw.json        — SARIF output
        artifacts/codeql_candidates.json — normalized Finding[] JSON
    """
    if not is_codeql_available():
        logger.warning(
            "[codeql] codeql CLI not installed — skipping. "
            "Install: https://github.com/github/codeql-cli-binaries/releases"
        )
        return []

    # Determine language
    cql_lang = _detect_codeql_language(languages_hint or [])
    if not cql_lang:
        logger.warning(
            "[codeql] Cannot determine CodeQL language from hints: %s — skipping",
            languages_hint,
        )
        return []

    logger.info("[codeql] Language: %s, Target: %s", cql_lang, target_dir)

    # Database path
    db_dir = artifacts_dir / "codeql-db"
    sarif_path = artifacts_dir / "codeql_raw.json"

    # Step 1: Create database
    logger.info("[codeql] Creating database...")
    create_cmd = [
        "codeql", "database", "create",
        str(db_dir),
        f"--language={cql_lang}",
        f"--source-root={target_dir}",
        "--overwrite",
    ]

    try:
        create_result = subprocess.run(
            create_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if create_result.returncode != 0:
            logger.error("[codeql] Database creation failed: %s", create_result.stderr[:500])
            return []
    except subprocess.TimeoutExpired:
        logger.error("[codeql] Database creation timed out")
        return []
    except Exception as exc:
        logger.error("[codeql] Database creation error: %s", exc)
        return []

    logger.info("[codeql] Database created at: %s", db_dir)

    # Step 2: Run analysis
    logger.info("[codeql] Running analysis...")
    analyze_cmd = [
        "codeql", "database", "analyze",
        str(db_dir),
        f"--format=sarif-latest",
        f"--output={sarif_path}",
        "--",
        f"codeql/{cql_lang}-queries:codeql-suites/{cql_lang}-security-extended.qls",
    ]

    try:
        analyze_result = subprocess.run(
            analyze_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if analyze_result.returncode != 0:
            logger.error("[codeql] Analysis failed: %s", analyze_result.stderr[:500])
            # Still try to read partial results
    except subprocess.TimeoutExpired:
        logger.error("[codeql] Analysis timed out")
        return []
    except Exception as exc:
        logger.error("[codeql] Analysis error: %s", exc)
        return []

    # Step 3: Parse SARIF
    if not sarif_path.exists():
        logger.warning("[codeql] SARIF output not found: %s", sarif_path)
        return []

    try:
        raw_sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        logger.error("[codeql] Failed to parse SARIF output")
        return []

    # Extract results from SARIF runs
    all_results: list[dict[str, Any]] = []
    for run in raw_sarif.get("runs", []):
        all_results.extend(run.get("results", []))

    logger.info("[codeql] Found %d raw results", len(all_results))

    if not all_results:
        candidates_path = artifacts_dir / "codeql_candidates.json"
        save_candidates([], candidates_path)
        return []

    # Step 4: Normalize
    findings = normalize_codeql(all_results)

    candidates_path = artifacts_dir / "codeql_candidates.json"
    save_candidates(findings, candidates_path)

    return findings
