"""Evidence bundler — creates evidence_bundle.zip from run artifacts.

Collects all artifacts relevant to the analysis into a single ZIP file
for sharing with security teams or maintainers.

Included in the bundle:
  - REPORT.md
  - findings.json
  - triage.json
  - validation_results.json
  - fuzz_attempts.json
  - hypotheses.json
  - logs/ (sanitizer logs, execution logs)
  - harnesses/ (generated test files, build scripts)
  - run_result.json

NOT included:
  - Full repository contents (too large, privacy)
  - Credentials or environment variables
  - Docker images or containers
"""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path

logger = logging.getLogger("cve_agent.reporting.bundler")

# Files to include from artifacts/ dir
_ARTIFACT_FILES = [
    "findings.json",
    "triage.json",
    "validation_results.json",
    "fuzz_attempts.json",
    "hypotheses.json",
    "candidates.json",
    "repo_index.json",
    "hotspots.json",
    "run_result.json",
]

# Directories to include recursively
_ARTIFACT_DIRS = [
    "logs",
    "harnesses",
]


def create_evidence_bundle(
    run_dir: Path,
    artifacts_dir: Path,
    *,
    output_name: str = "evidence_bundle.zip",
) -> Path:
    """Create a ZIP bundle of all evidence artifacts.

    Args:
        run_dir: Run directory (parent of artifacts/).
        artifacts_dir: Directory containing JSON artifacts.
        output_name: Name of the output ZIP file.

    Returns:
        Path to the created ZIP file.
    """
    zip_path = run_dir / output_name
    added = 0

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Include REPORT.md from run_dir
        report_path = run_dir / "REPORT.md"
        if report_path.exists():
            zf.write(report_path, "REPORT.md")
            added += 1
            logger.debug("[bundle] Added REPORT.md")

        # Include artifact JSON files
        for filename in _ARTIFACT_FILES:
            filepath = artifacts_dir / filename
            if filepath.exists():
                arcname = f"artifacts/{filename}"
                zf.write(filepath, arcname)
                added += 1
                logger.debug("[bundle] Added %s", arcname)

        # Include artifact directories
        for dirname in _ARTIFACT_DIRS:
            dirpath = artifacts_dir / dirname
            if dirpath.exists() and dirpath.is_dir():
                for child in sorted(dirpath.rglob("*")):
                    if child.is_file():
                        arcname = f"artifacts/{child.relative_to(artifacts_dir)}"
                        # Safety: skip very large files (> 5MB)
                        if child.stat().st_size > 5 * 1024 * 1024:
                            logger.warning(
                                "[bundle] Skipped large file: %s (%d bytes)",
                                child.name, child.stat().st_size,
                            )
                            continue
                        zf.write(child, arcname)
                        added += 1

        # Include run_result.json from run_dir if present
        run_result = run_dir / "run_result.json"
        if run_result.exists():
            zf.write(run_result, "run_result.json")
            added += 1

    logger.info(
        "Created evidence bundle: %s (%d files, %d bytes)",
        zip_path, added, zip_path.stat().st_size,
    )

    return zip_path
