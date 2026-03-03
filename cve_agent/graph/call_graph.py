"""Call graph builder — walks indexed files and assembles a call graph.

Iterates through files in a repo, parses each with tree-sitter,
collects CodeUnits and call edges, then writes artifacts.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from cve_agent.graph.code_parser import is_parseable, parse_file
from cve_agent.graph.code_units import (
    CallGraphArtifact,
    CodeUnit,
    CodeUnitsArtifact,
    GraphEdge,
    GraphNode,
)
from cve_agent.schemas.config import RunConfig

logger = logging.getLogger("cve_agent.graph.call_graph")


def build_graph(
    config: RunConfig,
    *,
    base_dir: Path | None = None,
) -> tuple[CodeUnitsArtifact, CallGraphArtifact]:
    """Walk the target repo and build code units + call graph.

    Args:
        config: Validated RunConfig.
        base_dir: Override base directory (for tests).

    Returns:
        (CodeUnitsArtifact, CallGraphArtifact)
    """
    target_dir = base_dir or Path(config.target.path_or_url).resolve()
    ignores = config.target.all_ignores

    logger.info("Building code graph from: %s", target_dir)

    all_units: list[CodeUnit] = []
    all_edges: list[tuple[str, str]] = []
    files_parsed = 0

    if not target_dir.exists():
        logger.warning("Target directory does not exist: %s", target_dir)
        return CodeUnitsArtifact(), CallGraphArtifact()

    # Import _should_ignore from repo_indexer
    from cve_agent.analyzers.repo_indexer import _should_ignore

    for root, dirs, filenames in os.walk(target_dir):
        root_path = Path(root)
        rel_root = root_path.relative_to(target_dir)

        # Prune ignored directories
        dirs[:] = [d for d in dirs if not _should_ignore(rel_root / d, ignores)]

        for fname in filenames:
            file_path = root_path / fname
            rel_path = file_path.relative_to(target_dir)

            if _should_ignore(rel_path, ignores):
                continue

            if not is_parseable(file_path):
                continue

            units, edges = parse_file(file_path, rel_to=target_dir)
            if units:
                all_units.extend(units)
                all_edges.extend(edges)
                files_parsed += 1
                logger.debug(
                    "  Parsed %s: %d units, %d edges",
                    rel_path, len(units), len(edges),
                )

    logger.info(
        "Code graph: %d files parsed, %d units extracted, %d edges",
        files_parsed, len(all_units), len(all_edges),
    )

    # ── Build artifacts ────────────────────────────────────

    units_artifact = CodeUnitsArtifact(units=all_units)

    # Nodes (one per unit)
    nodes = [
        GraphNode(
            unit_id=u.unit_id,
            signature=u.signature,
            location=u.location,
        )
        for u in all_units
    ]

    # Edges (deduplicated)
    seen_edges: set[tuple[str, str]] = set()
    graph_edges: list[GraphEdge] = []
    for from_id, to_sym in all_edges:
        key = (from_id, to_sym)
        if key not in seen_edges:
            seen_edges.add(key)
            graph_edges.append(GraphEdge(from_unit_id=from_id, to_symbol=to_sym))

    graph_artifact = CallGraphArtifact(nodes=nodes, edges=graph_edges)

    return units_artifact, graph_artifact


def save_graph_artifacts(
    units: CodeUnitsArtifact,
    graph: CallGraphArtifact,
    artifacts_dir: Path,
) -> tuple[Path, Path]:
    """Save code_units.json and call_graph.json.

    Returns:
        (units_path, graph_path)
    """
    units_path = artifacts_dir / "code_units.json"
    graph_path = artifacts_dir / "call_graph.json"

    units_path.write_text(
        units.model_dump_json(indent=2),
        encoding="utf-8",
    )
    graph_path.write_text(
        graph.model_dump_json(indent=2),
        encoding="utf-8",
    )

    logger.info("Saved: %s (%d units)", units_path, len(units.units))
    logger.info("Saved: %s (%d nodes, %d edges)", graph_path, len(graph.nodes), len(graph.edges))

    return units_path, graph_path
