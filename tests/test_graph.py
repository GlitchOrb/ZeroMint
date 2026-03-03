"""Tests for STEP 3 — code graph: parsing, code units, call graph, retriever.

Covers:
  1. Code units extraction (>= 2 units from fixture)
  2. Call graph edges (>= 1 edge)
  3. Retriever returns correct top result
  4. Python and JavaScript parsing
  5. Artifact serialisation and roundtrip
  6. Retriever keyword + TF-IDF modes
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cve_agent.graph.code_parser import parse_file, is_parseable, language_for_file
from cve_agent.graph.call_graph import build_graph, save_graph_artifacts
from cve_agent.graph.code_units import (
    CallGraphArtifact,
    CodeUnit,
    CodeUnitsArtifact,
)
from cve_agent.graph.retriever import CodeRetriever
from cve_agent.schemas.config import RunConfig, TargetConfig

# ── Fixtures ──────────────────────────────────────────────

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sample_repo"


@pytest.fixture
def sample_repo() -> Path:
    assert FIXTURES_DIR.exists()
    return FIXTURES_DIR


@pytest.fixture
def repo_config(sample_repo: Path) -> RunConfig:
    return RunConfig(
        target=TargetConfig(type="repo", path_or_url=str(sample_repo)),
    )


# ── code_parser tests ────────────────────────────────────


class TestCodeParser:
    """Test tree-sitter code parsing."""

    def test_python_parse_extracts_units(self, sample_repo: Path) -> None:
        """Parsing auth_handler.py should yield multiple code units."""
        py_file = sample_repo / "auth_handler.py"
        units, edges = parse_file(py_file, rel_to=sample_repo)

        assert len(units) >= 2, f"Expected >= 2 units, got {len(units)}"
        # Should find functions and the AuthManager class
        unit_names = [u.location.symbol for u in units]
        assert any("eval_input" in (n or "") for n in unit_names)
        assert any("AuthManager" in (n or "") for n in unit_names)

    def test_python_units_have_correct_fields(self, sample_repo: Path) -> None:
        """Each unit should have all required fields populated."""
        py_file = sample_repo / "auth_handler.py"
        units, _ = parse_file(py_file, rel_to=sample_repo)

        for unit in units:
            assert unit.unit_id, "unit_id should not be empty"
            assert unit.language == "python"
            assert unit.location.file == "auth_handler.py"
            assert unit.location.start_line >= 1
            assert unit.location.end_line >= unit.location.start_line
            assert unit.signature, "signature should not be empty"
            assert unit.text, "text should not be empty"
            assert unit.tokens_estimate > 0

    def test_javascript_parse_extracts_units(self, sample_repo: Path) -> None:
        """Parsing api_server.js should yield code units (arrow functions)."""
        js_file = sample_repo / "api_server.js"
        units, edges = parse_file(js_file, rel_to=sample_repo)

        # JS arrow functions and callbacks should be captured
        assert len(units) >= 1, f"Expected >= 1 JS units, got {len(units)}"
        for unit in units:
            assert unit.language == "javascript"

    def test_call_edges_extracted(self, sample_repo: Path) -> None:
        """Parsing should extract at least one call edge."""
        py_file = sample_repo / "auth_handler.py"
        units, edges = parse_file(py_file, rel_to=sample_repo)

        assert len(edges) >= 1, f"Expected >= 1 edges, got {len(edges)}"
        # eval_input should call "eval"
        edge_callees = [callee for _, callee in edges]
        assert any("eval" in c for c in edge_callees), (
            f"Expected 'eval' in callees, got: {edge_callees[:10]}"
        )

    def test_is_parseable(self, sample_repo: Path) -> None:
        assert is_parseable(sample_repo / "auth_handler.py") is True
        assert is_parseable(sample_repo / "api_server.js") is True
        assert is_parseable(Path("data.csv")) is False

    def test_language_for_file(self) -> None:
        assert language_for_file(Path("main.py")) == "python"
        assert language_for_file(Path("app.js")) == "javascript"
        assert language_for_file(Path("lib.ts")) == "javascript"  # TS via JS grammar
        assert language_for_file(Path("data.txt")) is None

    def test_unparseable_file_returns_empty(self) -> None:
        """Non-source files should return empty results."""
        units, edges = parse_file(Path("README.md"), rel_to=Path("."))
        assert units == []
        assert edges == []

    def test_nonexistent_file_returns_empty(self) -> None:
        """Missing file should return empty (not crash)."""
        units, edges = parse_file(Path("/no/such/file.py"), rel_to=Path("/no"))
        assert units == []
        assert edges == []


# ── call_graph tests ──────────────────────────────────────


class TestCallGraph:
    """Test full call graph building."""

    def test_build_graph_produces_units_and_edges(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """build_graph should return non-empty units and edges."""
        units_art, graph_art = build_graph(repo_config, base_dir=sample_repo)

        assert isinstance(units_art, CodeUnitsArtifact)
        assert isinstance(graph_art, CallGraphArtifact)
        assert len(units_art.units) >= 2
        assert len(graph_art.nodes) >= 2
        assert len(graph_art.edges) >= 1

    def test_nodes_match_units(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """Graph nodes should correspond 1:1 with code units."""
        units_art, graph_art = build_graph(repo_config, base_dir=sample_repo)

        unit_ids = {u.unit_id for u in units_art.units}
        node_ids = {n.unit_id for n in graph_art.nodes}
        assert unit_ids == node_ids

    def test_edges_reference_valid_sources(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """Edge from_unit_id should exist in the node set."""
        units_art, graph_art = build_graph(repo_config, base_dir=sample_repo)

        node_ids = {n.unit_id for n in graph_art.nodes}
        for edge in graph_art.edges:
            assert edge.from_unit_id in node_ids, (
                f"Edge source {edge.from_unit_id} not in nodes"
            )

    def test_save_artifacts(self, repo_config: RunConfig, sample_repo: Path, tmp_path: Path) -> None:
        """Artifacts should be written and round-trip via JSON."""
        units_art, graph_art = build_graph(repo_config, base_dir=sample_repo)
        units_path, graph_path = save_graph_artifacts(units_art, graph_art, tmp_path)

        assert units_path.exists()
        assert graph_path.exists()

        # Round-trip
        restored_units = CodeUnitsArtifact.model_validate_json(
            units_path.read_text(encoding="utf-8")
        )
        restored_graph = CallGraphArtifact.model_validate_json(
            graph_path.read_text(encoding="utf-8")
        )
        assert len(restored_units.units) == len(units_art.units)
        assert len(restored_graph.edges) == len(graph_art.edges)

    def test_ignores_pycache(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """Files in __pycache__ should not be parsed."""
        units_art, _ = build_graph(repo_config, base_dir=sample_repo)

        for unit in units_art.units:
            assert "__pycache__" not in unit.unit_id

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Empty dir should produce empty graph."""
        config = RunConfig(target=TargetConfig(type="repo", path_or_url=str(tmp_path)))
        units_art, graph_art = build_graph(config, base_dir=tmp_path)
        assert len(units_art.units) == 0
        assert len(graph_art.edges) == 0


# ── retriever tests ───────────────────────────────────────


class TestRetriever:
    """Test code unit retrieval."""

    def test_keyword_retrieves_eval(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """Querying 'eval' should rank eval_input at top."""
        units_art, _ = build_graph(repo_config, base_dir=sample_repo)
        retriever = CodeRetriever(units_art)

        results = retriever.retrieve("eval", top_k=5, mode="keyword")
        assert len(results) >= 1

        top_unit, top_score = results[0]
        assert "eval" in top_unit.unit_id.lower() or "eval" in top_unit.text.lower()
        assert top_score > 0

    def test_keyword_retrieves_auth(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """Querying 'AuthManager login' should find the AuthManager class or login method."""
        units_art, _ = build_graph(repo_config, base_dir=sample_repo)
        retriever = CodeRetriever(units_art)

        results = retriever.retrieve("AuthManager login", top_k=5, mode="keyword")
        assert len(results) >= 1

        found_names = [r[0].location.symbol or "" for r in results]
        assert any("AuthManager" in n or "login" in n for n in found_names)

    def test_tfidf_mode(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """TF-IDF mode should return scored results."""
        units_art, _ = build_graph(repo_config, base_dir=sample_repo)
        retriever = CodeRetriever(units_art)

        results = retriever.retrieve("subprocess shell command", top_k=5, mode="tfidf")
        assert len(results) >= 1
        # run_shell_command should score high
        top_symbols = [r[0].location.symbol or "" for r in results[:3]]
        assert any("shell" in s.lower() or "subprocess" in (r[0].text.lower()) for r, s in zip(results[:3], top_symbols))

    def test_combined_mode(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """Combined mode should blend keyword + TF-IDF signals."""
        units_art, _ = build_graph(repo_config, base_dir=sample_repo)
        retriever = CodeRetriever(units_art)

        results = retriever.retrieve("pickle deserialize", top_k=5, mode="combined")
        assert len(results) >= 1
        top_text = results[0][0].text.lower()
        assert "pickle" in top_text

    def test_empty_query(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """Empty query should return empty results."""
        units_art, _ = build_graph(repo_config, base_dir=sample_repo)
        retriever = CodeRetriever(units_art)

        results = retriever.retrieve("", top_k=5)
        assert len(results) == 0

    def test_no_match_query(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """Query with no matches should return empty."""
        units_art, _ = build_graph(repo_config, base_dir=sample_repo)
        retriever = CodeRetriever(units_art)

        results = retriever.retrieve("zzznonexistenttokenxxx", top_k=5)
        assert len(results) == 0

    def test_find_callers(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """find_callers should return units that call a given symbol."""
        units_art, graph_art = build_graph(repo_config, base_dir=sample_repo)
        retriever = CodeRetriever(units_art)

        raw_edges = [(e.from_unit_id, e.to_symbol) for e in graph_art.edges]
        callers = retriever.find_callers("eval", raw_edges)

        assert len(callers) >= 1
        assert any("eval_input" in c.unit_id for c in callers)

    def test_find_callees(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """find_callees should return symbols called by a given unit."""
        units_art, graph_art = build_graph(repo_config, base_dir=sample_repo)

        # Find the eval_input unit
        eval_unit = next(
            (u for u in units_art.units if "eval_input" in u.unit_id), None
        )
        assert eval_unit is not None

        retriever = CodeRetriever(units_art)
        raw_edges = [(e.from_unit_id, e.to_symbol) for e in graph_art.edges]
        callees = retriever.find_callees(eval_unit.unit_id, raw_edges)

        assert len(callees) >= 1
        assert any("eval" in c for c in callees)

    def test_retriever_from_artifact(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """CodeRetriever should accept CodeUnitsArtifact directly."""
        units_art, _ = build_graph(repo_config, base_dir=sample_repo)
        retriever = CodeRetriever(units_art)  # Passing artifact, not list

        assert len(retriever.units) == len(units_art.units)
        results = retriever.retrieve("sql", top_k=3)
        assert len(results) >= 1
