"""Tests for repo_indexer — STEP 2 recon stage.

Covers:
  1. Indexing produces repo_index.json and hotspots.json
  2. Ignore patterns (.git, node_modules, __pycache__) are respected
  3. Hotspot scoring ranks vulnerable files above clean ones
  4. Language detection works for .py and .js files
  5. RunStats fields (indexed_files, languages, hotspot_top5) are populated
  6. Custom ignore_patterns from config are applied
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cve_agent.analyzers.repo_indexer import (
    HotspotIndex,
    RepoIndex,
    index_repo,
    save_artifacts,
    _should_ignore,
    _guess_language,
    _score_filename,
    _score_content,
)
from cve_agent.schemas.config import RunConfig, TargetConfig

# ── Locate fixture directory ──────────────────────────────

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sample_repo"


@pytest.fixture
def sample_repo() -> Path:
    """Return path to the sample repo fixture."""
    assert FIXTURES_DIR.exists(), f"Fixture not found: {FIXTURES_DIR}"
    return FIXTURES_DIR


@pytest.fixture
def repo_config(sample_repo: Path) -> RunConfig:
    """RunConfig pointing at the sample repo."""
    return RunConfig(
        target=TargetConfig(
            type="repo",
            path_or_url=str(sample_repo),
        ),
    )


# ── Tests ─────────────────────────────────────────────────


class TestIndexRepo:
    """Core indexing functionality."""

    def test_produces_files_and_hotspots(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """index_repo should return non-empty RepoIndex and HotspotIndex."""
        repo_index, hotspot_index = index_repo(repo_config, base_dir=sample_repo)

        assert isinstance(repo_index, RepoIndex)
        assert isinstance(hotspot_index, HotspotIndex)
        assert len(repo_index.files) > 0
        assert len(hotspot_index.items) > 0

    def test_language_detection(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """Should detect both Python and JavaScript files."""
        repo_index, _ = index_repo(repo_config, base_dir=sample_repo)

        languages = repo_index.summary.language_counts
        assert "python" in languages
        assert "javascript" in languages

    def test_file_count_excludes_ignored(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """Files in __pycache__ and node_modules should NOT be indexed."""
        repo_index, _ = index_repo(repo_config, base_dir=sample_repo)

        indexed_paths = [f.path for f in repo_index.files]

        # Should include these
        assert any("auth_handler.py" in p for p in indexed_paths)
        assert any("api_server.js" in p for p in indexed_paths)
        assert any("utils.py" in p for p in indexed_paths)

        # Should NOT include these (ignored dirs)
        assert not any("__pycache__" in p for p in indexed_paths)
        assert not any("node_modules" in p for p in indexed_paths)

    def test_summary_stats(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """Summary should have correct aggregate numbers."""
        repo_index, _ = index_repo(repo_config, base_dir=sample_repo)
        s = repo_index.summary

        assert s.total_files >= 3  # auth_handler.py, api_server.js, utils.py
        assert s.total_bytes > 0
        assert s.suspicious_keyword_hits > 0

    def test_hotspot_ranking(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """auth_handler.py and api_server.js should rank above utils.py."""
        _, hotspot_index = index_repo(repo_config, base_dir=sample_repo)

        paths = [h.path for h in hotspot_index.items]

        # auth_handler.py should be in top hotspots
        assert any("auth_handler.py" in p for p in paths[:5])

        # api_server.js should also score high
        assert any("api_server.js" in p for p in paths[:5])

        # If utils.py appears, it should be ranked lower
        if any("utils.py" in p for p in paths):
            utils_idx = next(i for i, p in enumerate(paths) if "utils.py" in p)
            auth_idx = next(i for i, p in enumerate(paths) if "auth_handler.py" in p)
            assert auth_idx < utils_idx

    def test_hotspot_has_reasons(self, repo_config: RunConfig, sample_repo: Path) -> None:
        """Each hotspot should have non-empty reasons."""
        _, hotspot_index = index_repo(repo_config, base_dir=sample_repo)

        for item in hotspot_index.items:
            assert item.score > 0
            assert len(item.reasons) > 0

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Indexing an empty directory should produce empty results."""
        config = RunConfig(target=TargetConfig(type="repo", path_or_url=str(tmp_path)))
        repo_index, hotspot_index = index_repo(config, base_dir=tmp_path)

        assert len(repo_index.files) == 0
        assert len(hotspot_index.items) == 0
        assert repo_index.summary.total_files == 0

    def test_nonexistent_directory(self) -> None:
        """Indexing a nonexistent directory should return empty (not crash)."""
        config = RunConfig(target=TargetConfig(type="repo", path_or_url="/no/such/path"))
        repo_index, hotspot_index = index_repo(config, base_dir=Path("/no/such/path"))

        assert len(repo_index.files) == 0
        assert len(hotspot_index.items) == 0


class TestCustomIgnorePatterns:
    """Test that user-specified ignore_patterns are applied."""

    def test_custom_ignore_hides_file(self, sample_repo: Path) -> None:
        """Adding '*.js' to ignore_patterns should exclude JavaScript files."""
        config = RunConfig(
            target=TargetConfig(
                type="repo",
                path_or_url=str(sample_repo),
                ignore_patterns=["*.js"],
            ),
        )
        repo_index, _ = index_repo(config, base_dir=sample_repo)

        indexed_paths = [f.path for f in repo_index.files]
        assert not any(p.endswith(".js") for p in indexed_paths)
        # Python files should still be present
        assert any("auth_handler.py" in p for p in indexed_paths)

    def test_custom_ignore_directory(self, tmp_path: Path) -> None:
        """Custom directory pattern should be respected."""
        # Create structure
        (tmp_path / "src" / "main.py").parent.mkdir(parents=True)
        (tmp_path / "src" / "main.py").write_text("x = 1", encoding="utf-8")
        (tmp_path / "vendor" / "lib.py").parent.mkdir(parents=True)
        (tmp_path / "vendor" / "lib.py").write_text("y = 2", encoding="utf-8")

        config = RunConfig(
            target=TargetConfig(
                type="repo",
                path_or_url=str(tmp_path),
                ignore_patterns=["vendor"],
            ),
        )
        repo_index, _ = index_repo(config, base_dir=tmp_path)

        indexed_paths = [f.path for f in repo_index.files]
        assert any("main.py" in p for p in indexed_paths)
        assert not any("vendor" in p for p in indexed_paths)


class TestSaveArtifacts:
    """Test artifact serialisation."""

    def test_writes_json_files(self, repo_config: RunConfig, sample_repo: Path, tmp_path: Path) -> None:
        """save_artifacts should create repo_index.json and hotspots.json."""
        repo_index, hotspot_index = index_repo(repo_config, base_dir=sample_repo)
        repo_path, hotspot_path = save_artifacts(repo_index, hotspot_index, tmp_path)

        assert repo_path.exists()
        assert hotspot_path.exists()
        assert repo_path.name == "repo_index.json"
        assert hotspot_path.name == "hotspots.json"

        # Verify JSON is valid and round-trips
        repo_data = json.loads(repo_path.read_text(encoding="utf-8"))
        assert "files" in repo_data
        assert "summary" in repo_data
        assert repo_data["summary"]["total_files"] >= 3

        hotspot_data = json.loads(hotspot_path.read_text(encoding="utf-8"))
        assert "items" in hotspot_data
        assert len(hotspot_data["items"]) > 0

        # Verify pydantic roundtrip
        restored_repo = RepoIndex.model_validate(repo_data)
        assert len(restored_repo.files) == len(repo_index.files)

        restored_hs = HotspotIndex.model_validate(hotspot_data)
        assert len(restored_hs.items) == len(hotspot_index.items)


class TestHelpers:
    """Unit tests for internal helper functions."""

    def test_should_ignore_git(self) -> None:
        assert _should_ignore(Path(".git/config"), [".git"]) is True
        assert _should_ignore(Path("src/main.py"), [".git"]) is False

    def test_should_ignore_glob(self) -> None:
        assert _should_ignore(Path("lib.egg-info/PKG-INFO"), ["*.egg-info"]) is True
        assert _should_ignore(Path("src/lib.py"), ["*.egg-info"]) is False

    def test_guess_language(self) -> None:
        assert _guess_language(Path("main.py")) == "python"
        assert _guess_language(Path("app.js")) == "javascript"
        assert _guess_language(Path("lib.rs")) == "rust"
        assert _guess_language(Path("Dockerfile")) == "dockerfile"
        assert _guess_language(Path("data.xyz")) == "unknown"

    def test_score_filename(self) -> None:
        score, reasons = _score_filename("src/auth_handler.py")
        assert score > 0
        assert any("auth" in r for r in reasons)

        score2, _ = _score_filename("src/utils.py")
        assert score > score2

    def test_score_content(self) -> None:
        code = "result = eval(user_input)\nos.system(cmd)\npickle.loads(data)"
        score, reasons, matches = _score_content(code)

        assert score > 0
        assert any("eval" in r for r in reasons)
        assert any("pickle" in r for r in reasons)
        assert len(matches) > 0

    def test_score_content_clean(self) -> None:
        code = "def add(a, b): return a + b"
        score, reasons, matches = _score_content(code)
        # Very clean code should score zero or near-zero
        # (may get minor hits from "return" matching nothing, etc.)
        assert score < 5.0
