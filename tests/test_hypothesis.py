"""Tests for STEP 5 — Hypothesis Agent.

Covers:
  1. Offline mode generates hypotheses.json from hotspots
  2. All hypotheses pass pydantic validation
  3. Every hypothesis has self_critique and conservative confidence
  4. DummyLLM produces valid Hypothesis JSON
  5. LLM retry logic on parse failure
  6. Integration: full offline pipeline produces hypotheses
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cve_agent.agents.hypothesis_agent import (
    _offline_hypothesis_from_finding,
    _offline_hypothesis_from_hotspot,
    _parse_llm_response,
    generate_hypotheses,
    save_hypotheses,
)
from cve_agent.agents.llm_clients.base import BaseLLMClient
from cve_agent.agents.llm_clients.dummy import DummyLLMClient
from cve_agent.analyzers.normalize_findings import (
    normalize_semgrep,
    save_candidates,
)
from cve_agent.analyzers.repo_indexer import HotspotIndex, HotspotItem
from cve_agent.schemas.config import FeaturesConfig, LLMConfig, RunConfig, TargetConfig
from cve_agent.schemas.findings import (
    CodeLocation,
    EvidenceItem,
    EvidenceKind,
    Finding,
    FindingStatus,
    Hypothesis,
    Severity,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sample_repo"


# ── Fixtures ──────────────────────────────────────────────


@pytest.fixture
def sample_hotspots() -> list[HotspotItem]:
    return [
        HotspotItem(
            path="auth_handler.py",
            score=35.0,
            reasons=["name:auth", "code:eval", "code:pickle", "code:subprocess"],
            top_matches=["return eval(user_input)", "pickle.loads(data)"],
        ),
        HotspotItem(
            path="api_server.js",
            score=20.0,
            reasons=["name:api", "code:exec", "code:innerHTML"],
            top_matches=["exec(cmd, ...)", "innerHTML"],
        ),
        HotspotItem(
            path="utils.py",
            score=3.0,
            reasons=["code:open("],
            top_matches=["open(filename, 'r')"],
        ),
    ]


@pytest.fixture
def sample_findings() -> list[Finding]:
    return normalize_semgrep([
        {
            "check_id": "python.lang.security.audit.eval-detected",
            "path": "auth_handler.py",
            "start": {"line": 15, "col": 12},
            "end": {"line": 15, "col": 30},
            "extra": {
                "severity": "ERROR",
                "message": "Detected use of eval(). Dangerous with untrusted input.",
                "lines": "    return eval(user_input)",
                "metadata": {},
            },
        },
    ])


@pytest.fixture
def artifacts_with_hotspots(tmp_path: Path, sample_hotspots: list[HotspotItem]) -> Path:
    """Create artifacts directory with hotspots.json."""
    arts = tmp_path / "artifacts"
    arts.mkdir()
    hot_idx = HotspotIndex(items=sample_hotspots)
    (arts / "hotspots.json").write_text(
        hot_idx.model_dump_json(indent=2), encoding="utf-8",
    )
    return arts


@pytest.fixture
def artifacts_with_all(
    artifacts_with_hotspots: Path,
    sample_findings: list[Finding],
) -> Path:
    """Create artifacts with hotspots + semgrep candidates."""
    save_candidates(sample_findings, artifacts_with_hotspots / "semgrep_candidates.json")
    return artifacts_with_hotspots


# ── BaseLLMClient / DummyLLM ──────────────────────────────


class TestDummyLLM:
    """Test the DummyLLMClient."""

    def test_name(self) -> None:
        client = DummyLLMClient()
        assert client.name == "dummy/placeholder"

    def test_generate_returns_valid_json(self) -> None:
        client = DummyLLMClient()
        response = client.generate("Analyse eval() usage in auth_handler.py")
        data = json.loads(response)
        assert "vuln_type" in data
        assert "self_critique" in data
        assert data["confidence"] <= 0.5

    def test_generate_with_eval_keyword(self) -> None:
        client = DummyLLMClient()
        response = client.generate("eval() with user input")
        data = json.loads(response)
        assert data["vuln_type"] == "code_injection"

    def test_generate_with_sql_keyword(self) -> None:
        client = DummyLLMClient()
        response = client.generate("SQL query construction")
        data = json.loads(response)
        assert data["vuln_type"] == "sql_injection"

    def test_generate_with_pickle_keyword(self) -> None:
        client = DummyLLMClient()
        response = client.generate("pickle deserialization")
        data = json.loads(response)
        assert data["vuln_type"] == "insecure_deserialization"

    def test_generate_produces_valid_hypothesis(self) -> None:
        """DummyLLM output should pass Hypothesis validation."""
        client = DummyLLMClient()
        response = client.generate("subprocess shell=True command injection")
        hyp = Hypothesis.model_validate_json(response)
        assert hyp.vuln_type == "command_injection"
        assert hyp.self_critique != ""

    def test_estimate_tokens(self) -> None:
        client = DummyLLMClient()
        assert client.estimate_tokens("hello world") >= 1


# ── Offline hypothesis from hotspot ───────────────────────


class TestOfflineFromHotspot:
    """Test rule-based hypothesis from hotspots."""

    def test_produces_hypothesis(self, sample_hotspots: list[HotspotItem]) -> None:
        hyp = _offline_hypothesis_from_hotspot(sample_hotspots[0])
        assert isinstance(hyp, Hypothesis)
        assert hyp.vuln_type != ""
        assert hyp.self_critique != ""

    def test_confidence_conservative(self, sample_hotspots: list[HotspotItem]) -> None:
        """Offline confidence should be <= 0.4."""
        for hs in sample_hotspots:
            if hs.score < 5.0:
                continue
            hyp = _offline_hypothesis_from_hotspot(hs)
            assert hyp.confidence <= 0.4

    def test_self_critique_present(self, sample_hotspots: list[HotspotItem]) -> None:
        """Every hypothesis must have self_critique."""
        for hs in sample_hotspots:
            hyp = _offline_hypothesis_from_hotspot(hs)
            assert len(hyp.self_critique) > 10

    def test_eval_detected(self, sample_hotspots: list[HotspotItem]) -> None:
        """auth_handler.py with eval keyword should → code_injection."""
        hyp = _offline_hypothesis_from_hotspot(sample_hotspots[0])
        assert hyp.vuln_type == "code_injection"

    def test_pydantic_validates(self, sample_hotspots: list[HotspotItem]) -> None:
        for hs in sample_hotspots:
            hyp = _offline_hypothesis_from_hotspot(hs)
            validated = Hypothesis.model_validate(hyp.model_dump())
            assert validated.vuln_type == hyp.vuln_type


# ── Offline hypothesis from Finding ──────────────────────


class TestOfflineFromFinding:
    """Test rule-based hypothesis from static analysis findings."""

    def test_produces_hypothesis(self, sample_findings: list[Finding]) -> None:
        hyp = _offline_hypothesis_from_finding(sample_findings[0])
        assert isinstance(hyp, Hypothesis)
        assert hyp.self_critique != ""

    def test_confidence_conservative(self, sample_findings: list[Finding]) -> None:
        for f in sample_findings:
            hyp = _offline_hypothesis_from_finding(f)
            assert hyp.confidence <= 0.5

    def test_pydantic_validates(self, sample_findings: list[Finding]) -> None:
        for f in sample_findings:
            hyp = _offline_hypothesis_from_finding(f)
            validated = Hypothesis.model_validate(hyp.model_dump())
            assert validated.vuln_type == hyp.vuln_type


# ── LLM parse + retry ────────────────────────────────────


class TestParseLLMResponse:
    """Test JSON parse with retry logic."""

    def test_valid_json_parses(self) -> None:
        valid = json.dumps({
            "vuln_type": "sql_injection",
            "attack_surface": "query param",
            "preconditions": [],
            "exploit_idea": "test",
            "confidence": 0.5,
            "related_sinks": [],
            "related_sources": [],
            "self_critique": "manual review needed",
        })
        hyp = _parse_llm_response(valid)
        assert hyp is not None
        assert hyp.vuln_type == "sql_injection"

    def test_json_with_markdown_fences(self) -> None:
        fenced = "```json\n" + json.dumps({
            "vuln_type": "xss",
            "attack_surface": "input",
            "preconditions": [],
            "exploit_idea": "test",
            "confidence": 0.3,
            "related_sinks": [],
            "related_sources": [],
            "self_critique": "needs review",
        }) + "\n```"
        hyp = _parse_llm_response(fenced)
        assert hyp is not None
        assert hyp.vuln_type == "xss"

    def test_invalid_json_returns_none(self) -> None:
        hyp = _parse_llm_response("not valid json at all")
        assert hyp is None

    def test_retry_with_llm(self) -> None:
        """Retry should call LLM again and succeed if second response is valid."""
        valid = json.dumps({
            "vuln_type": "rce",
            "attack_surface": "endpoint",
            "preconditions": [],
            "exploit_idea": "inject",
            "confidence": 0.4,
            "related_sinks": [],
            "related_sources": [],
            "self_critique": "possible FP",
        })

        class FixingLLM(BaseLLMClient):
            def __init__(self):
                self.calls = 0
            @property
            def name(self) -> str:
                return "test/fixing"
            def generate(self, prompt, **kwargs) -> str:
                self.calls += 1
                return valid

        llm = FixingLLM()
        hyp = _parse_llm_response(
            "bad json", max_retries=2, llm=llm, prompt="test",
        )
        assert hyp is not None
        assert llm.calls >= 1


# ── generate_hypotheses integration ───────────────────────


class TestGenerateHypotheses:
    """Test full hypothesis generation."""

    def test_offline_from_hotspots(self, artifacts_with_hotspots: Path) -> None:
        """Should generate hypotheses from hotspots in offline mode."""
        config = RunConfig(
            target=TargetConfig(type="repo", path_or_url=str(FIXTURES_DIR)),
            features=FeaturesConfig(enable_graph=False),
        )
        findings = generate_hypotheses(config, artifacts_with_hotspots)

        # auth_handler.py (score=35) and api_server.js (score=20)
        # utils.py (score=3) should be skipped (< 5.0)
        assert len(findings) >= 2

        for f in findings:
            assert isinstance(f, Finding)
            assert f.status == FindingStatus.CANDIDATE
            assert f.hypothesis is not None
            assert f.hypothesis.self_critique != ""
            assert f.hypothesis.confidence <= 0.5

    def test_offline_from_static_candidates(self, artifacts_with_all: Path) -> None:
        """Should generate hypotheses from static analysis candidates."""
        config = RunConfig(
            target=TargetConfig(type="repo", path_or_url=str(FIXTURES_DIR)),
            features=FeaturesConfig(enable_graph=False),
        )
        findings = generate_hypotheses(config, artifacts_with_all)

        # Should have findings from both semgrep and hotspots
        assert len(findings) >= 1
        # At least one should come from semgrep
        sg_findings = [f for f in findings if "[semgrep]" in f.title]
        assert len(sg_findings) >= 1

    def test_with_dummy_llm(self, artifacts_with_hotspots: Path) -> None:
        """DummyLLM mode should work end-to-end."""
        config = RunConfig(
            target=TargetConfig(type="repo", path_or_url=str(FIXTURES_DIR)),
            features=FeaturesConfig(enable_graph=False),
            llm=LLMConfig(enabled=True, provider="dummy"),
        )
        llm = DummyLLMClient()
        findings = generate_hypotheses(
            config, artifacts_with_hotspots, llm_client=llm,
        )

        assert len(findings) >= 2
        for f in findings:
            assert f.hypothesis is not None
            assert f.hypothesis.self_critique != ""

    def test_save_hypotheses(self, artifacts_with_hotspots: Path) -> None:
        """hypotheses.json should be saved and round-trip."""
        config = RunConfig(
            target=TargetConfig(type="repo", path_or_url=str(FIXTURES_DIR)),
            features=FeaturesConfig(enable_graph=False),
        )
        findings = generate_hypotheses(config, artifacts_with_hotspots)
        out = save_hypotheses(findings, artifacts_with_hotspots)

        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        assert len(data) == len(findings)

        # Validate each
        for item in data:
            restored = Finding.model_validate(item)
            assert restored.hypothesis is not None

    def test_empty_artifacts(self, tmp_path: Path) -> None:
        """No hotspots/candidates → empty hypotheses."""
        arts = tmp_path / "empty_arts"
        arts.mkdir()
        config = RunConfig(
            target=TargetConfig(type="repo", path_or_url=str(FIXTURES_DIR)),
            features=FeaturesConfig(enable_graph=False),
        )
        findings = generate_hypotheses(config, arts)
        assert findings == []

    def test_all_hypotheses_have_required_fields(
        self, artifacts_with_all: Path,
    ) -> None:
        """Every hypothesis must have vuln_type, exploit_idea, self_critique."""
        config = RunConfig(
            target=TargetConfig(type="repo", path_or_url=str(FIXTURES_DIR)),
            features=FeaturesConfig(enable_graph=False),
        )
        findings = generate_hypotheses(config, artifacts_with_all)

        for f in findings:
            assert f.hypothesis is not None
            h = f.hypothesis
            assert h.vuln_type, f"Missing vuln_type in {f.id}"
            assert h.exploit_idea, f"Missing exploit_idea in {f.id}"
            assert h.self_critique, f"Missing self_critique in {f.id}"
            assert 0.0 <= h.confidence <= 1.0
