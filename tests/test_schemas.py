"""Test 4: Schema roundtrip — serialize / deserialize all models."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from cve_agent.schemas import (
    CodeLocation,
    EvidenceItem,
    EvidenceKind,
    Finding,
    FindingStatus,
    Hypothesis,
    RunConfig,
    RunResult,
    RunStats,
    RunStatus,
    Severity,
    TargetType,
)


class TestSchemaRoundtrip:
    """Verify that all schemas survive JSON serialize → deserialize."""

    def test_run_config_roundtrip(self) -> None:
        """RunConfig should survive full serialization roundtrip."""
        original = RunConfig(
            target={"type": "api", "path_or_url": "https://api.example.com", "languages_hint": ["python", "go"]},
            features={"enable_graph": True, "enable_semgrep": True, "enable_codeql": False, "enable_fuzz": True, "enable_sanitizers": True},
            sandbox={"enabled": True, "network_off": True, "cpu": 2.0, "mem_mb": 1024, "timeout_sec": 120},
            llm={"enabled": True, "provider": "openai", "model": "gpt-4"},
            budget={"max_tokens": 100000, "max_cost_usd": 5.0},
        )

        json_str = original.model_dump_json()
        restored = RunConfig.model_validate_json(json_str)

        assert restored.target.type == TargetType.API
        assert restored.target.path_or_url == "https://api.example.com"
        assert restored.features.enable_semgrep is True
        assert restored.sandbox.cpu == 2.0
        assert restored.sandbox.mem_mb == 1024
        assert restored.llm.provider == "openai"
        assert restored.budget.max_tokens == 100000
        assert restored.budget.max_cost_usd == 5.0

    def test_code_location_roundtrip(self) -> None:
        loc = CodeLocation(file="src/main.py", start_line=10, end_line=25, symbol="process_input")
        restored = CodeLocation.model_validate_json(loc.model_dump_json())
        assert restored.file == "src/main.py"
        assert restored.symbol == "process_input"
        assert restored.start_line == 10

    def test_evidence_item_roundtrip(self) -> None:
        evidence = EvidenceItem(
            kind=EvidenceKind.CODE,
            summary="Dangerous eval() call with user input",
            location=CodeLocation(file="app.py", start_line=42, end_line=42),
            snippet="result = eval(user_input)",
            artifact_path="artifacts/eval_finding.json",
        )
        restored = EvidenceItem.model_validate_json(evidence.model_dump_json())
        assert restored.kind == EvidenceKind.CODE
        assert restored.location is not None
        assert restored.location.file == "app.py"
        assert restored.snippet == "result = eval(user_input)"

    def test_hypothesis_roundtrip(self) -> None:
        hyp = Hypothesis(
            vuln_type="injection",
            attack_surface="REST API /evaluate endpoint",
            preconditions=["User can send POST requests", "No input validation"],
            exploit_idea="Send crafted expression to trigger eval() execution",
            confidence=0.85,
            related_sinks=["eval", "exec"],
            related_sources=["request.body"],
            self_critique="May be mitigated by WAF rules not visible in source",
        )
        restored = Hypothesis.model_validate_json(hyp.model_dump_json())
        assert restored.vuln_type == "injection"
        assert restored.confidence == 0.85
        assert len(restored.preconditions) == 2
        assert "eval" in restored.related_sinks
        assert restored.self_critique.startswith("May be mitigated")

    def test_finding_roundtrip(self) -> None:
        finding = Finding(
            title="Code Injection via eval()",
            severity=Severity.CRITICAL,
            confidence=0.9,
            status=FindingStatus.CONFIRMED,
            hypothesis=Hypothesis(
                vuln_type="injection",
                attack_surface="/api/calc",
                exploit_idea="Send __import__('os').system('id') as expression",
                confidence=0.9,
            ),
            evidence=[
                EvidenceItem(kind=EvidenceKind.CODE, summary="eval call", snippet="eval(expr)"),
                EvidenceItem(kind=EvidenceKind.LOG, summary="crash log", artifact_path="crash.log"),
            ],
            reproduction_steps=["POST /api/calc with body: {expr: '__import__(\"os\")'}"],
            mitigation="Replace eval() with ast.literal_eval()",
            references=["CWE-94", "https://cwe.mitre.org/data/definitions/94.html"],
        )
        json_str = finding.model_dump_json()
        restored = Finding.model_validate_json(json_str)

        assert restored.title == "Code Injection via eval()"
        assert restored.severity == Severity.CRITICAL
        assert restored.status == FindingStatus.CONFIRMED
        assert restored.hypothesis is not None
        assert len(restored.evidence) == 2
        assert restored.evidence[0].kind == EvidenceKind.CODE
        assert len(restored.reproduction_steps) == 1
        assert "CWE-94" in restored.references

    def test_run_result_roundtrip(self) -> None:
        result = RunResult(
            run_id="test-roundtrip-001",
            status=RunStatus.COMPLETED,
            finished_at=datetime(2026, 3, 3, 12, 0, 0, tzinfo=timezone.utc),
            stats=RunStats(
                files_indexed=50,
                nodes_parsed=300,
                findings_confirmed=2,
                llm_tokens_used=15000,
                llm_cost_usd=0.45,
            ),
            findings=[
                Finding(
                    title="SQL Injection",
                    severity=Severity.HIGH,
                    status=FindingStatus.CONFIRMED,
                ),
                Finding(
                    title="Path Traversal",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.CANDIDATE,
                ),
            ],
        )
        json_str = result.model_dump_json()
        restored = RunResult.model_validate_json(json_str)

        assert restored.run_id == "test-roundtrip-001"
        assert restored.status == RunStatus.COMPLETED
        assert restored.stats.files_indexed == 50
        assert restored.stats.llm_cost_usd == 0.45
        assert len(restored.findings) == 2
        assert restored.findings[0].severity == Severity.HIGH
        assert restored.findings[1].status == FindingStatus.CANDIDATE

    def test_hypothesis_confidence_bounds(self) -> None:
        """Confidence must be between 0.0 and 1.0."""
        with pytest.raises(Exception):
            Hypothesis(
                vuln_type="test",
                attack_surface="test",
                exploit_idea="test",
                confidence=1.5,
            )

    def test_finding_default_values(self) -> None:
        """Finding should have sensible defaults."""
        f = Finding(title="Test finding")
        assert f.severity == Severity.MEDIUM
        assert f.status == FindingStatus.CANDIDATE
        assert f.confidence == 0.5
        assert f.evidence == []
        assert f.reproduction_steps == []
        assert f.references == []
        assert f.id is not None and len(f.id) == 12
