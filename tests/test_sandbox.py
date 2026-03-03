"""Tests for STEP 7 — Docker Sandbox & Validation Runner.

Covers:
  1. Docker command construction (network, cpu, mem, mounts)
  2. Dry-run mode produces valid SandboxResult
  3. ValidationOutcome and ValidationResults schemas
  4. Sanitizer flag injection (Makefile / CMake)
  5. Sanitizer output parsing
  6. Execution runner with dry-run (no Docker required)
  7. Evidence creation from outcomes
  8. Save/load validation_results.json roundtrip
  9. Integration: full pipeline dry-run produces validation_results.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cve_agent.sandbox.docker_runner import (
    SandboxResult,
    build_docker_command,
    is_docker_available,
    run_in_sandbox,
)
from cve_agent.analyzers.execution import (
    ValidationOutcome,
    ValidationResults,
    create_evidence_from_outcome,
    execute_validations,
    inject_sanitizer_flags,
    parse_sanitizer_output,
    save_validation_results,
)
from cve_agent.schemas.config import FeaturesConfig, SandboxConfig
from cve_agent.schemas.findings import EvidenceKind


# ── Docker command construction ───────────────────────────


class TestDockerCommand:
    """Test Docker command building."""

    def test_network_off(self) -> None:
        cfg = SandboxConfig(network_off=True)
        cmd = build_docker_command(["echo", "test"], sandbox_cfg=cfg)
        assert "--network=none" in cmd

    def test_network_on(self) -> None:
        cfg = SandboxConfig(network_off=False)
        cmd = build_docker_command(["echo", "test"], sandbox_cfg=cfg)
        assert "--network=none" not in cmd

    def test_cpu_limit(self) -> None:
        cfg = SandboxConfig(cpu=0.5)
        cmd = build_docker_command(["echo"], sandbox_cfg=cfg)
        idx = cmd.index("--cpus")
        assert cmd[idx + 1] == "0.5"

    def test_mem_limit(self) -> None:
        cfg = SandboxConfig(mem_mb=256)
        cmd = build_docker_command(["echo"], sandbox_cfg=cfg)
        idx = cmd.index("--memory")
        assert cmd[idx + 1] == "256m"

    def test_repo_readonly_mount(self, tmp_path: Path) -> None:
        cfg = SandboxConfig()
        cmd = build_docker_command(
            ["pytest"], sandbox_cfg=cfg, repo_dir=tmp_path,
        )
        mount_args = [a for a in cmd if ":ro" in a]
        assert len(mount_args) == 1, "Repo should be mounted read-only"

    def test_work_dir_mount(self, tmp_path: Path) -> None:
        cfg = SandboxConfig()
        cmd = build_docker_command(
            ["pytest"], sandbox_cfg=cfg, work_dir=tmp_path,
        )
        mount_args = [a for a in cmd if ":rw" in a]
        assert len(mount_args) == 1, "Work dir should be mounted read-write"

    def test_security_options(self) -> None:
        cfg = SandboxConfig()
        cmd = build_docker_command(["echo"], sandbox_cfg=cfg)
        assert "--cap-drop=ALL" in cmd
        assert "no-new-privileges" in " ".join(cmd)

    def test_command_at_end(self) -> None:
        cfg = SandboxConfig()
        cmd = build_docker_command(["python", "-m", "pytest"], sandbox_cfg=cfg)
        assert cmd[-3:] == ["python", "-m", "pytest"]

    def test_custom_image(self) -> None:
        cfg = SandboxConfig()
        cmd = build_docker_command(["echo"], sandbox_cfg=cfg, image="alpine:latest")
        assert "alpine:latest" in cmd


# ── SandboxResult ─────────────────────────────────────────


class TestSandboxResult:
    """Test SandboxResult dataclass."""

    def test_defaults(self) -> None:
        r = SandboxResult(status="success")
        assert r.exit_code == 0
        assert r.stdout == ""
        assert r.errors == []

    def test_dry_run_status(self) -> None:
        r = SandboxResult(status="dry_run")
        assert r.status == "dry_run"


# ── Dry-run sandbox execution ────────────────────────────


class TestDryRunExecution:
    """Test sandbox execution in dry-run mode."""

    def test_dry_run_returns_dry_run_status(self) -> None:
        cfg = SandboxConfig()
        result = run_in_sandbox(
            ["echo", "test"],
            sandbox_cfg=cfg,
            dry_run=True,
        )
        assert result.status == "dry_run"
        assert "Would execute" in result.stdout

    def test_dry_run_with_log_dir(self, tmp_path: Path) -> None:
        cfg = SandboxConfig()
        result = run_in_sandbox(
            ["pytest", "test.py"],
            sandbox_cfg=cfg,
            dry_run=True,
            log_dir=tmp_path / "logs",
            label="test_run",
        )
        assert result.status == "dry_run"


# ── Sanitizer helpers ─────────────────────────────────────


class TestSanitizers:
    """Test sanitizer flag injection and output parsing."""

    def test_inject_asan_into_makefile(self) -> None:
        makefile = "CC = clang\nCFLAGS = -g\nTARGET = fuzz\n"
        updated = inject_sanitizer_flags(makefile)
        assert "-fsanitize=address" in updated
        assert "-fsanitize=undefined" in updated

    def test_inject_skips_existing(self) -> None:
        makefile = "CFLAGS = -fsanitize=address -fsanitize=undefined\n"
        updated = inject_sanitizer_flags(makefile)
        # Should not duplicate
        assert updated.count("-fsanitize=address") == 1

    def test_inject_into_cmake(self) -> None:
        cmake = 'target_compile_options(fuzz PRIVATE -fsanitize=fuzzer)\n'
        updated = inject_sanitizer_flags(cmake)
        assert "-fsanitize=address" in updated

    def test_parse_asan_output(self) -> None:
        output = (
            "some normal output\n"
            "==12345==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "READ of size 4 at address 0x123\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow\n"
            "more output\n"
        )
        parsed = parse_sanitizer_output(output)
        assert "AddressSanitizer" in parsed
        assert "heap-buffer-overflow" in parsed

    def test_parse_empty_output(self) -> None:
        assert parse_sanitizer_output("no sanitizer output") == ""

    def test_parse_ubsan_output(self) -> None:
        output = "runtime error: signed integer overflow\n"
        parsed = parse_sanitizer_output(output)
        assert "signed integer overflow" in parsed


# ── ValidationOutcome and ValidationResults ───────────────


class TestValidationSchemas:
    """Test validation result schemas."""

    def test_outcome_defaults(self) -> None:
        o = ValidationOutcome(finding_id="abc123")
        assert o.status == "pending"
        assert o.exit_code == 0
        assert o.errors == []

    def test_outcome_serialization(self) -> None:
        o = ValidationOutcome(
            finding_id="abc",
            test_file="test_abc.py",
            status="success",
            passed_count=5,
            failed_count=0,
        )
        data = o.model_dump()
        restored = ValidationOutcome.model_validate(data)
        assert restored.finding_id == "abc"
        assert restored.passed_count == 5

    def test_results_defaults(self) -> None:
        r = ValidationResults()
        assert r.total == 0
        assert r.outcomes == []

    def test_results_serialization(self) -> None:
        r = ValidationResults(
            total=3,
            success=1,
            failure=1,
            crash=1,
            outcomes=[
                ValidationOutcome(finding_id="a", status="success"),
                ValidationOutcome(finding_id="b", status="failure"),
                ValidationOutcome(finding_id="c", status="crash"),
            ],
        )
        json_str = r.model_dump_json()
        restored = ValidationResults.model_validate_json(json_str)
        assert restored.total == 3
        assert len(restored.outcomes) == 3


# ── Evidence creation ─────────────────────────────────────


class TestEvidenceCreation:
    """Test EvidenceItem creation from outcomes."""

    def test_success_evidence(self) -> None:
        o = ValidationOutcome(
            finding_id="abc",
            status="success",
            passed_count=5,
            duration_sec=1.2,
        )
        ev = create_evidence_from_outcome(o)
        assert ev.kind == EvidenceKind.TOOL_OUTPUT
        assert "success" in ev.summary
        assert "passed=5" in ev.summary

    def test_crash_with_sanitizer(self) -> None:
        o = ValidationOutcome(
            finding_id="xyz",
            status="crash",
            sanitizer_output="AddressSanitizer: heap-buffer-overflow",
        )
        ev = create_evidence_from_outcome(o)
        assert "SANITIZER" in ev.summary
        assert ev.snippet is not None
        assert "AddressSanitizer" in ev.snippet


# ── Execution runner (dry-run, no Docker) ─────────────────


class TestExecuteValidations:
    """Test the full execution runner with dry-run."""

    def test_no_attempts_file(self, tmp_path: Path) -> None:
        """No fuzz_attempts.json → empty results."""
        results = execute_validations(
            tmp_path,
            sandbox_cfg=SandboxConfig(),
            features_cfg=FeaturesConfig(),
            dry_run=True,
        )
        assert results.total == 0

    def test_dry_run_with_attempts(self, tmp_path: Path) -> None:
        """Dry-run should produce outcomes without executing."""
        # Create a test file and fuzz_attempts.json
        harness_dir = tmp_path / "harnesses" / "test_001"
        harness_dir.mkdir(parents=True)
        test_file = harness_dir / "test_test_001.py"
        test_file.write_text("def test_ok(): pass\n", encoding="utf-8")

        attempts = [{
            "finding_id": "test_001",
            "test_file": str(test_file.relative_to(tmp_path)),
            "language": "python",
            "vuln_type": "code_injection",
            "status": "generated",
        }]
        (tmp_path / "fuzz_attempts.json").write_text(
            json.dumps(attempts), encoding="utf-8",
        )

        results = execute_validations(
            tmp_path,
            sandbox_cfg=SandboxConfig(),
            features_cfg=FeaturesConfig(),
            dry_run=True,
        )
        assert results.total == 1
        assert results.outcomes[0].status == "dry_run"

    def test_missing_test_file(self, tmp_path: Path) -> None:
        """Missing test file → skipped."""
        attempts = [{
            "finding_id": "missing_001",
            "test_file": "nonexistent/test.py",
            "language": "python",
            "status": "generated",
        }]
        (tmp_path / "fuzz_attempts.json").write_text(
            json.dumps(attempts), encoding="utf-8",
        )

        results = execute_validations(
            tmp_path,
            sandbox_cfg=SandboxConfig(),
            features_cfg=FeaturesConfig(),
            dry_run=True,
        )
        assert results.total == 1
        assert results.outcomes[0].status == "skipped"

    def test_save_and_load_results(self, tmp_path: Path) -> None:
        """validation_results.json should roundtrip."""
        results = ValidationResults(
            total=2,
            success=1,
            failure=1,
            outcomes=[
                ValidationOutcome(finding_id="a", status="success", passed_count=3),
                ValidationOutcome(finding_id="b", status="failure", failed_count=2),
            ],
        )
        path = save_validation_results(results, tmp_path)
        assert path.exists()

        loaded = ValidationResults.model_validate_json(
            path.read_text(encoding="utf-8")
        )
        assert loaded.total == 2
        assert loaded.outcomes[0].passed_count == 3
        assert loaded.outcomes[1].failed_count == 2


# ── Integration ───────────────────────────────────────────


class TestIntegration:
    """Integration: dry-run pipeline produces validation_results.json."""

    def test_full_dry_run_pipeline(self, tmp_path: Path) -> None:
        """Full dry-run from hotspots → validation_results.json."""
        from cve_agent.analyzers.repo_indexer import HotspotIndex, HotspotItem
        from cve_agent.fuzz.test_generator import generate_tests_for_findings
        from cve_agent.fuzz.self_correction import save_fuzz_attempts
        from cve_agent.agents.hypothesis_agent import generate_hypotheses, save_hypotheses
        from cve_agent.schemas.config import RunConfig, TargetConfig

        fixtures = Path(__file__).parent / "fixtures" / "sample_repo"

        # Setup: hotspots
        hotspots = HotspotIndex(items=[
            HotspotItem(
                path="auth_handler.py",
                score=25.0,
                reasons=["code:eval", "name:auth"],
                top_matches=["eval(user_input)"],
            ),
        ])
        (tmp_path / "hotspots.json").write_text(
            hotspots.model_dump_json(indent=2), encoding="utf-8",
        )

        # Hypothesis
        config = RunConfig(
            target=TargetConfig(type="repo", path_or_url=str(fixtures)),
            features=FeaturesConfig(enable_graph=False),
        )
        hyps = generate_hypotheses(config, tmp_path)
        save_hypotheses(hyps, tmp_path)

        # Test generation
        attempts = generate_tests_for_findings(hyps, tmp_path)
        save_fuzz_attempts(attempts, tmp_path)

        # Execution (dry-run)
        results = execute_validations(
            tmp_path,
            sandbox_cfg=SandboxConfig(),
            features_cfg=FeaturesConfig(),
            dry_run=True,
        )
        save_validation_results(results, tmp_path)

        # Verify output
        out_path = tmp_path / "validation_results.json"
        assert out_path.exists()

        loaded = ValidationResults.model_validate_json(
            out_path.read_text(encoding="utf-8")
        )
        assert loaded.total >= 1
        assert all(o.status == "dry_run" for o in loaded.outcomes)
