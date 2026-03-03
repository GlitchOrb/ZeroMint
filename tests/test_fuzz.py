"""Tests for STEP 6 — Fuzzing/Test Generator.

Covers:
  1. Python test generation for various vuln types
  2. Generated tests are valid Python (compile check)
  3. Safety checks block network patterns
  4. Harness generation for C/C++ targets
  5. Self-correction loop (dry-run mode)
  6. Integration: generate-tests from sample fixtures
  7. Generated tests actually run via pytest
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from cve_agent.fuzz.test_generator import (
    _safety_check,
    generate_python_test,
    generate_tests_for_findings,
)
from cve_agent.fuzz.harness_generator import (
    generate_build_script,
    generate_harness_for_finding,
    generate_libfuzzer_harness,
)
from cve_agent.fuzz.self_correction import (
    _parse_pytest_summary,
    generate_correction_instruction,
    run_all_tests,
    save_fuzz_attempts,
    self_correction_loop,
)
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


def _make_finding(
    vuln_type: str = "code_injection",
    file: str = "auth_handler.py",
    line: int = 15,
    fid: str = "test123abc00",
) -> Finding:
    return Finding(
        id=fid,
        title=f"[test] {vuln_type} in {file}",
        severity=Severity.HIGH,
        confidence=0.6,
        status=FindingStatus.CANDIDATE,
        hypothesis=Hypothesis(
            vuln_type=vuln_type,
            attack_surface=f"{vuln_type} pattern",
            preconditions=["Attacker controls input"],
            exploit_idea="Supply crafted input",
            confidence=0.3,
            related_sinks=["eval"],
            related_sources=["user_input"],
            self_critique="Offline analysis only",
        ),
        evidence=[
            EvidenceItem(
                kind=EvidenceKind.TOOL_OUTPUT,
                summary=f"Test {vuln_type}",
                location=CodeLocation(file=file, start_line=line, end_line=line),
            ),
        ],
    )


# ── Python test generation ────────────────────────────────


class TestPythonTestGeneration:
    """Test Python test file generation."""

    @pytest.mark.parametrize("vuln_type", [
        "code_injection",
        "sql_injection",
        "command_injection",
        "insecure_deserialization",
        "path_traversal",
        "cross_site_scripting",
        "broken_authentication",
        "buffer_overflow",
        "unknown",
    ])
    def test_generates_for_all_vuln_types(self, vuln_type: str) -> None:
        """Should generate valid Python for every vuln type."""
        finding = _make_finding(vuln_type=vuln_type)
        code = generate_python_test(finding)
        assert code != ""
        # Must compile without SyntaxError
        compile(code, f"test_{vuln_type}.py", "exec")

    def test_no_hypothesis_returns_empty(self) -> None:
        finding = Finding(
            id="nohyp123",
            title="No hypothesis",
            severity=Severity.LOW,
        )
        assert generate_python_test(finding) == ""

    def test_contains_test_class(self) -> None:
        finding = _make_finding()
        code = generate_python_test(finding)
        assert "class TestFinding_" in code

    def test_contains_pytest_import(self) -> None:
        finding = _make_finding()
        code = generate_python_test(finding)
        assert "import pytest" in code

    def test_contains_parametrize(self) -> None:
        finding = _make_finding()
        code = generate_python_test(finding)
        assert "@pytest.mark.parametrize" in code

    def test_contains_null_byte_test(self) -> None:
        finding = _make_finding()
        code = generate_python_test(finding)
        assert "test_null_byte" in code

    def test_contains_unicode_test(self) -> None:
        finding = _make_finding()
        code = generate_python_test(finding)
        assert "test_unicode_edge_cases" in code

    def test_contains_extreme_length_test(self) -> None:
        finding = _make_finding()
        code = generate_python_test(finding)
        assert "test_extreme_length" in code

    def test_contains_warning_header(self) -> None:
        finding = _make_finding()
        code = generate_python_test(finding)
        assert "VERIFICATION test" in code
        assert "not an exploit" in code


# ── Safety checks ─────────────────────────────────────────


class TestSafetyCheck:
    """Test that generated code is safe."""

    def test_clean_code_passes(self) -> None:
        assert _safety_check("def test_foo(): pass") is True

    def test_blocks_requests(self) -> None:
        assert _safety_check("import requests\nrequests.get('http://evil')") is False

    def test_blocks_urllib(self) -> None:
        assert _safety_check("urllib.request.urlopen('http://x')") is False

    def test_blocks_subprocess_call(self) -> None:
        assert _safety_check("subprocess.call('rm -rf /')") is False

    def test_blocks_socket(self) -> None:
        assert _safety_check("socket.connect(('evil.com', 80))") is False


# ── Harness generation ────────────────────────────────────


class TestHarnessGeneration:
    """Test C/C++ harness generation."""

    def test_generates_libfuzzer_harness(self) -> None:
        finding = _make_finding(file="vuln.c")
        code = generate_libfuzzer_harness(finding)
        assert "LLVMFuzzerTestOneInput" in code
        assert "malloc" in code
        assert "free" in code

    def test_no_hypothesis_returns_empty(self) -> None:
        finding = Finding(id="noh", title="No hyp", severity=Severity.LOW)
        assert generate_libfuzzer_harness(finding) == ""

    def test_makefile_script(self) -> None:
        script = generate_build_script("abc123", "harness.c", use_cmake=False)
        assert "clang" in script
        assert "-fsanitize=fuzzer" in script

    def test_cmake_script(self) -> None:
        script = generate_build_script("abc123", "harness.c", use_cmake=True)
        assert "cmake_minimum_required" in script
        assert "fsanitize" in script

    def test_generate_for_c_finding(self, tmp_path: Path) -> None:
        finding = _make_finding(vuln_type="buffer_overflow", file="vuln.c")
        result = generate_harness_for_finding(finding, tmp_path)
        assert result is not None
        assert result["language"] == "c_cpp"
        assert (tmp_path / "harnesses" / finding.id / "harness.c").exists()
        assert (tmp_path / "harnesses" / finding.id / "Makefile").exists()

    def test_skip_non_c_finding(self, tmp_path: Path) -> None:
        finding = _make_finding(file="handler.py")
        result = generate_harness_for_finding(finding, tmp_path)
        assert result is None


# ── Self-correction ───────────────────────────────────────


class TestSelfCorrection:
    """Test self-correction loop."""

    def test_parse_summary_passed(self) -> None:
        output = "5 passed in 0.12s"
        passed, failed, errors = _parse_pytest_summary(output)
        assert passed == 5
        assert failed == 0

    def test_parse_summary_mixed(self) -> None:
        output = "3 passed, 2 failed, 1 error"
        passed, failed, errors = _parse_pytest_summary(output)
        assert passed == 3
        assert failed == 2
        assert errors == 1

    def test_parse_summary_empty(self) -> None:
        passed, failed, errors = _parse_pytest_summary("")
        assert passed == 0
        assert failed == 0

    def test_correction_instruction(self) -> None:
        instruction = generate_correction_instruction(
            Path("test_foo.py"),
            ["ImportError: No module named 'foo'"],
            1,
        )
        assert "iteration 1" in instruction
        assert "import" in instruction.lower()

    def test_dry_run_mode(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test_dummy.py"
        test_file.write_text("def test_ok(): pass", encoding="utf-8")

        attempt = {
            "finding_id": "abc",
            "test_file": str(test_file),
            "status": "generated",
            "iterations": 0,
            "errors": [],
        }
        result = self_correction_loop(test_file, attempt, dry_run=True)
        assert result["status"] == "dry_run"
        assert result["iterations"] == 0

    def test_save_fuzz_attempts(self, tmp_path: Path) -> None:
        attempts = [
            {"finding_id": "a", "status": "verified"},
            {"finding_id": "b", "status": "failed"},
        ]
        path = save_fuzz_attempts(attempts, tmp_path)
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data) == 2


# ── Integration ───────────────────────────────────────────


class TestIntegration:
    """Integration tests for the full test generation flow."""

    def test_generate_tests_for_findings(self, tmp_path: Path) -> None:
        """Generate test files from findings."""
        findings = [
            _make_finding("code_injection", fid="ci_001"),
            _make_finding("sql_injection", fid="sq_001"),
            _make_finding("path_traversal", fid="pt_001"),
        ]
        attempts = generate_tests_for_findings(findings, tmp_path)
        assert len(attempts) == 3

        for a in attempts:
            assert a["status"] == "generated"
            test_path = tmp_path / a["test_file"]
            assert test_path.exists()
            # Verify it compiles
            code = test_path.read_text(encoding="utf-8")
            compile(code, str(test_path), "exec")

    def test_dry_run_all(self, tmp_path: Path) -> None:
        """Dry-run should not execute tests."""
        findings = [_make_finding("code_injection", fid="dr_001")]
        attempts = generate_tests_for_findings(findings, tmp_path)
        updated = run_all_tests(attempts, tmp_path, dry_run=True)
        assert all(a["status"] == "dry_run" for a in updated)

    def test_generated_test_runs_successfully(self, tmp_path: Path) -> None:
        """At least one generated test should actually pass when executed."""
        finding = _make_finding("code_injection", fid="run_001")
        attempts = generate_tests_for_findings([finding], tmp_path)
        assert len(attempts) == 1

        test_path = tmp_path / attempts[0]["test_file"]
        assert test_path.exists()

        # Actually run it via pytest subprocess
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_path), "-v", "--tb=short", "-q"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Should have at least some passed tests
        assert "passed" in result.stdout or result.returncode == 0

    def test_fuzz_attempts_json_structure(self, tmp_path: Path) -> None:
        """fuzz_attempts.json should have correct structure."""
        findings = [
            _make_finding("code_injection", fid="fa_001"),
            _make_finding("sql_injection", fid="fa_002"),
        ]
        attempts = generate_tests_for_findings(findings, tmp_path)
        path = save_fuzz_attempts(attempts, tmp_path)

        data = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        for item in data:
            assert "finding_id" in item
            assert "test_file" in item
            assert "vuln_type" in item
            assert "status" in item
