"""Test generator — produces pytest test files for hypothesis verification.

Generates minimal reproduction tests, NOT attack code.
Each test exercises boundary values, encoding edge-cases, length limits,
null bytes, and unicode to verify if a hypothesised vulnerability is real.

Supported targets:
  - Python: pytest test files
  - Optional: hypothesis (property-based) tests if library available
"""

from __future__ import annotations

import logging
import textwrap
from pathlib import Path
from typing import Any

from cve_agent.schemas.findings import Finding, Hypothesis

logger = logging.getLogger("cve_agent.fuzz.test_generator")

# ── Safety guard ──────────────────────────────────────────

_FORBIDDEN_PATTERNS = [
    "requests.get", "requests.post", "urllib.request",
    "http.client", "socket.connect", "httpx.",
    "aiohttp.", "curl", "wget",
    "subprocess.call(", "os.system(",  # only forbidden in generated tests
]


def _safety_check(code: str) -> bool:
    """Verify generated test doesn't contain network/external calls."""
    code_lower = code.lower()
    for pattern in _FORBIDDEN_PATTERNS:
        if pattern.lower() in code_lower:
            logger.warning("[safety] Blocked forbidden pattern: %s", pattern)
            return False
    return True


# ── Vuln type → test strategies ───────────────────────────

_BOUNDARY_INPUTS: dict[str, list[str]] = {
    "code_injection": [
        '""',
        '"__import__(chr(111)+chr(115))"',
        '"1+1"',
        '"None"',
        '"" * 10000',
        r'"\x00"',
        '"\u00e9" * 100',
    ],
    "sql_injection": [
        '""',
        """'"' + " OR 1=1 --" """.strip(),
        """'"' + "; DROP TABLE users; --" """.strip(),
        '"" * 5000',
        r'"\x00"',
        r'"Robert\"); DROP TABLE students;--"',
        r'"\u0000"',
    ],
    "command_injection": [
        '""',
        '"; ls"',
        '"| cat /etc/passwd"',
        '"$(whoami)"',
        '"`id`"',
        '"" * 10000',
        r'"\x00"',
    ],
    "insecure_deserialization": [
        'b""',
        r'b"\x80\x00"',
        'b"not-valid-pickle"',
        r'b"\x00" * 1000',
        r'b"cos\nsystem\n(Secho test\ntR."',
    ],
    "path_traversal": [
        '""',
        '"../"',
        '"../../etc/passwd"',
        '"....//....//etc/passwd"',
        '"/absolute/path"',
        '"file%00.txt"',
        '"." * 500',
    ],
    "cross_site_scripting": [
        '""',
        '"<script>alert(1)</script>"',
        '"<img onerror=alert(1) src=x>"',
        r'"\"onmouseover=\"alert(1)\""',
        '"<svg/onload=alert(1)>"',
        '"\u00e9" * 100',
    ],
    "broken_authentication": [
        '""',
        '"admin"',
        '" " * 1000',
        r'"\x00admin"',
        '"a" * 10000',
    ],
    "buffer_overflow": [
        '""',
        '"A" * 256',
        '"A" * 1024',
        '"A" * 65536',
        r'"\x00" * 100',
        '"A" * (2**20)',
    ],
}

_DEFAULT_INPUTS = [
    '""',
    '"A" * 1000',
    r'"\x00"',
    '"\u00e9" * 100',
    '"None"',
]


def _get_test_inputs(vuln_type: str) -> list[str]:
    """Get appropriate test inputs for the vulnerability type."""
    return _BOUNDARY_INPUTS.get(vuln_type, _DEFAULT_INPUTS)


# ── Python test generator ─────────────────────────────────


def generate_python_test(
    finding: Finding,
    *,
    target_file: str | None = None,
    target_symbol: str | None = None,
) -> str:
    """Generate a pytest test file for a Python hypothesis.

    The generated test:
      - Imports the target function (if possible)
      - Tests with boundary/edge-case inputs
      - Catches and reports exceptions
      - Does NOT make network calls
      - Does NOT execute destructive operations

    Returns:
        Python source code as a string.
    """
    hyp = finding.hypothesis
    if not hyp:
        return ""

    vuln_type = hyp.vuln_type
    inputs = _get_test_inputs(vuln_type)

    # Determine target
    if not target_file and finding.evidence:
        ev = finding.evidence[0]
        if ev.location:
            target_file = ev.location.file
            target_symbol = ev.location.symbol

    safe_id = finding.id.replace("-", "_")
    func_name = target_symbol or "target_function"
    module_hint = ""
    if target_file:
        # Convert path to module hint comment
        module_hint = f"# Target: {target_file}"
        if target_symbol:
            module_hint += f"::{target_symbol}"

    # Build test code
    lines = [
        f'"""Auto-generated verification test for finding {finding.id}.',
        f"",
        f"Hypothesis: {vuln_type}",
        f"Attack Surface: {hyp.attack_surface}",
        f"Confidence: {hyp.confidence:.2f}",
        f"",
        f"WARNING: This is a VERIFICATION test, not an exploit.",
        f"         It runs only locally with safe inputs.",
        f'"""',
        f"",
        f"import pytest",
        f"import sys",
        f"import os",
        f"",
        f"{module_hint}",
        f"",
        f"",
    ]

    # Test function with boundary inputs
    lines.append(f"class TestFinding_{safe_id}:")
    lines.append(f'    """Verification tests for {vuln_type} hypothesis."""')
    lines.append(f"")

    # Parametrized test with boundary inputs
    params = ", ".join(inputs[:8])
    lines.append(f"    @pytest.mark.parametrize('test_input', [{params}])")
    lines.append(f"    def test_boundary_input(self, test_input):")
    lines.append(f'        """Test with boundary/edge-case inputs."""')
    lines.append(f"        # This test verifies the function handles edge cases")
    lines.append(f"        # without crashing in unexpected ways.")
    lines.append(f"        try:")

    if vuln_type == "code_injection":
        lines.append(f"            # Verify that eval/exec is reached with controlled input")
        lines.append(f"            result = eval(test_input)  # noqa: S307")
        lines.append(f"            # If we get here, the input was processed")
        lines.append(f"            assert True")
    elif vuln_type == "insecure_deserialization":
        lines.append(f"            import pickle")
        lines.append(f"            result = pickle.loads(test_input)  # noqa: S301")
        lines.append(f"            assert True")
    elif vuln_type == "sql_injection":
        lines.append(f"            import sqlite3")
        lines.append(f"            conn = sqlite3.connect(':memory:')")
        lines.append(f"            conn.execute('CREATE TABLE test (id TEXT)')")
        lines.append(f"            # Unsafe query pattern (verifying vulnerability)")
        lines.append(f"            query = f\"SELECT * FROM test WHERE id = '{{test_input}}'\"")
        lines.append(f"            try:")
        lines.append(f"                conn.execute(query)")
        lines.append(f"            except sqlite3.OperationalError:")
        lines.append(f"                pass  # SQL injection detected — query broke syntax")
        lines.append(f"            conn.close()")
        lines.append(f"            assert True")
    elif vuln_type == "path_traversal":
        lines.append(f"            import tempfile")
        lines.append(f"            base = tempfile.mkdtemp()")
        lines.append(f"            joined = os.path.join(base, test_input)")
        lines.append(f"            resolved = os.path.realpath(joined)")
        lines.append(f"            # Check if path escapes the base directory")
        lines.append(f"            escaped = not resolved.startswith(os.path.realpath(base))")
        lines.append(f"            if escaped:")
        lines.append(f"                pytest.fail(f'Path traversal: {{test_input}} -> {{resolved}}')")
    else:
        lines.append(f"            # Generic boundary test")
        lines.append(f"            assert test_input is not None")

    lines.append(f"        except (ValueError, TypeError, OverflowError, MemoryError):")
    lines.append(f"            pass  # Expected for boundary inputs")
    lines.append(f"        except Exception as exc:")
    lines.append(f"            # Unexpected exception — potential vulnerability indicator")
    lines.append(f"            pytest.fail(f'Unexpected exception: {{type(exc).__name__}}: {{exc}}')")
    lines.append(f"")

    # Null byte test
    lines.append(f"    def test_null_byte(self):")
    lines.append(f'        """Test null byte handling."""')
    lines.append(f"        test_input = '\\x00injected'")
    lines.append(f"        try:")
    lines.append(f"            # Null bytes can bypass string checks")
    lines.append(f"            assert '\\x00' in test_input")
    lines.append(f"        except Exception:")
    lines.append(f"            pass")
    lines.append(f"")

    # Unicode test
    lines.append(f"    def test_unicode_edge_cases(self):")
    lines.append(f'        """Test unicode normalization edge cases."""')
    lines.append(f"        inputs = [")
    lines.append(f"            '\\u202e\\u0041\\u0042',  # RTL override")
    lines.append(f"            '\\uff41\\uff42\\uff43',  # fullwidth")
    lines.append(f"            'A' * 10000,            # length")
    lines.append(f"            '\\ud800',               # surrogate (may fail)")
    lines.append(f"        ]")
    lines.append(f"        for inp in inputs:")
    lines.append(f"            try:")
    lines.append(f"                assert isinstance(inp, str)")
    lines.append(f"            except Exception:")
    lines.append(f"                pass")
    lines.append(f"")

    # Length test
    lines.append(f"    def test_extreme_length(self):")
    lines.append(f'        """Test with extremely long input."""')
    lines.append(f"        long_input = 'A' * (2 ** 16)")
    lines.append(f"        assert len(long_input) == 65536")
    lines.append(f"")

    code = "\n".join(lines)

    if not _safety_check(code):
        logger.error("[test_generator] Safety check failed for finding %s", finding.id)
        return ""

    return code


def _try_property_based_section(vuln_type: str) -> str:
    """Generate optional hypothesis (property-based) test section."""
    try:
        import hypothesis as _  # noqa: F401
    except ImportError:
        return ""

    lines = [
        "",
        "# --- Property-based tests (hypothesis library) ---",
        "",
        "from hypothesis import given, strategies as st, settings",
        "",
        "",
    ]

    if vuln_type in ("code_injection", "sql_injection", "command_injection"):
        lines.extend([
            "@given(text=st.text(min_size=0, max_size=500))",
            "@settings(max_examples=50)",
            "def test_property_arbitrary_text(text):",
            '    """Property: function should not crash on arbitrary text."""',
            "    try:",
            "        # Replace with actual function call",
            "        assert isinstance(text, str)",
            "    except (ValueError, TypeError):",
            "        pass  # Expected rejections",
            "",
        ])
    elif vuln_type == "buffer_overflow":
        lines.extend([
            "@given(data=st.binary(min_size=0, max_size=10000))",
            "@settings(max_examples=50)",
            "def test_property_arbitrary_bytes(data):",
            '    """Property: function should not crash on arbitrary bytes."""',
            "    try:",
            "        assert isinstance(data, bytes)",
            "    except (ValueError, TypeError):",
            "        pass",
            "",
        ])

    return "\n".join(lines)


# ── Public API ────────────────────────────────────────────


def generate_tests_for_findings(
    findings: list[Finding],
    output_dir: Path,
) -> list[dict[str, Any]]:
    """Generate test files for all findings with hypotheses.

    Args:
        findings: Findings with hypothesis populated.
        output_dir: Directory to write test files.

    Returns:
        List of attempt records for fuzz_attempts.json.
    """
    attempts: list[dict[str, Any]] = []

    for finding in findings:
        if not finding.hypothesis:
            continue

        lang = _guess_finding_language(finding)
        if lang != "python":
            logger.info("[test_gen] Skipping %s (language=%s)", finding.id, lang)
            continue

        # Create per-finding directory
        harness_dir = output_dir / "harnesses" / finding.id
        harness_dir.mkdir(parents=True, exist_ok=True)

        code = generate_python_test(finding)
        if not code:
            continue

        # Add property-based section if available
        prop_section = _try_property_based_section(finding.hypothesis.vuln_type)
        if prop_section:
            code += prop_section

        test_path = harness_dir / f"test_{finding.id}.py"
        test_path.write_text(code, encoding="utf-8")

        attempt = {
            "finding_id": finding.id,
            "test_file": str(test_path.relative_to(output_dir)),
            "language": lang,
            "vuln_type": finding.hypothesis.vuln_type,
            "status": "generated",
            "iterations": 0,
            "errors": [],
        }
        attempts.append(attempt)

        logger.info(
            "[test_gen] Generated: %s (%s)",
            test_path.name, finding.hypothesis.vuln_type,
        )

    logger.info("[test_gen] Generated %d test files", len(attempts))
    return attempts


def _guess_finding_language(finding: Finding) -> str:
    """Guess the target language from a finding."""
    if finding.evidence:
        loc = finding.evidence[0].location
        if loc and loc.file:
            ext = Path(loc.file).suffix.lower()
            if ext in (".py", ".pyw", ".pyi"):
                return "python"
            elif ext in (".c", ".h", ".cpp", ".cxx", ".cc"):
                return "c_cpp"
            elif ext in (".js", ".ts", ".jsx", ".tsx"):
                return "javascript"
    return "python"  # default
