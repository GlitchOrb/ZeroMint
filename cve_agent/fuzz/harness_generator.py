"""Harness generator — produces libFuzzer harness templates for C/C++ targets.

Optional module: only used when target language is C/C++.
Generates:
  - A minimal LLVMFuzzerTestOneInput harness
  - A build script (CMake or plain Makefile)
"""

from __future__ import annotations

import logging
import textwrap
from pathlib import Path
from typing import Any

from cve_agent.schemas.findings import Finding, Hypothesis

logger = logging.getLogger("cve_agent.fuzz.harness_generator")


def generate_libfuzzer_harness(
    finding: Finding,
    *,
    target_function: str | None = None,
    target_header: str | None = None,
) -> str:
    """Generate a libFuzzer harness for a C/C++ target.

    Returns:
        C source code as a string.
    """
    hyp = finding.hypothesis
    if not hyp:
        return ""

    func = target_function or "target_function"
    header = target_header or "target.h"

    code = textwrap.dedent(f"""\
        /*
         * Auto-generated libFuzzer harness for finding {finding.id}
         *
         * Hypothesis: {hyp.vuln_type}
         * Attack Surface: {hyp.attack_surface}
         *
         * WARNING: Verification harness — not an exploit.
         *          Runs locally only. No network calls.
         */

        #include <stdint.h>
        #include <stddef.h>
        #include <string.h>
        #include <stdlib.h>

        /* Include target header if available */
        /* #include "{header}" */

        int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
            /* Safety: limit input size */
            if (size > 65536) return 0;

            /* Create null-terminated copy for string functions */
            char *buf = (char *)malloc(size + 1);
            if (!buf) return 0;
            memcpy(buf, data, size);
            buf[size] = '\\0';

            /*
             * TODO: Replace with actual call to {func}()
             *
             * Example:
             *   {func}(buf, size);
             *
             * Sinks to test: {', '.join(hyp.related_sinks[:3]) or 'N/A'}
             */

            free(buf);
            return 0;
        }}
    """)
    return code


def generate_build_script(
    finding_id: str,
    harness_path: str,
    *,
    use_cmake: bool = False,
) -> str:
    """Generate a minimal build script for the harness.

    Args:
        finding_id: Finding ID for filenames.
        harness_path: Path to the harness .c file.
        use_cmake: If True, generate CMakeLists.txt; else Makefile.

    Returns:
        Build script content as a string.
    """
    if use_cmake:
        return textwrap.dedent(f"""\
            # Auto-generated CMakeLists.txt for finding {finding_id}
            cmake_minimum_required(VERSION 3.14)
            project(fuzz_{finding_id} C)

            add_executable(fuzz_{finding_id} {harness_path})
            target_compile_options(fuzz_{finding_id} PRIVATE -fsanitize=fuzzer,address)
            target_link_options(fuzz_{finding_id} PRIVATE -fsanitize=fuzzer,address)
        """)
    else:
        return textwrap.dedent(f"""\
            # Auto-generated Makefile for finding {finding_id}
            CC = clang
            CFLAGS = -fsanitize=fuzzer,address -g -O1
            TARGET = fuzz_{finding_id}

            all: $(TARGET)

            $(TARGET): {harness_path}
            \t$(CC) $(CFLAGS) -o $@ $<

            clean:
            \trm -f $(TARGET)

            .PHONY: all clean
        """)


def generate_harness_for_finding(
    finding: Finding,
    output_dir: Path,
) -> dict[str, Any] | None:
    """Generate a complete harness directory for a C/C++ finding.

    Creates:
      artifacts/harnesses/<finding_id>/harness.c
      artifacts/harnesses/<finding_id>/Makefile (or CMakeLists.txt)

    Returns:
        Attempt record dict, or None if not applicable.
    """
    if not finding.hypothesis:
        return None

    # Check if C/C++ target
    lang = _guess_lang(finding)
    if lang != "c_cpp":
        return None

    harness_dir = output_dir / "harnesses" / finding.id
    harness_dir.mkdir(parents=True, exist_ok=True)

    # Determine target info
    target_func = None
    target_header = None
    if finding.evidence and finding.evidence[0].location:
        target_func = finding.evidence[0].location.symbol
        target_header = finding.evidence[0].location.file

    # Generate harness
    harness_code = generate_libfuzzer_harness(
        finding,
        target_function=target_func,
        target_header=target_header,
    )
    harness_path = harness_dir / "harness.c"
    harness_path.write_text(harness_code, encoding="utf-8")

    # Detect CMake
    use_cmake = (output_dir.parent / "CMakeLists.txt").exists()

    build_script = generate_build_script(
        finding.id,
        "harness.c",
        use_cmake=use_cmake,
    )
    if use_cmake:
        build_path = harness_dir / "CMakeLists.txt"
    else:
        build_path = harness_dir / "Makefile"
    build_path.write_text(build_script, encoding="utf-8")

    logger.info("[harness_gen] Generated: %s", harness_dir)

    return {
        "finding_id": finding.id,
        "harness_file": str(harness_path.relative_to(output_dir)),
        "build_file": str(build_path.relative_to(output_dir)),
        "language": "c_cpp",
        "vuln_type": finding.hypothesis.vuln_type,
        "status": "generated",
        "iterations": 0,
        "errors": [],
    }


def _guess_lang(finding: Finding) -> str:
    if finding.evidence:
        loc = finding.evidence[0].location
        if loc and loc.file:
            ext = Path(loc.file).suffix.lower()
            if ext in (".c", ".h", ".cpp", ".cxx", ".cc", ".hpp"):
                return "c_cpp"
    return "other"
