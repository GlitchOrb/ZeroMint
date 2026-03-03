"""Tree-sitter based code parser — extracts functions/classes from source files.

Supports:
  - Python  (via tree-sitter-python)
  - JavaScript / TypeScript  (via tree-sitter-javascript)

Gracefully degrades if a language grammar is not installed.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from cve_agent.graph.code_units import CodeUnit
from cve_agent.schemas.findings import CodeLocation

logger = logging.getLogger("cve_agent.graph.code_parser")

# ── Language registry ─────────────────────────────────────

# Maps extension → (grammar_module, tree-sitter Language, node types)
_PARSERS: dict[str, Any] = {}
_INIT_DONE = False


def _get_ts_language(module_name: str) -> Any:
    """Import a tree-sitter language module and return its Language object."""
    try:
        import tree_sitter as ts
        mod = __import__(module_name)
        # tree-sitter >= 0.22: language() returns PyCapsule, wrap in Language
        if hasattr(mod, "language"):
            capsule = mod.language()
            return ts.Language(capsule)
        return None
    except ImportError:
        return None
    except Exception as exc:
        logger.debug("Failed to load %s: %s", module_name, exc)
        return None


def _ensure_parsers() -> None:
    """Lazy-initialise tree-sitter parsers for each supported language."""
    global _INIT_DONE
    if _INIT_DONE:
        return
    _INIT_DONE = True

    try:
        import tree_sitter as ts
    except ImportError:
        logger.warning("tree-sitter not installed — code parsing disabled")
        return

    # Python
    py_lang = _get_ts_language("tree_sitter_python")
    if py_lang:
        parser = ts.Parser(py_lang)
        _PARSERS["python"] = {
            "parser": parser,
            "lang": py_lang,
            "func_types": {"function_definition"},
            "class_types": {"class_definition"},
            "call_types": {"call", "attribute"},
        }
        logger.debug("Python parser initialised")

    # JavaScript (also covers light TypeScript)
    js_lang = _get_ts_language("tree_sitter_javascript")
    if js_lang:
        parser = ts.Parser(js_lang)
        _PARSERS["javascript"] = {
            "parser": parser,
            "lang": js_lang,
            "func_types": {
                "function_declaration",
                "arrow_function",
                "method_definition",
                "function",
            },
            "class_types": {"class_declaration"},
            "call_types": {"call_expression"},
        }
        logger.debug("JavaScript parser initialised")


# ── Extension → language mapping ──────────────────────────

_EXT_LANG: dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",   # light TS parse via JS grammar
    ".tsx": "javascript",
}


def language_for_file(path: Path) -> str | None:
    """Return the parser language key for a file, or None if unsupported."""
    return _EXT_LANG.get(path.suffix.lower())


# ── Extraction helpers ────────────────────────────────────


def _signature_python(node: Any, source: bytes) -> str:
    """Extract a Python function/class signature."""
    # function_definition → first child 'def', name, parameters
    text = node.text.decode("utf-8", errors="replace")
    lines = text.split("\n")
    # Signature = first line (possibly multiline params, truncated)
    sig = lines[0].rstrip()
    if sig.endswith(":"):
        return sig
    # Collect until we find ':'
    for line in lines[1:]:
        sig += " " + line.strip()
        if sig.rstrip().endswith(":"):
            break
    return sig.rstrip()


def _signature_js(node: Any, source: bytes) -> str:
    """Extract a JavaScript function signature."""
    text = node.text.decode("utf-8", errors="replace")
    first_line = text.split("\n")[0].rstrip()
    # Truncate body
    if "{" in first_line:
        return first_line[: first_line.index("{")].rstrip()
    return first_line


def _extract_call_names_python(node: Any, source: bytes) -> list[str]:
    """Extract called function names from a Python function body."""
    calls: list[str] = []

    def _walk(n: Any) -> None:
        if n.type == "call":
            func_node = n.child_by_field_name("function")
            if func_node:
                call_text = func_node.text.decode("utf-8", errors="replace")
                # Normalise: take last segment for attribute calls
                # e.g. "os.path.join" → "os.path.join" (keep full)
                calls.append(call_text)
        for child in n.children:
            _walk(child)

    _walk(node)
    return calls


def _extract_call_names_js(node: Any, source: bytes) -> list[str]:
    """Extract called function names from a JS function body."""
    calls: list[str] = []

    def _walk(n: Any) -> None:
        if n.type == "call_expression":
            func_node = n.child_by_field_name("function")
            if func_node:
                call_text = func_node.text.decode("utf-8", errors="replace")
                calls.append(call_text)
        for child in n.children:
            _walk(child)

    _walk(node)
    return calls


# ── Public API ────────────────────────────────────────────


def parse_file(
    file_path: Path,
    *,
    rel_to: Path | None = None,
) -> tuple[list[CodeUnit], list[tuple[str, str]]]:
    """Parse a source file and extract code units + raw call edges.

    Args:
        file_path: Absolute path to the source file.
        rel_to: Base directory for relative paths in CodeLocation.

    Returns:
        (code_units, call_edges)
        where call_edges = [(from_unit_id, to_symbol), ...]
    """
    _ensure_parsers()

    lang = language_for_file(file_path)
    if lang is None or lang not in _PARSERS:
        return [], []

    pinfo = _PARSERS[lang]
    parser = pinfo["parser"]
    func_types = pinfo["func_types"]
    class_types = pinfo["class_types"]

    try:
        source = file_path.read_bytes()
    except OSError as e:
        logger.debug("Cannot read %s: %s", file_path, e)
        return [], []

    tree = parser.parse(source)
    root = tree.root_node

    rel_path = str(file_path.relative_to(rel_to)) if rel_to else str(file_path)

    units: list[CodeUnit] = []
    edges: list[tuple[str, str]] = []

    def _process_node(node: Any, parent_name: str = "") -> None:
        """Recursively walk AST, extract functions/classes."""
        ntype = node.type

        if ntype in func_types or ntype in class_types:
            # Get name
            name_node = node.child_by_field_name("name")
            if name_node:
                name = name_node.text.decode("utf-8", errors="replace")
            else:
                # Arrow functions / anonymous — use line number
                name = f"<anonymous@L{node.start_point[0] + 1}>"

            full_name = f"{parent_name}.{name}" if parent_name else name
            unit_id = f"{rel_path}::{full_name}"

            # Extract signature
            if lang == "python":
                sig = _signature_python(node, source)
            else:
                sig = _signature_js(node, source)

            text = node.text.decode("utf-8", errors="replace")
            tokens_est = max(1, len(text) // 4)

            location = CodeLocation(
                file=rel_path,
                start_line=node.start_point[0] + 1,  # 1-indexed
                end_line=node.end_point[0] + 1,
                symbol=full_name,
            )

            unit = CodeUnit(
                unit_id=unit_id,
                language=lang,
                location=location,
                signature=sig,
                text=text,
                tokens_estimate=tokens_est,
            )
            units.append(unit)

            # Extract calls inside this function
            if ntype in func_types:
                if lang == "python":
                    call_names = _extract_call_names_python(node, source)
                else:
                    call_names = _extract_call_names_js(node, source)

                for callee in call_names:
                    edges.append((unit_id, callee))

            # Recurse for nested definitions (classes with methods)
            for child in node.children:
                _process_node(child, parent_name=full_name)
            return  # Don't recurse children again below

        # Default: recurse
        for child in node.children:
            _process_node(child, parent_name=parent_name)

    _process_node(root)
    return units, edges


def is_parseable(file_path: Path) -> bool:
    """Check if we have a parser for this file type."""
    _ensure_parsers()
    lang = language_for_file(file_path)
    return lang is not None and lang in _PARSERS
