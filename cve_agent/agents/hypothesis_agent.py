"""Hypothesis Agent — generates vulnerability hypotheses from analysis data.

Two modes:
  1. Offline (rule-based): tool results + hotspot keywords → hypothesis
     - No LLM required; conservative confidence
     - Always includes self_critique
  2. Online (LLM-assisted): retriever gathers code context, LLM produces JSON
     - JSON-only output enforced
     - Pydantic validation with up to 2 retries
     - Falls back to offline if LLM fails

Inputs:
  - hotspots.json
  - semgrep_candidates.json / codeql_candidates.json (if present)
  - code_units.json (if enable_graph)

Output:
  - artifacts/hypotheses.json  (Finding[] with hypothesis populated)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from pydantic import TypeAdapter, ValidationError

from cve_agent.agents.llm_clients.base import BaseLLMClient
from cve_agent.analyzers.repo_indexer import HotspotIndex, HotspotItem
from cve_agent.graph.code_units import CodeUnitsArtifact
from cve_agent.schemas.config import RunConfig
from cve_agent.schemas.findings import (
    CodeLocation,
    EvidenceItem,
    EvidenceKind,
    Finding,
    FindingStatus,
    Hypothesis,
    Severity,
)

logger = logging.getLogger("cve_agent.agents.hypothesis_agent")

# ── Keyword→vuln_type mapping for offline mode ────────────

_KEYWORD_VULN_MAP: dict[str, tuple[str, str]] = {
    # keyword → (vuln_type, attack_surface_description)
    "eval": ("code_injection", "eval() with user-controlled input"),
    "exec": ("code_injection", "exec() with dynamic code"),
    "compile": ("code_injection", "compile() with user string"),
    "subprocess": ("command_injection", "subprocess with shell=True"),
    "shell": ("command_injection", "shell command execution"),
    "os.system": ("command_injection", "os.system() call"),
    "popen": ("command_injection", "popen() shell execution"),
    "pickle": ("insecure_deserialization", "pickle.loads with untrusted data"),
    "deserialize": ("insecure_deserialization", "deserialization of untrusted data"),
    "yaml.load": ("insecure_deserialization", "yaml.load without SafeLoader"),
    "sql": ("sql_injection", "SQL query with string interpolation"),
    "query": ("sql_injection", "dynamic query construction"),
    "innerHTML": ("cross_site_scripting", "innerHTML assignment"),
    "document.write": ("cross_site_scripting", "document.write with user data"),
    "traversal": ("path_traversal", "file path from user input"),
    "path": ("path_traversal", "unsanitised file path"),
    "upload": ("unrestricted_upload", "file upload endpoint"),
    "redirect": ("open_redirect", "redirect with user-supplied URL"),
    "auth": ("broken_authentication", "authentication endpoint"),
    "password": ("broken_authentication", "password handling"),
    "jwt": ("broken_authentication", "JWT token handling"),
    "token": ("broken_authentication", "token-based auth"),
    "secret": ("hardcoded_secret", "hardcoded secret or key"),
    "md5": ("weak_cryptography", "MD5 hash usage"),
    "sha1": ("weak_cryptography", "SHA-1 hash usage"),
    "strcpy": ("buffer_overflow", "strcpy without bounds check"),
    "gets": ("buffer_overflow", "gets() — dangerous C function"),
    "sprintf": ("buffer_overflow", "sprintf() without bounds"),
}

_SINK_KEYWORDS = {
    "eval", "exec", "subprocess", "os.system", "pickle.loads",
    "cursor.execute", "innerHTML", "document.write", "open",
    "yaml.load", "strcpy", "gets", "sprintf", "popen",
}

_SOURCE_KEYWORDS = {
    "request", "input", "argv", "stdin", "query", "param",
    "body", "headers", "cookie", "form", "file", "upload",
    "user", "data", "payload",
}


# ── Offline hypothesis generation ─────────────────────────


def _offline_hypothesis_from_hotspot(
    hotspot: HotspotItem,
) -> Hypothesis:
    """Generate a rule-based hypothesis from a hotspot."""
    reasons_lower = " ".join(hotspot.reasons).lower()
    matches_text = " ".join(hotspot.top_matches).lower()
    combined = reasons_lower + " " + matches_text

    # Find best matching vuln_type
    vuln_type = "unknown"
    attack_surface = "security-relevant code pattern"
    best_weight = 0.0

    for keyword, (vtype, surface) in _KEYWORD_VULN_MAP.items():
        if keyword.lower() in combined:
            # Use hotspot score as proxy for relevance
            vuln_type = vtype
            attack_surface = surface
            break

    # Collect sinks and sources from matches
    sinks = [s for s in _SINK_KEYWORDS if s.lower() in combined]
    sources = [s for s in _SOURCE_KEYWORDS if s.lower() in combined]

    return Hypothesis(
        vuln_type=vuln_type,
        attack_surface=attack_surface,
        preconditions=[
            "Attacker can control input reaching this code path",
            "No upstream validation or sanitisation observed",
        ],
        exploit_idea=(
            f"Supply crafted input to trigger {vuln_type} at "
            f"{hotspot.path}. Verify by observing error/exception."
        ),
        confidence=min(0.4, hotspot.score / 100.0),  # conservative
        related_sinks=sinks[:5],
        related_sources=sources[:5],
        self_critique=(
            "Generated offline from keyword analysis only. "
            "Cannot confirm exploitability without dynamic testing. "
            "Input sanitisation may exist elsewhere. "
            f"Hotspot score ({hotspot.score:.1f}) is heuristic, not definitive."
        ),
    )


def _offline_hypothesis_from_finding(
    finding: Finding,
) -> Hypothesis:
    """Generate a rule-based hypothesis from a static analysis finding."""
    title_lower = finding.title.lower()
    evidence_text = ""
    if finding.evidence:
        evidence_text = (finding.evidence[0].summary or "").lower()

    combined = title_lower + " " + evidence_text

    vuln_type = "unknown"
    attack_surface = "static analysis alert"
    for keyword, (vtype, surface) in _KEYWORD_VULN_MAP.items():
        if keyword.lower() in combined:
            vuln_type = vtype
            attack_surface = surface
            break

    sinks = [s for s in _SINK_KEYWORDS if s.lower() in combined]
    sources = [s for s in _SOURCE_KEYWORDS if s.lower() in combined]

    return Hypothesis(
        vuln_type=vuln_type,
        attack_surface=attack_surface,
        preconditions=[
            "Static analysis tool flagged this code pattern",
            "Attacker can reach this code path with controlled input",
        ],
        exploit_idea=(
            f"The static tool reports a potential {vuln_type}. "
            f"Verify by supplying input that exercises the flagged code path."
        ),
        confidence=min(0.5, finding.confidence * 0.8),  # conservative
        related_sinks=sinks[:5],
        related_sources=sources[:5],
        self_critique=(
            "Based on static analysis output — may be a false positive. "
            "Tool confidence was mapped conservatively. "
            "Manual review recommended before exploitation attempt."
        ),
    )


# ── Online hypothesis generation (LLM) ───────────────────

_SYSTEM_PROMPT = """\
You are a security researcher analysing source code for vulnerabilities.
Given code context and tool findings, produce a JSON object with exactly these fields:
  vuln_type: string (e.g. "sql_injection", "command_injection", "path_traversal")
  attack_surface: string (entry point description)
  preconditions: list[string]
  exploit_idea: string (non-destructive PoC sketch)
  confidence: float 0.0-1.0
  related_sinks: list[string]
  related_sources: list[string]
  self_critique: string (your own assessment of false-positive risk)

Output ONLY valid JSON. No markdown, no explanation, no code fences.
Be conservative with confidence — prefer lower values unless evidence is strong.
Always include a thoughtful self_critique.
"""


def _build_llm_prompt(
    finding: Finding | None,
    hotspot: HotspotItem | None,
    code_context: str,
) -> str:
    """Build a detailed prompt for the LLM."""
    parts: list[str] = ["Analyse the following for vulnerabilities:\n"]

    if finding:
        parts.append(f"## Static Analysis Finding\n")
        parts.append(f"Title: {finding.title}\n")
        parts.append(f"Severity: {finding.severity.value}\n")
        if finding.evidence:
            ev = finding.evidence[0]
            parts.append(f"Summary: {ev.summary}\n")
            if ev.snippet:
                parts.append(f"Snippet:\n```\n{ev.snippet}\n```\n")
            if ev.location:
                parts.append(
                    f"Location: {ev.location.file}:"
                    f"{ev.location.start_line}-{ev.location.end_line}\n"
                )

    if hotspot:
        parts.append(f"\n## Hotspot\n")
        parts.append(f"File: {hotspot.path}\n")
        parts.append(f"Score: {hotspot.score}\n")
        parts.append(f"Reasons: {', '.join(hotspot.reasons[:10])}\n")
        if hotspot.top_matches:
            parts.append("Matches:\n")
            for m in hotspot.top_matches[:5]:
                parts.append(f"  - {m}\n")

    if code_context:
        parts.append(f"\n## Code Context\n```\n{code_context[:3000]}\n```\n")

    parts.append("\nProduce a hypothesis as JSON.")
    return "".join(parts)


def _parse_llm_response(
    response: str,
    max_retries: int = 2,
    llm: BaseLLMClient | None = None,
    prompt: str = "",
) -> Hypothesis | None:
    """Parse LLM response as Hypothesis JSON, with retries.

    If initial parse fails and llm is provided, re-prompts up to
    max_retries times asking for corrected JSON.
    """
    for attempt in range(1 + max_retries):
        try:
            # Strip markdown fences if present
            text = response.strip()
            if text.startswith("```"):
                lines = text.split("\n")
                # Remove first and last fence lines
                lines = [l for l in lines if not l.strip().startswith("```")]
                text = "\n".join(lines)

            data = json.loads(text)
            hyp = Hypothesis.model_validate(data)
            return hyp

        except (json.JSONDecodeError, ValidationError) as exc:
            logger.warning(
                "[hypothesis] Parse attempt %d/%d failed: %s",
                attempt + 1, 1 + max_retries, exc,
            )
            if attempt < max_retries and llm is not None:
                retry_prompt = (
                    f"Your previous response was not valid JSON or "
                    f"failed schema validation:\n{exc}\n\n"
                    f"Original prompt:\n{prompt[:1000]}\n\n"
                    f"Please respond with ONLY valid JSON matching the schema."
                )
                try:
                    response = llm.generate(
                        retry_prompt,
                        system=_SYSTEM_PROMPT,
                        json_mode=True,
                    )
                except Exception as retry_exc:
                    logger.error("[hypothesis] Retry LLM call failed: %s", retry_exc)
                    break

    return None


# ── Main agent ────────────────────────────────────────────


def generate_hypotheses(
    config: RunConfig,
    artifacts_dir: Path,
    *,
    llm_client: BaseLLMClient | None = None,
) -> list[Finding]:
    """Generate hypotheses for all candidate findings and hotspots.

    Workflow:
      1. Load hotspots.json, static candidate files, code_units.json
      2. For each candidate/hotspot, generate a Hypothesis
         (offline or via LLM)
      3. Return Finding[] with hypothesis populated

    Args:
        config: RunConfig.
        artifacts_dir: Path to artifacts/ directory with existing files.
        llm_client: Optional LLM client. If None, uses offline mode.

    Returns:
        List of Findings with hypotheses attached.
    """
    use_llm = llm_client is not None and config.llm.enabled
    mode_label = f"online ({llm_client.name})" if use_llm else "offline (rule-based)"
    logger.info("[hypothesis] Mode: %s", mode_label)

    # ── Load inputs ───────────────────────────────────────

    # Hotspots
    hotspots: list[HotspotItem] = []
    hotspots_path = artifacts_dir / "hotspots.json"
    if hotspots_path.exists():
        try:
            hotspot_idx = HotspotIndex.model_validate_json(
                hotspots_path.read_text(encoding="utf-8")
            )
            hotspots = hotspot_idx.items
            logger.info("[hypothesis] Loaded %d hotspots", len(hotspots))
        except Exception as exc:
            logger.warning("[hypothesis] Failed to load hotspots: %s", exc)

    # Static candidates
    static_findings: list[Finding] = []
    for candidate_file in ("semgrep_candidates.json", "codeql_candidates.json"):
        cpath = artifacts_dir / candidate_file
        if cpath.exists():
            try:
                adapter = TypeAdapter(list[Finding])
                findings = adapter.validate_json(cpath.read_text(encoding="utf-8"))
                static_findings.extend(findings)
                logger.info(
                    "[hypothesis] Loaded %d findings from %s",
                    len(findings), candidate_file,
                )
            except Exception as exc:
                logger.warning("[hypothesis] Failed to load %s: %s", candidate_file, exc)

    # Code units (for retriever context)
    code_units: CodeUnitsArtifact | None = None
    retriever = None
    units_path = artifacts_dir / "code_units.json"
    if config.features.enable_graph and units_path.exists():
        try:
            code_units = CodeUnitsArtifact.model_validate_json(
                units_path.read_text(encoding="utf-8")
            )
            from cve_agent.graph.retriever import CodeRetriever
            retriever = CodeRetriever(code_units)
            logger.info("[hypothesis] Loaded %d code units for context", len(code_units.units))
        except Exception as exc:
            logger.warning("[hypothesis] Failed to load code units: %s", exc)

    # ── Process ───────────────────────────────────────────

    output_findings: list[Finding] = []
    seen_ids: set[str] = set()

    # 1. Process static analysis findings
    for finding in static_findings:
        if finding.id in seen_ids:
            continue
        seen_ids.add(finding.id)

        if use_llm and llm_client:
            hyp = _generate_online_hypothesis(
                finding=finding,
                hotspot=None,
                retriever=retriever,
                llm=llm_client,
            )
        else:
            hyp = _offline_hypothesis_from_finding(finding)

        finding.hypothesis = hyp
        output_findings.append(finding)

    # 2. Process hotspots (that aren't already covered by static findings)
    static_files = {
        f.evidence[0].location.file
        for f in static_findings
        if f.evidence and f.evidence[0].location
    }

    for hotspot in hotspots:
        if hotspot.path in static_files:
            continue  # Already covered by a static finding
        if hotspot.score < 5.0:
            continue  # Too low — not worth hypothesising

        from cve_agent.analyzers.normalize_findings import stable_finding_id
        fid = stable_finding_id(hotspot.path, "hotspot", int(hotspot.score))
        if fid in seen_ids:
            continue
        seen_ids.add(fid)

        if use_llm and llm_client:
            hyp = _generate_online_hypothesis(
                finding=None,
                hotspot=hotspot,
                retriever=retriever,
                llm=llm_client,
            )
        else:
            hyp = _offline_hypothesis_from_hotspot(hotspot)

        location = CodeLocation(
            file=hotspot.path,
            start_line=1,
            end_line=1,
        )
        evidence = EvidenceItem(
            kind=EvidenceKind.CODE,
            summary=f"Hotspot (score={hotspot.score:.1f}): {', '.join(hotspot.reasons[:5])}",
            location=location,
        )

        finding = Finding(
            id=fid,
            title=f"[hotspot] {hyp.vuln_type}: {hotspot.path}",
            severity=_vuln_type_severity(hyp.vuln_type),
            confidence=hyp.confidence,
            status=FindingStatus.CANDIDATE,
            hypothesis=hyp,
            evidence=[evidence],
        )
        output_findings.append(finding)

    logger.info("[hypothesis] Generated %d hypotheses", len(output_findings))
    return output_findings


def _generate_online_hypothesis(
    *,
    finding: Finding | None,
    hotspot: HotspotItem | None,
    retriever: Any,
    llm: BaseLLMClient,
) -> Hypothesis:
    """Use LLM + retriever to generate a hypothesis."""
    # Build search query for retriever
    search_query = ""
    if finding:
        search_query = finding.title
    elif hotspot:
        search_query = " ".join(hotspot.reasons[:5]) + " " + hotspot.path

    # Gather code context from retriever
    code_context = ""
    if retriever and search_query:
        results = retriever.retrieve(search_query, top_k=3)
        code_snippets = [unit.text[:500] for unit, _ in results]
        code_context = "\n---\n".join(code_snippets)

    prompt = _build_llm_prompt(finding, hotspot, code_context)

    try:
        response = llm.generate(
            prompt,
            system=_SYSTEM_PROMPT,
            json_mode=True,
        )
        hyp = _parse_llm_response(
            response,
            max_retries=2,
            llm=llm,
            prompt=prompt,
        )
        if hyp:
            return hyp
    except Exception as exc:
        logger.warning("[hypothesis] LLM failed, falling back to offline: %s", exc)

    # Fallback to offline
    if finding:
        return _offline_hypothesis_from_finding(finding)
    elif hotspot:
        return _offline_hypothesis_from_hotspot(hotspot)
    else:
        return Hypothesis(
            vuln_type="unknown",
            attack_surface="unknown",
            exploit_idea="Unable to determine.",
            self_critique="No information available for analysis.",
        )


def _vuln_type_severity(vuln_type: str) -> Severity:
    """Map vulnerability type to a conservative severity."""
    high_types = {
        "code_injection", "command_injection", "sql_injection",
        "insecure_deserialization", "buffer_overflow",
    }
    medium_types = {
        "path_traversal", "cross_site_scripting", "broken_authentication",
        "unrestricted_upload", "hardcoded_secret",
    }
    if vuln_type in high_types:
        return Severity.HIGH
    elif vuln_type in medium_types:
        return Severity.MEDIUM
    return Severity.LOW


def save_hypotheses(
    findings: list[Finding],
    artifacts_dir: Path,
) -> Path:
    """Save hypotheses.json artifact.

    Returns:
        Path to the saved file.
    """
    out_path = artifacts_dir / "hypotheses.json"
    adapter = TypeAdapter(list[Finding])
    out_path.write_text(
        adapter.dump_json(findings, indent=2).decode(),
        encoding="utf-8",
    )
    logger.info("Saved %d hypotheses to %s", len(findings), out_path)
    return out_path
