"""Dummy LLM client — returns structured placeholder responses.

Used for testing and development. Produces valid Hypothesis JSON
without any network calls. Designed so the pipeline can run
end-to-end even without an API key.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from cve_agent.agents.llm_clients.base import BaseLLMClient

logger = logging.getLogger("cve_agent.agents.llm_clients.dummy")


class DummyLLMClient(BaseLLMClient):
    """LLM client that returns deterministic canned responses."""

    @property
    def name(self) -> str:
        return "dummy/placeholder"

    def generate(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.3,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> str:
        """Return a plausible placeholder Hypothesis JSON.

        Parses the prompt for hints about the vulnerability type
        and produces a structurally valid response.
        """
        logger.debug("[dummy] generate called (len=%d)", len(prompt))

        # Try to extract clues from the prompt
        prompt_lower = prompt.lower()

        vuln_type = "unknown"
        attack_surface = "user input"
        sinks: list[str] = []
        sources: list[str] = []

        if "eval" in prompt_lower:
            vuln_type = "code_injection"
            attack_surface = "eval() with user-controlled input"
            sinks = ["eval"]
            sources = ["user_input", "request.body"]
        elif "sql" in prompt_lower or "query" in prompt_lower:
            vuln_type = "sql_injection"
            attack_surface = "SQL query with string concatenation"
            sinks = ["cursor.execute", "db.query"]
            sources = ["request.params", "user_id"]
        elif "pickle" in prompt_lower or "deserializ" in prompt_lower:
            vuln_type = "insecure_deserialization"
            attack_surface = "pickle.loads with untrusted data"
            sinks = ["pickle.loads", "yaml.load"]
            sources = ["network_data", "file_upload"]
        elif "subprocess" in prompt_lower or "shell" in prompt_lower or "exec" in prompt_lower:
            vuln_type = "command_injection"
            attack_surface = "subprocess/shell execution with user input"
            sinks = ["subprocess.call", "os.system", "exec"]
            sources = ["request.query", "user_input"]
        elif "path" in prompt_lower or "traversal" in prompt_lower:
            vuln_type = "path_traversal"
            attack_surface = "file path constructed from user input"
            sinks = ["open", "os.path.join"]
            sources = ["filename_param", "request.path"]
        elif "xss" in prompt_lower or "innerhtml" in prompt_lower:
            vuln_type = "cross_site_scripting"
            attack_surface = "HTML rendering with unescaped user input"
            sinks = ["innerHTML", "document.write"]
            sources = ["request.query", "user_input"]
        elif "auth" in prompt_lower or "password" in prompt_lower:
            vuln_type = "broken_authentication"
            attack_surface = "authentication endpoint"
            sinks = ["login", "verify_password"]
            sources = ["credentials", "session_token"]

        result = {
            "vuln_type": vuln_type,
            "attack_surface": attack_surface,
            "preconditions": [
                "Attacker can control the relevant input parameter",
                "No input validation or sanitisation in place",
            ],
            "exploit_idea": (
                f"Supply crafted input to trigger {vuln_type}. "
                f"Verify by observing error/exception or unexpected behaviour."
            ),
            "confidence": 0.3,
            "related_sinks": sinks,
            "related_sources": sources,
            "self_critique": (
                "This hypothesis is generated without full context analysis. "
                "The confidence is low because static analysis alone cannot "
                "confirm exploitability. Input validation middleware may exist "
                "elsewhere in the codebase that prevents exploitation."
            ),
        }

        return json.dumps(result, indent=2)
