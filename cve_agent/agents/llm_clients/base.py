"""Abstract base class for LLM clients.

All LLM backends (OpenAI, Anthropic, local, dummy) must subclass
BaseLLMClient and implement `generate`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseLLMClient(ABC):
    """Interface every LLM backend must follow."""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        *,
        system: str = "",
        temperature: float = 0.3,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> str:
        """Send a prompt and return the raw text response.

        Args:
            prompt: User message / main prompt.
            system: System-level instruction (optional).
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            json_mode: If True, force JSON-only output.

        Returns:
            Raw text response from the LLM.

        Raises:
            Exception: On API / network errors.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable backend name (e.g. 'openai/gpt-4o')."""
        ...

    def estimate_tokens(self, text: str) -> int:
        """Rough token estimate (chars / 4)."""
        return max(1, len(text) // 4)
