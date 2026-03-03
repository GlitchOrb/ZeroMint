"""Code unit retriever — find relevant units by keyword / TF-IDF scoring.

Operates entirely in-memory, no vector DB required.
Supports two retrieval strategies:
  1. Keyword match (file path, symbol name, text content)
  2. TF-IDF scoring for more nuanced ranking
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import Optional

from cve_agent.graph.code_units import CodeUnit, CodeUnitsArtifact

logger = logging.getLogger("cve_agent.graph.retriever")

# ── Tokeniser ─────────────────────────────────────────────

_TOKEN_RE = re.compile(r"[a-zA-Z_]\w*")


def _tokenise(text: str) -> list[str]:
    """Split text into lowercase identifier tokens."""
    return [m.lower() for m in _TOKEN_RE.findall(text)]


# ── Retriever ─────────────────────────────────────────────


class CodeRetriever:
    """In-memory retriever over CodeUnit objects.

    Indexes:
      - unit_id (file::symbol)
      - signature
      - full text content (for TF-IDF)

    Query modes:
      - keyword: exact substring match on symbol/file, boosted
      - tfidf: TF-IDF scoring across all unit texts
      - combined (default): blend both signals
    """

    def __init__(self, units: list[CodeUnit] | CodeUnitsArtifact) -> None:
        if isinstance(units, CodeUnitsArtifact):
            self._units = units.units
        else:
            self._units = list(units)

        # Build TF-IDF index
        self._doc_tokens: list[list[str]] = []
        self._df: Counter[str] = Counter()
        self._n_docs = len(self._units)

        for unit in self._units:
            tokens = _tokenise(unit.text)
            self._doc_tokens.append(tokens)
            # Document frequency: count each token once per doc
            for token in set(tokens):
                self._df[token] += 1

        logger.debug("CodeRetriever indexed %d units", self._n_docs)

    @property
    def units(self) -> list[CodeUnit]:
        return self._units

    def retrieve(
        self,
        query: str,
        *,
        top_k: int = 10,
        mode: str = "combined",
    ) -> list[tuple[CodeUnit, float]]:
        """Retrieve top-k code units matching the query.

        Args:
            query: Free-text search query.
            top_k: Number of results to return.
            mode: "keyword", "tfidf", or "combined" (default).

        Returns:
            List of (CodeUnit, score) tuples, highest score first.
        """
        if not self._units:
            return []

        query_lower = query.strip().lower()
        if not query_lower:
            return []

        scores: list[float] = [0.0] * self._n_docs
        query_tokens = _tokenise(query)

        if mode in ("keyword", "combined"):
            self._score_keyword(query_lower, scores)

        if mode in ("tfidf", "combined"):
            self._score_tfidf(query_tokens, scores)

        # Rank
        ranked = sorted(
            enumerate(scores),
            key=lambda x: x[1],
            reverse=True,
        )

        results: list[tuple[CodeUnit, float]] = []
        for idx, score in ranked[:top_k]:
            if score > 0:
                results.append((self._units[idx], score))

        return results

    def _score_keyword(self, query_lower: str, scores: list[float]) -> None:
        """Add keyword-match signals to score array.

        Boosting:
          - symbol name match: +10
          - file path match: +5
          - signature match: +3
          - text content match: +1
        """
        query_parts = query_lower.split()

        for i, unit in enumerate(self._units):
            unit_id_lower = unit.unit_id.lower()
            sig_lower = unit.signature.lower()
            path_lower = unit.location.file.lower()
            symbol_lower = (unit.location.symbol or "").lower()

            for part in query_parts:
                if part in symbol_lower:
                    scores[i] += 10.0
                if part in path_lower:
                    scores[i] += 5.0
                if part in sig_lower:
                    scores[i] += 3.0

            # Full query substring in text (cheaper than per-token)
            if query_lower in unit.text.lower():
                scores[i] += 1.0

    def _score_tfidf(self, query_tokens: list[str], scores: list[float]) -> None:
        """Add TF-IDF score for each unit."""
        if not query_tokens:
            return

        for i, doc_tokens in enumerate(self._doc_tokens):
            if not doc_tokens:
                continue

            tf_counter = Counter(doc_tokens)
            doc_len = len(doc_tokens)
            score = 0.0

            for qt in query_tokens:
                tf = tf_counter.get(qt, 0) / doc_len if doc_len else 0
                df = self._df.get(qt, 0)
                if df > 0 and tf > 0:
                    idf = math.log(1 + self._n_docs / df)
                    score += tf * idf

            scores[i] += score

    def find_callers(self, symbol: str, edges: list[tuple[str, str]]) -> list[CodeUnit]:
        """Find units that call the given symbol.

        Args:
            symbol: The callee symbol name to search for.
            edges: List of (from_unit_id, to_symbol) edges.

        Returns:
            List of CodeUnits that call the symbol.
        """
        caller_ids = {
            from_id
            for from_id, to_sym in edges
            if symbol.lower() in to_sym.lower()
        }
        unit_map = {u.unit_id: u for u in self._units}
        return [unit_map[uid] for uid in caller_ids if uid in unit_map]

    def find_callees(self, unit_id: str, edges: list[tuple[str, str]]) -> list[str]:
        """Find symbols called by a given unit.

        Args:
            unit_id: The calling unit's ID.
            edges: List of (from_unit_id, to_symbol) edges.

        Returns:
            List of callee symbol names.
        """
        return [to_sym for from_id, to_sym in edges if from_id == unit_id]
