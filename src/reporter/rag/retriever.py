"""Hybrid retrieval combining FAISS vector search with knowledge graph context.

Uses vector similarity search as the primary retrieval method and optionally
augments results with structured context from the knowledge graph.  The two
result streams are merged, deduplicated, and ranked by a unified score.

When FAISS or the embedding provider is unavailable the retriever degrades
gracefully: it relies solely on the knowledge graph (if present) or returns
an empty list so the chatbot can fall back to TF-IDF keyword search.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.infra.decorators import logged
from src.infra.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class RetrievedContext:
    """A single piece of retrieved context with source attribution.

    Attributes:
        text:     The text content of the context.
        source:   Origin of the context: ``"vector_search"`` or ``"knowledge_graph"``.
        score:    Relevance score normalised to the 0-1 range.
        metadata: Extra information — chunk metadata for vector results,
                  graph query type for knowledge-graph results.
    """

    text: str
    source: str  # "vector_search" or "knowledge_graph"
    score: float
    metadata: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Intent detection helpers
# ---------------------------------------------------------------------------

_ENDPOINT_PATTERN = re.compile(
    r"(/(?:rest|api|ftp|admin|b2b|metrics|security|socket|video)[\w/.-]*)"
)

_SEVERITY_KEYWORDS = {
    "critical",
    "critique",
    "high",
    "eleve",
    "medium",
    "moyen",
    "low",
    "faible",
}

_REMEDIATION_KEYWORDS = {
    "remediation",
    "recommandation",
    "corriger",
    "correction",
    "fix",
    "mitigation",
    "attenuer",
    "proteger",
    "securiser",
}

_ATTACK_TYPE_KEYWORDS = {
    "sqli",
    "sql injection",
    "xss",
    "cross-site scripting",
    "idor",
    "csrf",
    "path traversal",
    "auth bypass",
    "command injection",
    "info disclosure",
    "open redirect",
    "injection",
}

_OWASP_KEYWORDS = {"owasp", "a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10"}


def _detect_intents(question: str) -> list[str]:
    """Detect question intents to guide knowledge-graph queries.

    Returns a list of intent labels such as ``"endpoint"``, ``"severity"``,
    ``"remediation"``, ``"attack_type"``, ``"owasp"``.
    """
    lower = question.lower()
    intents: list[str] = []

    if _ENDPOINT_PATTERN.search(question):
        intents.append("endpoint")

    if any(kw in lower for kw in _SEVERITY_KEYWORDS):
        intents.append("severity")

    if any(kw in lower for kw in _REMEDIATION_KEYWORDS):
        intents.append("remediation")

    if any(kw in lower for kw in _ATTACK_TYPE_KEYWORDS):
        intents.append("attack_type")

    if any(kw in lower for kw in _OWASP_KEYWORDS):
        intents.append("owasp")

    return intents


# ---------------------------------------------------------------------------
# HybridRetriever
# ---------------------------------------------------------------------------


class HybridRetriever:
    """Combines vector search (FAISS) with knowledge graph for retrieval.

    The retriever always attempts vector search first.  When a
    :class:`KnowledgeGraph` instance is provided, structured context is
    retrieved in parallel and merged into the final result list.

    Parameters
    ----------
    vector_store:
        A :class:`VectorStore` instance backed by FAISS.
    knowledge_graph:
        An optional :class:`KnowledgeGraph` instance.  When ``None``,
        only vector search is used.
    """

    # Fixed relevance score assigned to knowledge-graph results so they
    # mix reasonably with normalised vector-search scores.
    _KG_BASE_SCORE: float = 0.80

    def __init__(self, vector_store, knowledge_graph=None):
        self.vector_store = vector_store
        self.kg = knowledge_graph

    # ------------------------------------------------------------------ #
    # Main retrieve entry-point
    # ------------------------------------------------------------------ #

    @logged
    def retrieve(self, question: str, k: int = 5) -> list[RetrievedContext]:
        """Retrieve relevant context using both vector search and graph queries.

        Strategy:
            1. Run vector search (FAISS) for top *k* chunks.
            2. If a knowledge graph is available, get structured context
               guided by detected question intents.
            3. Merge and deduplicate results.
            4. Rank by relevance score (descending).

        Args:
            question: Natural-language user question.
            k:        Maximum number of vector-search results to fetch.

        Returns:
            A list of :class:`RetrievedContext` objects ordered by
            descending relevance score.
        """
        results: list[RetrievedContext] = []

        # --- 1. Vector search ------------------------------------------------
        vector_results = self._vector_search(question, k)
        results.extend(vector_results)

        # --- 2. Knowledge-graph augmentation ----------------------------------
        if self.kg is not None:
            kg_results = self._kg_search(question)
            results.extend(kg_results)

        # --- 3. Deduplicate by text content -----------------------------------
        results = self._deduplicate(results)

        # --- 4. Sort by score descending --------------------------------------
        results.sort(key=lambda r: r.score, reverse=True)

        logger.debug(
            "HybridRetriever returned %d results (vector=%d, kg=%d)",
            len(results),
            len(vector_results),
            len(kg_results) if self.kg is not None else 0,
        )
        return results

    # ------------------------------------------------------------------ #
    # Vector search
    # ------------------------------------------------------------------ #

    def _vector_search(self, question: str, k: int) -> list[RetrievedContext]:
        """Run FAISS vector search and normalise scores to 0-1."""
        try:
            raw_results = self.vector_store.search(question, k=k)
        except Exception as exc:
            logger.warning("Vector search failed (%s), skipping", exc)
            return []

        if not raw_results:
            return []

        # raw_results is expected to be a list of (chunk, score) tuples or
        # objects with .text/.score/.metadata.  Adapt to whatever the
        # VectorStore returns.
        contexts: list[RetrievedContext] = []

        # Normalise scores: FAISS L2 distance -> similarity.  Lower distance
        # means more similar, so invert.  If cosine similarity is used the
        # scores are already between 0 and 1.
        max_score = max((self._extract_score(r) for r in raw_results), default=1.0) or 1.0

        for result in raw_results:
            text = self._extract_text(result)
            raw_score = self._extract_score(result)
            metadata = self._extract_metadata(result)

            # Normalise to 0-1 range
            normalised_score = raw_score / max_score if max_score > 0 else 0.0
            # Clamp
            normalised_score = max(0.0, min(1.0, normalised_score))

            contexts.append(
                RetrievedContext(
                    text=text,
                    source="vector_search",
                    score=normalised_score,
                    metadata=metadata,
                )
            )

        return contexts

    # ------------------------------------------------------------------ #
    # Knowledge-graph search
    # ------------------------------------------------------------------ #

    def _kg_search(self, question: str) -> list[RetrievedContext]:
        """Get structured context from the knowledge graph."""
        try:
            kg_context = self.kg.get_context_for_query(question)
        except Exception as exc:
            logger.warning("Knowledge graph query failed (%s), skipping", exc)
            return []

        if not kg_context:
            return []

        # kg_context may be a single string or a list of strings
        if isinstance(kg_context, str):
            if not kg_context.strip():
                return []
            return [
                RetrievedContext(
                    text=kg_context.strip(),
                    source="knowledge_graph",
                    score=self._KG_BASE_SCORE,
                    metadata={"query_intents": _detect_intents(question)},
                )
            ]

        # Assume iterable of strings
        contexts: list[RetrievedContext] = []
        intents = _detect_intents(question)
        for idx, item in enumerate(kg_context):
            text = item if isinstance(item, str) else str(item)
            if not text.strip():
                continue
            # Slight score decay for later items
            score = max(self._KG_BASE_SCORE - idx * 0.02, 0.5)
            contexts.append(
                RetrievedContext(
                    text=text.strip(),
                    source="knowledge_graph",
                    score=score,
                    metadata={"query_intents": intents},
                )
            )
        return contexts

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _deduplicate(results: list[RetrievedContext]) -> list[RetrievedContext]:
        """Remove duplicate contexts, keeping the one with the highest score."""
        seen: dict[str, RetrievedContext] = {}
        for ctx in results:
            # Use a normalised version of text as the key
            key = ctx.text.strip()[:200]
            if key not in seen or ctx.score > seen[key].score:
                seen[key] = ctx
        return list(seen.values())

    @staticmethod
    def _extract_text(result) -> str:
        """Extract text from a vector-store result (adapts to different formats)."""
        if isinstance(result, tuple):
            return str(result[0])
        if hasattr(result, "text"):
            return result.text
        if hasattr(result, "page_content"):
            return result.page_content
        return str(result)

    @staticmethod
    def _extract_score(result) -> float:
        """Extract score from a vector-store result."""
        if isinstance(result, tuple) and len(result) >= 2:
            return float(result[1])
        if hasattr(result, "score"):
            return float(result.score)
        return 0.5

    @staticmethod
    def _extract_metadata(result) -> dict:
        """Extract metadata from a vector-store result."""
        if isinstance(result, tuple) and len(result) >= 3:
            return result[2] if isinstance(result[2], dict) else {}
        if hasattr(result, "metadata"):
            meta = result.metadata
            return meta if isinstance(meta, dict) else {}
        return {}
