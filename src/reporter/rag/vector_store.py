"""FAISS-based vector store for semantic search over security report chunks.

Uses FAISS ``IndexFlatIP`` (inner product) with L2-normalized vectors to
perform exact cosine-similarity search.  This is appropriate for the small
datasets typical of security reports (hundreds of chunks, not millions).

If FAISS is not installed, a pure-Python fallback computes cosine similarity
directly so that the RAG pipeline remains functional without native extensions.
"""

from __future__ import annotations

import math

from src.infra.decorators import logged, timed
from src.infra.logging import get_logger

from .chunker import Chunk
from .embeddings import EmbeddingProvider

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# FAISS import with graceful fallback
# ---------------------------------------------------------------------------

try:
    import faiss  # type: ignore[import-untyped]
    import numpy as np

    _HAS_FAISS = True
    logger.debug("FAISS available — using native vector search")
except ImportError:
    _HAS_FAISS = False
    logger.warning(
        "faiss-cpu not installed — falling back to pure-Python cosine similarity. "
        "Install with: pip install faiss-cpu"
    )

# Also try numpy alone for the fallback path
if not _HAS_FAISS:
    try:
        import numpy as np  # type: ignore[no-redef]

        _HAS_NUMPY = True
    except ImportError:
        _HAS_NUMPY = False


# ---------------------------------------------------------------------------
# Pure-Python cosine similarity helpers (fallback when FAISS is unavailable)
# ---------------------------------------------------------------------------


def _dot(a: list[float], b: list[float]) -> float:
    """Dot product of two vectors."""
    return sum(x * y for x, y in zip(a, b, strict=False))


def _norm(a: list[float]) -> float:
    """L2 norm of a vector."""
    return math.sqrt(sum(x * x for x in a))


def _normalize_vector(vec: list[float]) -> list[float]:
    """L2-normalize a vector in place-safe manner."""
    n = _norm(vec)
    if n == 0.0:
        return vec
    return [x / n for x in vec]


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two L2-normalized vectors (= dot product)."""
    return _dot(a, b)


# ---------------------------------------------------------------------------
# Vector store
# ---------------------------------------------------------------------------


class VectorStore:
    """FAISS-based vector store for semantic search.

    Embeds chunks using the provided :class:`EmbeddingProvider`, builds a
    FAISS ``IndexFlatIP`` index with L2-normalized vectors, and supports
    both plain search and metadata-filtered search.

    When FAISS is not available, falls back to brute-force cosine similarity
    using pure Python (suitable for the small datasets in security reports).
    """

    def __init__(self, embedding_provider: EmbeddingProvider) -> None:
        self._embedder = embedding_provider
        self._index = None  # faiss.IndexFlatIP or None
        self._chunks: list[Chunk] = []
        self._vectors: list[list[float]] = []  # Kept for fallback path

    @logged
    @timed
    def index(self, chunks: list[Chunk]) -> None:
        """Index chunks: embed texts, normalize, and build FAISS index.

        Args:
            chunks: List of Chunk objects to index.
        """
        if not chunks:
            logger.warning("No chunks to index")
            return

        self._chunks = chunks
        texts = [c.text for c in chunks]

        # Fit the TF-IDF vocabulary if using the fallback embedder
        self._embedder.fit(texts)

        # Embed all chunk texts
        raw_vectors = self._embedder.embed(texts)

        if _HAS_FAISS:
            # Convert to numpy and L2-normalize for cosine similarity via IP
            vectors_np = np.array(raw_vectors, dtype=np.float32)
            faiss.normalize_L2(vectors_np)

            # Build the index
            dim = vectors_np.shape[1]
            self._index = faiss.IndexFlatIP(dim)
            self._index.add(vectors_np)

            logger.info(
                "FAISS index built: %d vectors of dimension %d",
                self._index.ntotal,
                dim,
            )
        else:
            # Fallback: store normalized vectors as plain lists
            self._vectors = [_normalize_vector(v) for v in raw_vectors]
            logger.info(
                "Pure-Python vector store built: %d vectors of dimension %d",
                len(self._vectors),
                len(self._vectors[0]) if self._vectors else 0,
            )

    @timed
    def search(self, query: str, k: int = 5) -> list[tuple[Chunk, float]]:
        """Search for the k most similar chunks to the query.

        Args:
            query: The search query text.
            k:     Number of results to return.

        Returns:
            List of (Chunk, score) tuples, ordered by descending similarity.
        """
        if not self._chunks:
            return []

        k = min(k, len(self._chunks))
        query_vec = self._embedder.embed_query(query)

        if _HAS_FAISS and self._index is not None:
            query_np = np.array([query_vec], dtype=np.float32)
            faiss.normalize_L2(query_np)
            scores, indices = self._index.search(query_np, k)

            results: list[tuple[Chunk, float]] = []
            for score, idx in zip(scores[0], indices[0], strict=False):
                if idx < 0:
                    continue  # FAISS returns -1 for missing results
                results.append((self._chunks[idx], float(score)))
            return results
        else:
            # Fallback: brute-force cosine similarity
            query_normalized = _normalize_vector(query_vec)
            scored: list[tuple[int, float]] = []
            for i, vec in enumerate(self._vectors):
                sim = _cosine_similarity(query_normalized, vec)
                scored.append((i, sim))

            scored.sort(key=lambda x: x[1], reverse=True)
            return [(self._chunks[i], score) for i, score in scored[:k]]

    @timed
    def search_with_filter(
        self,
        query: str,
        k: int = 5,
        severity: str | None = None,
        attack_type: str | None = None,
    ) -> list[tuple[Chunk, float]]:
        """Search with metadata filtering.

        Retrieves ``k * 3`` candidates from the vector index, applies
        metadata filters, and returns the top ``k`` matching results.

        Args:
            query:       The search query text.
            k:           Number of results to return.
            severity:    Filter by severity level (CRITICAL, HIGH, MEDIUM, LOW).
            attack_type: Filter by attack type (sqli, xss, idor, etc.).

        Returns:
            List of (Chunk, score) tuples, ordered by descending similarity.
        """
        if not self._chunks:
            return []

        # Fetch extra candidates to allow for filtering
        candidates = self.search(query, k=min(k * 3, len(self._chunks)))

        filtered: list[tuple[Chunk, float]] = []
        for chunk, score in candidates:
            meta = chunk.metadata

            # Apply severity filter
            if severity is not None:
                chunk_severity = meta.get("severity")
                if chunk_severity is None or chunk_severity.upper() != severity.upper():
                    continue

            # Apply attack type filter
            if attack_type is not None:
                chunk_attacks = meta.get("attack_types", [])
                if attack_type.lower() not in [a.lower() for a in chunk_attacks]:
                    continue

            filtered.append((chunk, score))

            if len(filtered) >= k:
                break

        return filtered

    @property
    def size(self) -> int:
        """Number of indexed chunks."""
        if _HAS_FAISS and self._index is not None:
            return self._index.ntotal
        return len(self._vectors)
