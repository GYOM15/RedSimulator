"""Embedding provider with fastembed primary and TF-IDF fallback.

Provides text embeddings via two strategies:

1. **fastembed** (primary): Uses ``fastembed.TextEmbedding`` with the
   ``BAAI/bge-small-en-v1.5`` model (33 MB, ONNX runtime, no PyTorch needed).
   Produces 384-dimensional dense vectors with good semantic quality.

2. **TF-IDF** (fallback): If fastembed is unavailable, falls back to a
   lightweight TF-IDF vectorizer built from scratch (no sklearn dependency).
   Vocabulary and IDF scores are computed from the indexed documents.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from src.infra.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Stop words for TF-IDF tokenization (English + French)
# ---------------------------------------------------------------------------

_STOP_WORDS: set[str] = {
    # French
    "le",
    "la",
    "les",
    "de",
    "du",
    "des",
    "un",
    "une",
    "et",
    "en",
    "est",
    "a",
    "au",
    "aux",
    "ce",
    "ces",
    "que",
    "qui",
    "dans",
    "pour",
    "par",
    "sur",
    "avec",
    "son",
    "sa",
    "ses",
    "ne",
    "pas",
    "plus",
    "ou",
    "si",
    "il",
    "elle",
    "on",
    "nous",
    "vous",
    "ils",
    "elles",
    "se",
    "sont",
    "ete",
    "avoir",
    "etre",
    "fait",
    "comme",
    "tout",
    "aussi",
    "autre",
    # English
    "the",
    "is",
    "of",
    "and",
    "to",
    "in",
    "it",
    "for",
    "with",
    "this",
    "that",
    "are",
    "was",
    "be",
    "has",
    "an",
    "at",
    "not",
    "but",
}


def _tokenize(text: str) -> list[str]:
    """Lowercase tokenization, stripping non-alpha chars and stop words."""
    raw = re.findall(r"[a-zA-ZÀ-ÿ0-9_]+", text.lower())
    return [w for w in raw if len(w) > 1 and w not in _STOP_WORDS]


# ---------------------------------------------------------------------------
# TF-IDF vectorizer (zero-dependency fallback)
# ---------------------------------------------------------------------------


class _TfidfVectorizer:
    """Minimal TF-IDF vectorizer built without external dependencies.

    Builds a vocabulary and IDF scores from a corpus of documents, then
    produces dense vectors suitable for FAISS indexing.
    """

    def __init__(self) -> None:
        self._vocab: dict[str, int] = {}
        self._idf: list[float] = []
        self._fitted = False

    @property
    def dimension(self) -> int:
        """Dimensionality of the TF-IDF vectors."""
        return len(self._vocab)

    def fit(self, documents: list[str]) -> None:
        """Build vocabulary and compute IDF scores from the corpus.

        Args:
            documents: List of text documents to learn vocabulary from.
        """
        n_docs = len(documents)
        if n_docs == 0:
            logger.warning("TF-IDF fit called with empty document list")
            return

        # Build document-frequency counts
        doc_freq: Counter[str] = Counter()
        for doc in documents:
            unique_tokens = set(_tokenize(doc))
            doc_freq.update(unique_tokens)

        # Build vocabulary (sorted for deterministic ordering)
        self._vocab = {term: idx for idx, term in enumerate(sorted(doc_freq.keys()))}

        # Compute IDF: log((N + 1) / (df + 1)) + 1.0 (smoothed)
        self._idf = [0.0] * len(self._vocab)
        for term, idx in self._vocab.items():
            df = doc_freq[term]
            self._idf[idx] = math.log((n_docs + 1) / (df + 1)) + 1.0

        self._fitted = True
        logger.info("TF-IDF vocabulary built: %d terms from %d documents", len(self._vocab), n_docs)

    def transform(self, texts: list[str]) -> list[list[float]]:
        """Transform texts into TF-IDF vectors.

        Args:
            texts: List of texts to vectorize.

        Returns:
            List of dense float vectors, one per input text.
        """
        if not self._fitted or not self._vocab:
            # Return zero vectors if not fitted
            return [[0.0] for _ in texts]

        dim = len(self._vocab)
        vectors: list[list[float]] = []

        for text in texts:
            tokens = _tokenize(text)
            if not tokens:
                vectors.append([0.0] * dim)
                continue

            tf_counts = Counter(tokens)
            n_tokens = len(tokens)
            vec = [0.0] * dim

            for token, count in tf_counts.items():
                if token in self._vocab:
                    idx = self._vocab[token]
                    tf = count / n_tokens
                    vec[idx] = tf * self._idf[idx]

            vectors.append(vec)

        return vectors


# ---------------------------------------------------------------------------
# Main embedding provider
# ---------------------------------------------------------------------------


class EmbeddingProvider:
    """Provides text embeddings with fastembed primary and TF-IDF fallback.

    On initialization, attempts to load fastembed with the
    ``BAAI/bge-small-en-v1.5`` model.  If that fails (import error, model
    download failure, etc.), silently falls back to TF-IDF vectorization.

    The fallback requires a call to :meth:`fit` before :meth:`embed` will
    produce meaningful vectors.
    """

    def __init__(self) -> None:
        self._model = None
        self._mode: str = "tfidf"
        self._tfidf = _TfidfVectorizer()
        self._try_init_fastembed()

    def _try_init_fastembed(self) -> None:
        """Attempt to initialize fastembed; fall back to TF-IDF on failure."""
        try:
            from fastembed import TextEmbedding  # type: ignore[import-untyped]

            self._model = TextEmbedding(model_name="BAAI/bge-small-en-v1.5")
            self._mode = "fastembed"
            logger.info("Embedding provider initialized with fastembed (BAAI/bge-small-en-v1.5)")
        except ImportError:
            logger.warning(
                "fastembed not installed — falling back to TF-IDF embeddings. "
                "Install with: pip install fastembed"
            )
        except Exception as exc:
            logger.warning(
                "fastembed initialization failed (%s: %s) — falling back to TF-IDF",
                type(exc).__name__,
                exc,
            )

    def fit(self, documents: list[str]) -> None:
        """Fit the TF-IDF vocabulary from documents.

        Only needed when running in TF-IDF mode.  Has no effect when
        fastembed is available.

        Args:
            documents: Corpus of texts to build vocabulary from.
        """
        if self._mode == "tfidf":
            self._tfidf.fit(documents)

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Embed a list of texts into vectors.

        Args:
            texts: Texts to embed.

        Returns:
            List of embedding vectors (one per input text).
        """
        if not texts:
            return []

        if self._mode == "fastembed" and self._model is not None:
            # fastembed returns a generator of numpy arrays
            embeddings = list(self._model.embed(texts))
            return [emb.tolist() for emb in embeddings]
        else:
            return self._tfidf.transform(texts)

    def embed_query(self, query: str) -> list[float]:
        """Embed a single query string.

        For fastembed this uses the query-optimized embedding path.
        For TF-IDF this is equivalent to ``embed([query])[0]``.

        Args:
            query: The query text to embed.

        Returns:
            A single embedding vector.
        """
        if self._mode == "fastembed" and self._model is not None:
            embeddings = list(self._model.query_embed(query))
            return embeddings[0].tolist()
        else:
            result = self._tfidf.transform([query])
            return result[0]

    @property
    def dimension(self) -> int:
        """Embedding dimension (384 for bge-small, varies for TF-IDF)."""
        if self._mode == "fastembed":
            return 384
        return self._tfidf.dimension

    @property
    def mode(self) -> str:
        """Current embedding mode: 'fastembed' or 'tfidf'."""
        return self._mode
