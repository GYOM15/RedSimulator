"""RAG chatbot for exploring vulnerability reports.

Indexes the report into a FAISS vector store (with optional knowledge graph)
and answers user questions by retrieving relevant context and generating
answers with Claude API.

The module is designed for graceful degradation:

- **Full mode:** FAISS + knowledge graph + Claude LLM
- **Partial mode:** FAISS only (no KG, or no scan/plan/results data)
- **Degraded mode:** TF-IDF keyword search + simple context dump (when
  fastembed / FAISS are not installed or no API key is available)

The public API (``index_report``, ``ask_report``) is backward-compatible:
callers that only pass ``report_text`` will still work.
"""

from __future__ import annotations

import math
import re
import textwrap
from collections import Counter
from typing import TYPE_CHECKING

from src.infra.config import settings
from src.infra.decorators import logged
from src.infra.logging import get_logger

if TYPE_CHECKING:
    from src.models import AttackPlan, AttackResult, ScanResult

    from .retriever import HybridRetriever, RetrievedContext

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_retriever: HybridRetriever | None = None
_kg = None  # KnowledgeGraph | None

# TF-IDF fallback state (used when FAISS is unavailable)
_chunks: list[str] = []
_idf_scores: dict[str, float] = {}


# ---------------------------------------------------------------------------
# TF-IDF fallback helpers (ported from the old rag_chatbot)
# ---------------------------------------------------------------------------

_STOP_WORDS: set[str] = {
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

_BOOST_TERMS: set[str] = {
    "critical",
    "high",
    "medium",
    "low",
    "critique",
    "eleve",
    "moyen",
    "faible",
    "sqli",
    "xss",
    "idor",
    "csrf",
    "injection",
    "traversal",
    "redirect",
    "auth_bypass",
    "command_injection",
    "info_disclosure",
    "exploitee",
    "reussi",
    "echoue",
    "remediation",
    "recommandation",
    "payload",
    "vulnerabilite",
    "risque",
    "owasp",
}

_BOOST_FACTOR: float = 2.0


def _tokenize(text: str) -> list[str]:
    """Lowercase tokenization, stripping non-alpha chars and stop words."""
    raw = re.findall(r"[a-zA-ZàâäéèêëïîôùûüçÀÂÄÉÈÊËÏÎÔÙÛÜÇ0-9_]+", text.lower())
    return [w for w in raw if len(w) > 1 and w not in _STOP_WORDS]


def _build_idf(chunks: list[str]) -> dict[str, float]:
    """Compute IDF scores across all chunks."""
    n = len(chunks)
    if n == 0:
        return {}

    doc_freq: Counter[str] = Counter()
    for chunk in chunks:
        unique_tokens = set(_tokenize(chunk))
        doc_freq.update(unique_tokens)

    idf: dict[str, float] = {}
    for term, df in doc_freq.items():
        idf[term] = math.log((n + 1) / (df + 1)) + 1.0
    return idf


def _tfidf_score(query_tokens: list[str], chunk: str, idf: dict[str, float]) -> float:
    """Score a chunk against query tokens using TF-IDF with boost terms."""
    chunk_tokens = _tokenize(chunk)
    if not chunk_tokens:
        return 0.0

    chunk_tf: Counter[str] = Counter(chunk_tokens)
    chunk_len = len(chunk_tokens)

    score = 0.0
    for qt in query_tokens:
        tf = chunk_tf.get(qt, 0) / chunk_len
        idf_val = idf.get(qt, 1.0)
        term_score = tf * idf_val
        if qt in _BOOST_TERMS:
            term_score *= _BOOST_FACTOR
        score += term_score

    return score


def _tfidf_search(question: str, n_results: int = 5) -> list[str]:
    """Keyword-based fallback search using TF-IDF scoring."""
    if not _chunks:
        return []

    query_tokens = _tokenize(question)
    if not query_tokens:
        return []

    scored: list[tuple[float, str]] = []
    for chunk in _chunks:
        score = _tfidf_score(query_tokens, chunk, _idf_scores)
        if score > 0:
            scored.append((score, chunk))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [chunk for _, chunk in scored[:n_results]]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@logged
def index_report(
    report_text: str,
    scan: ScanResult | None = None,
    plan: AttackPlan | None = None,
    results: AttackResult | None = None,
) -> int:
    """Index a report for RAG queries.

    Steps:
        1. Smart-chunk the report text.
        2. Build a FAISS vector index (via :class:`VectorStore`).
        3. If *scan*, *plan*, and *results* are provided, build a knowledge
           graph for structured queries.
        4. Create a :class:`HybridRetriever` combining both sources.

    When FAISS or the embedding provider is not installed the function falls
    back to TF-IDF keyword indexing so that ``ask_report`` still works in
    degraded mode.

    Args:
        report_text: Markdown text of the vulnerability report.
        scan:        Optional scan results for knowledge-graph construction.
        plan:        Optional attack plan for knowledge-graph construction.
        results:     Optional attack results for knowledge-graph construction.

    Returns:
        Number of chunks indexed.
    """
    global _retriever, _kg, _chunks, _idf_scores

    logger.info("Indexing report for RAG queries...")

    # ----- Step 1: Smart-chunk the report ---------------------------------
    chunk_objects = None
    try:
        from .chunker import smart_chunk

        chunk_objects = smart_chunk(report_text)
        chunk_texts = [c.text for c in chunk_objects]
    except Exception as exc:
        logger.warning("Smart chunker failed (%s), using simple split", exc)
        chunk_objects = None
        chunk_texts = _simple_chunk(report_text)

    if not chunk_texts:
        logger.warning("No chunks produced from report text")
        return 0

    # Always keep a plain-text copy for TF-IDF fallback
    _chunks = chunk_texts
    _idf_scores = _build_idf(_chunks)
    logger.debug("%d chunks created", len(_chunks))

    # ----- Step 2: Build FAISS vector index --------------------------------
    vector_store = None
    try:
        from .embeddings import EmbeddingProvider
        from .vector_store import VectorStore

        embedding_provider = EmbeddingProvider()
        vector_store = VectorStore(embedding_provider)

        if chunk_objects:
            vector_store.index(chunk_objects)
        else:
            # If we only have plain strings, wrap them in minimal Chunk objects
            from .chunker import Chunk

            minimal_chunks = [
                Chunk(text=t, metadata={"index": i}) for i, t in enumerate(chunk_texts)
            ]
            vector_store.index(minimal_chunks)

        logger.info("%d chunks indexed in FAISS vector store", len(chunk_texts))
    except ImportError as exc:
        logger.warning(
            "Vector store dependencies not available (%s), using TF-IDF fallback only",
            exc,
        )
    except Exception as exc:
        logger.error("Failed to build FAISS index: %s, using TF-IDF fallback", exc)

    # ----- Step 3: Build knowledge graph (optional) -----------------------
    _kg = None
    if scan is not None and plan is not None and results is not None:
        try:
            from .knowledge_graph import KnowledgeGraph

            kg = KnowledgeGraph()
            kg.build(scan, plan, results)
            _kg = kg
            logger.info("Knowledge graph built successfully")
        except ImportError as exc:
            logger.warning("Knowledge graph module not available (%s)", exc)
        except Exception as exc:
            logger.error("Failed to build knowledge graph: %s", exc)

    # ----- Step 4: Create hybrid retriever --------------------------------
    if vector_store is not None:
        from .retriever import HybridRetriever

        _retriever = HybridRetriever(vector_store, knowledge_graph=_kg)
        logger.info(
            "Hybrid retriever created (vector=True, kg=%s)",
            _kg is not None,
        )
    else:
        _retriever = None
        logger.info("No vector store available; will use TF-IDF fallback for queries")

    return len(chunk_texts)


@logged
def ask_report(question: str) -> str:
    """Answer a question about the indexed report.

    Steps:
        1. Retrieve relevant context via the hybrid retriever (vector + graph).
           Falls back to TF-IDF keyword search when the retriever is unavailable.
        2. If a Claude API key is configured, generate an LLM answer grounded
           in the retrieved context.
        3. Otherwise, format the retrieved context as a structured answer.

    Args:
        question: Natural-language question about the report.

    Returns:
        Answer string (LLM-generated or formatted context).
    """
    logger.info("Question: %s", question)

    # ----- Step 1: Retrieve context ---------------------------------------
    retrieved_contexts: list[RetrievedContext] = []
    relevant_texts: list[str] = []

    if _retriever is not None:
        try:
            retrieved_contexts = _retriever.retrieve(question, k=5)
            relevant_texts = [ctx.text for ctx in retrieved_contexts]
        except Exception as exc:
            logger.warning("Hybrid retriever failed (%s), falling back to TF-IDF", exc)

    # Fallback to TF-IDF if retriever produced nothing
    if not relevant_texts:
        relevant_texts = _tfidf_search(question, n_results=5)

    if not relevant_texts:
        return "Aucune information trouvee dans le rapport pour cette question."

    logger.debug("%d relevant chunks found", len(relevant_texts))

    # ----- Step 2: Generate answer ----------------------------------------
    context_str = "\n\n---\n\n".join(relevant_texts)

    api_key = settings.anthropic_api_key or ""
    if api_key and not api_key.startswith("sk-ant-..."):
        return _answer_with_llm(question, context_str, retrieved_contexts, api_key)
    else:
        return _answer_simple(question, relevant_texts, retrieved_contexts)


# ---------------------------------------------------------------------------
# LLM answer generation
# ---------------------------------------------------------------------------


def _answer_with_llm(
    question: str,
    context: str,
    retrieved: list[RetrievedContext],
    api_key: str,
) -> str:
    """Generate an answer using Claude API, grounded in retrieved context."""
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)

        # Include source attribution in the context block
        source_info = ""
        if retrieved:
            sources = set(ctx.source for ctx in retrieved)
            source_info = (
                f"\n\n[Sources: {', '.join(sources)}. "
                f"{len(retrieved)} context fragments retrieved.]"
            )

        system_prompt = textwrap.dedent("""\
            You are a security analyst answering questions about a vulnerability report.
            Answer ONLY based on the provided context.
            Cite specific vulnerability IDs (e.g. VEC-001) and endpoints when available.

            Rules:
            - Be precise and concise.  Answer in the same language as the question.
            - If the context includes OWASP references, mention them.
            - Structure your answer with bullet points when appropriate.
            - If the requested information is NOT in the context, say so explicitly.
            - Never fabricate information absent from the context.""")

        user_prompt = textwrap.dedent(f"""\
            ## Context extracted from the report
            {context}{source_info}

            ## Question
            {question}

            Answer based ONLY on the context above.
            Cite specific vulnerability IDs, endpoints, and severities.""")

        message = client.messages.create(
            model=settings.llm_model,
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        answer = message.content[0].text
        logger.info("Answer generated with Claude API")
        return answer

    except Exception as exc:
        logger.error("LLM API error: %s, falling back to simple answer", exc)
        return _answer_simple(question, [context], retrieved)


def _answer_simple(
    question: str,
    relevant_texts: list[str],
    retrieved: list[RetrievedContext] | None = None,
) -> str:
    """Format retrieved context as a structured answer without an LLM.

    Numbers the relevant chunks and extracts section headers when available.
    """
    parts: list[str] = [
        f"**Question :** {question}",
        "",
        "Voici les extraits pertinents trouves dans le rapport :",
        "",
    ]

    for idx, chunk_text in enumerate(relevant_texts, 1):
        # Extract a heading from the chunk if present
        heading_match = re.match(r"^(#{1,3}\s+.+)", chunk_text)
        label = heading_match.group(1) if heading_match else f"Extrait {idx}"

        # Add source attribution if we have retrieval metadata
        source_tag = ""
        if retrieved and idx <= len(retrieved):
            ctx = retrieved[idx - 1]
            source_tag = f" *(source: {ctx.source}, score: {ctx.score:.2f})*"

        parts.append(f"### {label}{source_tag}")
        parts.append("")
        parts.append(chunk_text)
        parts.append("")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _simple_chunk(text: str, chunk_size: int = 500) -> list[str]:
    """Emergency fallback: split by ``##`` headings then by size."""
    pattern = re.compile(r"^(##\s+.+)$", re.MULTILINE)
    positions = [m.start() for m in pattern.finditer(text)]

    if not positions:
        # No headings -- split by paragraphs
        paragraphs = re.split(r"\n\s*\n", text)
        return [p.strip() for p in paragraphs if p.strip()]

    sections: list[str] = []
    if positions[0] > 0:
        preamble = text[: positions[0]].strip()
        if preamble:
            sections.append(preamble)

    for idx, pos in enumerate(positions):
        end = positions[idx + 1] if idx + 1 < len(positions) else len(text)
        section = text[pos:end].strip()
        if section:
            if len(section) <= chunk_size:
                sections.append(section)
            else:
                # Split oversized sections at sentence boundaries
                raw = re.split(r"(?<=[.!?:;])\s+", section)
                current: list[str] = []
                current_len = 0
                for sent in raw:
                    sent = sent.strip()
                    if not sent:
                        continue
                    if current and current_len + len(sent) + 1 > chunk_size:
                        sections.append(" ".join(current))
                        current = [sent]
                        current_len = len(sent)
                    else:
                        current.append(sent)
                        current_len += len(sent) + 1
                if current:
                    sections.append(" ".join(current))

    return [s for s in sections if s.strip()]
