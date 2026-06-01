"""Chatbot RAG pour explorer le rapport de vulnerabilites.

Indexe le rapport dans ChromaDB et repond aux questions en
cherchant les chunks similaires et en generant une reponse.
"""

import contextlib
import math
import re
import textwrap
from collections import Counter

from src.infra.config import settings
from src.infra.decorators import logged
from src.infra.logging import get_logger

logger = get_logger(__name__)

# Collection ChromaDB pour le rapport
_collection = None
_chunks: list[str] = []

# IDF scores computed at indexing time for the keyword fallback
_idf_scores: dict[str, float] = {}

# Terms that receive a scoring boost in keyword search
_BOOST_TERMS: set[str] = {
    # Severity levels
    "critical",
    "high",
    "medium",
    "low",
    "critique",
    "eleve",
    "moyen",
    "faible",
    # Vulnerability types
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
    # Action words
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


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------


def _split_by_sections(text: str) -> list[str]:
    """Split markdown text by ## headings, keeping each heading with its body.

    Falls back to the full text as a single section when no headings are found.
    """
    # Match lines starting with ## (level-2 headings)
    pattern = re.compile(r"^(##\s+.+)$", re.MULTILINE)
    positions = [m.start() for m in pattern.finditer(text)]

    if not positions:
        return [text]

    sections: list[str] = []
    # Text before the first heading (if any)
    if positions[0] > 0:
        preamble = text[: positions[0]].strip()
        if preamble:
            sections.append(preamble)

    for idx, pos in enumerate(positions):
        end = positions[idx + 1] if idx + 1 < len(positions) else len(text)
        section = text[pos:end].strip()
        if section:
            sections.append(section)

    return sections


def _sentence_boundary_split(text: str, max_size: int, overlap_sentences: int = 2) -> list[str]:
    """Split a text block into chunks at sentence boundaries with overlap.

    Each chunk respects *max_size* characters (best-effort) and overlaps
    with the next chunk by *overlap_sentences* sentences for continuity.
    """
    # Split on sentence-ending punctuation followed by whitespace
    raw_sentences = re.split(r"(?<=[.!?:;])\s+", text)
    sentences = [s.strip() for s in raw_sentences if s.strip()]

    if not sentences:
        return [text] if text.strip() else []

    chunks: list[str] = []
    start_idx = 0

    while start_idx < len(sentences):
        current_chunk: list[str] = []
        current_len = 0

        idx = start_idx
        while idx < len(sentences):
            sent = sentences[idx]
            addition = len(sent) + (1 if current_chunk else 0)
            if current_chunk and current_len + addition > max_size:
                break
            current_chunk.append(sent)
            current_len += addition
            idx += 1

        if current_chunk:
            chunks.append(" ".join(current_chunk))

        # Advance by (consumed - overlap) but at least 1 sentence
        consumed = idx - start_idx
        advance = max(consumed - overlap_sentences, 1)
        start_idx += advance

    return chunks


def _chunk_text(text: str, chunk_size: int = 500, overlap_sentences: int = 2) -> list[str]:
    """Decoupe le texte en chunks par section Markdown puis par taille.

    Strategy:
    1. Split the report by ``##`` headings so each section is self-contained.
    2. For sections larger than *chunk_size*, further split at sentence
       boundaries with *overlap_sentences* sentences of overlap.
    3. Prepend the section header to sub-chunks so they keep context.

    Args:
        text: Texte a decouper.
        chunk_size: Taille maximale de chaque chunk (en caracteres).
        overlap_sentences: Nombre de phrases de chevauchement entre sous-chunks.

    Returns:
        Liste de chunks de texte.
    """
    sections = _split_by_sections(text)
    chunks: list[str] = []

    for section in sections:
        if len(section) <= chunk_size:
            chunks.append(section)
            continue

        # Extract the heading line (if present) to prepend to sub-chunks
        heading = ""
        body = section
        first_line_match = re.match(r"^(##\s+.+)\n", section)
        if first_line_match:
            heading = first_line_match.group(1)
            body = section[first_line_match.end() :]

        sub_chunks = _sentence_boundary_split(body, chunk_size, overlap_sentences)
        for sc in sub_chunks:
            if heading:
                chunks.append(f"{heading}\n\n{sc}")
            else:
                chunks.append(sc)

    return [c for c in chunks if c.strip()]


# ---------------------------------------------------------------------------
# TF-IDF helpers for the keyword fallback
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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@logged
def index_report(report_text: str) -> int:
    """Indexe le rapport dans ChromaDB.

    Decoupe le rapport en chunks et les stocke dans une collection ChromaDB.

    Args:
        report_text: Texte du rapport Markdown.

    Returns:
        Nombre de chunks indexes.
    """
    global _collection, _chunks, _idf_scores

    logger.info("Indexation du rapport dans ChromaDB...")

    _chunks = _chunk_text(report_text)
    _idf_scores = _build_idf(_chunks)
    logger.debug("%d chunks crees", len(_chunks))

    try:
        import chromadb

        client = chromadb.Client()

        # Supprimer la collection existante si elle existe
        with contextlib.suppress(Exception):
            client.delete_collection("report")

        _collection = client.create_collection(
            name="report",
            metadata={"hnsw:space": "cosine"},
        )

        # Ajouter les chunks
        _collection.add(
            documents=_chunks,
            ids=[f"chunk-{i}" for i in range(len(_chunks))],
            metadatas=[{"index": i} for i in range(len(_chunks))],
        )

        logger.info("%d chunks indexes dans ChromaDB", len(_chunks))

    except ImportError:
        logger.warning("ChromaDB non installe, utilisation du fallback en memoire")
    except Exception as e:
        logger.error("Erreur ChromaDB: %s, fallback en memoire", e)

    return len(_chunks)


@logged
def ask_report(question: str) -> str:
    """Repond a une question sur le rapport.

    Cherche les chunks les plus similaires dans ChromaDB,
    puis genere une reponse avec Claude ou un fallback simple.

    Args:
        question: Question de l'utilisateur.

    Returns:
        Reponse generee.
    """
    logger.info("Question: %s", question)

    # Chercher les chunks similaires
    relevant_chunks = _search_chunks(question, n_results=3)

    if not relevant_chunks:
        return "Aucune information trouvee dans le rapport pour cette question."

    context = "\n\n---\n\n".join(relevant_chunks)
    logger.debug("%d chunks pertinents trouves", len(relevant_chunks))

    # Generer la reponse
    api_key = settings.anthropic_api_key or ""
    if api_key and not api_key.startswith("sk-ant-..."):
        return _answer_with_llm(question, context, api_key)
    else:
        return _answer_simple(question, relevant_chunks)


def _search_chunks(question: str, n_results: int = 3) -> list[str]:
    """Cherche les chunks les plus similaires a la question."""
    global _collection, _chunks

    if _collection is not None:
        try:
            results = _collection.query(
                query_texts=[question],
                n_results=min(n_results, len(_chunks)),
            )
            return results["documents"][0] if results["documents"] else []
        except Exception as e:
            logger.error("Erreur de recherche ChromaDB: %s", e)

    # Fallback : TF-IDF keyword scoring
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


def _answer_with_llm(question: str, context: str, api_key: str) -> str:
    """Genere une reponse avec Claude API."""
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)

        system_prompt = textwrap.dedent("""\
            Tu es un assistant specialise en securite informatique.
            Tu reponds aux questions en te basant UNIQUEMENT sur le contexte fourni,
            extrait d'un rapport de test d'intrusion.

            Regles :
            - Reponds de maniere precise et concise, en francais.
            - Cite les sections ou les identifiants de vulnerabilites specifiques du rapport.
            - Si l'information demandee n'est PAS dans le contexte, dis-le explicitement.
            - Ne fabrique jamais d'information absente du contexte.
            - Structure ta reponse avec des listes a puces quand c'est pertinent.""")

        user_prompt = textwrap.dedent(f"""\
            ## Contexte extrait du rapport

            {context}

            ## Question

            {question}

            Reponds en te basant uniquement sur le contexte ci-dessus.
            Cite les elements specifiques (ID de vulnerabilite, endpoints, severites) pour appuyer ta reponse.""")

        message = client.messages.create(
            model=settings.llm_model,
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        answer = message.content[0].text
        logger.info("Reponse generee avec Claude API")
        return answer

    except Exception as e:
        logger.error("Erreur API: %s, fallback simple", e)
        return _answer_simple(question, [context])


def _answer_simple(question: str, relevant_chunks: list[str]) -> str:
    """Genere une reponse simple sans LLM.

    Formats the relevant chunks with numbering and their section headers
    so the user can trace back to the report.
    """
    parts: list[str] = [
        f"**Question :** {question}",
        "",
        "Voici les extraits pertinents trouves dans le rapport :",
        "",
    ]
    for idx, chunk in enumerate(relevant_chunks, 1):
        # Extract a heading from the chunk if present
        heading_match = re.match(r"^(#{1,3}\s+.+)", chunk)
        label = heading_match.group(1) if heading_match else f"Extrait {idx}"
        parts.append(f"### {label}")
        parts.append("")
        parts.append(chunk)
        parts.append("")

    return "\n".join(parts)


if __name__ == "__main__":
    import json
    from pathlib import Path

    from src.infra.logging import setup_logging

    setup_logging(level=settings.log_level, fmt=settings.log_format)

    from src.models import AttackPlan, AttackResult, ScanResult

    from .report_generator import generate_report

    data_dir = Path(__file__).parent.parent.parent / "data" / "fixtures"

    scan = ScanResult.model_validate(json.loads((data_dir / "scan_result.json").read_text()))
    plan = AttackPlan.model_validate(json.loads((data_dir / "attack_plan.json").read_text()))
    results = AttackResult.model_validate(json.loads((data_dir / "attack_result.json").read_text()))

    # Generer et indexer le rapport
    report = generate_report(scan, plan, results)
    index_report(report)

    # Tester quelques questions
    questions = [
        "Quelles sont les vulnerabilites critiques trouvees ?",
        "L'injection SQL a-t-elle reussi ?",
        "Quelles sont les recommandations pour le XSS ?",
    ]

    for q in questions:
        answer = ask_report(q)
        logger.info("Q: %s", q)
        logger.info("R: %s", answer[:300])
