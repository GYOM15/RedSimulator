"""Chatbot RAG pour explorer le rapport de vulnerabilites.

Indexe le rapport dans ChromaDB et repond aux questions en
cherchant les chunks similaires et en generant une reponse.

TODO: Ameliorer le chunking, ajouter le streaming,
    integrer dans le dashboard Streamlit.
"""

import contextlib

from src.infra.config import settings
from src.infra.decorators import logged
from src.infra.logging import get_logger

logger = get_logger(__name__)

# Collection ChromaDB pour le rapport
_collection = None
_chunks: list[str] = []


def _chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> list[str]:
    """Decoupe le texte en chunks avec chevauchement.

    Args:
        text: Texte a decouper.
        chunk_size: Taille maximale de chaque chunk (en caracteres).
        overlap: Chevauchement entre les chunks.

    Returns:
        Liste de chunks de texte.
    """
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        if chunk.strip():
            chunks.append(chunk.strip())
        start = end - overlap
    return chunks


@logged
def index_report(report_text: str) -> int:
    """Indexe le rapport dans ChromaDB.

    Decoupe le rapport en chunks et les stocke dans une collection ChromaDB.

    Args:
        report_text: Texte du rapport Markdown.

    Returns:
        Nombre de chunks indexes.
    """
    global _collection, _chunks

    logger.info("Indexation du rapport dans ChromaDB...")

    _chunks = _chunk_text(report_text)
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

    context = "\n\n".join(relevant_chunks)
    logger.debug("%d chunks pertinents trouves", len(relevant_chunks))

    # Generer la reponse
    api_key = settings.anthropic_api_key or ""
    if api_key and not api_key.startswith("sk-ant-..."):
        return _answer_with_llm(question, context, api_key)
    else:
        return _answer_simple(question, context)


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

    # Fallback : recherche par mots-cles
    if not _chunks:
        return []

    question_words = set(question.lower().split())
    scored = []
    for chunk in _chunks:
        chunk_words = set(chunk.lower().split())
        score = len(question_words & chunk_words)
        scored.append((score, chunk))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [chunk for _, chunk in scored[:n_results] if _ > 0]


def _answer_with_llm(question: str, context: str, api_key: str) -> str:
    """Genere une reponse avec Claude API."""
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)

        prompt = f"""En te basant sur le contexte suivant extrait d'un rapport de securite,
                reponds a la question de maniere precise et concise. Si l'information n'est pas
                dans le contexte, dis-le clairement.

                ## Contexte
                {context}

                ## Question
                {question}"""

        message = client.messages.create(
            model=settings.llm_model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )

        answer = message.content[0].text
        logger.info("Reponse generee avec Claude API")
        return answer

    except Exception as e:
        logger.error("Erreur API: %s, fallback simple", e)
        return _answer_simple(question, context)


def _answer_simple(question: str, context: str) -> str:
    """Genere une reponse simple sans LLM (retourne le contexte pertinent)."""
    return f"Voici les informations pertinentes trouvees dans le rapport :\n\n{context}"


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
