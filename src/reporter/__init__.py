"""Module Reporter — Generation de rapports et chatbot RAG.

Genere un rapport Markdown des vulnerabilites trouvees et
offre un chatbot RAG pour explorer le rapport interactivement.

The RAG subsystem supports three modes of operation:

- **Full mode:** FAISS vector search + knowledge graph + Claude LLM
- **Partial mode:** FAISS only (no knowledge graph data provided)
- **Degraded mode:** TF-IDF keyword search + context dump (no FAISS / no API key)
"""

from .rag import ask_report, index_report
from .report_generator import generate_report

__all__ = ["ask_report", "generate_report", "index_report"]
