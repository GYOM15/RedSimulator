"""Module Reporter — Generation de rapports et chatbot RAG.

Genere un rapport Markdown des vulnerabilites trouvees et
offre un chatbot RAG pour explorer le rapport interactivement.
"""

from .rag_chatbot import ask_report, index_report
from .report_generator import generate_report

__all__ = ["ask_report", "generate_report", "index_report"]
