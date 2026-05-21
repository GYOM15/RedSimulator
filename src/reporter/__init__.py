"""Module Reporter — Generation de rapports et chatbot RAG.

Genere un rapport Markdown des vulnerabilites trouvees et
offre un chatbot RAG pour explorer le rapport interactivement.
"""

from .report_generator import generate_report
from .rag_chatbot import index_report, ask_report

__all__ = ["generate_report", "index_report", "ask_report"]
