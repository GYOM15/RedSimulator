"""Point d'entree du module reporter.

Usage: python -m src.reporter

Loads fixture data, generates a report, indexes it with the full RAG
pipeline (FAISS + knowledge graph), and tests a set of questions including
graph-aware queries.
"""

import json
from pathlib import Path

from src.infra.config import settings
from src.infra.logging import get_logger, setup_logging
from src.models import AttackPlan, AttackResult, ScanResult

from .rag import ask_report, index_report
from .report_generator import generate_report

setup_logging(level=settings.log_level, fmt=settings.log_format)
logger = get_logger(__name__)

data_dir = Path(__file__).parent.parent.parent / "data" / "fixtures"

scan = ScanResult.model_validate(json.loads((data_dir / "scan_result.json").read_text()))
plan = AttackPlan.model_validate(json.loads((data_dir / "attack_plan.json").read_text()))
results = AttackResult.model_validate(json.loads((data_dir / "attack_result.json").read_text()))

# Generer le rapport
report = generate_report(scan, plan, results)
logger.info("Rapport genere:\n%s", report)

# Indexer avec toutes les donnees (active le knowledge graph)
logger.info("Test du chatbot RAG (mode complet : vector + knowledge graph)")
n_chunks = index_report(report, scan=scan, plan=plan, results=results)
logger.info("Nombre de chunks indexes: %d", n_chunks)

# Tester des questions variees, y compris des questions graph-aware
questions = [
    # Questions classiques (vector search)
    "Quelles sont les vulnerabilites critiques trouvees ?",
    "L'injection SQL a-t-elle reussi ?",
    "Quelles sont les recommandations pour le XSS ?",
    # Questions graph-aware (knowledge graph)
    "What vulnerabilities affect the login endpoint?",
    "Quels sont les vecteurs d'attaque de severite HIGH ?",
    "Quelles sont les remediations prioritaires ?",
]

for q in questions:
    answer = ask_report(q)
    logger.info("Q: %s", q)
    logger.info("R: %s", answer[:300])
