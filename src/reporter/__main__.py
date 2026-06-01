"""Point d'entree du module reporter.

Usage: python -m src.reporter
"""

import json
from pathlib import Path

from src.infra.config import settings
from src.infra.logging import get_logger, setup_logging
from src.models import AttackPlan, AttackResult, ScanResult

from .report_generator import generate_report
from .rag_chatbot import index_report, ask_report

setup_logging(level=settings.log_level, fmt=settings.log_format)
logger = get_logger(__name__)

data_dir = Path(__file__).parent.parent.parent / "data" / "fixtures"

scan = ScanResult.model_validate(json.loads((data_dir / "scan_result.json").read_text()))
plan = AttackPlan.model_validate(json.loads((data_dir / "attack_plan.json").read_text()))
results = AttackResult.model_validate(json.loads((data_dir / "attack_result.json").read_text()))

# Generer le rapport
report = generate_report(scan, plan, results)
logger.info("Rapport genere:\n%s", report)

# Indexer et tester le RAG
logger.info("Test du chatbot RAG")
index_report(report)

questions = [
    "Quelles sont les vulnerabilites critiques trouvees ?",
    "L'injection SQL a-t-elle reussi ?",
    "Quelles sont les recommandations pour le XSS ?",
]

for q in questions:
    answer = ask_report(q)
    logger.info("Q: %s", q)
    logger.info("R: %s", answer[:300])
