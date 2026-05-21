"""Point d'entree du module reporter.

Usage: python -m src.reporter
"""

import json
from pathlib import Path

from src.models import AttackPlan, AttackResult, ScanResult

from .report_generator import generate_report
from .rag_chatbot import index_report, ask_report

data_dir = Path(__file__).parent.parent.parent / "data" / "fixtures"

scan = ScanResult.model_validate(json.loads((data_dir / "scan_result.json").read_text()))
plan = AttackPlan.model_validate(json.loads((data_dir / "attack_plan.json").read_text()))
results = AttackResult.model_validate(json.loads((data_dir / "attack_result.json").read_text()))

# Generer le rapport
report = generate_report(scan, plan, results)
print(report)

# Indexer et tester le RAG
print("\n=== Test du chatbot RAG ===\n")
index_report(report)

questions = [
    "Quelles sont les vulnerabilites critiques trouvees ?",
    "L'injection SQL a-t-elle reussi ?",
    "Quelles sont les recommandations pour le XSS ?",
]

for q in questions:
    answer = ask_report(q)
    print(f"Q: {q}")
    print(f"R: {answer[:300]}")
    print()
