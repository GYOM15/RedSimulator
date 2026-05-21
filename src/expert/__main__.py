"""Point d'entree du module expert.

Usage: python -m src.expert
"""

import json
from pathlib import Path

from src.models import ScanResult

from .facts import scan_result_to_facts
from .engine import ExpertEngine
from .rules import get_all_rules

fixture_path = Path(__file__).parent.parent.parent / "data" / "fixtures" / "scan_result.json"
data = json.loads(fixture_path.read_text())
scan = ScanResult.model_validate(data)

print("=== Systeme Expert — Chainage Avant ===\n")

# Etape 1: Convertir le scan en faits
facts = scan_result_to_facts(scan)

# Etape 2: Creer le moteur et charger les regles
engine = ExpertEngine()
engine.inject_facts(facts)
engine.load_rules(get_all_rules())

# Etape 3: Lancer le chainage avant
plan = engine.run()

# Etape 4: Afficher le resultat
print("\n=== Plan d'Attaque Genere ===")
print(plan.model_dump_json(indent=2))
