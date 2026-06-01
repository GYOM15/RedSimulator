"""Point d'entree du module expert.

Usage: python -m src.expert
"""

import json
from pathlib import Path

from src.infra.logging import get_logger, setup_logging
from src.models import ScanResult

from .engine import ExpertEngine
from .facts import scan_result_to_facts
from .rules import get_all_rules

setup_logging()
logger = get_logger(__name__)

fixture_path = Path(__file__).parent.parent.parent / "data" / "fixtures" / "scan_result.json"
data = json.loads(fixture_path.read_text())
scan = ScanResult.model_validate(data)

logger.info("=== Systeme Expert — Chainage Avant ===")

# Etape 1: Convertir le scan en faits
facts = scan_result_to_facts(scan)

# Etape 2: Creer le moteur et charger les regles
engine = ExpertEngine()
engine.inject_facts(facts)
engine.load_rules(get_all_rules())

# Etape 3: Lancer le chainage avant (with optional LLM second pass)
plan = engine.run(scan=scan)

# Etape 4: Afficher le resultat
logger.info("=== Plan d'Attaque Genere ===")
logger.info(plan.model_dump_json(indent=2))
