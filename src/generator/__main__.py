"""Point d'entree du module generator.

Usage: python -m src.generator
"""

import json
from pathlib import Path

from src.infra.config import settings
from src.infra.logging import get_logger, setup_logging
from src.models import AttackPlan

from .generate import generate_for_plan

setup_logging(settings.log_level, settings.log_format)
logger = get_logger(__name__)

data_dir = Path(__file__).parent.parent.parent / "data"
fixture_path = data_dir / "fixtures" / "attack_plan.json"

if not fixture_path.exists():
    logger.error("Fixture non trouvee: %s", fixture_path)
    raise SystemExit(1)

logger.info("Chargement du plan d'attaque depuis %s", fixture_path)

data = json.loads(fixture_path.read_text())
plan = AttackPlan.model_validate(data)

result = generate_for_plan(plan)

logger.info("Resultats: %d payloads generes", len(result.payloads))
for gp in result.payloads:
    logger.info("  [%s] %s -> %d variantes", gp.vector_id, gp.original[:40], len(gp.variants))
