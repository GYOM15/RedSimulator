"""Point d'entree du module executor.

Usage: python -m src.executor [--fixtures]
"""

import json
import sys
from pathlib import Path

from src.infra.config import settings
from src.infra.logging import get_logger, setup_logging
from src.models import AttackPlan, PayloadResult

from .runner import AttackExecutor

setup_logging(level=settings.log_level, fmt=settings.log_format)
logger = get_logger(__name__)

if "--fixture" in sys.argv or "--fixtures" in sys.argv:
    logger.info("Mode fixture")
    result = AttackExecutor.from_fixtures()
else:
    data_dir = Path(__file__).parent.parent.parent / "data" / "fixtures"
    plan_data = json.loads((data_dir / "attack_plan.json").read_text())
    payload_data = json.loads((data_dir / "payload_result.json").read_text())

    plan = AttackPlan.model_validate(plan_data)
    payloads = PayloadResult.model_validate(payload_data)

    executor = AttackExecutor(settings.target_url)
    result = executor.execute_all(plan, payloads)

logger.info("Resultats:\n%s", result.model_dump_json(indent=2))
