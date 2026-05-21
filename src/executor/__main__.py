"""Point d'entree du module executor.

Usage: python -m src.executor [--fixtures]
"""

import json
import sys
from pathlib import Path

from src.models import AttackPlan, AttackResult, PayloadResult

from .runner import AttackExecutor

if "--fixture" in sys.argv or "--fixtures" in sys.argv:
    print("=== Mode fixture ===")
    result = AttackExecutor.from_fixtures()
else:
    data_dir = Path(__file__).parent.parent.parent / "data" / "fixtures"
    plan_data = json.loads((data_dir / "attack_plan.json").read_text())
    payload_data = json.loads((data_dir / "payload_result.json").read_text())

    plan = AttackPlan.model_validate(plan_data)
    payloads = PayloadResult.model_validate(payload_data)

    executor = AttackExecutor("http://localhost:3000")
    result = executor.execute_all(plan, payloads)

print("\n=== Resultats ===")
print(result.model_dump_json(indent=2))
