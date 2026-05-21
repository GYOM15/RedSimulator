"""Point d'entree du module scanner.

Usage: python3 -m src.scanner [--fixtures]
"""

import os
import sys

from .agent import ReconAgent

if "--fixture" in sys.argv or "--fixtures" in sys.argv:
    print("=== Mode fixture ===")
    scan = ReconAgent.from_fixture()
else:
    target = os.getenv("TARGET_URL", "http://localhost:3000")
    agent = ReconAgent(target)
    scan = agent.run()

    # Afficher le raisonnement de l'agent si disponible
    if agent.agent_messages:
        print(f"\n{'='*60}")
        print("Raisonnement de l'agent:")
        print(f"{'='*60}")
        for step in agent.agent_messages:
            if step["type"] == "think":
                print(f"\n  THINK: {step['content'][:200]}")
            elif step["type"] == "act":
                print(f"  ACT:   {step['tool']}({step['args']})")
            elif step["type"] == "observe":
                print(f"  OBS:   {step['tool']} -> {step['content'][:100]}")

print(f"\n{'='*60}")
print("Resultat du scan:")
print(f"{'='*60}")
print(scan.model_dump_json(indent=2))
