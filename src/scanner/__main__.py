"""Point d'entree du module scanner.

Usage: python3 -m src.scanner [--fixtures]
"""

import sys

from src.infra.logging import setup_logging, get_logger
from src.infra.config import settings
from .agent import ReconAgent

setup_logging(level=settings.log_level, fmt=settings.log_format)
logger = get_logger(__name__)

if "--fixture" in sys.argv or "--fixtures" in sys.argv:
    logger.info("=== Mode fixture ===")
    scan = ReconAgent.from_fixture()
else:
    target = settings.target_url
    agent = ReconAgent(target)
    scan = agent.run()

    # Afficher le raisonnement de l'agent si disponible
    if agent.agent_messages:
        logger.info("=" * 60)
        logger.info("Raisonnement de l'agent:")
        logger.info("=" * 60)
        for step in agent.agent_messages:
            if step["type"] == "think":
                logger.info("  THINK: %s", step['content'][:200])
            elif step["type"] == "act":
                logger.info("  ACT:   %s(%s)", step['tool'], step['args'])
            elif step["type"] == "observe":
                logger.info("  OBS:   %s -> %s", step['tool'], step['content'][:100])

logger.info("=" * 60)
logger.info("Resultat du scan:")
logger.info("=" * 60)
logger.info(scan.model_dump_json(indent=2))
