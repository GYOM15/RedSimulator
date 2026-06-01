"""Point d'entree du module generator.

Usage: python -m src.generator
"""

from pathlib import Path

import torch

from src.infra.config import settings
from src.infra.logging import get_logger, setup_logging

from .vae_model import PayloadVAE
from .generate import generate_from_fixture

setup_logging()
logger = get_logger(__name__)

data_dir = Path(__file__).parent.parent.parent / "data"
model_path = Path(settings.vae_model_path)
if not model_path.is_absolute():
    model_path = data_dir.parent / model_path
fixture_path = data_dir / "fixtures" / "attack_plan.json"

model = PayloadVAE()

if model_path.exists():
    logger.info("Chargement du modele depuis %s", model_path)
    model.load_state_dict(torch.load(model_path, weights_only=True))
else:
    logger.warning("Modele non trouve, utilisation du modele non entraine")
    logger.warning("Lancez d'abord: python -m src.generator.train")

generate_from_fixture(model, fixture_path)
