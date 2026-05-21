"""Point d'entree du module generator.

Usage: python -m src.generator
"""

from pathlib import Path

import torch

from .vae_model import PayloadVAE
from .generate import generate_from_fixture

data_dir = Path(__file__).parent.parent.parent / "data"
model_path = data_dir / "vae_model.pt"
fixture_path = data_dir / "fixtures" / "attack_plan.json"

model = PayloadVAE()

if model_path.exists():
    print(f"[GENERATOR] Chargement du modele depuis {model_path}")
    model.load_state_dict(torch.load(model_path, weights_only=True))
else:
    print("[GENERATOR] Modele non trouve, utilisation du modele non entraine")
    print("[GENERATOR] Lancez d'abord: python -m src.generator.train")

generate_from_fixture(model, fixture_path)
