"""Generation de variantes de payloads avec le VAE.

Encode un payload de base, echantillonne autour de son vecteur latent,
et decode pour obtenir des variantes syntaxiquement proches mais differentes.
"""

from pathlib import Path

import torch

from .vae_model import (
    PayloadVAE,
    encode_payload,
    decode_indices,
    MAX_LEN,
    START_IDX,
)


def generate_variants(
    model: PayloadVAE,
    base_payload: str,
    n_variants: int = 5,
    temperature: float = 0.5,
    noise_scale: float = 0.5,
) -> list[str]:
    """Genere des variantes d'un payload en echantillonnant autour de son embedding latent.

    Args:
        model: Modele VAE entraine.
        base_payload: Payload de base a varier.
        n_variants: Nombre de variantes a generer.
        temperature: Temperature pour le sampling (plus haut = plus divers).
        noise_scale: Amplitude du bruit ajoute au vecteur latent.

    Returns:
        Liste de variantes uniques et differentes du payload de base.
    """
    model.eval()

    with torch.no_grad():
        # Encoder le payload de base
        encoded = torch.tensor([encode_payload(base_payload)], dtype=torch.long)
        mu, logvar = model.encode(encoded)

        variants = []
        attempts = 0
        max_attempts = n_variants * 5  # Eviter les boucles infinies

        while len(variants) < n_variants and attempts < max_attempts:
            attempts += 1

            # Echantillonner autour du vecteur latent
            noise = torch.randn_like(mu) * noise_scale
            z = mu + noise

            # Decoder avec sampling par temperature
            hidden = model.latent_to_hidden(z).unsqueeze(0)
            input_token = torch.full((1, 1), START_IDX, dtype=torch.long)
            generated_indices = []

            for _ in range(MAX_LEN):
                embedded = model.embedding(input_token)
                output, hidden = model.decoder_gru(embedded, hidden)
                logits = model.output_layer(output).squeeze(1)

                # Appliquer la temperature
                probs = torch.softmax(logits / temperature, dim=-1)
                next_token = torch.multinomial(probs, 1)

                generated_indices.append(next_token.item())
                input_token = next_token.unsqueeze(0) if next_token.dim() == 1 else next_token.view(1, 1)

            # Decoder les indices en texte
            variant = decode_indices(generated_indices)

            # Filtrer : non vide, different du base, pas deja genere
            if (
                variant
                and variant != base_payload
                and variant not in variants
                and len(variant) > 2
            ):
                variants.append(variant)

    return variants


def generate_from_fixture(model: PayloadVAE, fixture_path: str | Path) -> None:
    """Genere des variantes pour chaque payload du plan d'attaque fixture."""
    import json

    from src.models import AttackPlan

    path = Path(fixture_path)
    data = json.loads(path.read_text())
    plan = AttackPlan.model_validate(data)

    print(f"\n{'='*60}")
    print("[GENERATOR] Generation de variantes de payloads")
    print(f"{'='*60}")

    for vector in plan.vectors:
        print(f"\n--- Vecteur {vector.id} ({vector.attack_type.value}) ---")
        for base_payload in vector.base_payloads:
            print(f"\n  Base: {base_payload}")
            variants = generate_variants(model, base_payload, n_variants=3)
            for i, v in enumerate(variants):
                print(f"    Variante {i+1}: {v}")
            if not variants:
                print("    (aucune variante generee — modele pas assez entraine)")


if __name__ == "__main__":
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
