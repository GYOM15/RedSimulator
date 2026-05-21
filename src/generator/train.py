"""Entrainement du VAE sur les payloads SQLi.

Charge le dataset depuis sqli_payloads.txt, encode les payloads,
entraine le VAE et sauvegarde le modele.

Entrainement rapide : 50 epochs max, petit dataset.
TODO: Ameliorer avec SecLists, data augmentation, scheduling du lr.
"""

from pathlib import Path

import torch
from torch.utils.data import DataLoader, TensorDataset

from .vae_model import PayloadVAE, encode_payload, vae_loss


def load_payloads(filepath: str | Path) -> list[str]:
    """Charge les payloads depuis un fichier texte (un par ligne)."""
    path = Path(filepath)
    payloads = []
    for line in path.read_text().strip().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            payloads.append(line)
    print(f"[TRAIN] {len(payloads)} payloads charges depuis {path.name}")
    return payloads


def train_vae(
    payloads: list[str],
    epochs: int = 50,
    batch_size: int = 16,
    lr: float = 1e-3,
    kl_weight: float = 0.1,
    save_path: str | Path | None = None,
) -> PayloadVAE:
    """Entraine le VAE sur les payloads.

    Args:
        payloads: Liste de payloads en texte.
        epochs: Nombre d'epochs.
        batch_size: Taille des batches.
        lr: Learning rate.
        kl_weight: Poids de la KL divergence.
        save_path: Chemin pour sauvegarder le modele.

    Returns:
        Modele entraine.
    """
    print(f"\n[TRAIN] Demarrage de l'entrainement")
    print(f"  - Payloads: {len(payloads)}")
    print(f"  - Epochs: {epochs}")
    print(f"  - Batch size: {batch_size}")
    print(f"  - Learning rate: {lr}")
    print(f"  - KL weight: {kl_weight}")

    # Encoder les payloads
    encoded = [encode_payload(p) for p in payloads]
    tensor_data = torch.tensor(encoded, dtype=torch.long)
    dataset = TensorDataset(tensor_data)
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    # Creer le modele
    model = PayloadVAE()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    print(f"\n[TRAIN] Modele: {sum(p.numel() for p in model.parameters()):,} parametres")
    print()

    model.train()
    for epoch in range(epochs):
        total_loss = 0.0
        total_recon = 0.0
        total_kl = 0.0
        n_batches = 0

        for (batch,) in dataloader:
            optimizer.zero_grad()

            logits, mu, logvar = model(batch)
            loss, recon, kl = vae_loss(logits, batch, mu, logvar, kl_weight)

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            total_loss += loss.item()
            total_recon += recon.item()
            total_kl += kl.item()
            n_batches += 1

        avg_loss = total_loss / n_batches
        avg_recon = total_recon / n_batches
        avg_kl = total_kl / n_batches

        if (epoch + 1) % 5 == 0 or epoch == 0:
            print(
                f"  Epoch {epoch+1:3d}/{epochs} | "
                f"Loss: {avg_loss:.4f} | "
                f"Recon: {avg_recon:.4f} | "
                f"KL: {avg_kl:.4f}"
            )

    # Sauvegarder le modele
    if save_path:
        save_path = Path(save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(model.state_dict(), save_path)
        print(f"\n[TRAIN] Modele sauvegarde dans {save_path}")

    return model


if __name__ == "__main__":
    data_dir = Path(__file__).parent.parent.parent / "data"
    payloads_path = data_dir / "payloads" / "sqli_payloads.txt"
    model_path = data_dir / "vae_model.pt"

    payloads = load_payloads(payloads_path)
    model = train_vae(payloads, epochs=50, save_path=model_path)

    print("\n[TRAIN] Entrainement termine!")
