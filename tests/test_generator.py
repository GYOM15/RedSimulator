"""Tests du module generateur VAE.

Verifie que le VAE compile, que l'entrainement reduit la loss,
et que les variantes generees sont differentes du payload de base.
"""

import torch

from src.generator.generate import generate_variants
from src.generator.vae_model import (
    MAX_LEN,
    VOCAB_SIZE,
    PayloadVAE,
    decode_indices,
    encode_payload,
    vae_loss,
)


class TestVAEModel:
    """Tests de l'architecture du VAE."""

    def test_model_compiles(self):
        model = PayloadVAE()
        assert model is not None

    def test_forward_shapes(self):
        model = PayloadVAE()
        batch = torch.tensor([encode_payload("' OR 1=1--")])
        logits, mu, logvar = model(batch)

        assert logits.shape == (1, MAX_LEN, VOCAB_SIZE)
        assert mu.shape == (1, 16)  # latent_dim = 16
        assert logvar.shape == (1, 16)

    def test_encode_decode_roundtrip(self):
        payload = "' OR 1=1--"
        encoded = encode_payload(payload)
        decoded = decode_indices(encoded)
        assert decoded == payload

    def test_loss_computes(self):
        model = PayloadVAE()
        batch = torch.tensor([encode_payload("test")])
        logits, mu, logvar = model(batch)
        total, recon, kl = vae_loss(logits, batch, mu, logvar)

        assert total.item() > 0
        assert recon.item() > 0
        assert kl.item() >= 0


class TestTraining:
    """Tests de l'entrainement."""

    def test_training_reduces_loss(self):
        """Verifie que quelques epochs reduisent la loss."""
        model = PayloadVAE()
        optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)

        payloads = ["' OR 1=1--", "admin'--", "' OR '1'='1'--"]
        batch = torch.tensor([encode_payload(p) for p in payloads])

        # Premiere loss
        model.train()
        logits, mu, logvar = model(batch)
        initial_loss, _, _ = vae_loss(logits, batch, mu, logvar)
        initial_loss_val = initial_loss.item()

        # Entrainer 20 epochs
        for _ in range(20):
            optimizer.zero_grad()
            logits, mu, logvar = model(batch)
            loss, _, _ = vae_loss(logits, batch, mu, logvar)
            loss.backward()
            optimizer.step()

        # Loss finale
        logits, mu, logvar = model(batch)
        final_loss, _, _ = vae_loss(logits, batch, mu, logvar)
        final_loss_val = final_loss.item()

        assert final_loss_val < initial_loss_val, (
            f"La loss devrait diminuer: {initial_loss_val:.4f} → {final_loss_val:.4f}"
        )


class TestGeneration:
    """Tests de la generation de variantes."""

    def test_generate_returns_list(self):
        model = PayloadVAE()
        variants = generate_variants(model, "' OR 1=1--", n_variants=3)
        assert isinstance(variants, list)

    def test_variants_differ_from_base(self):
        """Les variantes doivent etre differentes du payload de base."""
        model = PayloadVAE()
        base = "' OR 1=1--"
        variants = generate_variants(model, base, n_variants=5, temperature=1.0)
        for v in variants:
            assert v != base, f"Variante identique au base: {v}"
