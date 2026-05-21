"""Module Generateur — VAE PyTorch pour la generation de variantes de payloads.

Utilise un Variational Autoencoder (VAE) avec encodeur/decodeur GRU
pour apprendre la distribution latente des payloads et generer des variantes.
"""

from .vae_model import PayloadVAE
from .generate import generate_variants

__all__ = ["PayloadVAE", "generate_variants"]
