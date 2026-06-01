"""Architecture du Variational Autoencoder (VAE) pour les payloads.

Le VAE apprend une representation latente des payloads de securite
et peut generer des variantes en echantillonnant autour d'un point
dans l'espace latent.

Architecture :
- Embedding : caracteres ASCII → vecteurs denses (embed_dim=32)
- Encodeur : GRU (embed_dim → hidden_dim=128) → mu, logvar (latent_dim=16)
- Decodeur : linear(latent_dim → hidden_dim) + GRU → output(hidden_dim → vocab_size)
"""

import string

import torch
import torch.nn as nn
import torch.nn.functional as F

from src.infra.config import settings
from src.infra.logging import get_logger

logger = get_logger(__name__)


# Vocabulaire : tous les caracteres ASCII imprimables + padding + start + end
VOCAB_CHARS = list(string.printable)
PAD_TOKEN = "<PAD>"
START_TOKEN = "<START>"
END_TOKEN = "<END>"

SPECIAL_TOKENS = [PAD_TOKEN, START_TOKEN, END_TOKEN]
FULL_VOCAB = SPECIAL_TOKENS + VOCAB_CHARS

CHAR_TO_IDX = {ch: i for i, ch in enumerate(FULL_VOCAB)}
IDX_TO_CHAR = {i: ch for i, ch in enumerate(FULL_VOCAB)}

VOCAB_SIZE = len(FULL_VOCAB)
PAD_IDX = CHAR_TO_IDX[PAD_TOKEN]
START_IDX = CHAR_TO_IDX[START_TOKEN]
END_IDX = CHAR_TO_IDX[END_TOKEN]

MAX_LEN = 128

# Dimensions du modele
EMBED_DIM = 32
HIDDEN_DIM = 128
LATENT_DIM = settings.vae_latent_dim


def encode_payload(payload: str) -> list[int]:
    """Encode un payload en liste d'indices.

    Ajoute START et END tokens, puis padde jusqu'a MAX_LEN.
    """
    indices = [START_IDX]
    for ch in payload[: MAX_LEN - 2]:
        indices.append(CHAR_TO_IDX.get(ch, CHAR_TO_IDX[" "]))
    indices.append(END_IDX)

    # Padding
    while len(indices) < MAX_LEN:
        indices.append(PAD_IDX)

    return indices


def decode_indices(indices: list[int]) -> str:
    """Decode une liste d'indices en string.

    S'arrete au premier END token ou PAD token.
    """
    chars = []
    for idx in indices:
        if idx in (END_IDX, PAD_IDX):
            break
        if idx == START_IDX:
            continue
        ch = IDX_TO_CHAR.get(idx, "?")
        chars.append(ch)
    return "".join(chars)


class PayloadVAE(nn.Module):
    """Variational Autoencoder pour la generation de payloads.

    Utilise des GRU pour l'encodeur et le decodeur, avec un
    espace latent de dimension LATENT_DIM.
    """

    def __init__(
        self,
        vocab_size: int = VOCAB_SIZE,
        embed_dim: int = EMBED_DIM,
        hidden_dim: int = HIDDEN_DIM,
        latent_dim: int = LATENT_DIM,
    ):
        super().__init__()

        self.vocab_size = vocab_size
        self.embed_dim = embed_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim

        # Embedding partage
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=PAD_IDX)

        # Encodeur GRU
        self.encoder_gru = nn.GRU(embed_dim, hidden_dim, batch_first=True, bidirectional=False)

        # Couches pour mu et logvar
        self.fc_mu = nn.Linear(hidden_dim, latent_dim)
        self.fc_logvar = nn.Linear(hidden_dim, latent_dim)

        # Decodeur
        self.latent_to_hidden = nn.Linear(latent_dim, hidden_dim)
        self.decoder_gru = nn.GRU(embed_dim, hidden_dim, batch_first=True, bidirectional=False)
        self.output_layer = nn.Linear(hidden_dim, vocab_size)

    def encode(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        """Encode une sequence en vecteurs mu et logvar.

        Args:
            x: Tensor de shape (batch, seq_len) avec les indices des caracteres.

        Returns:
            Tuple (mu, logvar) chacun de shape (batch, latent_dim).
        """
        embedded = self.embedding(x)  # (batch, seq_len, embed_dim)
        _, hidden = self.encoder_gru(embedded)  # hidden: (1, batch, hidden_dim)
        hidden = hidden.squeeze(0)  # (batch, hidden_dim)

        mu = self.fc_mu(hidden)  # (batch, latent_dim)
        logvar = self.fc_logvar(hidden)  # (batch, latent_dim)

        return mu, logvar

    def reparameterize(self, mu: torch.Tensor, logvar: torch.Tensor) -> torch.Tensor:
        """Reparameterization trick : z = mu + std * epsilon.

        Args:
            mu: Moyenne de la distribution latente.
            logvar: Log-variance de la distribution latente.

        Returns:
            Echantillon z de l'espace latent.
        """
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std

    def decode(self, z: torch.Tensor, target: torch.Tensor | None = None) -> torch.Tensor:
        """Decode un vecteur latent en sequence de logits.

        Args:
            z: Vecteur latent de shape (batch, latent_dim).
            target: Sequence cible pour le teacher forcing (batch, seq_len).

        Returns:
            Logits de shape (batch, seq_len, vocab_size).
        """
        hidden = self.latent_to_hidden(z).unsqueeze(0)  # (1, batch, hidden_dim)

        if target is not None:
            # Teacher forcing : utiliser la sequence cible comme entree
            embedded = self.embedding(target)  # (batch, seq_len, embed_dim)
            output, _ = self.decoder_gru(embedded, hidden)  # (batch, seq_len, hidden_dim)
            logits = self.output_layer(output)  # (batch, seq_len, vocab_size)
        else:
            # Generation auto-regressive
            batch_size = z.shape[0]
            input_token = torch.full((batch_size, 1), START_IDX, dtype=torch.long, device=z.device)
            outputs = []

            for _ in range(MAX_LEN):
                embedded = self.embedding(input_token)  # (batch, 1, embed_dim)
                output, hidden = self.decoder_gru(embedded, hidden)
                logits = self.output_layer(output)  # (batch, 1, vocab_size)
                outputs.append(logits)

                # Prochain token = argmax
                input_token = logits.argmax(dim=-1)  # (batch, 1)

            logits = torch.cat(outputs, dim=1)  # (batch, seq_len, vocab_size)

        return logits

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Forward pass complet : encode → reparameterize → decode.

        Args:
            x: Tensor de shape (batch, seq_len) avec les indices des caracteres.

        Returns:
            Tuple (logits, mu, logvar).
        """
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        logits = self.decode(z, target=x)
        return logits, mu, logvar


def vae_loss(
    logits: torch.Tensor,
    targets: torch.Tensor,
    mu: torch.Tensor,
    logvar: torch.Tensor,
    kl_weight: float = 0.1,
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    """Calcule la loss du VAE : reconstruction + KL divergence.

    Args:
        logits: Predictions du decodeur (batch, seq_len, vocab_size).
        targets: Sequence cible (batch, seq_len).
        mu: Moyenne latente.
        logvar: Log-variance latente.
        kl_weight: Poids de la KL divergence (beta-VAE).

    Returns:
        Tuple (total_loss, recon_loss, kl_loss).
    """
    # Reconstruction loss (cross-entropy)
    _batch_size, _seq_len, vocab_size = logits.shape
    recon_loss = F.cross_entropy(
        logits.reshape(-1, vocab_size),
        targets.reshape(-1),
        ignore_index=PAD_IDX,
    )

    # KL divergence
    kl_loss = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp())

    total_loss = recon_loss + kl_weight * kl_loss
    return total_loss, recon_loss, kl_loss


if __name__ == "__main__":
    logger.info("=== Test du modele VAE ===")

    model = PayloadVAE()
    logger.info("Parametres: %s", f"{sum(p.numel() for p in model.parameters()):,}")

    # Test avec un batch de payloads
    payloads = ["' OR 1=1--", "admin'--", "<script>alert(1)</script>"]
    batch = torch.tensor([encode_payload(p) for p in payloads])
    logger.info("Input shape: %s", batch.shape)

    logits, mu, logvar = model(batch)
    logger.info("Output shape: %s", logits.shape)
    logger.info("Mu shape: %s", mu.shape)
    logger.info("Logvar shape: %s", logvar.shape)

    total, recon, kl = vae_loss(logits, batch, mu, logvar)
    logger.info("Loss: total=%.4f, recon=%.4f, kl=%.4f", total, recon, kl)
