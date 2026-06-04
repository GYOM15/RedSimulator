"""Generation intelligente de variantes de payloads via Claude API.

Ce module utilise l'API Anthropic (Claude) pour generer des variantes
semantiquement equivalentes de payloads d'attaque, capables de contourner
les filtres WAF et les mecanismes de protection.
"""

from __future__ import annotations

import re

from src.infra.config import settings
from src.infra.decorators import logged, retry
from src.infra.exceptions import LLMError
from src.infra.llm import is_llm_available, llm_chat
from src.infra.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a security testing payload generator used in an authorized penetration \
testing framework. Your role is to generate semantically equivalent payload variants \
that test WAF bypass techniques. This is for defensive security testing only.

Rules:
- Generate exactly the requested number of variants.
- Each variant must be functionally equivalent to the original.
- Variants should use different evasion techniques (encoding, case variation, \
comment injection, alternative syntax, etc.).
- Output ONLY the payloads, one per line, with no numbering, no quotes, no explanation.
- Do not repeat the original payload.
"""

_USER_PROMPT_TEMPLATE = """\
Attack type: {attack_type}
Original payload: {payload}
{context_line}
Generate {n_variants} semantically equivalent variants that could bypass WAF/filters.
Output only the payloads, one per line:"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_llm_response(response_text: str, original: str) -> list[str]:
    """Parse la reponse LLM et extrait les payloads propres.

    Supprime la numerotation, les guillemets, les backticks et les lignes vides.
    Filtre les doublons et les variants identiques a l'original.
    """
    lines = response_text.strip().splitlines()
    payloads: list[str] = []
    seen: set[str] = set()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Supprimer la numerotation (1. , 1) , - , * , etc.)
        line = re.sub(r"^\d+[\.\)]\s*", "", line)
        line = re.sub(r"^[-*]\s+", "", line)

        # Supprimer les guillemets et backticks englobants
        if (line.startswith('"') and line.endswith('"')) or (
            line.startswith("'") and line.endswith("'")
        ):
            line = line[1:-1]
        if line.startswith("`") and line.endswith("`"):
            line = line[1:-1]

        # Supprimer les blocs de code markdown
        if line.startswith("```"):
            continue

        line = line.strip()
        if not line:
            continue

        # Filtrer les doublons et l'original
        if line != original and line not in seen:
            seen.add(line)
            payloads.append(line)

    return payloads


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@logged
@retry(max_attempts=2, exceptions=(LLMError,))
def mutate_with_llm(
    payload: str,
    attack_type: str,
    n_variants: int = 5,
    context: str = "",
) -> list[str]:
    """Genere des variantes de payload via l'API Claude.

    Args:
        payload: Payload original a varier.
        attack_type: Type d'attaque (sqli, xss, idor, path_traversal, etc.).
        n_variants: Nombre de variantes a generer.
        context: Contexte supplementaire optionnel (endpoint cible, etc.).

    Returns:
        Liste de variantes uniques differentes de l'original.

    Raises:
        LLMError: Si l'appel API echoue.
    """
    if not is_llm_available():
        raise LLMError("Aucun fournisseur LLM disponible")

    context_line = f"Context: {context}\n" if context else ""
    user_prompt = _USER_PROMPT_TEMPLATE.format(
        attack_type=attack_type,
        payload=payload,
        context_line=context_line,
        n_variants=n_variants,
    )

    try:
        response_text = llm_chat(
            messages=[{"role": "user", "content": user_prompt}],
            system=_SYSTEM_PROMPT,
            max_tokens=settings.llm_max_tokens,
        )

        variants = _parse_llm_response(response_text, payload)

        logger.info(
            "LLM mutation: %d variantes generees pour '%s' (type=%s)",
            len(variants),
            payload[:50],
            attack_type,
        )

        return variants[:n_variants]

    except LLMError:
        raise
    except Exception as e:
        raise LLMError(
            f"Erreur inattendue lors de l'appel LLM: {e}",
            details={"payload": payload[:50], "attack_type": attack_type},
        ) from e
