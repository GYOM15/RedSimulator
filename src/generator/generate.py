"""Orchestrateur de generation de variantes de payloads.

Tente d'abord la generation via LLM (Claude API), puis se rabat
sur les mutations deterministes hors-ligne en cas d'echec ou
d'absence de cle API.
"""

from __future__ import annotations

from src.infra.config import settings
from src.infra.decorators import logged, timed
from src.infra.exceptions import LLMError
from src.infra.logging import get_logger
from src.models import AttackPlan, GeneratedPayload, PayloadResult

from .llm_mutator import mutate_with_llm
from .offline_mutator import mutate_payload
from .payload_db import payload_db

logger = get_logger(__name__)


@logged
def generate_variants(
    base_payload: str,
    attack_type: str = "sqli",
    n_variants: int = 5,
) -> list[str]:
    """Genere des variantes d'un payload avec fallback automatique.

    Si une cle API Anthropic est configuree, utilise le LLM pour generer
    des variantes intelligentes. En cas d'echec ou d'absence de cle,
    se rabat sur les mutations deterministes hors-ligne.

    Args:
        base_payload: Payload de base a varier.
        attack_type: Type d'attaque (sqli, xss, idor, path_traversal, etc.).
        n_variants: Nombre de variantes a generer.

    Returns:
        Liste de variantes uniques differentes du payload de base.
    """
    # Tentative LLM si cle API disponible
    if settings.anthropic_api_key:
        try:
            logger.info("Mode LLM: generation via Claude API")
            variants = mutate_with_llm(
                payload=base_payload,
                attack_type=attack_type,
                n_variants=n_variants,
            )
            if variants:
                return variants
            logger.warning("LLM n'a retourne aucune variante, fallback offline")
        except (LLMError, Exception) as e:
            logger.warning("Echec LLM (%s), fallback sur mutations offline", e)
    else:
        logger.info("Mode offline: pas de cle API Anthropic configuree")

    # Fallback : mutations deterministes hors-ligne
    variants = mutate_payload(
        payload=base_payload,
        attack_type=attack_type,
        n_variants=n_variants,
    )

    if not variants:
        logger.warning(
            "Aucune variante generee pour '%s' (type=%s)",
            base_payload[:50],
            attack_type,
        )

    return variants


@logged
@timed
def generate_for_plan(attack_plan: AttackPlan) -> PayloadResult:
    """Genere des variantes de payloads pour un plan d'attaque complet.

    Parcourt chaque vecteur du plan et genere des variantes pour
    chacun de ses payloads de base.

    Args:
        attack_plan: Plan d'attaque contenant les vecteurs et payloads de base.

    Returns:
        PayloadResult contenant tous les payloads generes.
    """
    logger.info("=" * 60)
    logger.info("Generation de variantes de payloads")
    logger.info("=" * 60)

    payloads: list[GeneratedPayload] = []

    for vector in attack_plan.vectors:
        logger.info("--- Vecteur %s (%s) ---", vector.id, vector.attack_type.value)

        # Augment base payloads with database payloads
        db_payloads = payload_db.get(
            vector.attack_type.value,
            limit=settings.max_payloads_per_vector,
        )
        all_base = list(dict.fromkeys(vector.base_payloads + db_payloads))
        logger.info(
            "  Merged %d base + %d db payloads -> %d unique",
            len(vector.base_payloads),
            len(db_payloads),
            len(all_base),
        )

        for base_payload in all_base:
            logger.info("  Base: %s", base_payload)
            variants = generate_variants(
                base_payload=base_payload,
                attack_type=vector.attack_type.value,
                n_variants=5,
            )

            for i, v in enumerate(variants):
                logger.info("    Variante %d: %s", i + 1, v)

            if not variants:
                logger.warning("    (aucune variante generee)")

            payloads.append(
                GeneratedPayload(
                    vector_id=vector.id,
                    original=base_payload,
                    variants=variants,
                )
            )

    result = PayloadResult(payloads=payloads)
    logger.info(
        "Generation terminee: %d payloads generes pour %d vecteurs",
        len(payloads),
        len(attack_plan.vectors),
    )
    return result
