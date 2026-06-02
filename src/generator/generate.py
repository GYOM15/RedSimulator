"""Orchestrateur de generation de variantes de payloads.

Tente d'abord la generation via LLM (Claude API), puis se rabat
sur les mutations deterministes hors-ligne en cas d'echec ou
d'absence de cle API.

When a ``ScanResult`` is provided, the generator uses the contextual
intelligence system to select payloads optimized for the target's
technology stack, WAF, and database engine.
"""

from __future__ import annotations

from src.infra.config import settings
from src.infra.decorators import logged, timed
from src.infra.exceptions import LLMError
from src.infra.logging import get_logger
from src.models import AttackPlan, GeneratedPayload, PayloadResult, ScanResult

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
def generate_for_plan(
    attack_plan: AttackPlan,
    scan_result: ScanResult | None = None,
) -> PayloadResult:
    """Genere des variantes de payloads pour un plan d'attaque complet.

    Parcourt chaque vecteur du plan et genere des variantes pour
    chacun de ses payloads de base.

    When a ``scan_result`` is provided, the contextual intelligence system
    selects payloads optimized for the target's detected technologies,
    WAF, and database engine. Payload explanations are passed to the LLM
    mutator for smarter variant generation.

    Args:
        attack_plan: Plan d'attaque contenant les vecteurs et payloads de base.
        scan_result: Optional scan result for context-aware payload selection.

    Returns:
        PayloadResult contenant tous les payloads generes.
    """
    logger.info("=" * 60)
    logger.info("Generation de variantes de payloads")
    logger.info("=" * 60)

    # Extract technologies and raw headers from scan result if available
    technologies: list[str] = []
    scan_headers: dict | None = None
    if scan_result is not None:
        technologies = scan_result.technologies
        # Build a raw header dict from the HeaderAnalysis model for WAF detection
        scan_headers = {}
        if scan_result.headers.server_info_leaked:
            scan_headers["server"] = "leaked"
        logger.info(
            "Scan context: %d technologies detected, headers available=%s",
            len(technologies),
            scan_headers is not None,
        )

    payloads: list[GeneratedPayload] = []

    for vector in attack_plan.vectors:
        logger.info("--- Vecteur %s (%s) ---", vector.id, vector.attack_type.value)

        # Use smart selector when scan context is available, otherwise fall back
        if technologies or scan_headers:
            intel_payloads = payload_db.select_for_target(
                attack_type=vector.attack_type.value,
                technologies=technologies,
                headers=scan_headers,
                limit=settings.max_payloads_per_vector,
            )
            db_payload_texts = [ip.text for ip in intel_payloads]

            # Build explanation context for LLM mutation
            explanation_context: dict[str, str] = {}
            for ip in intel_payloads:
                if ip.explanation:
                    explanation_context[ip.text] = ip.explanation

            logger.info(
                "  Smart selector: %d payloads selected (%d with explanations)",
                len(db_payload_texts),
                len(explanation_context),
            )
        else:
            # Legacy path: get payload texts without intelligence
            intel_payloads_legacy = payload_db.get(
                vector.attack_type.value,
                limit=settings.max_payloads_per_vector,
            )
            db_payload_texts = [ip.text for ip in intel_payloads_legacy]
            explanation_context = {}

        all_base = list(dict.fromkeys(vector.base_payloads + db_payload_texts))
        logger.info(
            "  Merged %d base + %d db payloads -> %d unique",
            len(vector.base_payloads),
            len(db_payload_texts),
            len(all_base),
        )

        for base_payload in all_base:
            logger.info("  Base: %s", base_payload)

            # Pass explanation to LLM mutator for smarter variants
            explanation = explanation_context.get(base_payload, "")
            if explanation:
                logger.debug("  Explanation context: %s", explanation[:100])

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
