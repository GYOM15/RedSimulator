"""Payload generation orchestrator.

When an LLM is available, generates targeted payloads per attack vector
by giving the LLM full scan context (one LLM call per vector, not per
payload). Falls back to offline mutations + payload database when no
LLM is configured.
"""

from __future__ import annotations

from src.infra.config import settings
from src.infra.decorators import logged, timed
from src.infra.exceptions import LLMError
from src.infra.llm import is_llm_available
from src.infra.logging import get_logger
from src.models import AttackPlan, GeneratedPayload, PayloadResult, ScanResult

from .llm_mutator import generate_payloads_for_vector
from .offline_mutator import mutate_payload
from .payload_db import payload_db

logger = get_logger(__name__)


@logged
def generate_variants(
    base_payload: str,
    attack_type: str = "sqli",
    n_variants: int = 5,
) -> list[str]:
    """Generate variants for a single payload (offline only).

    This is the simple path — used when no scan context is available
    or as a fallback. For context-aware generation, use generate_for_plan().
    """
    return mutate_payload(
        payload=base_payload,
        attack_type=attack_type,
        n_variants=n_variants,
    )


@logged
@timed
def generate_for_plan(
    attack_plan: AttackPlan,
    scan_result: ScanResult | None = None,
) -> PayloadResult:
    """Generate payloads for an attack plan.

    Strategy:
    - If LLM is available + scan context: ONE LLM call per vector with
      full context (pentester reasoning). The LLM generates targeted
      payloads specific to the target's technology stack and defenses.
    - If no LLM: use payload DB (context-aware selection) + offline mutations.

    Args:
        attack_plan: Attack plan with vectors from the expert system.
        scan_result: Scan results for context-aware generation.

    Returns:
        PayloadResult with generated payloads for each vector.
    """
    llm_available = is_llm_available()
    has_context = scan_result is not None

    # Extract context for LLM and payload DB
    technologies: list[str] = []
    missing_headers: list[str] = []
    all_endpoints: list[dict] = []
    scan_headers: dict | None = None

    if has_context:
        technologies = scan_result.technologies
        missing_headers = scan_result.headers.missing_security_headers
        all_endpoints = [
            {
                "path": ep.path,
                "method": ep.method,
                "auth_required": ep.auth_required,
                "parameters": ep.parameters,
            }
            for ep in scan_result.endpoints
        ]
        scan_headers = {}
        if scan_result.headers.server_info_leaked:
            scan_headers["server"] = "leaked"

    if llm_available and has_context:
        logger.info("Mode: LLM pentester (context-aware, 1 call per vector)")
    elif llm_available:
        logger.info("Mode: LLM mutation (no scan context)")
    else:
        logger.info("Mode: offline mutations + payload DB")

    payloads: list[GeneratedPayload] = []

    for vector in attack_plan.vectors:
        logger.info(
            "Vector %s (%s) -> %s",
            vector.id,
            vector.attack_type.value,
            vector.target_endpoint,
        )

        vector_payloads = _generate_for_vector(
            attack_type=vector.attack_type.value,
            target_endpoint=vector.target_endpoint,
            target_fields=vector.target_fields,
            base_payloads=vector.base_payloads,
            rationale=vector.rationale,
            technologies=technologies,
            missing_headers=missing_headers,
            all_endpoints=all_endpoints,
            scan_headers=scan_headers,
            llm_available=llm_available,
            has_context=has_context,
        )

        for p in vector_payloads:
            payloads.append(
                GeneratedPayload(
                    vector_id=vector.id,
                    original=p,
                    variants=[],
                )
            )

        logger.info("  -> %d payloads generated", len(vector_payloads))

    result = PayloadResult(payloads=payloads)
    logger.info(
        "Generation complete: %d payloads for %d vectors",
        len(payloads),
        len(attack_plan.vectors),
    )
    return result


def _generate_for_vector(
    attack_type: str,
    target_endpoint: str,
    target_fields: list[str],
    base_payloads: list[str],
    rationale: list[str],
    technologies: list[str],
    missing_headers: list[str],
    all_endpoints: list[dict],
    scan_headers: dict | None,
    llm_available: bool,
    has_context: bool,
) -> list[str]:
    """Generate payloads for a single vector using the best available strategy."""
    all_payloads: list[str] = []

    # Strategy 1: LLM pentester (one call with full context)
    if llm_available and has_context:
        try:
            llm_payloads = generate_payloads_for_vector(
                attack_type=attack_type,
                target_endpoint=target_endpoint,
                target_fields=target_fields,
                technologies=technologies,
                missing_headers=missing_headers,
                all_endpoints=all_endpoints,
                rationale=rationale,
                n_payloads=15,
            )
            all_payloads.extend(llm_payloads)
            logger.info("  LLM pentester: %d payloads", len(llm_payloads))
        except (LLMError, Exception) as e:
            logger.warning("  LLM failed (%s), falling back to offline", e)

    # Strategy 2: Payload DB (context-aware selection)
    if technologies or scan_headers:
        db_payloads = payload_db.select_for_target(
            attack_type=attack_type,
            technologies=technologies,
            headers=scan_headers,
            limit=settings.max_payloads_per_vector,
        )
        db_texts = [ip.text for ip in db_payloads]
    else:
        db_results = payload_db.get(attack_type, limit=settings.max_payloads_per_vector)
        db_texts = [ip.text for ip in db_results]

    # Strategy 3: Offline mutations on base payloads (only for injection types)
    offline_payloads: list[str] = []
    if attack_type in ("sqli", "xss", "command_injection", "path_traversal"):
        for bp in base_payloads[:3]:
            offline_payloads.extend(mutate_payload(bp, attack_type, n_variants=3))

    # Merge all sources, deduplicate, preserve order
    combined = list(dict.fromkeys(all_payloads + base_payloads + db_texts + offline_payloads))

    # Cap total payloads per vector
    max_total = settings.max_payloads_per_vector
    return combined[:max_total]
