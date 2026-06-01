"""Regles de securite liees aux headers HTTP et a la configuration.

4 regles implementees :
- MISSING_HSTS : absence du header Strict-Transport-Security
- MISSING_XFRAME : absence du header X-Frame-Options
- INSECURE_COOKIES : fuite d'information serveur (proxy pour cookies non securises)
- SENSITIVE_DATA_EXPOSURE : endpoints sensibles exposes sans authentification
"""

import re

from src.infra.logging import get_logger

from .engine import Rule
from .facts import Fact

logger = get_logger(__name__)


def _has_fact(memory: list[Fact], fact_type: str, **attrs) -> bool:
    """Verifie si un fait avec les attributs donnes existe dans la memoire."""
    for fact in memory:
        if fact.type != fact_type:
            continue
        match = True
        for key, value in attrs.items():
            if key not in fact.attributes or fact.attributes[key] != value:
                match = False
                break
        if match:
            return True
    return False


def _get_facts(memory: list[Fact], fact_type: str) -> list[Fact]:
    """Retourne tous les faits d'un type donne."""
    return [f for f in memory if f.type == fact_type]


def _next_vector_id(memory: list[Fact]) -> int:
    """Retourne le prochain ID de vecteur disponible."""
    existing_vectors = [f for f in memory if f.type == "attack_vector"]
    return len(existing_vectors) + 1


# ===========================================================================
# REGLE : MISSING_HSTS
# SI header Strict-Transport-Security manquant → attack_vector(info_disclosure, LOW)
# ===========================================================================


def _missing_hsts_conditions(memory: list[Fact]) -> bool:
    """Conditions : le header Strict-Transport-Security est manquant."""
    return _has_fact(memory, "missing_header", header="Strict-Transport-Security")


def _missing_hsts_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur info_disclosure pour HSTS manquant."""
    # Verifier qu'on n'a pas deja cree ce vecteur
    already_exists = any(
        f.type == "attack_vector"
        and f.attributes.get("attack_type") == "info_disclosure"
        and f.attributes.get("source_rule") == "MISSING_HSTS"
        for f in memory
    )
    if already_exists:
        return []

    next_id = _next_vector_id(memory)
    vector_id = f"VEC-{next_id:03d}"

    return [
        Fact(
            type="attack_vector",
            attributes={
                "id": vector_id,
                "attack_type": "info_disclosure",
                "target_endpoint": "*",
                "target_fields": [],
                "severity": "LOW",
                "owasp_ref": "A05:2021-Security Misconfiguration",
                "source_rule": "MISSING_HSTS",
                "rationale": [
                    "Header Strict-Transport-Security manquant",
                    "Le site est vulnerable aux attaques de type downgrade HTTPS vers HTTP",
                    "Un attaquant peut intercepter le trafic via man-in-the-middle",
                ],
                "base_payloads": [],
            },
            source="rule:MISSING_HSTS",
        )
    ]


MISSING_HSTS = Rule(
    name="MISSING_HSTS",
    conditions=_missing_hsts_conditions,
    action=_missing_hsts_action,
    priority=5,
)


# ===========================================================================
# REGLE : MISSING_XFRAME
# SI header X-Frame-Options manquant → attack_vector(info_disclosure, LOW)
# ===========================================================================


def _missing_xframe_conditions(memory: list[Fact]) -> bool:
    """Conditions : le header X-Frame-Options est manquant."""
    return _has_fact(memory, "missing_header", header="X-Frame-Options")


def _missing_xframe_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur info_disclosure pour X-Frame-Options manquant."""
    already_exists = any(
        f.type == "attack_vector"
        and f.attributes.get("attack_type") == "info_disclosure"
        and f.attributes.get("source_rule") == "MISSING_XFRAME"
        for f in memory
    )
    if already_exists:
        return []

    next_id = _next_vector_id(memory)
    vector_id = f"VEC-{next_id:03d}"

    return [
        Fact(
            type="attack_vector",
            attributes={
                "id": vector_id,
                "attack_type": "info_disclosure",
                "target_endpoint": "*",
                "target_fields": [],
                "severity": "LOW",
                "owasp_ref": "A05:2021-Security Misconfiguration",
                "source_rule": "MISSING_XFRAME",
                "rationale": [
                    "Header X-Frame-Options manquant",
                    "Le site est vulnerable aux attaques de type clickjacking",
                    "Un attaquant peut integrer le site dans une iframe malveillante",
                ],
                "base_payloads": [],
            },
            source="rule:MISSING_XFRAME",
        )
    ]


MISSING_XFRAME = Rule(
    name="MISSING_XFRAME",
    conditions=_missing_xframe_conditions,
    action=_missing_xframe_action,
    priority=5,
)


# ===========================================================================
# REGLE : INSECURE_COOKIES
# SI server_info_leaked=True → attack_vector(info_disclosure, MEDIUM)
# ===========================================================================


def _insecure_cookies_conditions(memory: list[Fact]) -> bool:
    """Conditions : fuite d'information serveur detectee (proxy pour cookies non securises)."""
    return _has_fact(memory, "server_info_leaked", leaked=True)


def _insecure_cookies_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur info_disclosure pour cookies potentiellement non securises."""
    already_exists = any(
        f.type == "attack_vector"
        and f.attributes.get("attack_type") == "info_disclosure"
        and f.attributes.get("source_rule") == "INSECURE_COOKIES"
        for f in memory
    )
    if already_exists:
        return []

    next_id = _next_vector_id(memory)
    vector_id = f"VEC-{next_id:03d}"

    return [
        Fact(
            type="attack_vector",
            attributes={
                "id": vector_id,
                "attack_type": "info_disclosure",
                "target_endpoint": "*",
                "target_fields": [],
                "severity": "MEDIUM",
                "owasp_ref": "A05:2021-Security Misconfiguration",
                "source_rule": "INSECURE_COOKIES",
                "rationale": [
                    "Information serveur exposee (server_info_leaked)",
                    "Les cookies de session peuvent manquer les attributs Secure, HttpOnly ou SameSite",
                    "Un attaquant peut exploiter les cookies non securises pour le vol de session",
                ],
                "base_payloads": [],
            },
            source="rule:INSECURE_COOKIES",
        )
    ]


INSECURE_COOKIES = Rule(
    name="INSECURE_COOKIES",
    conditions=_insecure_cookies_conditions,
    action=_insecure_cookies_action,
    priority=4,
)


# ===========================================================================
# REGLE : SENSITIVE_DATA_EXPOSURE
# SI endpoint avec path sensible (config, env, debug, etc.) ET auth_required=False
# → attack_vector(info_disclosure, HIGH)
# ===========================================================================

_SENSITIVE_PATTERNS = re.compile(
    r"(config|env|debug|status|health|metrics|actuator)", re.IGNORECASE
)


def _sensitive_data_conditions(memory: list[Fact]) -> bool:
    """Conditions : un endpoint sensible est accessible sans authentification."""
    endpoints = _get_facts(memory, "endpoint")
    for ep in endpoints:
        path = ep.attributes.get("path", "")
        auth_required = ep.attributes.get("auth_required", True)
        if not auth_required and _SENSITIVE_PATTERNS.search(path):
            return True
    return False


def _sensitive_data_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur info_disclosure pour chaque endpoint sensible expose."""
    new_facts = []
    endpoints = _get_facts(memory, "endpoint")
    next_id = _next_vector_id(memory)

    for ep in endpoints:
        path = ep.attributes.get("path", "")
        auth_required = ep.attributes.get("auth_required", True)

        if not auth_required and _SENSITIVE_PATTERNS.search(path):
            # Verifier qu'on n'a pas deja un vecteur pour cet endpoint
            already_targeted = any(
                f.type == "attack_vector"
                and f.attributes.get("target_endpoint") == path
                and f.attributes.get("source_rule") == "SENSITIVE_DATA_EXPOSURE"
                for f in memory
            )
            if already_targeted:
                continue

            vector_id = f"VEC-{next_id:03d}"
            next_id += 1

            new_facts.append(
                Fact(
                    type="attack_vector",
                    attributes={
                        "id": vector_id,
                        "attack_type": "info_disclosure",
                        "target_endpoint": path,
                        "target_fields": [],
                        "severity": "HIGH",
                        "owasp_ref": "A01:2021-Broken Access Control",
                        "source_rule": "SENSITIVE_DATA_EXPOSURE",
                        "rationale": [
                            f"Endpoint sensible detecte : {path}",
                            "Accessible sans authentification",
                            "Peut exposer des donnees de configuration, variables d'environnement ou metriques",
                        ],
                        "base_payloads": [],
                    },
                    source="rule:SENSITIVE_DATA_EXPOSURE",
                )
            )

    return new_facts


SENSITIVE_DATA_EXPOSURE = Rule(
    name="SENSITIVE_DATA_EXPOSURE",
    conditions=_sensitive_data_conditions,
    action=_sensitive_data_action,
    priority=4,
)


# ===========================================================================
# Fonction d'export
# ===========================================================================


def get_header_rules() -> list[Rule]:
    """Retourne des copies fraiches de toutes les regles header/config.

    Important: chaque appel retourne de nouvelles instances pour eviter
    que l'etat 'fired' persiste entre les executions.
    """
    templates = [MISSING_HSTS, MISSING_XFRAME, INSECURE_COOKIES, SENSITIVE_DATA_EXPOSURE]
    return [
        Rule(
            name=r.name,
            conditions=r.conditions,
            action=r.action,
            priority=r.priority,
        )
        for r in templates
    ]
