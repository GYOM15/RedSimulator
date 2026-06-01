"""Regles de chainage avance pour le systeme expert.

5 regles de chainage qui combinent des vecteurs existants pour
identifier des scenarios d'attaque composes et elever les severites :
- CHAIN_BYPASS_EXFIL : auth_bypass + sqli → CRITICAL
- CHAIN_XSS_SESSION : xss + info_disclosure → XSS eleve a HIGH
- CHAIN_IDOR_INFO : idor + info_disclosure → IDOR eleve a CRITICAL
- XSS_CRITICAL : xss sur endpoint sans auth → XSS eleve a HIGH
- MULTI_VULN_CRITICAL : 3+ vecteurs HIGH/CRITICAL → elevation systemique
"""

from src.infra.logging import get_logger

from .engine import Rule
from .facts import Fact

logger = get_logger(__name__)


def _get_facts(memory: list[Fact], fact_type: str) -> list[Fact]:
    """Retourne tous les faits d'un type donne."""
    return [f for f in memory if f.type == fact_type]


def _has_vector(memory: list[Fact], attack_type: str) -> bool:
    """Verifie si un vecteur d'attaque d'un type donne existe."""
    return any(
        f.type == "attack_vector" and f.attributes.get("attack_type") == attack_type for f in memory
    )


def _get_vectors(memory: list[Fact], attack_type: str) -> list[Fact]:
    """Retourne tous les vecteurs d'attaque d'un type donne."""
    return [
        f
        for f in memory
        if f.type == "attack_vector" and f.attributes.get("attack_type") == attack_type
    ]


def _has_elevation(memory: list[Fact], source_rule: str) -> bool:
    """Verifie si une elevation de severite a deja ete creee par une regle."""
    return any(f.type == "severity_elevation" and f.source == f"rule:{source_rule}" for f in memory)


# ===========================================================================
# REGLE : CHAIN_BYPASS_EXFIL (priority=10)
# SI auth_bypass + sqli → elever les deux a CRITICAL
# ===========================================================================


def _chain_bypass_exfil_conditions(memory: list[Fact]) -> bool:
    """Conditions : vecteurs auth_bypass ET sqli existent."""
    return _has_vector(memory, "auth_bypass") and _has_vector(memory, "sqli")


def _chain_bypass_exfil_action(memory: list[Fact]) -> list[Fact]:
    """Action : elever auth_bypass et sqli a CRITICAL."""
    if _has_elevation(memory, "CHAIN_BYPASS_EXFIL"):
        return []

    elevations = []

    # Elever tous les vecteurs auth_bypass a CRITICAL
    for vec in _get_vectors(memory, "auth_bypass"):
        if vec.attributes.get("severity") != "CRITICAL":
            old_severity = vec.attributes["severity"]
            vec.attributes["severity"] = "CRITICAL"
            vec.attributes["rationale"].append(
                "Eleve a CRITICAL : chainage auth_bypass + sqli = exfiltration complete"
            )
            elevations.append(
                Fact(
                    type="severity_elevation",
                    attributes={
                        "vector_id": vec.attributes["id"],
                        "from": old_severity,
                        "to": "CRITICAL",
                        "reason": "Chainage auth_bypass + sqli = exfiltration complete des donnees",
                    },
                    source="rule:CHAIN_BYPASS_EXFIL",
                )
            )

    # Elever tous les vecteurs sqli a CRITICAL
    for vec in _get_vectors(memory, "sqli"):
        if vec.attributes.get("severity") != "CRITICAL":
            old_severity = vec.attributes["severity"]
            vec.attributes["severity"] = "CRITICAL"
            vec.attributes["rationale"].append(
                "Eleve a CRITICAL : chainage sqli + auth_bypass = exfiltration complete"
            )
            elevations.append(
                Fact(
                    type="severity_elevation",
                    attributes={
                        "vector_id": vec.attributes["id"],
                        "from": old_severity,
                        "to": "CRITICAL",
                        "reason": "Chainage sqli + auth_bypass = exfiltration complete des donnees",
                    },
                    source="rule:CHAIN_BYPASS_EXFIL",
                )
            )

    return elevations


CHAIN_BYPASS_EXFIL = Rule(
    name="CHAIN_BYPASS_EXFIL",
    conditions=_chain_bypass_exfil_conditions,
    action=_chain_bypass_exfil_action,
    priority=10,
)


# ===========================================================================
# REGLE : CHAIN_XSS_SESSION (priority=10)
# SI xss + info_disclosure → elever XSS a HIGH
# ===========================================================================


def _chain_xss_session_conditions(memory: list[Fact]) -> bool:
    """Conditions : vecteur xss ET vecteur info_disclosure existent."""
    return _has_vector(memory, "xss") and _has_vector(memory, "info_disclosure")


def _chain_xss_session_action(memory: list[Fact]) -> list[Fact]:
    """Action : elever les vecteurs XSS a HIGH (session hijacking possible)."""
    if _has_elevation(memory, "CHAIN_XSS_SESSION"):
        return []

    elevations = []

    for vec in _get_vectors(memory, "xss"):
        if vec.attributes.get("severity") in ("LOW", "MEDIUM"):
            old_severity = vec.attributes["severity"]
            vec.attributes["severity"] = "HIGH"
            vec.attributes["rationale"].append(
                "Eleve a HIGH : XSS + cookies/headers non securises = vol de session possible"
            )
            elevations.append(
                Fact(
                    type="severity_elevation",
                    attributes={
                        "vector_id": vec.attributes["id"],
                        "from": old_severity,
                        "to": "HIGH",
                        "reason": "XSS + info_disclosure (cookies/headers non securises) = session hijacking",
                    },
                    source="rule:CHAIN_XSS_SESSION",
                )
            )

    return elevations


CHAIN_XSS_SESSION = Rule(
    name="CHAIN_XSS_SESSION",
    conditions=_chain_xss_session_conditions,
    action=_chain_xss_session_action,
    priority=10,
)


# ===========================================================================
# REGLE : CHAIN_IDOR_INFO (priority=10)
# SI idor + info_disclosure → elever IDOR a CRITICAL
# ===========================================================================


def _chain_idor_info_conditions(memory: list[Fact]) -> bool:
    """Conditions : vecteur idor ET vecteur info_disclosure existent."""
    return _has_vector(memory, "idor") and _has_vector(memory, "info_disclosure")


def _chain_idor_info_action(memory: list[Fact]) -> list[Fact]:
    """Action : elever les vecteurs IDOR a CRITICAL."""
    if _has_elevation(memory, "CHAIN_IDOR_INFO"):
        return []

    elevations = []

    for vec in _get_vectors(memory, "idor"):
        if vec.attributes.get("severity") != "CRITICAL":
            old_severity = vec.attributes["severity"]
            vec.attributes["severity"] = "CRITICAL"
            vec.attributes["rationale"].append(
                "Eleve a CRITICAL : IDOR + info_disclosure = exfiltration ciblee de donnees"
            )
            elevations.append(
                Fact(
                    type="severity_elevation",
                    attributes={
                        "vector_id": vec.attributes["id"],
                        "from": old_severity,
                        "to": "CRITICAL",
                        "reason": "IDOR + info_disclosure = exfiltration ciblee de donnees utilisateur",
                    },
                    source="rule:CHAIN_IDOR_INFO",
                )
            )

    return elevations


CHAIN_IDOR_INFO = Rule(
    name="CHAIN_IDOR_INFO",
    conditions=_chain_idor_info_conditions,
    action=_chain_idor_info_action,
    priority=10,
)


# ===========================================================================
# REGLE : XSS_CRITICAL (priority=8)
# SI xss ET endpoint cible sans auth → elever XSS a HIGH
# ===========================================================================


def _xss_critical_conditions(memory: list[Fact]) -> bool:
    """Conditions : vecteur xss existe ET l'endpoint cible n'exige pas d'auth."""
    xss_vectors = _get_vectors(memory, "xss")
    if not xss_vectors:
        return False

    for vec in xss_vectors:
        target_ep = vec.attributes.get("target_endpoint", "")
        for ep_fact in memory:
            if (
                ep_fact.type == "endpoint"
                and ep_fact.attributes.get("path") == target_ep
                and not ep_fact.attributes.get("auth_required", True)
            ):
                return True

    return False


def _xss_critical_action(memory: list[Fact]) -> list[Fact]:
    """Action : elever les vecteurs XSS sur endpoints sans auth a HIGH."""
    if _has_elevation(memory, "XSS_CRITICAL"):
        return []

    elevations = []

    xss_vectors = _get_vectors(memory, "xss")
    for vec in xss_vectors:
        target_ep = vec.attributes.get("target_endpoint", "")
        for ep_fact in memory:
            if (
                ep_fact.type == "endpoint"
                and ep_fact.attributes.get("path") == target_ep
                and not ep_fact.attributes.get("auth_required", True)
            ):
                if vec.attributes.get("severity") in ("LOW", "MEDIUM"):
                    old_severity = vec.attributes["severity"]
                    vec.attributes["severity"] = "HIGH"
                    vec.attributes["rationale"].append(
                        "Eleve a HIGH : XSS sur page non authentifiee = impact elargi (stored/reflected)"
                    )
                    elevations.append(
                        Fact(
                            type="severity_elevation",
                            attributes={
                                "vector_id": vec.attributes["id"],
                                "from": old_severity,
                                "to": "HIGH",
                                "reason": "XSS sur endpoint sans authentification = impact elargi",
                            },
                            source="rule:XSS_CRITICAL",
                        )
                    )
                break

    return elevations


XSS_CRITICAL = Rule(
    name="XSS_CRITICAL",
    conditions=_xss_critical_conditions,
    action=_xss_critical_action,
    priority=8,
)


# ===========================================================================
# REGLE : MULTI_VULN_CRITICAL (priority=12)
# SI 3+ vecteurs HIGH/CRITICAL → elevation systemique des MEDIUM restants
# ===========================================================================


def _multi_vuln_conditions(memory: list[Fact]) -> bool:
    """Conditions : 3+ vecteurs d'attaque avec severite HIGH ou CRITICAL."""
    high_critical_vectors = [
        f
        for f in memory
        if f.type == "attack_vector" and f.attributes.get("severity") in ("HIGH", "CRITICAL")
    ]
    return len(high_critical_vectors) >= 3


def _multi_vuln_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un fait de synthese et elever les vecteurs MEDIUM restants a HIGH."""
    if _has_elevation(memory, "MULTI_VULN_CRITICAL"):
        return []

    new_facts = []

    # Fait de synthese : systeme gravement compromis
    high_critical_vectors = [
        f
        for f in memory
        if f.type == "attack_vector" and f.attributes.get("severity") in ("HIGH", "CRITICAL")
    ]

    new_facts.append(
        Fact(
            type="system_assessment",
            attributes={
                "status": "severely_compromised",
                "high_critical_count": len(high_critical_vectors),
                "rationale": (
                    f"{len(high_critical_vectors)} vulnerabilites HIGH/CRITICAL detectees — "
                    "defaillance systemique de la securite"
                ),
            },
            source="rule:MULTI_VULN_CRITICAL",
        )
    )

    # Elever les vecteurs MEDIUM restants a HIGH
    medium_vectors = [
        f for f in memory if f.type == "attack_vector" and f.attributes.get("severity") == "MEDIUM"
    ]

    for vec in medium_vectors:
        old_severity = vec.attributes["severity"]
        vec.attributes["severity"] = "HIGH"
        vec.attributes["rationale"].append(
            "Eleve a HIGH : multiples vulnerabilites critiques indiquent une defaillance systemique"
        )
        new_facts.append(
            Fact(
                type="severity_elevation",
                attributes={
                    "vector_id": vec.attributes["id"],
                    "from": old_severity,
                    "to": "HIGH",
                    "reason": "Multiples vulnerabilites HIGH/CRITICAL — elevation systemique",
                },
                source="rule:MULTI_VULN_CRITICAL",
            )
        )

    return new_facts


MULTI_VULN_CRITICAL = Rule(
    name="MULTI_VULN_CRITICAL",
    conditions=_multi_vuln_conditions,
    action=_multi_vuln_action,
    priority=12,
)


# ===========================================================================
# Fonction d'export
# ===========================================================================


def get_chaining_rules() -> list[Rule]:
    """Retourne des copies fraiches de toutes les regles de chainage avance.

    Important: chaque appel retourne de nouvelles instances pour eviter
    que l'etat 'fired' persiste entre les executions.
    """
    templates = [
        CHAIN_BYPASS_EXFIL,
        CHAIN_XSS_SESSION,
        CHAIN_IDOR_INFO,
        XSS_CRITICAL,
        MULTI_VULN_CRITICAL,
    ]
    return [
        Rule(
            name=r.name,
            conditions=r.conditions,
            action=r.action,
            priority=r.priority,
        )
        for r in templates
    ]
