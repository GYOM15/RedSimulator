"""Regles OWASP pour le systeme expert.

Chaque regle est une instance de Rule avec :
- conditions : fonction qui verifie si les faits necessaires sont presents
- action : fonction qui produit de nouveaux faits (vecteurs d'attaque)

3 regles implementees, 5+ a ajouter.

TODO: Ajouter les regles manquantes :
  - IDOR : SI endpoint avec ID numerique dans l'URL → attack_vector(idor, HIGH)
  - PATH_TRAVERSAL : SI endpoint avec parametre fichier → attack_vector(path_traversal, MEDIUM)
  - AUTH_BYPASS : SI endpoint admin sans auth → attack_vector(auth_bypass, HIGH)
  - INFO_DISCLOSURE : SI server_info_leaked → attack_vector(info_disclosure, LOW)
  - CHAIN_BYPASS_EXFIL : SI auth_bypass + sqli → elever les deux a CRITICAL
"""

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


# ===========================================================================
# REGLE 1 : SQL_INJECTION
# SI formulaire avec champs + technologie SQL → attack_vector(sqli, HIGH)
# ===========================================================================


def _sqli_conditions(memory: list[Fact]) -> bool:
    """Conditions : un formulaire existe ET une techno SQL est detectee."""
    has_form = any(f.type == "form" for f in memory)
    has_sql_tech = any(
        f.type == "technology" and "sql" in f.attributes.get("name", "").lower() for f in memory
    )
    return has_form and has_sql_tech


def _sqli_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur d'attaque SQLi pour chaque formulaire."""
    new_facts = []
    forms = _get_facts(memory, "form")

    for i, form in enumerate(forms):
        vector_id = f"VEC-{i + 1:03d}"
        new_facts.append(
            Fact(
                type="attack_vector",
                attributes={
                    "id": vector_id,
                    "attack_type": "sqli",
                    "target_endpoint": form.attributes["endpoint"],
                    "target_fields": form.attributes.get("fields", []),
                    "severity": "HIGH",
                    "owasp_ref": "A03:2021-Injection",
                    "rationale": [
                        f"Formulaire detecte sur {form.attributes['endpoint']}",
                        "Technologie SQL detectee (SQLite/MySQL/PostgreSQL)",
                    ],
                    "base_payloads": [
                        "' OR 1=1--",
                        "admin'--",
                        "' UNION SELECT * FROM Users--",
                    ],
                },
                source="rule:SQL_INJECTION",
            )
        )

    return new_facts


SQL_INJECTION = Rule(
    name="SQL_INJECTION",
    conditions=_sqli_conditions,
    action=_sqli_action,
    priority=1,
)


# ===========================================================================
# REGLE 2 : XSS_REFLECTED
# SI endpoint POST + missing CSP → attack_vector(xss, MEDIUM)
# ===========================================================================


def _xss_conditions(memory: list[Fact]) -> bool:
    """Conditions : endpoint POST existe ET header CSP manquant."""
    has_post = any(f.type == "endpoint" and f.attributes.get("method") == "POST" for f in memory)
    has_missing_csp = _has_fact(memory, "missing_header", header="Content-Security-Policy")
    return has_post and has_missing_csp


def _xss_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur XSS pour les endpoints POST."""
    new_facts = []
    post_endpoints = [
        f for f in memory if f.type == "endpoint" and f.attributes.get("method") == "POST"
    ]

    # Trouver le prochain ID disponible
    existing_vectors = [f for f in memory if f.type == "attack_vector"]
    next_id = len(existing_vectors) + 1

    for ep in post_endpoints:
        # Ne pas creer de vecteur XSS si un vecteur SQLi existe deja pour cet endpoint
        endpoint_path = ep.attributes["path"]
        already_targeted = any(
            f.type == "attack_vector"
            and f.attributes.get("target_endpoint") == endpoint_path
            and f.attributes.get("attack_type") == "xss"
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
                    "attack_type": "xss",
                    "target_endpoint": endpoint_path,
                    "target_fields": ep.attributes.get("parameters", []),
                    "severity": "MEDIUM",
                    "owasp_ref": "A03:2021-Injection",
                    "rationale": [
                        f"Endpoint POST detecte ({endpoint_path})",
                        "Header Content-Security-Policy manquant",
                    ],
                    "base_payloads": [
                        "<script>alert('xss')</script>",
                        "<img src=x onerror=alert(1)>",
                        "<svg onload=alert('xss')>",
                    ],
                },
                source="rule:XSS_REFLECTED",
            )
        )

    return new_facts


XSS_REFLECTED = Rule(
    name="XSS_REFLECTED",
    conditions=_xss_conditions,
    action=_xss_action,
    priority=2,
)


# ===========================================================================
# REGLE 3 : SQL_INJECTION_CRITICAL
# SI sqli deja deduit + endpoint sans auth → elever a CRITICAL
# (Demontre le CHAINAGE : cette regle depend de SQL_INJECTION)
# ===========================================================================


def _sqli_critical_conditions(memory: list[Fact]) -> bool:
    """Conditions : un vecteur SQLi existe ET l'endpoint n'a pas d'auth."""
    sqli_vectors = [
        f for f in memory if f.type == "attack_vector" and f.attributes.get("attack_type") == "sqli"
    ]

    if not sqli_vectors:
        return False

    # Verifier qu'au moins un endpoint cible n'exige pas d'auth
    for vec in sqli_vectors:
        target_ep = vec.attributes.get("target_endpoint", "")
        for ep_fact in memory:
            if (
                ep_fact.type == "endpoint"
                and ep_fact.attributes.get("path") == target_ep
                and not ep_fact.attributes.get("auth_required", True)
            ):
                return True

    return False


def _sqli_critical_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un fait d'elevation de severite."""
    # Trouver les vecteurs SQLi sur des endpoints sans auth
    elevations = []

    sqli_vectors = [
        f for f in memory if f.type == "attack_vector" and f.attributes.get("attack_type") == "sqli"
    ]

    for vec in sqli_vectors:
        target_ep = vec.attributes.get("target_endpoint", "")
        for ep_fact in memory:
            if (
                ep_fact.type == "endpoint"
                and ep_fact.attributes.get("path") == target_ep
                and not ep_fact.attributes.get("auth_required", True)
            ):
                # Elever la severite dans les attributs du vecteur
                vec.attributes["severity"] = "CRITICAL"
                vec.attributes["rationale"].append(
                    "Eleve a CRITICAL : endpoint sans authentification"
                )

                elevations.append(
                    Fact(
                        type="severity_elevation",
                        attributes={
                            "vector_id": vec.attributes["id"],
                            "from": "HIGH",
                            "to": "CRITICAL",
                            "reason": "Endpoint sans authentification",
                        },
                        source="rule:SQL_INJECTION_CRITICAL",
                    )
                )
                break

    return elevations


SQL_INJECTION_CRITICAL = Rule(
    name="SQL_INJECTION_CRITICAL",
    conditions=_sqli_critical_conditions,
    action=_sqli_critical_action,
    priority=5,  # Priorite plus basse → s'execute apres SQL_INJECTION
)


# ===========================================================================
# TODO: Regles supplementaires a implementer
# ===========================================================================

# TODO: IDOR
# SI endpoint avec pattern numerique (ex: /rest/basket/1) → attack_vector(idor, HIGH)
# Conditions: endpoint.path contient un nombre, auth_required = True
# Action: creer un vecteur IDOR avec payloads de type ID enumeration

# TODO: PATH_TRAVERSAL
# SI endpoint avec parametre de type fichier → attack_vector(path_traversal, MEDIUM)
# Conditions: endpoint.parameters contient 'file', 'path', 'document', etc.
# Action: creer un vecteur path_traversal avec payloads ../../etc/passwd

# TODO: AUTH_BYPASS
# SI endpoint admin accessible sans auth → attack_vector(auth_bypass, HIGH)
# Conditions: endpoint.path contient 'admin' ET auth_required = False
# Action: creer un vecteur auth_bypass

# TODO: INFO_DISCLOSURE
# SI server_info_leaked OU missing_headers multiples → attack_vector(info_disclosure, LOW)
# Conditions: fait server_info_leaked existe OU 2+ missing_header
# Action: creer un vecteur info_disclosure

# TODO: CHAIN_BYPASS_EXFIL
# SI auth_bypass ET sqli → elever les deux a CRITICAL
# Conditions: vecteurs auth_bypass ET sqli existent
# Action: creer un fait de chainage critique


def get_all_rules() -> list[Rule]:
    """Retourne des copies fraiches de toutes les regles du systeme expert.

    Important: chaque appel retourne de nouvelles instances pour eviter
    que l'etat 'fired' persiste entre les executions.
    """
    return [
        Rule(
            name=SQL_INJECTION.name,
            conditions=SQL_INJECTION.conditions,
            action=SQL_INJECTION.action,
            priority=SQL_INJECTION.priority,
        ),
        Rule(
            name=XSS_REFLECTED.name,
            conditions=XSS_REFLECTED.conditions,
            action=XSS_REFLECTED.action,
            priority=XSS_REFLECTED.priority,
        ),
        Rule(
            name=SQL_INJECTION_CRITICAL.name,
            conditions=SQL_INJECTION_CRITICAL.conditions,
            action=SQL_INJECTION_CRITICAL.action,
            priority=SQL_INJECTION_CRITICAL.priority,
        ),
    ]
