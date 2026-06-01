"""Regles OWASP pour le systeme expert.

Chaque regle est une instance de Rule avec :
- conditions : fonction qui verifie si les faits necessaires sont presents
- action : fonction qui produit de nouveaux faits (vecteurs d'attaque)

20 regles implementees (11 dans ce fichier + 4 header/config + 5 chainage avance).
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
# REGLE 4 : IDOR
# SI endpoint avec ID numerique dans l'URL ET auth requise → attack_vector(idor, HIGH)
# ===========================================================================


def _idor_conditions(memory: list[Fact]) -> bool:
    """Conditions : endpoint avec pattern numerique dans le path OU parametres de type ID, ET auth requise."""
    endpoints = _get_facts(memory, "endpoint")
    for ep in endpoints:
        path = ep.attributes.get("path", "")
        params = ep.attributes.get("parameters", [])
        auth_required = ep.attributes.get("auth_required", False)

        if not auth_required:
            continue

        # Verifier un pattern numerique dans le path (ex: /rest/basket/1)
        if re.search(r"/\d+", path):
            return True

        # Verifier des parametres de type ID
        id_params = {"id", "userid", "basketid"}
        for param in params:
            if param.lower() in id_params:
                return True

    return False


def _idor_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur IDOR pour chaque endpoint avec ID numerique."""
    new_facts = []
    endpoints = _get_facts(memory, "endpoint")

    existing_vectors = [f for f in memory if f.type == "attack_vector"]
    next_id = len(existing_vectors) + 1

    for ep in endpoints:
        path = ep.attributes.get("path", "")
        params = ep.attributes.get("parameters", [])
        auth_required = ep.attributes.get("auth_required", False)

        if not auth_required:
            continue

        has_numeric_path = bool(re.search(r"/\d+", path))
        id_params = {"id", "userid", "basketid"}
        has_id_param = any(p.lower() in id_params for p in params)

        if not has_numeric_path and not has_id_param:
            continue

        # Ne pas creer de doublon
        already_targeted = any(
            f.type == "attack_vector"
            and f.attributes.get("target_endpoint") == path
            and f.attributes.get("attack_type") == "idor"
            for f in memory
        )
        if already_targeted:
            continue

        vector_id = f"VEC-{next_id:03d}"
        next_id += 1

        rationale = [
            f"Endpoint avec identification numerique detecte ({path})",
            "Authentification requise — risque d'enumeration d'identifiants",
        ]

        new_facts.append(
            Fact(
                type="attack_vector",
                attributes={
                    "id": vector_id,
                    "attack_type": "idor",
                    "target_endpoint": path,
                    "target_fields": params,
                    "severity": "HIGH",
                    "owasp_ref": "A01:2021-Broken Access Control",
                    "rationale": rationale,
                    "base_payloads": ["0", "2", "99", "100", "-1"],
                },
                source="rule:IDOR",
            )
        )

    return new_facts


IDOR = Rule(
    name="IDOR",
    conditions=_idor_conditions,
    action=_idor_action,
    priority=3,
)


# ===========================================================================
# REGLE 5 : PATH_TRAVERSAL
# SI endpoint avec parametre de type fichier → attack_vector(path_traversal, MEDIUM)
# ===========================================================================


def _path_traversal_conditions(memory: list[Fact]) -> bool:
    """Conditions : endpoint avec parametres lies a un fichier."""
    file_params = {"file", "path", "document", "download", "template", "img", "src"}
    endpoints = _get_facts(memory, "endpoint")

    for ep in endpoints:
        params = ep.attributes.get("parameters", [])
        for param in params:
            if param.lower() in file_params:
                return True

    return False


def _path_traversal_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur path_traversal pour les endpoints avec parametres fichier."""
    new_facts = []
    file_params = {"file", "path", "document", "download", "template", "img", "src"}
    endpoints = _get_facts(memory, "endpoint")

    existing_vectors = [f for f in memory if f.type == "attack_vector"]
    next_id = len(existing_vectors) + 1

    for ep in endpoints:
        params = ep.attributes.get("parameters", [])
        matching_params = [p for p in params if p.lower() in file_params]

        if not matching_params:
            continue

        endpoint_path = ep.attributes.get("path", "")

        already_targeted = any(
            f.type == "attack_vector"
            and f.attributes.get("target_endpoint") == endpoint_path
            and f.attributes.get("attack_type") == "path_traversal"
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
                    "attack_type": "path_traversal",
                    "target_endpoint": endpoint_path,
                    "target_fields": matching_params,
                    "severity": "MEDIUM",
                    "owasp_ref": "A01:2021-Broken Access Control",
                    "rationale": [
                        f"Endpoint avec parametres fichier detecte ({endpoint_path})",
                        f"Parametres sensibles: {', '.join(matching_params)}",
                    ],
                    "base_payloads": [
                        "../../etc/passwd",
                        "..\\..\\windows\\system32\\config\\sam",
                    ],
                },
                source="rule:PATH_TRAVERSAL",
            )
        )

    return new_facts


PATH_TRAVERSAL = Rule(
    name="PATH_TRAVERSAL",
    conditions=_path_traversal_conditions,
    action=_path_traversal_action,
    priority=3,
)


# ===========================================================================
# REGLE 6 : AUTH_BYPASS
# SI endpoint admin accessible sans auth → attack_vector(auth_bypass, HIGH)
# ===========================================================================


def _auth_bypass_conditions(memory: list[Fact]) -> bool:
    """Conditions : endpoint contenant 'admin' dans le path ET sans authentification."""
    endpoints = _get_facts(memory, "endpoint")

    for ep in endpoints:
        path = ep.attributes.get("path", "")
        auth_required = ep.attributes.get("auth_required", True)

        if "admin" in path.lower() and not auth_required:
            return True

    return False


def _auth_bypass_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur auth_bypass pour les endpoints admin sans auth."""
    new_facts = []
    endpoints = _get_facts(memory, "endpoint")

    existing_vectors = [f for f in memory if f.type == "attack_vector"]
    next_id = len(existing_vectors) + 1

    for ep in endpoints:
        path = ep.attributes.get("path", "")
        auth_required = ep.attributes.get("auth_required", True)

        if "admin" not in path.lower() or auth_required:
            continue

        already_targeted = any(
            f.type == "attack_vector"
            and f.attributes.get("target_endpoint") == path
            and f.attributes.get("attack_type") == "auth_bypass"
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
                    "attack_type": "auth_bypass",
                    "target_endpoint": path,
                    "target_fields": ep.attributes.get("parameters", []),
                    "severity": "HIGH",
                    "owasp_ref": "A01:2021-Broken Access Control",
                    "rationale": [
                        f"Endpoint d'administration sans authentification ({path})",
                        "Acces direct a une zone d'administration protegee",
                    ],
                    "base_payloads": [],
                },
                source="rule:AUTH_BYPASS",
            )
        )

    return new_facts


AUTH_BYPASS = Rule(
    name="AUTH_BYPASS",
    conditions=_auth_bypass_conditions,
    action=_auth_bypass_action,
    priority=2,
)


# ===========================================================================
# REGLE 7 : INFO_DISCLOSURE
# SI server_info_leaked OU 2+ missing_header → attack_vector(info_disclosure, LOW)
# ===========================================================================


def _info_disclosure_conditions(memory: list[Fact]) -> bool:
    """Conditions : server_info_leaked existe OU 2+ headers de securite manquants."""
    has_leaked = _has_fact(memory, "server_info_leaked", leaked=True)
    missing_headers = _get_facts(memory, "missing_header")
    return has_leaked or len(missing_headers) >= 2


def _info_disclosure_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur info_disclosure."""
    new_facts = []

    # Ne pas creer de doublon
    already_exists = any(
        f.type == "attack_vector" and f.attributes.get("attack_type") == "info_disclosure"
        for f in memory
    )
    if already_exists:
        return new_facts

    existing_vectors = [f for f in memory if f.type == "attack_vector"]
    next_id = len(existing_vectors) + 1

    vector_id = f"VEC-{next_id:03d}"

    rationale = []
    has_leaked = _has_fact(memory, "server_info_leaked", leaked=True)
    if has_leaked:
        rationale.append("Le serveur expose des informations sensibles (version, technologie)")

    missing_headers = _get_facts(memory, "missing_header")
    if len(missing_headers) >= 2:
        header_names = [h.attributes.get("header", "") for h in missing_headers]
        rationale.append(
            f"{len(missing_headers)} headers de securite manquants: {', '.join(header_names)}"
        )

    new_facts.append(
        Fact(
            type="attack_vector",
            attributes={
                "id": vector_id,
                "attack_type": "info_disclosure",
                "target_endpoint": "/",
                "target_fields": [],
                "severity": "LOW",
                "owasp_ref": "A05:2021-Security Misconfiguration",
                "rationale": rationale,
                "base_payloads": [],
            },
            source="rule:INFO_DISCLOSURE",
        )
    )

    return new_facts


INFO_DISCLOSURE = Rule(
    name="INFO_DISCLOSURE",
    conditions=_info_disclosure_conditions,
    action=_info_disclosure_action,
    priority=4,
)


# ===========================================================================
# REGLE 8 : CSRF
# SI formulaire POST ET header X-CSRF-Token manquant OU pas de champ CSRF
# → attack_vector(xss, MEDIUM) avec rationale CSRF
# ===========================================================================


def _csrf_conditions(memory: list[Fact]) -> bool:
    """Conditions : formulaire POST existe ET protection CSRF absente."""
    forms = _get_facts(memory, "form")
    post_forms = [f for f in forms if f.attributes.get("method", "").upper() == "POST"]

    if not post_forms:
        return False

    # Verifier si le header X-CSRF-Token est manquant
    missing_csrf_header = _has_fact(memory, "missing_header", header="X-CSRF-Token")

    # Verifier si un champ CSRF existe dans les formulaires
    csrf_field_names = {"csrf", "csrf_token", "_csrf", "csrfmiddlewaretoken", "xsrf", "_token"}
    for form in post_forms:
        fields = form.attributes.get("fields", [])
        has_csrf_field = any(f.lower() in csrf_field_names for f in fields)

        if missing_csrf_header or not has_csrf_field:
            return True

    return False


def _csrf_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur XSS avec rationale CSRF pour les formulaires vulnerables."""
    new_facts = []
    forms = _get_facts(memory, "form")
    post_forms = [f for f in forms if f.attributes.get("method", "").upper() == "POST"]

    missing_csrf_header = _has_fact(memory, "missing_header", header="X-CSRF-Token")
    csrf_field_names = {"csrf", "csrf_token", "_csrf", "csrfmiddlewaretoken", "xsrf", "_token"}

    existing_vectors = [f for f in memory if f.type == "attack_vector"]
    next_id = len(existing_vectors) + 1

    for form in post_forms:
        endpoint = form.attributes.get("endpoint", "")
        fields = form.attributes.get("fields", [])
        has_csrf_field = any(f.lower() in csrf_field_names for f in fields)

        if not missing_csrf_header and has_csrf_field:
            continue

        # Ne pas creer de doublon CSRF pour le meme endpoint
        already_targeted = any(
            f.type == "attack_vector"
            and f.attributes.get("target_endpoint") == endpoint
            and "CSRF" in " ".join(f.attributes.get("rationale", []))
            for f in memory
        )
        if already_targeted:
            continue

        vector_id = f"VEC-{next_id:03d}"
        next_id += 1

        rationale = [
            f"Formulaire POST sans protection CSRF ({endpoint})",
        ]
        if missing_csrf_header:
            rationale.append("Header X-CSRF-Token manquant")
        if not has_csrf_field:
            rationale.append("Aucun champ CSRF detecte dans le formulaire")
        rationale.append(
            "Risque de Cross-Site Request Forgery : un attaquant peut forger des requetes"
        )

        new_facts.append(
            Fact(
                type="attack_vector",
                attributes={
                    "id": vector_id,
                    "attack_type": "xss",
                    "target_endpoint": endpoint,
                    "target_fields": fields,
                    "severity": "MEDIUM",
                    "owasp_ref": "A01:2021-Broken Access Control",
                    "rationale": rationale,
                    "base_payloads": [
                        '<form action="TARGET" method="POST"><input type="hidden" name="field" value="evil"></form>',
                        '<img src="TARGET?action=delete" style="display:none">',
                    ],
                },
                source="rule:CSRF",
            )
        )

    return new_facts


CSRF = Rule(
    name="CSRF",
    conditions=_csrf_conditions,
    action=_csrf_action,
    priority=3,
)


# ===========================================================================
# REGLE 9 : OPEN_REDIRECT
# SI endpoint avec parametres de redirection → attack_vector(auth_bypass, MEDIUM)
# ===========================================================================


def _open_redirect_conditions(memory: list[Fact]) -> bool:
    """Conditions : endpoint avec parametres lies a une redirection."""
    redirect_params = {"redirect", "url", "next", "return", "goto", "destination"}
    endpoints = _get_facts(memory, "endpoint")

    for ep in endpoints:
        params = ep.attributes.get("parameters", [])
        for param in params:
            if param.lower() in redirect_params:
                return True

    return False


def _open_redirect_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur auth_bypass avec payloads de redirection."""
    new_facts = []
    redirect_params = {"redirect", "url", "next", "return", "goto", "destination"}
    endpoints = _get_facts(memory, "endpoint")

    existing_vectors = [f for f in memory if f.type == "attack_vector"]
    next_id = len(existing_vectors) + 1

    for ep in endpoints:
        params = ep.attributes.get("parameters", [])
        matching_params = [p for p in params if p.lower() in redirect_params]

        if not matching_params:
            continue

        endpoint_path = ep.attributes.get("path", "")

        already_targeted = any(
            f.type == "attack_vector"
            and f.attributes.get("target_endpoint") == endpoint_path
            and "Open Redirect" in " ".join(f.attributes.get("rationale", []))
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
                    "attack_type": "auth_bypass",
                    "target_endpoint": endpoint_path,
                    "target_fields": matching_params,
                    "severity": "MEDIUM",
                    "owasp_ref": "A01:2021-Broken Access Control",
                    "rationale": [
                        f"Open Redirect detecte sur {endpoint_path}",
                        f"Parametres de redirection: {', '.join(matching_params)}",
                        "Risque de redirection vers un site malveillant (phishing, vol de tokens)",
                    ],
                    "base_payloads": [
                        "https://evil.com",
                        "//evil.com",
                        "/\\evil.com",
                        "https://evil.com/%2f..",
                    ],
                },
                source="rule:OPEN_REDIRECT",
            )
        )

    return new_facts


OPEN_REDIRECT = Rule(
    name="OPEN_REDIRECT",
    conditions=_open_redirect_conditions,
    action=_open_redirect_action,
    priority=4,
)


# ===========================================================================
# REGLE 10 : COMMAND_INJECTION
# SI endpoint avec parametres de commande ET technologie non statique
# → attack_vector(sqli, HIGH) avec rationale injection de commandes
# ===========================================================================


def _command_injection_conditions(memory: list[Fact]) -> bool:
    """Conditions : endpoint avec parametres de commande ET pas uniquement un framework statique."""
    cmd_params = {"cmd", "exec", "command", "ping", "query", "search"}
    static_frameworks = {"html", "css", "bootstrap", "tailwind", "jquery"}

    endpoints = _get_facts(memory, "endpoint")
    has_cmd_param = False

    for ep in endpoints:
        params = ep.attributes.get("parameters", [])
        for param in params:
            if param.lower() in cmd_params:
                has_cmd_param = True
                break
        if has_cmd_param:
            break

    if not has_cmd_param:
        return False

    # Verifier que la technologie n'est pas uniquement un framework statique
    techs = _get_facts(memory, "technology")
    if not techs:
        return True  # Pas de technologie connue — on considere le risque

    tech_names = {t.attributes.get("name", "").lower() for t in techs}
    # Si toutes les technologies sont statiques, pas de risque
    return not (tech_names and tech_names.issubset(static_frameworks))


def _command_injection_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur sqli avec rationale injection de commandes."""
    new_facts = []
    cmd_params = {"cmd", "exec", "command", "ping", "query", "search"}
    endpoints = _get_facts(memory, "endpoint")

    existing_vectors = [f for f in memory if f.type == "attack_vector"]
    next_id = len(existing_vectors) + 1

    for ep in endpoints:
        params = ep.attributes.get("parameters", [])
        matching_params = [p for p in params if p.lower() in cmd_params]

        if not matching_params:
            continue

        endpoint_path = ep.attributes.get("path", "")

        already_targeted = any(
            f.type == "attack_vector"
            and f.attributes.get("target_endpoint") == endpoint_path
            and "Command Injection" in " ".join(f.attributes.get("rationale", []))
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
                    "attack_type": "sqli",
                    "target_endpoint": endpoint_path,
                    "target_fields": matching_params,
                    "severity": "HIGH",
                    "owasp_ref": "A03:2021-Injection",
                    "rationale": [
                        f"Command Injection potentielle sur {endpoint_path}",
                        f"Parametres suspects: {', '.join(matching_params)}",
                        "Type sqli utilise car command_injection non disponible dans l'enum",
                    ],
                    "base_payloads": [
                        "; ls",
                        "| cat /etc/passwd",
                        "$(whoami)",
                    ],
                },
                source="rule:COMMAND_INJECTION",
            )
        )

    return new_facts


COMMAND_INJECTION = Rule(
    name="COMMAND_INJECTION",
    conditions=_command_injection_conditions,
    action=_command_injection_action,
    priority=2,
)


# ===========================================================================
# REGLE 11 : BROKEN_AUTH
# SI formulaire de login existe ET pas de headers de rate limiting
# → attack_vector(auth_bypass, MEDIUM) avec rationale brute force
# ===========================================================================


def _broken_auth_conditions(memory: list[Fact]) -> bool:
    """Conditions : formulaire de login/auth existe ET pas de rate limiting."""
    # Chercher un endpoint ou formulaire de login
    endpoints = _get_facts(memory, "endpoint")
    forms = _get_facts(memory, "form")

    has_login_endpoint = any(
        "login" in ep.attributes.get("path", "").lower()
        or "auth" in ep.attributes.get("path", "").lower()
        for ep in endpoints
    )

    has_login_form = any(
        "login" in f.attributes.get("endpoint", "").lower()
        or "auth" in f.attributes.get("endpoint", "").lower()
        for f in forms
    )

    if not has_login_endpoint and not has_login_form:
        return False

    # Verifier l'absence de headers de rate limiting
    rate_limit_headers = {"X-Rate-Limit", "X-RateLimit-Limit", "Retry-After"}
    any(_has_fact(memory, "missing_header", header=h) for h in rate_limit_headers)

    # Si les headers de rate limiting sont dans les missing_headers, pas de protection
    # Si on ne trouve aucune mention de rate limiting, on assume pas de protection
    return True


def _broken_auth_action(memory: list[Fact]) -> list[Fact]:
    """Action : creer un vecteur auth_bypass avec rationale brute force."""
    new_facts = []
    endpoints = _get_facts(memory, "endpoint")
    forms = _get_facts(memory, "form")

    existing_vectors = [f for f in memory if f.type == "attack_vector"]
    next_id = len(existing_vectors) + 1

    # Collecter les endpoints de login
    login_endpoints = []
    for ep in endpoints:
        path = ep.attributes.get("path", "")
        if "login" in path.lower() or "auth" in path.lower():
            login_endpoints.append(path)

    for f in forms:
        endpoint = f.attributes.get("endpoint", "")
        if (
            "login" in endpoint.lower() or "auth" in endpoint.lower()
        ) and endpoint not in login_endpoints:
            login_endpoints.append(endpoint)

    for login_ep in login_endpoints:
        already_targeted = any(
            f.type == "attack_vector"
            and f.attributes.get("target_endpoint") == login_ep
            and "Brute force" in " ".join(f.attributes.get("rationale", []))
            for f in memory
        )
        if already_targeted:
            continue

        vector_id = f"VEC-{next_id:03d}"
        next_id += 1

        # Recuperer les champs du formulaire si disponible
        target_fields = []
        for f in forms:
            if f.attributes.get("endpoint", "") == login_ep:
                target_fields = f.attributes.get("fields", [])
                break

        new_facts.append(
            Fact(
                type="attack_vector",
                attributes={
                    "id": vector_id,
                    "attack_type": "auth_bypass",
                    "target_endpoint": login_ep,
                    "target_fields": target_fields,
                    "severity": "MEDIUM",
                    "owasp_ref": "A07:2021-Identification and Authentication Failures",
                    "rationale": [
                        f"Brute force possible sur le formulaire de login ({login_ep})",
                        "Aucun mecanisme de rate limiting detecte",
                        "Risque d'enumeration de comptes et d'attaque par dictionnaire",
                    ],
                    "base_payloads": [
                        "admin:admin",
                        "admin:password",
                        "admin:123456",
                        "test:test",
                    ],
                },
                source="rule:BROKEN_AUTH",
            )
        )

    return new_facts


BROKEN_AUTH = Rule(
    name="BROKEN_AUTH",
    conditions=_broken_auth_conditions,
    action=_broken_auth_action,
    priority=2,
)


# ===========================================================================
# Fonction de chargement de toutes les regles
# ===========================================================================


def get_all_rules() -> list[Rule]:
    """Retourne des copies fraiches de toutes les regles du systeme expert.

    Important: chaque appel retourne de nouvelles instances pour eviter
    que l'etat 'fired' persiste entre les executions.
    """
    all_rules = [
        SQL_INJECTION,
        XSS_REFLECTED,
        SQL_INJECTION_CRITICAL,
        IDOR,
        PATH_TRAVERSAL,
        AUTH_BYPASS,
        INFO_DISCLOSURE,
        CSRF,
        OPEN_REDIRECT,
        COMMAND_INJECTION,
        BROKEN_AUTH,
    ]

    rules = [
        Rule(
            name=r.name,
            conditions=r.conditions,
            action=r.action,
            priority=r.priority,
        )
        for r in all_rules
    ]

    # Regles header/config et chainage avance (fichiers separes)
    from .rules_chaining import get_chaining_rules
    from .rules_header import get_header_rules

    rules.extend(get_header_rules())
    rules.extend(get_chaining_rules())

    return rules
