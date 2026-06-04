"""CVSS v3.1 base score calculator.

Computes CVSS base scores from vulnerability characteristics
following the official CVSS v3.1 specification.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from src.infra.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Metric value weights per the CVSS v3.1 specification
# ---------------------------------------------------------------------------

_AV_WEIGHTS: dict[str, float] = {
    "N": 0.85,  # Network
    "A": 0.62,  # Adjacent
    "L": 0.55,  # Local
    "P": 0.20,  # Physical
}

_AC_WEIGHTS: dict[str, float] = {
    "L": 0.77,  # Low
    "H": 0.44,  # High
}

# Privileges Required weights depend on Scope
_PR_WEIGHTS_UNCHANGED: dict[str, float] = {
    "N": 0.85,  # None
    "L": 0.62,  # Low
    "H": 0.27,  # High
}

_PR_WEIGHTS_CHANGED: dict[str, float] = {
    "N": 0.85,  # None
    "L": 0.68,  # Low
    "H": 0.50,  # High
}

_UI_WEIGHTS: dict[str, float] = {
    "N": 0.85,  # None
    "R": 0.62,  # Required
}

_CIA_WEIGHTS: dict[str, float] = {
    "H": 0.56,  # High
    "L": 0.22,  # Low
    "N": 0.00,  # None
}

# ---------------------------------------------------------------------------
# Severity thresholds per CVSS v3.1
# ---------------------------------------------------------------------------

_SEVERITY_THRESHOLDS: list[tuple[float, str]] = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
]


def _severity_label(score: float) -> str:
    """Map a CVSS score to its severity label."""
    if score == 0.0:
        return "NONE"
    for threshold, label in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "NONE"


def _roundup(value: float) -> float:
    """CVSS v3.1 roundup function.

    Rounds up to the nearest tenth as defined in the specification:
    Roundup(x) = ceiling(x * 10) / 10.0
    """
    return math.ceil(value * 10) / 10.0


# ---------------------------------------------------------------------------
# CVSSVector dataclass
# ---------------------------------------------------------------------------


@dataclass
class CVSSVector:
    """CVSS v3.1 base metrics.

    Each field uses the standard single-letter abbreviation:
        attack_vector:       N=Network, A=Adjacent, L=Local, P=Physical
        attack_complexity:   L=Low, H=High
        privileges_required: N=None, L=Low, H=High
        user_interaction:    N=None, R=Required
        scope:               U=Unchanged, C=Changed
        confidentiality:     N=None, L=Low, H=High
        integrity:           N=None, L=Low, H=High
        availability:        N=None, L=Low, H=High
    """

    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "H"
    integrity: str = "H"
    availability: str = "N"

    def to_vector_string(self) -> str:
        """Return the standard CVSS v3.1 vector string.

        Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
        """
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
            f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
            f"/S:{self.scope}"
            f"/C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"
        )


# ---------------------------------------------------------------------------
# Core calculation
# ---------------------------------------------------------------------------


def calculate_cvss_score(vector: CVSSVector) -> tuple[float, str]:
    """Calculate CVSS v3.1 base score and severity label.

    Implements the official CVSS v3.1 base score formula from
    https://www.first.org/cvss/v3.1/specification-document

    Returns:
        (score, severity) where score is 0.0-10.0 and severity is
        "CRITICAL", "HIGH", "MEDIUM", "LOW", or "NONE".
    """
    # Look up metric weights
    av = _AV_WEIGHTS[vector.attack_vector]
    ac = _AC_WEIGHTS[vector.attack_complexity]
    ui = _UI_WEIGHTS[vector.user_interaction]

    # PR weight depends on Scope
    if vector.scope == "C":
        pr = _PR_WEIGHTS_CHANGED[vector.privileges_required]
    else:
        pr = _PR_WEIGHTS_UNCHANGED[vector.privileges_required]

    c = _CIA_WEIGHTS[vector.confidentiality]
    i = _CIA_WEIGHTS[vector.integrity]
    a = _CIA_WEIGHTS[vector.availability]

    # Impact Sub-Score (ISS)
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    # If ISS is 0, the base score is 0
    if iss <= 0:
        return 0.0, "NONE"

    # Impact depends on scope
    if vector.scope == "U":  # noqa: SIM108
        impact = 6.42 * iss
    else:
        # Scope Changed
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # If impact is negative or zero, base score is 0
    if impact <= 0:
        return 0.0, "NONE"

    # Exploitability sub-score
    exploitability = 8.22 * av * ac * pr * ui

    # Base score calculation depends on scope
    if vector.scope == "U":
        base_score = _roundup(min(impact + exploitability, 10.0))
    else:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))

    severity = _severity_label(base_score)

    logger.debug(
        "CVSS score: %s -> %.1f (%s) [ISS=%.4f, Impact=%.4f, Exploit=%.4f]",
        vector.to_vector_string(),
        base_score,
        severity,
        iss,
        impact,
        exploitability,
    )

    return base_score, severity


# ---------------------------------------------------------------------------
# Attack type -> CVSS vector mapping
# ---------------------------------------------------------------------------

# Default CVSS vectors for RedSimulator attack types.
# These are reasonable defaults; a human analyst would refine them
# for the specific context and environment.

_ATTACK_TYPE_VECTORS: dict[str, CVSSVector] = {
    # sqli: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N -> 9.1 (CRITICAL)
    "sqli": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="H",
        availability="N",
    ),
    # xss (reflected): AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -> 6.1 (MEDIUM)
    "xss": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="R",
        scope="C",
        confidentiality="L",
        integrity="L",
        availability="N",
    ),
    # idor: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N -> 6.5 (MEDIUM)
    "idor": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="L",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="N",
        availability="N",
    ),
    # path_traversal: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N -> 7.5 (HIGH)
    "path_traversal": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="N",
        availability="N",
    ),
    # auth_bypass: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N -> 9.1 (CRITICAL)
    "auth_bypass": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="H",
        availability="N",
    ),
    # info_disclosure: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N -> 5.3 (MEDIUM)
    "info_disclosure": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="L",
        integrity="N",
        availability="N",
    ),
    # command_injection: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8 (CRITICAL)
    "command_injection": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="H",
        availability="H",
    ),
    # csrf: AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N -> 6.5 (MEDIUM)
    "csrf": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="R",
        scope="U",
        confidentiality="N",
        integrity="H",
        availability="N",
    ),
    # open_redirect: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -> 6.1 (MEDIUM)
    "open_redirect": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="R",
        scope="C",
        confidentiality="L",
        integrity="L",
        availability="N",
    ),
}

# Authenticated variants: PR changes from N to L
_ATTACK_TYPE_VECTORS_AUTH: dict[str, CVSSVector] = {}
for _atype, _vec in _ATTACK_TYPE_VECTORS.items():
    if _vec.privileges_required == "N":
        _ATTACK_TYPE_VECTORS_AUTH[_atype] = CVSSVector(
            attack_vector=_vec.attack_vector,
            attack_complexity=_vec.attack_complexity,
            privileges_required="L",
            user_interaction=_vec.user_interaction,
            scope=_vec.scope,
            confidentiality=_vec.confidentiality,
            integrity=_vec.integrity,
            availability=_vec.availability,
        )
    else:
        _ATTACK_TYPE_VECTORS_AUTH[_atype] = _vec


def attack_type_to_cvss(attack_type: str, auth_required: bool = False) -> CVSSVector:
    """Map a RedSimulator attack type to a default CVSS vector.

    These are reasonable defaults -- a human analyst would refine them
    for the specific context and environment.

    Args:
        attack_type: One of the RedSimulator AttackType values
            (e.g. "sqli", "xss", "command_injection").
        auth_required: If True, sets PR to at least "L" (Low) to
            reflect that authentication is needed to exploit.

    Returns:
        A CVSSVector with default metrics for the attack type.
        Falls back to a generic MEDIUM vector for unknown types.
    """
    source = _ATTACK_TYPE_VECTORS_AUTH if auth_required else _ATTACK_TYPE_VECTORS

    if attack_type in source:
        vec = source[attack_type]
        # Return a copy to avoid mutation of module-level defaults
        return CVSSVector(
            attack_vector=vec.attack_vector,
            attack_complexity=vec.attack_complexity,
            privileges_required=vec.privileges_required,
            user_interaction=vec.user_interaction,
            scope=vec.scope,
            confidentiality=vec.confidentiality,
            integrity=vec.integrity,
            availability=vec.availability,
        )

    # Unknown attack type: return a generic MEDIUM vector
    logger.warning("Unknown attack type %r, using generic CVSS vector", attack_type)
    return CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="L",
        integrity="L",
        availability="N",
    )
