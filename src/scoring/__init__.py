"""CVSS v3.1 scoring module for RedSimulator.

Provides CVSS base score calculation and attack-type-to-vector mapping.
"""

from .cvss import CVSSVector, attack_type_to_cvss, calculate_cvss_score

__all__ = [
    "CVSSVector",
    "attack_type_to_cvss",
    "calculate_cvss_score",
]
