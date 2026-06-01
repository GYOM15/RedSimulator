"""Modeles Pydantic partages entre tous les modules de RedSimulator.

Ces modeles constituent le contrat d'interface entre les modules.
Chaque module consomme et/ou produit des instances de ces modeles.
"""

from .attack_plan import AttackPlan, AttackType, AttackVector, Severity
from .attack_result import AttackResult, SingleAttackResult
from .payload_result import GeneratedPayload, PayloadResult
from .scan_result import (
    EndpointInfo,
    FormInfo,
    HeaderAnalysis,
    PortInfo,
    ScanResult,
)

__all__ = [
    "AttackPlan",
    "AttackResult",
    "AttackType",
    "AttackVector",
    "EndpointInfo",
    "FormInfo",
    "GeneratedPayload",
    "HeaderAnalysis",
    "PayloadResult",
    "PortInfo",
    "ScanResult",
    "Severity",
    "SingleAttackResult",
]
