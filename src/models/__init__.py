"""Modeles Pydantic partages entre tous les modules de RedSimulator.

Ces modeles constituent le contrat d'interface entre les modules.
Chaque module consomme et/ou produit des instances de ces modeles.
"""

from .scan_result import (
    EndpointInfo,
    FormInfo,
    HeaderAnalysis,
    PortInfo,
    ScanResult,
)
from .attack_plan import AttackPlan, AttackType, AttackVector, Severity
from .payload_result import GeneratedPayload, PayloadResult
from .attack_result import AttackResult, SingleAttackResult

__all__ = [
    "PortInfo",
    "EndpointInfo",
    "HeaderAnalysis",
    "FormInfo",
    "ScanResult",
    "Severity",
    "AttackType",
    "AttackVector",
    "AttackPlan",
    "GeneratedPayload",
    "PayloadResult",
    "SingleAttackResult",
    "AttackResult",
]
