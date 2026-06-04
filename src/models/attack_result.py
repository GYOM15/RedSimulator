"""Modeles Pydantic pour les resultats d'execution des attaques.

Ces modeles representent la sortie du module Executor. Chaque attaque
executee produit un resultat indiquant si elle a reussi ou echoue.
"""

from pydantic import BaseModel, ConfigDict


class SingleAttackResult(BaseModel):
    """Resultat d'une seule tentative d'attaque."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "vector_id": "VEC-001",
                    "payload_used": "' OR 1=1--",
                    "target_endpoint": "/rest/user/login",
                    "http_status": 200,
                    "response_snippet": '{"authentication":{"token":"eyJ..."}}',
                    "success": True,
                    "detection_method": "Authentication token returned without valid credentials",
                }
            ]
        }
    )

    vector_id: str
    payload_used: str
    target_endpoint: str
    http_status: int
    response_snippet: str
    success: bool
    detection_method: str
    confidence: float = 0.0
    confidence_label: str = "unvalidated"
    validation_details: list[str] = []


class AttackResult(BaseModel):
    """Resultat global de l'execution de toutes les attaques."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "results": [],
                    "total_attempts": 12,
                    "successful_attacks": 3,
                }
            ]
        }
    )

    results: list[SingleAttackResult] = []
    total_attempts: int = 0
    successful_attacks: int = 0
