"""Modeles Pydantic pour les resultats de generation de payloads.

Ces modeles representent la sortie du module VAE. Pour chaque vecteur
d'attaque, le VAE genere des variantes du payload de base.
"""

from pydantic import BaseModel, ConfigDict


class GeneratedPayload(BaseModel):
    """Variantes generees pour un vecteur d'attaque."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "vector_id": "VEC-001",
                    "original": "' OR 1=1--",
                    "variants": [
                        "' OR 1=1 --",
                        "' OR '1'='1'--",
                        "' OR 1=1#",
                        "'  OR  1=1--",
                    ],
                }
            ]
        }
    )

    vector_id: str
    original: str
    variants: list[str] = []


class PayloadResult(BaseModel):
    """Ensemble des payloads generes pour tout le plan d'attaque."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "payloads": [
                        {
                            "vector_id": "VEC-001",
                            "original": "' OR 1=1--",
                            "variants": ["' OR 1=1 --", "' OR '1'='1'--"],
                        }
                    ]
                }
            ]
        }
    )

    payloads: list[GeneratedPayload] = []
