"""Modeles Pydantic pour le plan d'attaque.

Ces modeles representent la sortie du Systeme Expert. Le plan contient
les vecteurs d'attaque identifies, classes par severite, avec les
payloads de base a tester.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Severity(StrEnum):
    """Niveaux de severite OWASP."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AttackType(StrEnum):
    """Types d'attaques supportes."""

    sqli = "sqli"
    xss = "xss"
    idor = "idor"
    path_traversal = "path_traversal"
    auth_bypass = "auth_bypass"
    info_disclosure = "info_disclosure"
    command_injection = "command_injection"
    csrf = "csrf"
    open_redirect = "open_redirect"


class AttackVector(BaseModel):
    """Un vecteur d'attaque identifie par le systeme expert."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "id": "VEC-001",
                    "attack_type": "sqli",
                    "target_endpoint": "/rest/user/login",
                    "target_fields": ["email", "password"],
                    "severity": "CRITICAL",
                    "owasp_ref": "A03:2021-Injection",
                    "rationale": [
                        "Formulaire de login sans protection",
                        "Backend SQLite detecte",
                        "Endpoint sans authentification",
                    ],
                    "base_payloads": [
                        "' OR 1=1--",
                        "admin'--",
                        "' UNION SELECT * FROM Users--",
                    ],
                }
            ]
        }
    )

    id: str
    attack_type: AttackType
    target_endpoint: str
    target_fields: list[str] = []
    severity: Severity
    owasp_ref: str
    rationale: list[str] = []
    base_payloads: list[str] = []


class AttackPlan(BaseModel):
    """Plan d'attaque complet genere par le systeme expert."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "scan_id": "scan-001",
                    "generated_at": "2025-01-15T10:35:00Z",
                    "vectors": [],
                    "rules_fired": [
                        "SQL_INJECTION",
                        "SQL_INJECTION_CRITICAL",
                        "XSS_REFLECTED",
                    ],
                }
            ]
        }
    )

    scan_id: str
    generated_at: str
    vectors: list[AttackVector] = []
    rules_fired: list[str] = []
