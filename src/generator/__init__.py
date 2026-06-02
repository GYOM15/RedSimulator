"""Module Generateur — Generation de variantes de payloads via LLM + fallback offline.

Utilise l'API Claude pour generer des variantes intelligentes de payloads,
avec un fallback sur des mutations deterministes hors-ligne si l'API
n'est pas disponible.

The contextual intelligence system (payload_models, feedback) provides
smart payload selection based on target technologies, WAF detection,
and historical effectiveness tracking.
"""

from .feedback import FeedbackTracker, feedback_tracker
from .generate import generate_for_plan, generate_variants
from .payload_db import PayloadDatabase, payload_db
from .payload_models import IntelPayload, PayloadStats

__all__ = [
    "FeedbackTracker",
    "IntelPayload",
    "PayloadDatabase",
    "PayloadStats",
    "feedback_tracker",
    "generate_for_plan",
    "generate_variants",
    "payload_db",
]
