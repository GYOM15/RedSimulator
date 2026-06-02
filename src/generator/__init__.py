"""Module Generateur — Generation de variantes de payloads via LLM + fallback offline.

Utilise l'API Claude pour generer des variantes intelligentes de payloads,
avec un fallback sur des mutations deterministes hors-ligne si l'API
n'est pas disponible.
"""

from .generate import generate_for_plan, generate_variants
from .payload_db import PayloadDatabase, payload_db

__all__ = ["PayloadDatabase", "generate_for_plan", "generate_variants", "payload_db"]
