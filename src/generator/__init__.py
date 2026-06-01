"""Module Generateur — Generation de variantes de payloads via LLM + fallback offline.

Utilise l'API Claude pour generer des variantes intelligentes de payloads,
avec un fallback sur des mutations deterministes hors-ligne si l'API
n'est pas disponible.
"""

from .generate import generate_for_plan, generate_variants

__all__ = ["generate_for_plan", "generate_variants"]
