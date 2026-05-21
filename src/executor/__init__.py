"""Module Executor — Execution des attaques contre la cible.

Execute les payloads generes contre les endpoints cibles et
enregistre les resultats (succes/echec, reponse HTTP, etc.).
"""

from .runner import AttackExecutor

__all__ = ["AttackExecutor"]
