"""Module Executor — Execution des attaques contre la cible.

Execute les payloads generes contre les endpoints cibles et
enregistre les resultats (succes/echec, reponse HTTP, etc.).

Uses a plugin architecture: each attack type is handled by a
dedicated :class:`AttackHandler` subclass discovered at runtime
from the ``src.executor.attacks`` package.
"""

from .base import AttackHandler
from .runner import AttackExecutor
from .session import SessionManager

__all__ = ["AttackExecutor", "AttackHandler", "SessionManager"]
