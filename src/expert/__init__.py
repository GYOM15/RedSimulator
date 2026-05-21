"""Module Systeme Expert — Analyse de vulnerabilites par chainage avant.

Utilise un moteur a regles pour deduire les vecteurs d'attaque
a partir des faits extraits du scan.
"""

from .engine import ExpertEngine, Rule
from .facts import Fact, scan_result_to_facts
from .rules import get_all_rules

__all__ = ["ExpertEngine", "Rule", "Fact", "scan_result_to_facts", "get_all_rules"]
