"""Module Systeme Expert — Analyse de vulnerabilites par chainage avant.

Utilise un moteur a regles pour deduire les vecteurs d'attaque
a partir des faits extraits du scan.
"""

from .custom_rules import CustomRuleDefinition, CustomRuleEngine
from .engine import ExpertEngine, Rule
from .facts import Fact, passive_findings_to_facts, scan_result_to_facts
from .llm_analyst import llm_analyze
from .rules import get_all_rules
from .rules_chaining import get_chaining_rules
from .rules_header import get_header_rules

__all__ = [
    "CustomRuleDefinition",
    "CustomRuleEngine",
    "ExpertEngine",
    "Fact",
    "Rule",
    "get_all_rules",
    "get_chaining_rules",
    "get_header_rules",
    "llm_analyze",
    "passive_findings_to_facts",
    "scan_result_to_facts",
]
