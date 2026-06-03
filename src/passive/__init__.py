"""Module Passive — Analyse passive des reponses HTTP.

Analyse les headers, cookies, corps de reponse et URLs pour detecter
des problemes de securite sans envoyer de nouvelles requetes actives.

Structure du module :
- models.py       : PassiveFinding, PassiveReport, FindingSeverity
- analyzer.py     : PassiveAnalyzer orchestrateur principal
- checks/         : Implementations des verifications passives
  - base.py       : Classe abstraite PassiveCheck
  - headers.py    : Headers de securite manquants / fuite d'info
  - cookies.py    : Flags de securite des cookies
  - information.py: Fuite d'information dans le corps de reponse
  - transport.py  : Securite du transport (contenu mixte, redirections)
  - sensitive_urls.py : Donnees sensibles dans les URLs
  - cors.py       : Misconfiguration CORS
"""

from src.passive.analyzer import PassiveAnalyzer, analyze_response
from src.passive.models import FindingSeverity, PassiveFinding, PassiveReport

__all__ = [
    "FindingSeverity",
    "PassiveAnalyzer",
    "PassiveFinding",
    "PassiveReport",
    "analyze_response",
]
