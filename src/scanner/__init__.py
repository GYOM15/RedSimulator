"""Module Scanner — Agent ReAct autonome pour la reconnaissance de cible.

L'agent decide seul quels outils utiliser, dans quel ordre, et combien de fois.
Il adapte sa strategie selon ce qu'il decouvre sur la cible.

Structure du module :
- agent.py        : Orchestration de l'agent ReAct + fallback sequentiel
- tools.py        : 8 outils (@tool) pour l'agent
- http_utils.py   : Requetes HTTP paralleles + cache + formatage d'erreurs
- crawlers.py     : Decouverte de chemins (HTML + JS + Playwright conditionnel)
- form_parsing.py : Analyse de formulaires (statique + dynamique)
- tech_detector.py: Detection des technologies et versions
- memory.py       : Memoire persistante entre les scans
"""

from .agent import ReconAgent
from .tools import (
    directory_bruteforce,
    dns_enum,
    endpoint_discovery,
    form_analyzer,
    header_checker,
    port_scan,
    probe_endpoint,
    tech_detector,
)

__all__ = [
    "ReconAgent",
    "directory_bruteforce",
    "dns_enum",
    "endpoint_discovery",
    "form_analyzer",
    "header_checker",
    "port_scan",
    "probe_endpoint",
    "tech_detector",
]
