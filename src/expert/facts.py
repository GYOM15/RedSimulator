"""Gestion des faits pour le systeme expert.

Les faits representent les connaissances extraites du scan.
La fonction scan_result_to_facts convertit un ScanResult en
une liste de faits exploitables par le moteur de regles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from src.infra.logging import get_logger
from src.models import ScanResult

if TYPE_CHECKING:
    from src.passive.models import PassiveReport

logger = get_logger(__name__)


@dataclass
class Fact:
    """Un fait dans la memoire de travail du systeme expert.

    Attributes:
        type: Le type de fait (ex: 'open_port', 'endpoint', 'technology', etc.)
        attributes: Dictionnaire d'attributs specifiques au fait.
        source: Origine du fait ('scan', 'rule', 'user').
    """

    type: str
    attributes: dict[str, Any] = field(default_factory=dict)
    source: str = "scan"

    def __str__(self) -> str:
        attrs = ", ".join(f"{k}={v}" for k, v in self.attributes.items())
        return f"Fact({self.type}: {attrs}) [source={self.source}]"


def scan_result_to_facts(scan: ScanResult) -> list[Fact]:
    """Convertit un ScanResult en liste de faits pour le systeme expert.

    Extrait les faits suivants :
    - open_port : pour chaque port ouvert
    - endpoint : pour chaque endpoint decouvert
    - technology : pour chaque technologie detectee
    - missing_header : pour chaque header de securite manquant
    - server_info_leaked : si le serveur expose des informations
    - form : pour chaque formulaire detecte

    Args:
        scan: Resultat du scan de reconnaissance.

    Returns:
        Liste de faits prets pour le moteur de regles.
    """
    facts: list[Fact] = []

    # Faits sur les ports
    for port_info in scan.open_ports:
        facts.append(
            Fact(
                type="open_port",
                attributes={
                    "port": port_info.port,
                    "service": port_info.service,
                    "version": port_info.version,
                },
            )
        )

    # Faits sur les endpoints
    for ep in scan.endpoints:
        facts.append(
            Fact(
                type="endpoint",
                attributes={
                    "path": ep.path,
                    "method": ep.method,
                    "status_code": ep.status_code,
                    "auth_required": ep.auth_required,
                    "parameters": ep.parameters,
                },
            )
        )

    # Faits sur les technologies
    for tech in scan.technologies:
        facts.append(
            Fact(
                type="technology",
                attributes={"name": tech},
            )
        )

    # Faits sur les headers manquants
    for header in scan.headers.missing_security_headers:
        facts.append(
            Fact(
                type="missing_header",
                attributes={"header": header},
            )
        )

    # Fuite d'information serveur
    if scan.headers.server_info_leaked:
        facts.append(
            Fact(
                type="server_info_leaked",
                attributes={"leaked": True},
            )
        )

    # Faits sur les formulaires
    for form in scan.forms:
        facts.append(
            Fact(
                type="form",
                attributes={
                    "endpoint": form.endpoint,
                    "fields": [f.name for f in form.fields],
                    "method": form.method,
                },
            )
        )

    logger.info("%d faits extraits du scan:", len(facts))
    for f in facts:
        logger.debug("  - %s", f)

    return facts


def passive_findings_to_facts(report: PassiveReport) -> list[Fact]:
    """Convert passive scan findings into facts for the expert system.

    Each finding becomes a ``passive_finding`` fact with attributes:
    ``check_name``, ``severity``, ``url``, ``cwe_id``, ``title``,
    and ``description``.

    Args:
        report: PassiveReport from the passive analyzer.

    Returns:
        List of facts representing the passive findings.
    """
    from src.passive.models import PassiveReport

    if not isinstance(report, PassiveReport):
        logger.warning("passive_findings_to_facts: expected PassiveReport, got %s", type(report))
        return []

    facts: list[Fact] = []

    for finding in report.findings:
        facts.append(
            Fact(
                type="passive_finding",
                attributes={
                    "check_name": finding.check_name,
                    "severity": str(finding.severity),
                    "url": finding.url,
                    "cwe_id": finding.cwe_id,
                    "title": finding.title,
                    "description": finding.description,
                },
                source="passive_scan",
            )
        )

    logger.info("%d faits extraits de l'analyse passive:", len(facts))
    for f in facts:
        logger.debug("  - %s", f)

    return facts


if __name__ == "__main__":
    import json
    from pathlib import Path

    fixture_path = Path(__file__).parent.parent.parent / "data" / "fixtures" / "scan_result.json"
    data = json.loads(fixture_path.read_text())
    scan = ScanResult.model_validate(data)

    facts = scan_result_to_facts(scan)
    logger.info("Total: %d faits", len(facts))
