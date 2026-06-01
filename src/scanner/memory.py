"""Memoire persistante entre les scans.

Stocke l'historique des scans par cible dans un fichier JSON local.
Permet a l'agent de comparer avec les scans precedents et detecter
les changements de surface d'attaque.

Fichier: data/scan_history.json
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path

from src.infra.logging import get_logger
from src.infra.decorators import safe

logger = get_logger(__name__)

HISTORY_PATH = Path(__file__).parent.parent.parent / "data" / "scan_history.json"


@safe(fallback={})
def _load_history() -> dict:
    """Charge l'historique des scans."""
    if HISTORY_PATH.exists():
        return json.loads(HISTORY_PATH.read_text())
    return {}


@safe(fallback=None)
def _save_history(history: dict):
    """Sauvegarde l'historique."""
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_PATH.write_text(json.dumps(history, indent=2, default=str))


def _target_key(target: str) -> str:
    """Cle unique pour une cible (hash du domaine)."""
    return hashlib.md5(target.encode()).hexdigest()[:12]


def save_scan(scan_result) -> dict:
    """Sauvegarde un scan dans l'historique.

    Args:
        scan_result: ScanResult Pydantic

    Returns:
        Dict avec les changements detectes par rapport au scan precedent.
    """
    history = _load_history()
    key = _target_key(scan_result.target)

    # Creer l'entree pour cette cible si necessaire
    if key not in history:
        history[key] = {
            "target": scan_result.target,
            "scans": [],
        }

    # Extraire les donnees essentielles
    scan_entry = {
        "date": scan_result.scan_timestamp,
        "endpoints_count": len(scan_result.endpoints),
        "endpoints": [ep.path for ep in scan_result.endpoints],
        "ports": [p.port for p in scan_result.open_ports],
        "technologies": scan_result.technologies,
        "risk_score": scan_result.risk_score.get("score", 0) if scan_result.risk_score else 0,
        "missing_headers": scan_result.headers.missing_security_headers,
        "forms_count": len(scan_result.forms),
    }

    # Detecter les changements
    changes = _detect_changes(history[key].get("scans", []), scan_entry)

    # Ajouter le scan (garder max 10 scans par cible)
    history[key]["scans"].append(scan_entry)
    if len(history[key]["scans"]) > 10:
        history[key]["scans"] = history[key]["scans"][-10:]

    _save_history(history)
    return changes


def get_previous_context(target: str) -> str:
    """Retourne un contexte textuel des scans precedents pour l'agent.

    L'agent recoit ce texte dans son prompt pour adapter sa strategie.

    Args:
        target: URL de la cible

    Returns:
        Texte de contexte ou chaine vide si premier scan.
    """
    history = _load_history()
    key = _target_key(target)

    if key not in history or not history[key].get("scans"):
        return ""

    scans = history[key]["scans"]
    last = scans[-1]

    lines = [
        f"=== HISTORIQUE DES SCANS PRECEDENTS ({len(scans)} scan(s)) ===",
        f"Dernier scan: {last['date']}",
        f"  Endpoints: {last['endpoints_count']}",
        f"  Ports ouverts: {last['ports']}",
        f"  Technologies: {', '.join(last['technologies'])}",
        f"  Score de risque: {last['risk_score']}/100",
        f"  Headers manquants: {', '.join(last['missing_headers'])}",
    ]

    # Evolution si plusieurs scans
    if len(scans) >= 2:
        prev = scans[-2]
        lines.append(f"\nEvolution depuis le scan precedent ({prev['date']}) :")

        new_eps = set(last["endpoints"]) - set(prev["endpoints"])
        removed_eps = set(prev["endpoints"]) - set(last["endpoints"])
        new_ports = set(last["ports"]) - set(prev["ports"])
        removed_ports = set(prev["ports"]) - set(last["ports"])

        if new_eps:
            lines.append(f"  Nouveaux endpoints: {', '.join(list(new_eps)[:10])}")
        if removed_eps:
            lines.append(f"  Endpoints disparus: {', '.join(list(removed_eps)[:10])}")
        if new_ports:
            lines.append(f"  Nouveaux ports: {new_ports}")
        if removed_ports:
            lines.append(f"  Ports fermes: {removed_ports}")
        if last["risk_score"] != prev["risk_score"]:
            delta = last["risk_score"] - prev["risk_score"]
            direction = "augmente" if delta > 0 else "diminue"
            lines.append(f"  Score de risque {direction}: {prev['risk_score']} -> {last['risk_score']}")

        if not (new_eps or removed_eps or new_ports or removed_ports):
            lines.append("  Aucun changement significatif detecte.")

    lines.append("=== FIN HISTORIQUE ===")
    return "\n".join(lines)


def _detect_changes(previous_scans: list, current: dict) -> dict:
    """Detecte les changements entre le scan actuel et le precedent."""
    if not previous_scans:
        return {"first_scan": True, "changes": []}

    last = previous_scans[-1]
    changes = []

    new_eps = set(current["endpoints"]) - set(last["endpoints"])
    removed_eps = set(last["endpoints"]) - set(current["endpoints"])
    new_ports = set(current["ports"]) - set(last["ports"])
    removed_ports = set(last["ports"]) - set(current["ports"])

    if new_eps:
        changes.append({"type": "new_endpoints", "count": len(new_eps), "details": list(new_eps)[:10]})
    if removed_eps:
        changes.append({"type": "removed_endpoints", "count": len(removed_eps), "details": list(removed_eps)[:10]})
    if new_ports:
        changes.append({"type": "new_ports", "details": list(new_ports)})
    if removed_ports:
        changes.append({"type": "closed_ports", "details": list(removed_ports)})

    score_delta = current["risk_score"] - last["risk_score"]
    if abs(score_delta) >= 5:
        changes.append({"type": "risk_change", "from": last["risk_score"], "to": current["risk_score"]})

    return {"first_scan": False, "changes": changes}
