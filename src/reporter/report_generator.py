"""Generateur de rapports de vulnerabilites.

Utilise Claude API pour generer un rapport Markdown structure.
Fallback : template statique avec les donnees inserees.

TODO: Ameliorer les prompts, ajouter le streaming.
"""

from datetime import datetime
from zoneinfo import ZoneInfo

from src.infra.config import settings
from src.infra.decorators import logged
from src.infra.exceptions import ReporterError
from src.infra.logging import get_logger
from src.models import AttackPlan, AttackResult, ScanResult

logger = get_logger(__name__)


@logged
def generate_report(
    scan: ScanResult,
    plan: AttackPlan,
    results: AttackResult,
) -> str:
    """Genere un rapport Markdown des vulnerabilites trouvees.

    Tente d'utiliser Claude API pour generer le rapport.
    Si pas de cle API, retourne un rapport template.

    Args:
        scan: Resultats du scan.
        plan: Plan d'attaque genere.
        results: Resultats de l'execution.

    Returns:
        Rapport en format Markdown.
    """
    logger.info("Generation du rapport de vulnerabilites...")

    api_key = settings.anthropic_api_key or ""
    if api_key and not api_key.startswith("sk-ant-..."):
        return _generate_with_llm(scan, plan, results, api_key)
    else:
        logger.warning("Pas de cle API, utilisation du template statique")
        return _generate_template(scan, plan, results)


def _generate_with_llm(
    scan: ScanResult,
    plan: AttackPlan,
    results: AttackResult,
    api_key: str,
) -> str:
    """Genere le rapport via Claude API."""
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)

        prompt = f"""Genere un rapport de securite professionnel en Markdown a partir de ces donnees.

                ## Donnees du scan
                {scan.model_dump_json(indent=2)}

                ## Plan d'attaque
                {plan.model_dump_json(indent=2)}

                ## Resultats
                {results.model_dump_json(indent=2)}

                Le rapport doit contenir :
                1. Resume executif (2-3 phrases)
                2. Tableau recapitulatif des vulnerabilites (type, severite, endpoint, statut)
                3. Detail de chaque vulnerabilite trouvee avec recommandations
                4. Score de risque global
                5. Recommandations prioritaires

                Format: Markdown propre, professionnel, en francais."""

        message = client.messages.create(
            model=settings.llm_model,
            max_tokens=settings.llm_max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )

        report = message.content[0].text
        logger.info("Rapport genere avec Claude API")
        return report

    except Exception as e:
        logger.error("Erreur API: %s, fallback sur template", e)
        return _generate_template(scan, plan, results)


def _generate_template(
    scan: ScanResult,
    plan: AttackPlan,
    results: AttackResult,
) -> str:
    """Genere un rapport template sans LLM."""
    now = datetime.now(ZoneInfo("America/Toronto")).strftime("%Y-%m-%d %H:%M (Quebec)")

    # Compter les resultats par severite
    severity_counts: dict[str, int] = {}
    for v in plan.vectors:
        sev = v.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Construire le tableau des vulnerabilites
    vuln_rows = []
    for v in plan.vectors:
        # Trouver si l'attaque a reussi
        success = any(
            r.success and r.vector_id == v.id for r in results.results
        )
        status = "Exploitee" if success else "Non exploitee"
        vuln_rows.append(
            f"| {v.id} | {v.attack_type.value} | {v.severity.value} | "
            f"`{v.target_endpoint}` | {status} |"
        )

    vuln_table = "\n".join(vuln_rows)

    # Details par vulnerabilite
    details = []
    for v in plan.vectors:
        attack_results = [r for r in results.results if r.vector_id == v.id]
        successful = [r for r in attack_results if r.success]

        detail = f"""### {v.id} — {v.attack_type.value.upper()} ({v.severity.value})

                **Endpoint cible :** `{v.target_endpoint}`
                **Reference OWASP :** {v.owasp_ref}

                **Analyse :**
                """
        for r in v.rationale:
            detail += f"- {r}\n"

        if successful:
            detail += f"\n**Resultat :** Vulnerabilite confirmee ({len(successful)} payload(s) reussi(s))\n"
            for r in successful:
                detail += f"- Payload : `{r.payload_used}` → {r.detection_method}\n"
        else:
            detail += "\n**Resultat :** Non exploitee lors du test\n"

        details.append(detail)

    details_section = "\n".join(details)

    # Recommandations
    recommendations = []
    for v in plan.vectors:
        if v.attack_type.value == "sqli":
            recommendations.append(
                "- **Injection SQL** : Utiliser des requetes parametrees (prepared statements). "
                "Ne jamais concatener les entrees utilisateur dans les requetes SQL."
            )
        elif v.attack_type.value == "xss":
            recommendations.append(
                "- **XSS** : Implementer Content-Security-Policy. "
                "Encoder les sorties HTML. Utiliser un framework avec auto-escaping."
            )
        elif v.attack_type.value == "idor":
            recommendations.append(
                "- **IDOR** : Implementer des controles d'autorisation cote serveur. "
                "Utiliser des identifiants non previsibles (UUID)."
            )
        elif v.attack_type.value == "info_disclosure":
            recommendations.append(
                "- **Divulgation d'information** : Supprimer les headers Server/X-Powered-By. "
                "Restreindre l'acces aux endpoints d'administration."
            )

    reco_section = "\n".join(set(recommendations))

    report = f"""# Rapport de Securite — RedSimulator

            **Date :** {now}
            **Cible :** {scan.target}
            **Technologies :** {', '.join(scan.technologies)}

            ---

            ## Resume Executif

            Un scan de securite automatise a ete effectue sur `{scan.target}`. L'analyse a identifie
            **{len(plan.vectors)} vecteurs d'attaque** dont **{results.successful_attacks} ont ete exploites
            avec succes** sur {results.total_attempts} tentatives. Les vulnerabilites les plus critiques
            concernent l'injection SQL sur le formulaire de login.

            ---

            ## Tableau Recapitulatif

            | ID | Type | Severite | Endpoint | Statut |
            |----|------|----------|----------|--------|
            {vuln_table}

            ---

            ## Details des Vulnerabilites

            {details_section}

            ---

            ## Score de Risque

            | Severite | Nombre |
            |----------|--------|
            | CRITICAL | {severity_counts.get('CRITICAL', 0)} |
            | HIGH | {severity_counts.get('HIGH', 0)} |
            | MEDIUM | {severity_counts.get('MEDIUM', 0)} |
            | LOW | {severity_counts.get('LOW', 0)} |

            **Score global : {'CRITIQUE' if severity_counts.get('CRITICAL', 0) > 0 else 'ELEVE'}**

            ---

            ## Recommandations Prioritaires

            {reco_section}

            ---

            *Rapport genere par RedSimulator — PoC academique INF8790*
            """

    logger.info("Rapport genere (%d caracteres)", len(report))
    return report


if __name__ == "__main__":
    import json
    from pathlib import Path

    from src.infra.logging import setup_logging

    setup_logging(level=settings.log_level, fmt=settings.log_format)

    data_dir = Path(__file__).parent.parent.parent / "data" / "fixtures"

    scan = ScanResult.model_validate(json.loads((data_dir / "scan_result.json").read_text()))
    plan = AttackPlan.model_validate(json.loads((data_dir / "attack_plan.json").read_text()))
    results = AttackResult.model_validate(json.loads((data_dir / "attack_result.json").read_text()))

    report = generate_report(scan, plan, results)
    logger.info("Rapport genere:\n%s", report)
