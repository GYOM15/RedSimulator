"""Generateur de rapports de vulnerabilites.

Utilise Claude API pour generer un rapport Markdown structure.
Fallback : template statique avec les donnees inserees.
"""

import textwrap
from datetime import datetime
from zoneinfo import ZoneInfo

from src.infra.config import settings
from src.infra.decorators import logged
from src.infra.logging import get_logger
from src.models import AttackPlan, AttackResult, ScanResult

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) mapping for attack types
# ---------------------------------------------------------------------------
_OWASP_MAP: dict[str, str] = {
    "sqli": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection (Cross-Site Scripting)",
    "idor": "A01:2021 - Broken Access Control",
    "path_traversal": "A01:2021 - Broken Access Control",
    "auth_bypass": "A07:2021 - Identification and Authentication Failures",
    "info_disclosure": "A05:2021 - Security Misconfiguration",
    "command_injection": "A03:2021 - Injection",
    "csrf": "A01:2021 - Broken Access Control",
    "open_redirect": "A01:2021 - Broken Access Control",
}

# Remediation templates per attack type
_REMEDIATION_MAP: dict[str, dict[str, str]] = {
    "sqli": {
        "title": "Injection SQL",
        "short": "Utiliser des requetes parametrees (prepared statements).",
        "detail": (
            "- Utiliser des requetes parametrees (prepared statements) exclusivement.\n"
            "- Ne jamais concatener les entrees utilisateur dans les requetes SQL.\n"
            "- Implementer un ORM avec echappement automatique.\n"
            "- Valider et assainir toutes les entrees cote serveur.\n"
            "- Appliquer le principe de moindre privilege aux comptes de base de donnees."
        ),
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS)",
        "short": "Encoder les sorties et deployer Content-Security-Policy.",
        "detail": (
            "- Implementer une Content-Security-Policy (CSP) stricte.\n"
            "- Encoder systematiquement les sorties HTML (output encoding).\n"
            "- Utiliser un framework avec auto-escaping (React, Angular, etc.).\n"
            "- Valider les entrees cote serveur avec une whitelist.\n"
            "- Activer le flag HttpOnly sur les cookies de session."
        ),
    },
    "idor": {
        "title": "IDOR (Insecure Direct Object Reference)",
        "short": "Implementer des controles d'autorisation cote serveur.",
        "detail": (
            "- Implementer des controles d'autorisation cote serveur pour chaque ressource.\n"
            "- Utiliser des identifiants non previsibles (UUID v4).\n"
            "- Verifier que l'utilisateur est proprietaire de la ressource demandee.\n"
            "- Journaliser les tentatives d'acces non autorisees."
        ),
    },
    "path_traversal": {
        "title": "Path Traversal",
        "short": "Valider et normaliser tous les chemins de fichiers.",
        "detail": (
            "- Valider et canonicaliser tous les chemins de fichiers cote serveur.\n"
            "- Utiliser une whitelist de repertoires autorises.\n"
            "- Ne jamais exposer de chemins absolus dans les URL.\n"
            "- Restreindre les permissions du systeme de fichiers."
        ),
    },
    "auth_bypass": {
        "title": "Contournement d'authentification",
        "short": "Renforcer les mecanismes d'authentification.",
        "detail": (
            "- Implementer l'authentification multi-facteurs (MFA).\n"
            "- Verifier l'authentification a chaque requete cote serveur.\n"
            "- Invalider les sessions apres deconnexion.\n"
            "- Utiliser des tokens JWT signes avec rotation reguliere."
        ),
    },
    "info_disclosure": {
        "title": "Divulgation d'information",
        "short": "Supprimer les headers Server/X-Powered-By.",
        "detail": (
            "- Supprimer les headers Server et X-Powered-By en production.\n"
            "- Desactiver les pages d'erreur verbeuses.\n"
            "- Restreindre l'acces aux endpoints d'administration et de debogage.\n"
            "- Supprimer les fichiers de configuration et les backups du serveur web."
        ),
    },
    "command_injection": {
        "title": "Injection de commande",
        "short": "Ne jamais passer d'entrees utilisateur a un shell.",
        "detail": (
            "- Ne jamais executer de commandes systeme avec des entrees utilisateur.\n"
            "- Utiliser des API programmatiques au lieu de commandes shell.\n"
            "- Si necessaire, utiliser une whitelist de commandes autorisees.\n"
            "- Appliquer le principe de moindre privilege au processus serveur."
        ),
    },
    "csrf": {
        "title": "Cross-Site Request Forgery (CSRF)",
        "short": "Implementer des tokens CSRF sur tous les formulaires.",
        "detail": (
            "- Implementer des tokens CSRF uniques et valides par session.\n"
            "- Verifier l'en-tete Origin/Referer cote serveur.\n"
            "- Utiliser le flag SameSite=Strict sur les cookies.\n"
            "- Exiger une re-authentification pour les actions sensibles."
        ),
    },
    "open_redirect": {
        "title": "Redirection ouverte",
        "short": "Valider les URL de redirection contre une whitelist.",
        "detail": (
            "- Valider toutes les URL de redirection contre une whitelist de domaines.\n"
            "- Ne pas inclure d'URL controlees par l'utilisateur dans les redirections.\n"
            "- Afficher un avertissement avant de rediriger vers un domaine externe."
        ),
    },
}


def _compute_risk_level(severity_counts: dict[str, int], success_rate: float) -> str:
    """Compute an overall risk level label from severity counts and success rate.

    Returns one of: CRITICAL, HIGH, MEDIUM, LOW.
    """
    if severity_counts.get("CRITICAL", 0) > 0 and success_rate > 0:
        return "CRITICAL"
    if severity_counts.get("CRITICAL", 0) > 0 or severity_counts.get("HIGH", 0) >= 2:
        return "HIGH"
    if severity_counts.get("HIGH", 0) > 0 or severity_counts.get("MEDIUM", 0) >= 2:
        return "MEDIUM"
    return "LOW"


def _compute_risk_score(severity_counts: dict[str, int], success_rate: float) -> int:
    """Compute a numeric risk score (0-100) from severity counts and success rate.

    Weighting: CRITICAL=40, HIGH=25, MEDIUM=10, LOW=3 per occurrence,
    plus a bonus up to 20 points based on exploitation success rate.
    """
    weights = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3}
    score = sum(weights.get(sev, 0) * count for sev, count in severity_counts.items())
    score += int(success_rate * 20)
    return min(score, 100)


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

        # Prepare structured data for the prompt
        scan_json = scan.model_dump_json(indent=2)
        plan_json = plan.model_dump_json(indent=2)
        results_json = results.model_dump_json(indent=2)

        system_prompt = textwrap.dedent("""\
            Tu es un expert en securite informatique redacteur de rapports de pentest professionnels.
            Tu generes des rapports en francais, structures en Markdown, destines a une audience technique
            et manageriale. Tu dois etre precis, factuel, et ne jamais inventer de vulnerabilites
            qui ne sont pas dans les donnees fournies.""")

        user_prompt = textwrap.dedent(f"""\
            Genere un rapport de securite professionnel en Markdown a partir des donnees suivantes.

            ## Donnees du scan
            ```json
            {scan_json}
            ```

            ## Plan d'attaque
            ```json
            {plan_json}
            ```

            ## Resultats d'execution
            ```json
            {results_json}
            ```

            Le rapport DOIT contenir les sections suivantes dans cet ordre exact :

            ### 1. Resume executif (2-3 paragraphes)
            - Score de risque global (CRITICAL / HIGH / MEDIUM / LOW) avec justification
            - Nombre de vulnerabilites trouvees par severite
            - Pourcentage d'attaques reussies
            - Principaux risques metier

            ### 2. Matrice des vulnerabilites
            Tableau Markdown avec colonnes : ID | Type | Severite | Endpoint | Statut | OWASP Top 10

            ### 3. Detail de chaque vulnerabilite
            Pour chaque vulnerabilite :
            - **Description** : explication technique de la vulnerabilite
            - **Impact** : consequences potentielles en cas d'exploitation
            - **Preuve de concept** : payload utilise et resultat observe (si exploitee)
            - **Remediation** : correctifs recommandes, classes par priorite
            - **Reference OWASP** : categorie OWASP Top 10 2021 applicable

            ### 4. Cartographie OWASP Top 10
            Tableau recapitulatif montrant quelles categories OWASP Top 10 2021 sont affectees
            et combien de vulnerabilites s'y rapportent.

            ### 5. Feuille de route de remediation priorisee
            Liste des actions correctives ordonnees par priorite (critique d'abord),
            avec estimation de l'effort (faible / moyen / eleve) et de l'impact.

            ### 6. Implications de conformite
            - PCI-DSS : si des donnees d'authentification ou de paiement sont en jeu
            - RGPD/GDPR : si des donnees personnelles sont exposees
            - Autres normes applicables

            Format : Markdown propre, professionnel, en francais.
            Ne pas inventer de vulnerabilites absentes des donnees.""")

        message = client.messages.create(
            model=settings.llm_model,
            max_tokens=settings.llm_max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
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
    now = datetime.now(ZoneInfo("America/Toronto")).strftime("%Y-%m-%d %H:%M")

    # --- Severity counts ---
    severity_counts: dict[str, int] = {}
    for v in plan.vectors:
        sev = v.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # --- Success rate ---
    success_rate = (
        results.successful_attacks / results.total_attempts if results.total_attempts > 0 else 0.0
    )

    # --- Risk scoring ---
    risk_level = _compute_risk_level(severity_counts, success_rate)
    risk_score = _compute_risk_score(severity_counts, success_rate)

    # --- Vulnerability matrix table ---
    vuln_rows = []
    for v in plan.vectors:
        success = any(r.success and r.vector_id == v.id for r in results.results)
        status = "Exploitee" if success else "Non exploitee"
        owasp = _OWASP_MAP.get(v.attack_type.value, v.owasp_ref)
        vuln_rows.append(
            f"| {v.id} | {v.attack_type.value.upper()} | {v.severity.value} "
            f"| `{v.target_endpoint}` | {status} | {owasp} |"
        )
    vuln_table = "\n".join(vuln_rows) if vuln_rows else "| - | - | - | - | - | - |"

    # --- Per-vulnerability details ---
    details_parts: list[str] = []
    for v in plan.vectors:
        attack_results = [r for r in results.results if r.vector_id == v.id]
        successful = [r for r in attack_results if r.success]
        owasp = _OWASP_MAP.get(v.attack_type.value, v.owasp_ref)
        remed = _REMEDIATION_MAP.get(v.attack_type.value)

        lines: list[str] = []
        lines.append(f"### {v.id} -- {v.attack_type.value.upper()} ({v.severity.value})")
        lines.append("")
        lines.append(f"**Endpoint cible :** `{v.target_endpoint}`")
        lines.append(f"**Reference OWASP :** {owasp}")
        lines.append("")
        lines.append("**Description :**")
        lines.append("")
        for r in v.rationale:
            lines.append(f"- {r}")
        lines.append("")

        # Impact
        lines.append("**Impact :**")
        lines.append("")
        if v.severity.value == "CRITICAL":
            lines.append(
                "- Compromission complete du systeme possible. "
                "Acces non autorise aux donnees sensibles."
            )
        elif v.severity.value == "HIGH":
            lines.append(
                "- Risque eleve d'exploitation avec impact significatif "
                "sur la confidentialite ou l'integrite des donnees."
            )
        elif v.severity.value == "MEDIUM":
            lines.append(
                "- Impact modere necessitant une remediation planifiee. "
                "Exploitation possible sous certaines conditions."
            )
        else:
            lines.append(
                "- Impact limite. Recommandation de correction dans le cadre "
                "d'une amelioration continue de la securite."
            )
        lines.append("")

        # Proof of concept
        lines.append("**Preuve de concept :**")
        lines.append("")
        if successful:
            lines.append(
                f"Vulnerabilite **confirmee** -- "
                f"{len(successful)} payload(s) reussi(s) sur {len(attack_results)} tentative(s)."
            )
            lines.append("")
            for r in successful:
                lines.append(f"- Payload : `{r.payload_used}`")
                lines.append(f"  - Methode de detection : {r.detection_method}")
                lines.append(f"  - Code HTTP : {r.http_status}")
            lines.append("")
        else:
            lines.append("Non exploitee lors du test. Le vecteur reste a surveiller.")
            lines.append("")

        # Remediation
        lines.append("**Remediation :**")
        lines.append("")
        if remed:
            lines.append(remed["detail"])
        else:
            lines.append(
                "- Appliquer les recommandations de securite appropriees au type de vulnerabilite."
            )
        lines.append("")

        details_parts.append("\n".join(lines))

    details_section = "\n---\n\n".join(details_parts)

    # --- OWASP Top 10 mapping ---
    owasp_counts: dict[str, int] = {}
    for v in plan.vectors:
        cat = _OWASP_MAP.get(v.attack_type.value, v.owasp_ref)
        owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

    owasp_rows = []
    for cat, count in sorted(owasp_counts.items()):
        owasp_rows.append(f"| {cat} | {count} |")
    owasp_table = "\n".join(owasp_rows) if owasp_rows else "| - | - |"

    # --- Prioritized remediation roadmap ---
    remediation_items: list[str] = []
    priority_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    seen_types: set[str] = set()
    for priority in priority_order:
        for v in plan.vectors:
            if v.severity.value == priority and v.attack_type.value not in seen_types:
                seen_types.add(v.attack_type.value)
                remed = _REMEDIATION_MAP.get(v.attack_type.value)
                effort = "eleve" if priority in ("CRITICAL", "HIGH") else "moyen"
                title = remed["title"] if remed else v.attack_type.value.upper()
                short = remed["short"] if remed else "Corriger selon les bonnes pratiques."
                remediation_items.append(
                    f"| {len(remediation_items) + 1} | {priority} | {title} | {short} | {effort} |"
                )
    remediation_table = (
        "\n".join(remediation_items) if remediation_items else "| - | - | - | - | - |"
    )

    # --- Compliance implications ---
    compliance_lines: list[str] = []
    has_auth_vectors = any(v.attack_type.value in ("sqli", "auth_bypass") for v in plan.vectors)
    has_data_exposure = any(
        v.attack_type.value in ("idor", "info_disclosure", "path_traversal") for v in plan.vectors
    )

    if has_auth_vectors:
        compliance_lines.append("### PCI-DSS")
        compliance_lines.append("")
        compliance_lines.append(
            "- **Req. 6.5.1** : Les vulnerabilites d'injection identifiees violent "
            "l'exigence de protection contre les failles d'injection."
        )
        compliance_lines.append(
            "- **Req. 8.2** : Les failles d'authentification peuvent compromettre "
            "le controle d'acces aux donnees de titulaires de cartes."
        )
        compliance_lines.append("")

    if has_data_exposure:
        compliance_lines.append("### RGPD / GDPR")
        compliance_lines.append("")
        compliance_lines.append(
            "- **Art. 32** : L'obligation de securite des traitements n'est pas respectee "
            "en raison des vulnerabilites d'acces non autorise aux donnees."
        )
        compliance_lines.append(
            "- **Art. 33** : En cas d'exploitation, une notification de violation "
            "de donnees pourrait etre requise dans les 72 heures."
        )
        compliance_lines.append("")

    if not compliance_lines:
        compliance_lines.append("Aucune implication de conformite majeure identifiee pour ce scan.")

    compliance_section = "\n".join(compliance_lines)

    # --- Assemble the full report (no indentation artifacts) ---
    report = textwrap.dedent(f"""\
# Rapport de Securite -- RedSimulator

**Date :** {now} (America/Toronto)
**Cible :** {scan.target}
**Technologies detectees :** {", ".join(scan.technologies) if scan.technologies else "N/A"}
**Scan ID :** {plan.scan_id}
**Genere le :** {plan.generated_at}

---

## 1. Resume executif

Un scan de securite automatise a ete effectue sur `{scan.target}`.
L'analyse a identifie **{len(plan.vectors)} vecteur(s) d'attaque**
dont **{results.successful_attacks} ont ete exploites avec succes**
sur {results.total_attempts} tentative(s) ({success_rate:.0%} de reussite).

| Metrique | Valeur |
|----------|--------|
| Score de risque | **{risk_score}/100** |
| Niveau de risque | **{risk_level}** |
| Vulnerabilites CRITICAL | {severity_counts.get("CRITICAL", 0)} |
| Vulnerabilites HIGH | {severity_counts.get("HIGH", 0)} |
| Vulnerabilites MEDIUM | {severity_counts.get("MEDIUM", 0)} |
| Vulnerabilites LOW | {severity_counts.get("LOW", 0)} |
| Taux d'exploitation | {success_rate:.0%} |

---

## 2. Matrice des vulnerabilites

| ID | Type | Severite | Endpoint | Statut | OWASP Top 10 |
|----|------|----------|----------|--------|--------------|
{vuln_table}

---

## 3. Detail des vulnerabilites

{details_section}

---

## 4. Cartographie OWASP Top 10 (2021)

| Categorie OWASP | Nombre de vulnerabilites |
|------------------|--------------------------|
{owasp_table}

---

## 5. Feuille de route de remediation

| Priorite | Severite | Vulnerabilite | Action | Effort |
|----------|----------|---------------|--------|--------|
{remediation_table}

---

## 6. Implications de conformite

{compliance_section}

---

*Rapport genere par RedSimulator -- PoC academique INF8790*
*{now} (America/Toronto)*""")

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
