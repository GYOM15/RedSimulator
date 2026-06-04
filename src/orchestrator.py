"""Orchestrateur du pipeline RedSimulator.

Enchaine les 6 modules dans l'ordre :
1. Scanner → ScanResult
2. Expert → AttackPlan
3. Generator → PayloadResult
4. Executor → AttackResult
5. Validator → ValidationResult (optional, FP reduction)
6. Reporter → Rapport Markdown

Supporte un mode fixtures qui charge les JSON au lieu d'executer les vrais modules.
"""

import json
import time
import uuid
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from src.infra.config import settings
from src.infra.decorators import logged, timed
from src.infra.exceptions import PhaseError
from src.infra.logging import get_logger, setup_logging
from src.models import (
    AttackPlan,
    AttackResult,
    PayloadResult,
    ScanResult,
)

logger = get_logger(__name__)


class RedSimulatorPipeline:
    """Pipeline principal de RedSimulator."""

    def __init__(self, target_url: str | None = None, passive_scan: bool = True):
        self.target_url = target_url or settings.target_url
        self.passive_scan = passive_scan
        self.data_dir = Path(__file__).parent.parent / "data"
        self.fixtures_dir = self.data_dir / "fixtures"
        self.reports_dir = self.data_dir / "reports"

        # Resultats intermediaires
        self.scan_result: ScanResult | None = None
        self.passive_report = None  # PassiveReport | None
        self.attack_plan: AttackPlan | None = None
        self.payload_result: PayloadResult | None = None
        self.attack_result: AttackResult | None = None
        self.report: str = ""
        self.cvss_scores: list[dict] = []  # CVSS data per vector

    @logged
    @timed
    def run(self, use_fixtures: bool = False) -> str:
        """Execute le pipeline complet.

        Args:
            use_fixtures: Si True, charge les JSON au lieu d'executer les modules.

        Returns:
            Rapport Markdown final.
        """
        mode = "fixtures" if use_fixtures else "live"
        ts = datetime.now(ZoneInfo("America/Toronto")).strftime("%Y-%m-%d %H:%M (Quebec)")
        logger.info(
            "RedSimulator Pipeline — target=%s, mode=%s, date=%s", self.target_url, mode, ts
        )

        pipeline_start = time.perf_counter()

        # Etape 1 : Scanner
        self._step("1/6", "Scanner — Reconnaissance", lambda: self._run_scanner(use_fixtures))

        # Etape 1b (optionnelle) : Passive scan
        if self.passive_scan and self.scan_result:
            self._step(
                "1b/6",
                "Passive — Analyse passive des reponses HTTP",
                lambda: self._run_passive_scan(),
            )

        # Etape 2 : Expert
        self._step(
            "2/6", "Expert — Analyse des vulnerabilites", lambda: self._run_expert(use_fixtures)
        )

        # Etape 2b : CVSS scoring (after expert phase produces attack vectors)
        if self.attack_plan:
            self._step(
                "2b/6",
                "CVSS — Calcul des scores CVSS v3.1",
                lambda: self._compute_cvss_scores(),
            )

        # Etape 3 : Generator
        self._step(
            "3/6", "Generator — Generation de payloads", lambda: self._run_generator(use_fixtures)
        )

        # Etape 4 : Executor
        self._step(
            "4/6", "Executor — Execution des attaques", lambda: self._run_executor(use_fixtures)
        )

        # Etape 5 : Validation (optional)
        if not use_fixtures and settings.validation_enabled:
            self._step(
                "5/6",
                "Validator — Validation des faux positifs",
                lambda: self._run_validator(),
            )

        # Etape 6 : Reporter
        self._step("6/6", "Reporter — Generation du rapport", lambda: self._run_reporter())

        # Sauvegarder les resultats
        self._save_results()

        # Record to dashboard history
        duration_ms = (time.perf_counter() - pipeline_start) * 1000
        self._record_dashboard_snapshot(duration_ms)

        logger.info("Pipeline termine — rapport: %s", self.reports_dir / "report.md")

        return self.report

    def _step(self, step_num: str, name: str, func) -> None:
        """Execute une etape du pipeline avec affichage."""
        logger.info("[%s] %s", step_num, name)
        try:
            func()
            logger.info("[%s] OK", step_num)
        except Exception as e:
            logger.error("[%s] ERREUR: %s", step_num, e)
            raise PhaseError(f"Phase {name} failed: {e}", phase_name=name) from e

    def _run_scanner(self, use_fixtures: bool) -> None:
        """Execute ou charge le scanner."""
        if use_fixtures:
            data = json.loads((self.fixtures_dir / "scan_result.json").read_text())
            self.scan_result = ScanResult.model_validate(data)
            logger.info("Fixture chargee: %d endpoints", len(self.scan_result.endpoints))
        else:
            from src.scanner.agent import ReconAgent

            agent = ReconAgent(self.target_url)
            self.scan_result = agent.run()

    def _run_passive_scan(self) -> None:
        """Run passive analysis on all endpoints from the scan result."""
        from src.passive.analyzer import PassiveAnalyzer

        analyzer = PassiveAnalyzer()
        self.passive_report = analyzer.analyze_scan_result(self.scan_result)
        severity_counts = self.passive_report.by_severity
        logger.info(
            "Passive scan: %d finding(s) — %s",
            len(self.passive_report.findings),
            ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items())),
        )

    def _run_expert(self, use_fixtures: bool) -> None:
        """Execute ou charge le systeme expert."""
        if use_fixtures:
            data = json.loads((self.fixtures_dir / "attack_plan.json").read_text())
            self.attack_plan = AttackPlan.model_validate(data)
            logger.info("Fixture chargee: %d vecteurs", len(self.attack_plan.vectors))
        else:
            from src.expert.engine import ExpertEngine
            from src.expert.facts import passive_findings_to_facts, scan_result_to_facts
            from src.expert.rules import get_all_rules

            facts = scan_result_to_facts(self.scan_result)

            # Inject passive findings as additional facts if available
            if self.passive_report:
                passive_facts = passive_findings_to_facts(self.passive_report)
                facts.extend(passive_facts)
                logger.info("%d passive fact(s) added to expert system", len(passive_facts))

            engine = ExpertEngine()
            engine.inject_facts(facts)
            engine.load_rules(get_all_rules())
            self.attack_plan = engine.run()

    def _run_generator(self, use_fixtures: bool) -> None:
        """Execute ou charge le generateur de payloads."""
        if use_fixtures:
            data = json.loads((self.fixtures_dir / "payload_result.json").read_text())
            self.payload_result = PayloadResult.model_validate(data)
            logger.info("Fixture chargee: %d payloads", len(self.payload_result.payloads))
        else:
            from src.generator.generate import generate_for_plan

            self.payload_result = generate_for_plan(self.attack_plan)

    def _run_executor(self, use_fixtures: bool) -> None:
        """Execute ou charge l'executeur d'attaques."""
        if use_fixtures:
            data = json.loads((self.fixtures_dir / "attack_result.json").read_text())
            self.attack_result = AttackResult.model_validate(data)
            logger.info(
                "Fixture chargee: %d tentatives, %d succes",
                self.attack_result.total_attempts,
                self.attack_result.successful_attacks,
            )
        else:
            from src.executor.runner import AttackExecutor

            executor = AttackExecutor(self.target_url)
            self.attack_result = executor.execute_all(self.attack_plan, self.payload_result)

    def _run_validator(self) -> None:
        """Run false-positive validation on successful findings."""
        from src.validator import FPValidator

        validator = FPValidator(self.target_url)
        validation_results = validator.validate_results(self.attack_result, self.attack_plan)
        self._apply_validation(validation_results)

    def _apply_validation(self, validation_results: list) -> None:
        """Apply validation results back to the attack result.

        Updates each :class:`SingleAttackResult` with the confidence
        score and label from the validator, and adjusts the
        ``successful_attacks`` count based on ``validation_min_confidence``.
        """
        from src.validator.models import ValidationResult

        # Index validation results by vector_id
        vr_map: dict[str, ValidationResult] = {}
        for vr in validation_results:
            vr_map[vr.vector_id] = vr

        downgraded = 0
        for result in self.attack_result.results:
            if not result.success:
                continue

            vr = vr_map.get(result.vector_id)
            if vr is None:
                continue

            result.confidence = round(vr.confidence.value, 3)
            result.confidence_label = vr.confidence.label.value
            result.validation_details = vr.details

            # Downgrade findings below the minimum confidence threshold
            if vr.confidence.value < settings.validation_min_confidence:
                result.success = False
                result.detection_method = (
                    f"[DOWNGRADED] {result.detection_method} "
                    f"(confidence={vr.confidence.value:.2f}, "
                    f"label={vr.confidence.label.value})"
                )
                downgraded += 1

        if downgraded:
            self.attack_result.successful_attacks = max(
                0,
                self.attack_result.successful_attacks - downgraded,
            )
            logger.info(
                "Validation downgraded %d finding(s); successful_attacks now %d.",
                downgraded,
                self.attack_result.successful_attacks,
            )

    def _compute_cvss_scores(self) -> None:
        """Compute CVSS v3.1 base scores for each attack vector in the plan."""
        from src.scoring import attack_type_to_cvss, calculate_cvss_score

        self.cvss_scores = []
        for vector in self.attack_plan.vectors:
            cvss_vec = attack_type_to_cvss(vector.attack_type.value)
            score, severity = calculate_cvss_score(cvss_vec)
            self.cvss_scores.append(
                {
                    "vector_id": vector.id,
                    "score": score,
                    "severity": severity,
                    "vector_string": cvss_vec.to_vector_string(),
                }
            )
            logger.info(
                "CVSS %s: %.1f (%s) — %s",
                vector.id,
                score,
                severity,
                cvss_vec.to_vector_string(),
            )

    def _record_dashboard_snapshot(self, duration_ms: float) -> None:
        """Record a scan snapshot to the dashboard history store."""
        if not self.attack_plan or not self.attack_result:
            return

        try:
            from src.dashboard import DashboardStore, ScanSnapshot
            from src.reporter.report_generator import _compute_risk_score

            # Compute severity counts
            severity_counts: dict[str, int] = {}
            for v in self.attack_plan.vectors:
                sev = v.severity.value
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            # Compute success rate and risk score
            success_rate = (
                self.attack_result.successful_attacks / self.attack_result.total_attempts
                if self.attack_result.total_attempts > 0
                else 0.0
            )
            risk_score = _compute_risk_score(severity_counts, success_rate)

            # Unique attack types
            attack_types = list({v.attack_type.value for v in self.attack_plan.vectors})

            snapshot = ScanSnapshot(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(ZoneInfo("America/Toronto")).isoformat(),
                target=self.target_url,
                total_vectors=len(self.attack_plan.vectors),
                total_attempts=self.attack_result.total_attempts,
                successful_attacks=self.attack_result.successful_attacks,
                severity_counts=severity_counts,
                attack_types=sorted(attack_types),
                rules_fired=len(self.attack_plan.rules_fired),
                cvss_scores=self.cvss_scores,
                risk_score=risk_score,
                duration_ms=duration_ms,
            )

            db_path = str(self.data_dir / "dashboard" / "history.db")
            store = DashboardStore(db_path=db_path)
            store.record_scan(snapshot)
            store.close()

            logger.info(
                "Dashboard snapshot recorded: %s (risk=%d, duration=%.0fms)",
                snapshot.id,
                risk_score,
                duration_ms,
            )
        except Exception as e:
            # Dashboard recording is non-critical; log and continue
            logger.warning("Failed to record dashboard snapshot: %s", e)

    def _run_reporter(self) -> None:
        """Genere le rapport."""
        from src.reporter.report_generator import generate_report

        self.report = generate_report(
            self.scan_result,
            self.attack_plan,
            self.attack_result,
            cvss_scores=self.cvss_scores,
        )
        logger.info("Rapport genere: %d caracteres", len(self.report))

    def _save_results(self) -> None:
        """Sauvegarde tous les resultats intermediaires."""
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # Sauvegarder chaque resultat
        if self.scan_result:
            (self.reports_dir / "scan_result.json").write_text(
                self.scan_result.model_dump_json(indent=2)
            )
        if self.passive_report:
            passive_data = {
                "findings": [
                    {
                        "check_name": f.check_name,
                        "severity": str(f.severity),
                        "title": f.title,
                        "description": f.description,
                        "url": f.url,
                        "evidence": f.evidence,
                        "cwe_id": f.cwe_id,
                        "remediation": f.remediation,
                    }
                    for f in self.passive_report.findings
                ],
                "by_severity": self.passive_report.by_severity,
                "by_check": self.passive_report.by_check,
            }
            (self.reports_dir / "passive_report.json").write_text(
                json.dumps(passive_data, indent=2, ensure_ascii=False)
            )
        if self.attack_plan:
            (self.reports_dir / "attack_plan.json").write_text(
                self.attack_plan.model_dump_json(indent=2)
            )
        if self.payload_result:
            (self.reports_dir / "payload_result.json").write_text(
                self.payload_result.model_dump_json(indent=2)
            )
        if self.attack_result:
            (self.reports_dir / "attack_result.json").write_text(
                self.attack_result.model_dump_json(indent=2)
            )
        if self.report:
            (self.reports_dir / "report.md").write_text(self.report)

        logger.info("Resultats sauvegardes dans %s", self.reports_dir)


if __name__ == "__main__":
    import argparse

    setup_logging(settings.log_level, settings.log_format)

    parser = argparse.ArgumentParser(description="RedSimulator Pipeline")
    parser.add_argument(
        "--target",
        default=settings.target_url,
        help=f"URL de la cible (defaut: {settings.target_url})",
    )
    parser.add_argument(
        "--fixtures",
        action="store_true",
        help="Utiliser les fixtures au lieu des vrais modules",
    )
    parser.add_argument(
        "--no-passive",
        action="store_true",
        help="Desactiver l'analyse passive des reponses HTTP",
    )
    args = parser.parse_args()

    pipeline = RedSimulatorPipeline(target_url=args.target, passive_scan=not args.no_passive)
    report = pipeline.run(use_fixtures=args.fixtures)

    logger.info("Rapport final:\n%s", report)
