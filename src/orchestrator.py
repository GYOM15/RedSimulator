"""Orchestrateur du pipeline RedSimulator.

Enchaine les 5 modules dans l'ordre :
1. Scanner → ScanResult
2. Expert → AttackPlan
3. Generator → PayloadResult
4. Executor → AttackResult
5. Reporter → Rapport Markdown

Supporte un mode fixtures qui charge les JSON au lieu d'executer les vrais modules.
"""

import json
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

    def __init__(self, target_url: str | None = None):
        self.target_url = target_url or settings.target_url
        self.data_dir = Path(__file__).parent.parent / "data"
        self.fixtures_dir = self.data_dir / "fixtures"
        self.reports_dir = self.data_dir / "reports"

        # Resultats intermediaires
        self.scan_result: ScanResult | None = None
        self.attack_plan: AttackPlan | None = None
        self.payload_result: PayloadResult | None = None
        self.attack_result: AttackResult | None = None
        self.report: str = ""

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

        # Etape 1 : Scanner
        self._step("1/5", "Scanner — Reconnaissance", lambda: self._run_scanner(use_fixtures))

        # Etape 2 : Expert
        self._step(
            "2/5", "Expert — Analyse des vulnerabilites", lambda: self._run_expert(use_fixtures)
        )

        # Etape 3 : Generator
        self._step(
            "3/5", "Generator — Generation de payloads", lambda: self._run_generator(use_fixtures)
        )

        # Etape 4 : Executor
        self._step(
            "4/5", "Executor — Execution des attaques", lambda: self._run_executor(use_fixtures)
        )

        # Etape 5 : Reporter
        self._step("5/5", "Reporter — Generation du rapport", lambda: self._run_reporter())

        # Sauvegarder les resultats
        self._save_results()

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

    def _run_expert(self, use_fixtures: bool) -> None:
        """Execute ou charge le systeme expert."""
        if use_fixtures:
            data = json.loads((self.fixtures_dir / "attack_plan.json").read_text())
            self.attack_plan = AttackPlan.model_validate(data)
            logger.info("Fixture chargee: %d vecteurs", len(self.attack_plan.vectors))
        else:
            from src.expert.engine import ExpertEngine
            from src.expert.facts import scan_result_to_facts
            from src.expert.rules import get_all_rules

            facts = scan_result_to_facts(self.scan_result)
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

    def _run_reporter(self) -> None:
        """Genere le rapport."""
        from src.reporter.report_generator import generate_report

        self.report = generate_report(self.scan_result, self.attack_plan, self.attack_result)
        logger.info("Rapport genere: %d caracteres", len(self.report))

    def _save_results(self) -> None:
        """Sauvegarde tous les resultats intermediaires."""
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # Sauvegarder chaque resultat
        if self.scan_result:
            (self.reports_dir / "scan_result.json").write_text(
                self.scan_result.model_dump_json(indent=2)
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
    args = parser.parse_args()

    pipeline = RedSimulatorPipeline(target_url=args.target)
    report = pipeline.run(use_fixtures=args.fixtures)

    logger.info("Rapport final:\n%s", report)
