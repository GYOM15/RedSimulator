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
from zoneinfo import ZoneInfo
from pathlib import Path

from src.models import (
    AttackPlan,
    AttackResult,
    PayloadResult,
    ScanResult,
)


class RedSimulatorPipeline:
    """Pipeline principal de RedSimulator."""

    def __init__(self, target_url: str = "http://localhost:3000"):
        self.target_url = target_url
        self.data_dir = Path(__file__).parent.parent / "data"
        self.fixtures_dir = self.data_dir / "fixtures"
        self.reports_dir = self.data_dir / "reports"

        # Resultats intermediaires
        self.scan_result: ScanResult | None = None
        self.attack_plan: AttackPlan | None = None
        self.payload_result: PayloadResult | None = None
        self.attack_result: AttackResult | None = None
        self.report: str = ""

    def run(self, use_fixtures: bool = False) -> str:
        """Execute le pipeline complet.

        Args:
            use_fixtures: Si True, charge les JSON au lieu d'executer les modules.

        Returns:
            Rapport Markdown final.
        """
        print(f"\n{'#'*60}")
        print(f"#  RedSimulator Pipeline")
        print(f"#  Cible: {self.target_url}")
        print(f"#  Mode: {'fixtures' if use_fixtures else 'live'}")
        print(f"#  Date: {datetime.now(ZoneInfo('America/Toronto')).strftime('%Y-%m-%d %H:%M (Quebec)')}")
        print(f"{'#'*60}\n")

        # Etape 1 : Scanner
        self._step("1/5", "Scanner — Reconnaissance", lambda: self._run_scanner(use_fixtures))

        # Etape 2 : Expert
        self._step("2/5", "Expert — Analyse des vulnerabilites", lambda: self._run_expert(use_fixtures))

        # Etape 3 : Generator
        self._step("3/5", "Generator — Generation de payloads", lambda: self._run_generator(use_fixtures))

        # Etape 4 : Executor
        self._step("4/5", "Executor — Execution des attaques", lambda: self._run_executor(use_fixtures))

        # Etape 5 : Reporter
        self._step("5/5", "Reporter — Generation du rapport", lambda: self._run_reporter())

        # Sauvegarder les resultats
        self._save_results()

        print(f"\n{'#'*60}")
        print(f"#  Pipeline termine!")
        print(f"#  Rapport: {self.reports_dir / 'report.md'}")
        print(f"{'#'*60}\n")

        return self.report

    def _step(self, step_num: str, name: str, func) -> None:
        """Execute une etape du pipeline avec affichage."""
        print(f"\n{'='*60}")
        print(f"  [{step_num}] {name}")
        print(f"{'='*60}")
        try:
            func()
            print(f"  [{step_num}] OK")
        except Exception as e:
            print(f"  [{step_num}] ERREUR: {e}")
            raise

    def _run_scanner(self, use_fixtures: bool) -> None:
        """Execute ou charge le scanner."""
        if use_fixtures:
            data = json.loads((self.fixtures_dir / "scan_result.json").read_text())
            self.scan_result = ScanResult.model_validate(data)
            print(f"  Fixture chargee: {len(self.scan_result.endpoints)} endpoints")
        else:
            from src.scanner.agent import ReconAgent

            agent = ReconAgent(self.target_url)
            self.scan_result = agent.run()

    def _run_expert(self, use_fixtures: bool) -> None:
        """Execute ou charge le systeme expert."""
        if use_fixtures:
            data = json.loads((self.fixtures_dir / "attack_plan.json").read_text())
            self.attack_plan = AttackPlan.model_validate(data)
            print(f"  Fixture chargee: {len(self.attack_plan.vectors)} vecteurs")
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
            print(f"  Fixture chargee: {len(self.payload_result.payloads)} payloads")
        else:
            import torch

            from src.generator.generate import generate_variants
            from src.generator.vae_model import PayloadVAE
            from src.models import GeneratedPayload

            model = PayloadVAE()
            model_path = self.data_dir / "vae_model.pt"

            if model_path.exists():
                model.load_state_dict(torch.load(model_path, weights_only=True))
                print(f"  Modele charge depuis {model_path}")
            else:
                print("  Modele non entraine, generation avec modele aleatoire")

            payloads = []
            for vector in self.attack_plan.vectors:
                for base in vector.base_payloads:
                    variants = generate_variants(model, base, n_variants=3)
                    payloads.append(
                        GeneratedPayload(
                            vector_id=vector.id,
                            original=base,
                            variants=variants,
                        )
                    )

            self.payload_result = PayloadResult(payloads=payloads)

    def _run_executor(self, use_fixtures: bool) -> None:
        """Execute ou charge l'executeur d'attaques."""
        if use_fixtures:
            data = json.loads((self.fixtures_dir / "attack_result.json").read_text())
            self.attack_result = AttackResult.model_validate(data)
            print(
                f"  Fixture chargee: {self.attack_result.total_attempts} tentatives, "
                f"{self.attack_result.successful_attacks} succes"
            )
        else:
            from src.executor.runner import AttackExecutor

            executor = AttackExecutor(self.target_url)
            self.attack_result = executor.execute_all(
                self.attack_plan, self.payload_result
            )

    def _run_reporter(self) -> None:
        """Genere le rapport."""
        from src.reporter.report_generator import generate_report

        self.report = generate_report(
            self.scan_result, self.attack_plan, self.attack_result
        )
        print(f"  Rapport genere: {len(self.report)} caracteres")

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

        print(f"  Resultats sauvegardes dans {self.reports_dir}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="RedSimulator Pipeline")
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="URL de la cible (defaut: http://localhost:3000)",
    )
    parser.add_argument(
        "--fixtures",
        action="store_true",
        help="Utiliser les fixtures au lieu des vrais modules",
    )
    args = parser.parse_args()

    pipeline = RedSimulatorPipeline(target_url=args.target)
    report = pipeline.run(use_fixtures=args.fixtures)

    print("\n" + report)
