"""Moteur de chainage avant du systeme expert.

Implemente l'algorithme de chainage avant classique :
1. Charger les faits initiaux
2. Pour chaque regle non activee, verifier les conditions
3. Si les conditions sont satisfaites, activer la regle et ajouter les nouveaux faits
4. Repeter jusqu'a stabilite (aucune nouvelle regle activee)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from src.infra.decorators import logged, timed
from src.infra.exceptions import RuleError
from src.infra.logging import get_logger
from src.models import AttackPlan, AttackVector
from src.models.attack_plan import Severity

from .facts import Fact

logger = get_logger(__name__)


@dataclass
class Rule:
    """Une regle du systeme expert.

    Attributes:
        name: Nom unique de la regle.
        conditions: Fonction qui prend la memoire de travail et retourne True si applicable.
        action: Fonction qui prend la memoire de travail et retourne les nouveaux faits.
        priority: Priorite (plus bas = plus prioritaire). Defaut = 10.
        fired: Indique si la regle a deja ete activee.
    """

    name: str
    conditions: Callable[[list[Fact]], bool]
    action: Callable[[list[Fact]], list[Fact]]
    priority: int = 10
    fired: bool = False


class ExpertEngine:
    """Moteur d'inference a chainage avant.

    Prend des faits initiaux et des regles, puis infere de nouveaux faits
    jusqu'a stabilite. Produit un AttackPlan en sortie.
    """

    def __init__(self):
        self.working_memory: list[Fact] = []
        self.rules: list[Rule] = []
        self.fired_rules: list[str] = []
        self.attack_vectors: list[AttackVector] = []

    def inject_facts(self, facts: list[Fact]) -> None:
        """Ajoute des faits a la memoire de travail."""
        self.working_memory.extend(facts)
        logger.info("%d faits injectes dans la memoire de travail", len(facts))

    def load_rules(self, rules: list[Rule]) -> None:
        """Charge les regles triees par priorite."""
        self.rules = sorted(rules, key=lambda r: r.priority)
        logger.info("%d regles chargees:", len(rules))
        for r in self.rules:
            logger.info("  - %s (priorite=%d)", r.name, r.priority)

    @logged
    @timed
    def run(self, scan_id: str = "scan-001") -> AttackPlan:
        """Execute le chainage avant et produit un AttackPlan.

        L'algorithme boucle tant qu'au moins une regle s'active a chaque iteration.
        A chaque iteration, les regles sont evaluees dans l'ordre de priorite.

        Args:
            scan_id: Identifiant du scan source.

        Returns:
            AttackPlan contenant les vecteurs d'attaque identifies.
        """
        logger.info("=" * 60)
        logger.info("Demarrage du chainage avant")
        logger.info("=" * 60)
        logger.info("Memoire initiale: %d faits", len(self.working_memory))

        iteration = 0
        changed = True

        while changed:
            changed = False
            iteration += 1
            logger.info("--- Iteration %d ---", iteration)

            for rule in self.rules:
                if rule.fired:
                    continue

                try:
                    conditions_met = rule.conditions(self.working_memory)
                except Exception as exc:
                    raise RuleError(
                        f"Erreur lors de l'evaluation de la regle '{rule.name}': {exc}",
                        rule_name=rule.name,
                    ) from exc

                if conditions_met:
                    logger.info("  [FIRE] Regle '%s' activee!", rule.name)
                    try:
                        new_facts = rule.action(self.working_memory)
                    except Exception as exc:
                        raise RuleError(
                            f"Erreur lors de l'execution de la regle '{rule.name}': {exc}",
                            rule_name=rule.name,
                        ) from exc

                    if new_facts:
                        for fact in new_facts:
                            logger.info("    + Nouveau fait: %s", fact)
                            self.working_memory.append(fact)

                        # Extraire les vecteurs d'attaque et les elevations
                        for fact in new_facts:
                            if fact.type == "attack_vector":
                                vector = AttackVector(**fact.attributes)
                                self.attack_vectors.append(vector)
                                logger.info(
                                    "    >> Vecteur d'attaque: %s (%s, %s)",
                                    vector.id,
                                    vector.attack_type.value,
                                    vector.severity.value,
                                )
                            elif fact.type == "severity_elevation":
                                # Mettre a jour la severite des vecteurs existants
                                vid = fact.attributes["vector_id"]
                                new_sev = Severity(fact.attributes["to"])
                                for v in self.attack_vectors:
                                    if v.id == vid:
                                        v.severity = new_sev

                    rule.fired = True
                    self.fired_rules.append(rule.name)
                    changed = True
                else:
                    logger.info("  [SKIP] Regle '%s' — conditions non remplies", rule.name)

        logger.info("=" * 60)
        logger.info("Chainage termine apres %d iterations", iteration)
        logger.info("Regles activees: %s", self.fired_rules)
        logger.info("Vecteurs d'attaque: %d", len(self.attack_vectors))
        logger.info("=" * 60)

        return AttackPlan(
            scan_id=scan_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            vectors=self.attack_vectors,
            rules_fired=self.fired_rules,
        )


if __name__ == "__main__":
    import json
    from pathlib import Path

    from src.models import ScanResult

    from .facts import scan_result_to_facts
    from .rules import get_all_rules

    # Charger la fixture
    fixture_path = Path(__file__).parent.parent.parent / "data" / "fixtures" / "scan_result.json"
    data = json.loads(fixture_path.read_text())
    scan = ScanResult.model_validate(data)

    # Convertir en faits
    facts = scan_result_to_facts(scan)

    # Lancer le moteur
    engine = ExpertEngine()
    engine.inject_facts(facts)
    engine.load_rules(get_all_rules())
    plan = engine.run()

    logger.info("=== Attack Plan ===")
    logger.info(plan.model_dump_json(indent=2))
