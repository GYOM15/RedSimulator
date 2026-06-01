"""Plugin-based attack executor.

Auto-discovers attack handlers from :mod:`src.executor.attacks` and
dispatches each vector to the matching handler.  The public interface
(``AttackExecutor`` with ``execute_all``) is unchanged.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from src.infra.config import settings
from src.infra.decorators import logged, timed
from src.infra.logging import get_logger
from src.models import (
    AttackPlan,
    AttackResult,
    AttackVector,
    PayloadResult,
    SingleAttackResult,
)

from .attacks import get_all_handlers
from .base import AttackHandler
from .session import SessionManager

logger = get_logger(__name__)


class AttackExecutor:
    """Execute les attaques du plan contre la cible.

    Uses a plugin architecture: each attack type is handled by a
    dedicated :class:`~src.executor.base.AttackHandler` subclass
    discovered at runtime from the ``src.executor.attacks`` package.

    Rate-limited selon ``settings.attack_delay`` entre chaque requete
    pour ne pas surcharger la cible.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.delay = settings.attack_delay
        self.session_manager = SessionManager(self.base_url)

        # Discover and instantiate all available handlers.
        handler_classes = get_all_handlers()
        self._handlers: dict[str, AttackHandler] = {}
        for attack_type, handler_cls in handler_classes.items():
            self._handlers[attack_type] = handler_cls(
                base_url=self.base_url,
                session=self.session_manager,
            )
            logger.info(
                "Handler charge: %s -> %s",
                attack_type,
                handler_cls.__name__,
            )

        if self._handlers:
            logger.info(
                "%d handler(s) disponible(s): %s",
                len(self._handlers),
                ", ".join(sorted(self._handlers)),
            )
        else:
            logger.warning("Aucun handler d'attaque disponible.")

    def _execute_vector(
        self,
        vector: AttackVector,
        payloads: list[str],
    ) -> tuple[list[SingleAttackResult], int, int]:
        """Execute all payloads for a single vector.

        Returns:
            Tuple of (results list, total attempts, success count).
        """
        handler = self._handlers.get(vector.attack_type.value)
        if handler is None:
            logger.warning(
                "Aucun handler pour le type d'attaque '%s' (vecteur %s). Ignore.",
                vector.attack_type.value,
                vector.id,
            )
            return [], 0, 0

        logger.info(
            "Vecteur %s (%s) -> handler %s",
            vector.id,
            vector.attack_type.value,
            type(handler).__name__,
        )

        results: list[SingleAttackResult] = []
        total = 0
        success_count = 0

        for payload in payloads:
            total += 1
            time.sleep(self.delay)

            try:
                result = handler.test(vector, payload)
                results.append(result)
                if result.success:
                    success_count += 1
            except Exception:
                logger.exception(
                    "Erreur lors du test du vecteur %s avec payload %s",
                    vector.id,
                    payload[:80],
                )

        return results, total, success_count

    @logged
    @timed
    def execute_all(
        self,
        attack_plan: AttackPlan,
        payload_result: PayloadResult,
    ) -> AttackResult:
        """Execute toutes les attaques du plan.

        Args:
            attack_plan: Plan d'attaque avec les vecteurs.
            payload_result: Variantes de payloads generees.

        Returns:
            Resultats de toutes les attaques.
        """
        logger.info("Execution des attaques sur %s", self.base_url)

        all_results: list[SingleAttackResult] = []
        total = 0
        success_count = 0

        # Indexer les payloads par vector_id
        payload_map: dict[str, list[str]] = {}
        for gp in payload_result.payloads:
            if gp.vector_id not in payload_map:
                payload_map[gp.vector_id] = []
            payload_map[gp.vector_id].append(gp.original)
            payload_map[gp.vector_id].extend(gp.variants)

        for vector in attack_plan.vectors:
            payloads = payload_map.get(vector.id, vector.base_payloads)
            if not payloads:
                payloads = vector.base_payloads

            results, vec_total, vec_success = self._execute_vector(vector, payloads)
            all_results.extend(results)
            total += vec_total
            success_count += vec_success

        logger.info("Termine: %d tentatives, %d succes", total, success_count)

        return AttackResult(
            results=all_results,
            total_attempts=total,
            successful_attacks=success_count,
        )

    @staticmethod
    def from_fixtures() -> AttackResult:
        """Charge le resultat depuis la fixture JSON."""
        fixture_path = (
            Path(__file__).parent.parent.parent / "data" / "fixtures" / "attack_result.json"
        )
        logger.info("Chargement de la fixture: %s", fixture_path)
        data = json.loads(fixture_path.read_text())
        result = AttackResult.model_validate(data)
        logger.info(
            "Fixture chargee: %d tentatives, %d succes",
            result.total_attempts,
            result.successful_attacks,
        )
        return result


if __name__ == "__main__":
    import sys

    from src.infra.logging import setup_logging

    setup_logging(level=settings.log_level, fmt=settings.log_format)

    if "--fixture" in sys.argv or "--fixtures" in sys.argv:
        logger.info("Mode fixture")
        result = AttackExecutor.from_fixtures()
    else:
        # Charger les fixtures pour le plan et les payloads
        data_dir = Path(__file__).parent.parent.parent / "data" / "fixtures"
        plan_data = json.loads((data_dir / "attack_plan.json").read_text())
        payload_data = json.loads((data_dir / "payload_result.json").read_text())

        plan = AttackPlan.model_validate(plan_data)
        payloads = PayloadResult.model_validate(payload_data)

        executor = AttackExecutor(settings.target_url)
        result = executor.execute_all(plan, payloads)

    logger.info("Resultats:\n%s", result.model_dump_json(indent=2))
