"""Plugin-based attack executor.

Auto-discovers attack handlers from :mod:`src.executor.attacks` and
dispatches each vector to the matching handler.  The public interface
(``AttackExecutor`` with ``execute_all``) is unchanged.

After each attack result, the executor records feedback to the payload
intelligence system for cross-session learning.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from src.auth.models import AuthConfig, AuthType
from src.generator.payload_db import payload_db
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
from .rate_limiter import AdaptiveRateLimiter
from .session import SessionManager

logger = get_logger(__name__)


class AttackExecutor:
    """Execute les attaques du plan contre la cible.

    Uses a plugin architecture: each attack type is handled by a
    dedicated :class:`~src.executor.base.AttackHandler` subclass
    discovered at runtime from the ``src.executor.attacks`` package.

    Rate-limited via an adaptive rate limiter that dynamically adjusts
    the delay between requests based on server responses.  Falls back
    to a fixed delay when adaptive mode is disabled.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.delay = settings.attack_delay

        # Adaptive rate limiter
        self._adaptive_enabled = settings.rate_limit_adaptive
        self.rate_limiter = AdaptiveRateLimiter(
            base_delay=self.delay,
            min_delay=settings.rate_limit_min_delay,
            max_delay=settings.rate_limit_max_delay,
        )

        # Build auth config from settings.
        auth_config = self._build_auth_config()
        self.session_manager = SessionManager(self.base_url, auth_config=auth_config)

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

    @staticmethod
    def _build_auth_config() -> AuthConfig | None:
        """Create an :class:`AuthConfig` from the global settings.

        Returns ``None`` when auth_type is ``"none"`` so the session
        manager skips authentication entirely.
        """
        auth_type_str = settings.auth_type.lower().strip()
        if auth_type_str == "none":
            return None

        try:
            auth_type = AuthType(auth_type_str)
        except ValueError:
            logger.warning(
                "Unknown auth_type '%s' in settings; authentication disabled",
                auth_type_str,
            )
            return None

        return AuthConfig(
            auth_type=auth_type,
            username=settings.auth_username,
            password=settings.auth_password,
            token=settings.auth_token,
            login_url=settings.auth_login_url,
            token_url=settings.auth_token_url,
            client_id=settings.auth_client_id,
            client_secret=settings.auth_client_secret,
        )

    def _execute_vector(
        self,
        vector: AttackVector,
        payloads: list[str],
        technologies: list[str] | None = None,
    ) -> tuple[list[SingleAttackResult], int, int]:
        """Execute all payloads for a single vector.

        After each test, records the result in the payload feedback tracker
        for cross-session learning.

        Implements early-stop: when ``settings.early_stop_threshold`` consecutive
        responses have the same (status, body-length, success) signature, the
        remaining payloads are skipped to save time and API calls.

        Args:
            vector: The attack vector to test.
            payloads: List of payload strings to try.
            technologies: Detected technologies for feedback recording.

        Returns:
            Tuple of (results list, total attempts, success count).
        """
        handler = self._handlers.get(vector.attack_type.value)
        if handler is None:
            logger.warning(
                "Aucun handler pour le type d'attaque '%s' (vecteur %s). "
                "Type non supporte — vecteur ignore.",
                vector.attack_type.value,
                vector.id,
            )
            return [], 0, 0

        logger.info(
            "Vecteur %s (%s) -> handler %s | %d payloads a tester",
            vector.id,
            vector.attack_type.value,
            type(handler).__name__,
            len(payloads),
        )

        # Determine the primary technology for feedback recording
        tech_label = vector.attack_type.value
        if technologies:
            tech_label = technologies[0].lower()

        results: list[SingleAttackResult] = []
        total = 0
        success_count = 0

        # Early-stop state
        max_identical = settings.early_stop_threshold
        consecutive_identical = 0
        last_response_sig: tuple[int, int, bool] | None = None

        for payload in payloads:
            total += 1

            # Rate limiting: adaptive or fixed delay
            if self._adaptive_enabled:
                self.rate_limiter.wait()
            else:
                time.sleep(self.delay)

            try:
                start_time = time.monotonic()
                result = handler.test(vector, payload)
                elapsed_ms = (time.monotonic() - start_time) * 1000

                results.append(result)

                # Check for redundant responses (early-stop)
                if max_identical > 0:
                    response_sig = (
                        result.http_status,
                        len(result.response_snippet),
                        result.success,
                    )
                    if response_sig == last_response_sig:
                        consecutive_identical += 1
                        if consecutive_identical >= max_identical:
                            remaining = len(payloads) - total
                            logger.info(
                                "Early-stop: %d reponses identiques consecutives sur %s, "
                                "%d payloads restants ignores",
                                max_identical,
                                vector.id,
                                remaining,
                            )
                            break
                    else:
                        consecutive_identical = 0
                    last_response_sig = response_sig

                if result.success:
                    success_count += 1
                    logger.info(
                        "SUCCESS sur %s avec payload: %s",
                        vector.target_endpoint,
                        payload[:50],
                    )

                # Feed response data to the adaptive rate limiter
                if self._adaptive_enabled:
                    status = getattr(result, "status_code", 200)
                    self.rate_limiter.record_response(status, elapsed_ms)

                # Record feedback for the payload intelligence system
                try:
                    payload_db.record_result(
                        payload_text=payload,
                        technology=tech_label,
                        success=result.success,
                    )
                except Exception:
                    logger.debug(
                        "Failed to record feedback for payload %s",
                        payload[:50],
                    )

                # Periodic progress log every 5 payloads
                if total % 5 == 0:
                    logger.info(
                        "Progression %s: %d/%d testes, %d succes",
                        vector.id,
                        total,
                        len(payloads),
                        success_count,
                    )
            except Exception:
                logger.exception(
                    "Erreur lors du test du vecteur %s avec payload %s",
                    vector.id,
                    payload[:80],
                )
                # Record connection error for adaptive backoff
                if self._adaptive_enabled:
                    self.rate_limiter.record_error()

        logger.info(
            "Vecteur %s termine: %d/%d testes, %d succes",
            vector.id,
            total,
            len(payloads),
            success_count,
        )
        return results, total, success_count

    @logged
    @timed
    def execute_all(
        self,
        attack_plan: AttackPlan,
        payload_result: PayloadResult,
        technologies: list[str] | None = None,
    ) -> AttackResult:
        """Execute toutes les attaques du plan.

        Args:
            attack_plan: Plan d'attaque avec les vecteurs.
            payload_result: Variantes de payloads generees.
            technologies: Optional list of detected technologies for feedback.

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

        num_vectors = len(attack_plan.vectors)
        for vec_idx, vector in enumerate(attack_plan.vectors, 1):
            payloads = payload_map.get(vector.id, vector.base_payloads)
            if not payloads:
                payloads = vector.base_payloads

            logger.info(
                "Vecteur %d/%d: %s sur %s — %d payloads",
                vec_idx,
                num_vectors,
                vector.attack_type.value,
                vector.target_endpoint,
                len(payloads),
            )

            results, vec_total, vec_success = self._execute_vector(
                vector,
                payloads,
                technologies=technologies,
            )
            all_results.extend(results)
            total += vec_total
            success_count += vec_success

            logger.info(
                "Vecteur %d/%d termine: %d testes, %d succes (cumul: %d/%d)",
                vec_idx,
                num_vectors,
                vec_total,
                vec_success,
                success_count,
                total,
            )

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
