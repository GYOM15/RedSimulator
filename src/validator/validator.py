"""False positive validator — re-tests findings to confirm or reject.

The :class:`FPValidator` orchestrates multiple validation strategies
against each successful finding from the executor.  It produces a
:class:`~src.validator.models.ValidationResult` for every confirmed
hit, enabling the pipeline to discard or downgrade probable false
positives before the reporter stage.
"""

from __future__ import annotations

import requests

from src.infra.config import settings
from src.infra.decorators import logged, timed
from src.infra.logging import get_logger
from src.models import AttackPlan, AttackResult, AttackVector, SingleAttackResult

from .confidence import ConfidenceScorer
from .models import ValidationResult
from .strategies import get_all_strategies
from .strategies.base import ValidationStrategy

logger = get_logger(__name__)


class FPValidator:
    """False positive validator — re-tests findings to confirm or reject.

    Runs a configurable set of validation strategies against each
    successful finding, aggregates the confidence scores, and returns
    :class:`ValidationResult` objects that the orchestrator can use to
    update the original attack results.

    Parameters
    ----------
    base_url:
        Base URL of the target application.
    strategies:
        Optional list of strategy names to enable.  When ``None``,
        defaults to ``settings.validation_strategies``.
    """

    def __init__(
        self,
        base_url: str,
        strategies: list[str] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "RedSimulator/1.0 (Validator)",
                "Accept": "application/json, text/html, */*",
            }
        )
        self.scorer = ConfidenceScorer()

        # Resolve which strategies to use
        enabled_names = strategies or list(settings.validation_strategies)
        all_strategies = get_all_strategies()
        self._strategies: list[ValidationStrategy] = [
            s for s in all_strategies if s.name in enabled_names
        ]

        if not self._strategies:
            # Fall back to all strategies if none matched
            logger.warning(
                "No matching strategies for %s; using all available.",
                enabled_names,
            )
            self._strategies = all_strategies

        logger.info(
            "FPValidator initialized with %d strategy(ies): %s",
            len(self._strategies),
            ", ".join(s.name for s in self._strategies),
        )

    @logged
    @timed
    def validate_results(
        self,
        attack_result: AttackResult,
        attack_plan: AttackPlan,
    ) -> list[ValidationResult]:
        """Validate all successful findings in the attack result.

        Only findings where ``success=True`` are re-tested.  Failures
        are skipped because there is nothing to confirm.

        Args:
            attack_result: The executor output containing all findings.
            attack_plan: The attack plan (used to look up vector details).

        Returns:
            A :class:`ValidationResult` for each validated finding.
        """
        # Index vectors by ID for quick lookup
        vector_map: dict[str, AttackVector] = {v.id: v for v in attack_plan.vectors}

        successful_results = [r for r in attack_result.results if r.success]
        logger.info(
            "Validating %d successful finding(s) out of %d total.",
            len(successful_results),
            len(attack_result.results),
        )

        validation_results: list[ValidationResult] = []

        for result in successful_results:
            vector = vector_map.get(result.vector_id)
            if vector is None:
                logger.warning(
                    "Vector %s not found in attack plan; skipping validation.",
                    result.vector_id,
                )
                continue

            vr = self.validate_single(result, vector)
            validation_results.append(vr)

        confirmed = sum(1 for vr in validation_results if vr.confidence.value >= 0.6)
        rejected = sum(1 for vr in validation_results if vr.confidence.value < 0.4)
        logger.info(
            "Validation complete: %d confirmed, %d rejected, %d uncertain.",
            confirmed,
            rejected,
            len(validation_results) - confirmed - rejected,
        )

        return validation_results

    def validate_single(
        self,
        result: SingleAttackResult,
        vector: AttackVector,
    ) -> ValidationResult:
        """Validate a single finding against all configured strategies.

        Args:
            result: The single attack result to validate.
            vector: The attack vector definition.

        Returns:
            A :class:`ValidationResult` with aggregated confidence.
        """
        strategy_results: dict[str, tuple[float, str]] = {}

        for strategy in self._strategies:
            try:
                score, explanation = strategy.validate(
                    vector_id=result.vector_id,
                    payload=result.payload_used,
                    target_endpoint=vector.target_endpoint,
                    base_url=self.base_url,
                    original_result=result,
                    session=self.session,
                )
                strategy_results[strategy.name] = (score, explanation)
                logger.debug(
                    "Strategy '%s' for %s: score=%.2f — %s",
                    strategy.name,
                    result.vector_id,
                    score,
                    explanation,
                )
            except Exception as exc:
                logger.warning(
                    "Strategy '%s' raised an exception for %s: %s",
                    strategy.name,
                    result.vector_id,
                    exc,
                )
                strategy_results[strategy.name] = (-1, f"Strategy error: {exc}")

        # Aggregate scores
        confidence = self.scorer.aggregate(strategy_results)

        # Collect detail strings
        details = [
            f"[{name}] {explanation}" for name, (_score, explanation) in strategy_results.items()
        ]

        return ValidationResult(
            vector_id=result.vector_id,
            original_success=result.success,
            confidence=confidence,
            details=details,
            validated=True,
        )
