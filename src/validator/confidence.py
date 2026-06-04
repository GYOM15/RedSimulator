"""Confidence score aggregation across validation strategies.

Combines per-strategy scores using a weighted average.  Strategies
that did not run (score == -1) are excluded from the aggregation so
their weight is redistributed to the strategies that did produce a
result.
"""

from __future__ import annotations

from src.infra.logging import get_logger

from .models import ConfidenceScore

logger = get_logger(__name__)

# Default weights per strategy name.
_DEFAULT_WEIGHTS: dict[str, float] = {
    "differential": 0.30,
    "multi_payload": 0.35,
    "llm": 0.20,
    "timing": 0.15,
}


class ConfidenceScorer:
    """Aggregates scores from multiple validation strategies.

    Uses a weighted average where each strategy has a pre-defined
    weight.  Only strategies that actually ran (score != -1) are
    included; their weights are normalized to sum to 1.0.
    """

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights = weights or dict(_DEFAULT_WEIGHTS)

    def aggregate(
        self,
        strategy_results: dict[str, tuple[float, str]],
    ) -> ConfidenceScore:
        """Compute a weighted-average confidence score.

        Args:
            strategy_results: Mapping of strategy name to
                ``(score, explanation)`` tuples.  A score of ``-1``
                means the strategy did not run.

        Returns:
            An aggregated :class:`ConfidenceScore` with per-strategy
            breakdown in ``strategy_scores``.
        """
        # Collect scores that actually ran
        active_scores: dict[str, float] = {}
        active_weights: dict[str, float] = {}

        for name, (score, _explanation) in strategy_results.items():
            if score < 0:
                logger.debug("Strategy '%s' did not run (score=%s); excluded.", name, score)
                continue
            active_scores[name] = score
            active_weights[name] = self.weights.get(name, 0.1)

        if not active_scores:
            logger.warning("No validation strategies produced a result.")
            return ConfidenceScore.from_value(0.5, strategy_scores={})

        # Normalize weights to sum to 1.0
        total_weight = sum(active_weights.values())
        if total_weight <= 0:
            total_weight = 1.0

        weighted_sum = sum(
            active_scores[name] * (active_weights[name] / total_weight) for name in active_scores
        )

        logger.info(
            "Aggregated confidence: %.3f from %d strategies (%s)",
            weighted_sum,
            len(active_scores),
            ", ".join(f"{n}={s:.2f}" for n, s in active_scores.items()),
        )

        return ConfidenceScore.from_value(weighted_sum, strategy_scores=active_scores)
