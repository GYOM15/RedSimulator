"""Tests for false positive validation.

Verifies confidence scoring models, the ConfidenceScorer aggregator,
and validation result models. All tests run without Docker,
mitmproxy, or API keys.
"""

from src.validator.confidence import ConfidenceScorer
from src.validator.models import ConfidenceLabel, ConfidenceScore, ValidationResult

# ---------------------------------------------------------------------------
# TestConfidenceLabel
# ---------------------------------------------------------------------------


class TestConfidenceLabel:
    """Test ConfidenceLabel enum values."""

    def test_confirmed_value(self):
        assert ConfidenceLabel.CONFIRMED == "confirmed"

    def test_likely_value(self):
        assert ConfidenceLabel.LIKELY == "likely"

    def test_possible_value(self):
        assert ConfidenceLabel.POSSIBLE == "possible"

    def test_unlikely_value(self):
        assert ConfidenceLabel.UNLIKELY == "unlikely"

    def test_false_positive_value(self):
        assert ConfidenceLabel.FALSE_POSITIVE == "false_positive"


# ---------------------------------------------------------------------------
# TestConfidenceScore
# ---------------------------------------------------------------------------


class TestConfidenceScore:
    """Test ConfidenceScore model and from_value factory."""

    def test_from_value_confirmed(self):
        score = ConfidenceScore.from_value(0.85)
        assert score.label == ConfidenceLabel.CONFIRMED
        assert score.value == 0.85

    def test_from_value_likely(self):
        score = ConfidenceScore.from_value(0.7)
        assert score.label == ConfidenceLabel.LIKELY

    def test_from_value_possible(self):
        score = ConfidenceScore.from_value(0.5)
        assert score.label == ConfidenceLabel.POSSIBLE

    def test_from_value_unlikely(self):
        score = ConfidenceScore.from_value(0.3)
        assert score.label == ConfidenceLabel.UNLIKELY

    def test_from_value_false_positive(self):
        score = ConfidenceScore.from_value(0.1)
        assert score.label == ConfidenceLabel.FALSE_POSITIVE

    def test_clamping_high(self):
        score = ConfidenceScore.from_value(1.5)
        assert score.value == 1.0

    def test_clamping_low(self):
        score = ConfidenceScore.from_value(-0.5)
        assert score.value == 0.0

    def test_boundary_08_is_confirmed(self):
        score = ConfidenceScore.from_value(0.8)
        assert score.label == ConfidenceLabel.CONFIRMED

    def test_boundary_06_is_likely(self):
        score = ConfidenceScore.from_value(0.6)
        assert score.label == ConfidenceLabel.LIKELY

    def test_boundary_04_is_possible(self):
        score = ConfidenceScore.from_value(0.4)
        assert score.label == ConfidenceLabel.POSSIBLE

    def test_boundary_02_is_unlikely(self):
        score = ConfidenceScore.from_value(0.2)
        assert score.label == ConfidenceLabel.UNLIKELY

    def test_zero_is_false_positive(self):
        score = ConfidenceScore.from_value(0.0)
        assert score.label == ConfidenceLabel.FALSE_POSITIVE

    def test_one_is_confirmed(self):
        score = ConfidenceScore.from_value(1.0)
        assert score.label == ConfidenceLabel.CONFIRMED

    def test_strategy_scores_default_empty(self):
        score = ConfidenceScore.from_value(0.5)
        assert score.strategy_scores == {}

    def test_strategy_scores_populated(self):
        scores = {"differential": 0.8, "timing": 0.9}
        score = ConfidenceScore.from_value(0.85, strategy_scores=scores)
        assert score.strategy_scores == scores


# ---------------------------------------------------------------------------
# TestConfidenceScorer
# ---------------------------------------------------------------------------


class TestConfidenceScorer:
    """Test the weighted ConfidenceScorer aggregator."""

    def test_weighted_aggregate(self):
        scorer = ConfidenceScorer()
        results = {
            "differential": (0.8, "Different responses"),
            "multi_payload": (0.9, "3/5 payloads succeeded"),
        }
        score = scorer.aggregate(results)
        assert 0.7 <= score.value <= 1.0

    def test_skips_not_applicable(self):
        """Strategies with score -1 should be excluded from aggregation."""
        scorer = ConfidenceScorer()
        results = {
            "differential": (0.8, "ok"),
            "timing": (-1.0, "not applicable"),
        }
        score = scorer.aggregate(results)
        # Only differential contributed, so result should be close to 0.8
        assert score.value > 0.5

    def test_empty_results(self):
        """No strategies ran: should return a default score."""
        scorer = ConfidenceScorer()
        score = scorer.aggregate({})
        # With no results, the code returns 0.5 as default
        assert score.value == 0.5

    def test_all_not_applicable(self):
        """All strategies return -1: same as empty."""
        scorer = ConfidenceScorer()
        results = {
            "differential": (-1, "not applicable"),
            "timing": (-1, "not applicable"),
        }
        score = scorer.aggregate(results)
        assert score.value == 0.5

    def test_single_strategy(self):
        scorer = ConfidenceScorer()
        results = {
            "differential": (0.9, "strong signal"),
        }
        score = scorer.aggregate(results)
        # Single strategy = its score is the weighted average (normalized to itself)
        assert abs(score.value - 0.9) < 0.01

    def test_custom_weights(self):
        weights = {"a": 0.5, "b": 0.5}
        scorer = ConfidenceScorer(weights=weights)
        results = {
            "a": (1.0, "perfect"),
            "b": (0.0, "none"),
        }
        score = scorer.aggregate(results)
        # Equal weights: (1.0 * 0.5 + 0.0 * 0.5) / (0.5 + 0.5) = 0.5
        assert abs(score.value - 0.5) < 0.01

    def test_unknown_strategy_gets_default_weight(self):
        """Unknown strategies get a default weight of 0.1."""
        scorer = ConfidenceScorer()
        results = {
            "unknown_strategy": (0.8, "some result"),
        }
        score = scorer.aggregate(results)
        assert abs(score.value - 0.8) < 0.01

    def test_strategy_scores_included_in_result(self):
        scorer = ConfidenceScorer()
        results = {
            "differential": (0.7, "moderate"),
            "multi_payload": (0.9, "strong"),
        }
        score = scorer.aggregate(results)
        assert "differential" in score.strategy_scores
        assert "multi_payload" in score.strategy_scores
        assert score.strategy_scores["differential"] == 0.7
        assert score.strategy_scores["multi_payload"] == 0.9


# ---------------------------------------------------------------------------
# TestValidationResult
# ---------------------------------------------------------------------------


class TestValidationResult:
    """Test the ValidationResult model."""

    def test_defaults(self):
        result = ValidationResult(
            vector_id="VEC-001",
            original_success=True,
            confidence=ConfidenceScore.from_value(0.7),
        )
        assert result.validated is False
        assert result.details == []

    def test_vector_id(self):
        result = ValidationResult(
            vector_id="VEC-042",
            original_success=False,
            confidence=ConfidenceScore.from_value(0.3),
        )
        assert result.vector_id == "VEC-042"
        assert result.original_success is False

    def test_with_details(self):
        result = ValidationResult(
            vector_id="VEC-001",
            original_success=True,
            confidence=ConfidenceScore.from_value(0.8),
            details=["Differential: different responses", "Timing: confirmed"],
            validated=True,
        )
        assert result.validated is True
        assert len(result.details) == 2

    def test_confidence_is_score_object(self):
        score = ConfidenceScore.from_value(0.85)
        result = ValidationResult(
            vector_id="VEC-001",
            original_success=True,
            confidence=score,
        )
        assert result.confidence.label == ConfidenceLabel.CONFIRMED
        assert result.confidence.value == 0.85
