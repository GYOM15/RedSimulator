"""Data models for false-positive validation results.

Defines confidence labels, composite scores, and per-finding validation
outcomes used by the :class:`~src.validator.validator.FPValidator` pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ConfidenceLabel(StrEnum):
    """Human-readable confidence tier derived from a numeric score."""

    CONFIRMED = "confirmed"  # 0.8+
    LIKELY = "likely"  # 0.6-0.8
    POSSIBLE = "possible"  # 0.4-0.6
    UNLIKELY = "unlikely"  # 0.2-0.4
    FALSE_POSITIVE = "false_positive"  # <0.2


@dataclass
class ConfidenceScore:
    """Aggregated confidence score with per-strategy breakdown."""

    value: float  # 0.0 - 1.0
    label: ConfidenceLabel
    strategy_scores: dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_value(
        cls,
        value: float,
        strategy_scores: dict[str, float] | None = None,
    ) -> ConfidenceScore:
        """Create a :class:`ConfidenceScore` from a numeric value.

        The label is derived automatically from the value using the
        standard tier thresholds.
        """
        value = max(0.0, min(1.0, value))
        if value >= 0.8:
            label = ConfidenceLabel.CONFIRMED
        elif value >= 0.6:
            label = ConfidenceLabel.LIKELY
        elif value >= 0.4:
            label = ConfidenceLabel.POSSIBLE
        elif value >= 0.2:
            label = ConfidenceLabel.UNLIKELY
        else:
            label = ConfidenceLabel.FALSE_POSITIVE
        return cls(
            value=value,
            label=label,
            strategy_scores=strategy_scores or {},
        )


@dataclass
class ValidationResult:
    """Outcome of validating a single attack finding."""

    vector_id: str
    original_success: bool
    confidence: ConfidenceScore
    details: list[str] = field(default_factory=list)
    validated: bool = False  # True once validation has actually run
