"""Validation strategy implementations.

Each strategy independently scores a finding's likelihood of being a
true positive.  The :func:`get_all_strategies` helper returns every
available strategy so the validator can iterate over them.
"""

from .base import ValidationStrategy
from .differential import DifferentialStrategy
from .llm_analysis import LLMAnalysisStrategy
from .multi_payload import MultiPayloadStrategy
from .timing import TimingStrategy

__all__ = [
    "DifferentialStrategy",
    "LLMAnalysisStrategy",
    "MultiPayloadStrategy",
    "TimingStrategy",
    "ValidationStrategy",
    "get_all_strategies",
]


def get_all_strategies() -> list[ValidationStrategy]:
    """Return instances of every built-in validation strategy."""
    return [
        DifferentialStrategy(),
        MultiPayloadStrategy(),
        LLMAnalysisStrategy(),
        TimingStrategy(),
    ]
