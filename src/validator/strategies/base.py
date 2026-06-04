"""Abstract base class for validation strategies.

Every concrete strategy implements :meth:`validate` which re-tests a
single finding and returns a ``(score, explanation)`` tuple.  A score
of ``-1`` signals that the strategy was not applicable and should be
excluded from aggregation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from src.models import SingleAttackResult


class ValidationStrategy(ABC):
    """Base class for all false-positive validation strategies."""

    name: str

    @abstractmethod
    def validate(
        self,
        vector_id: str,
        payload: str,
        target_endpoint: str,
        base_url: str,
        original_result: SingleAttackResult,
        session: requests.Session | None = None,
    ) -> tuple[float, str]:
        """Validate a single finding.

        Args:
            vector_id: Identifier of the attack vector.
            payload: The payload that was originally sent.
            target_endpoint: The endpoint that was attacked.
            base_url: Base URL of the target application.
            original_result: The original execution result to validate.
            session: Optional HTTP session for re-testing.

        Returns:
            Tuple of ``(score, explanation)`` where *score* is in
            ``[0.0, 1.0]`` (higher = more likely a true positive) or
            ``-1`` when the strategy is not applicable.
        """
        ...
