"""Base class for attack handlers.

Each attack type (SQLi, XSS, IDOR, etc.) is implemented as a subclass
of ``AttackHandler``.  The runner auto-discovers all registered handlers
and dispatches to the correct one based on ``attack_type``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from src.models import AttackVector, SingleAttackResult

if TYPE_CHECKING:
    from src.executor.session import SessionManager


class AttackHandler(ABC):
    """Abstract base for all attack type handlers.

    Each handler implements testing logic for one attack type.
    The runner dispatches to the correct handler based on attack_type.

    Subclasses **must** set the ``attack_type`` class attribute to the
    string value of the :class:`~src.models.AttackType` enum member they
    handle (e.g. ``"sqli"``, ``"xss"``).
    """

    attack_type: str  # Must match AttackType enum value

    def __init__(self, base_url: str, session: SessionManager | None = None):
        self.base_url = base_url.rstrip("/")
        self.session = session

    @abstractmethod
    def test(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Execute a single attack test.

        Args:
            vector: Attack vector from the expert system.
            payload: Payload string to test.

        Returns:
            Result of the attack attempt.
        """
        ...

    def _make_result(
        self,
        vector: AttackVector,
        payload: str,
        status: int,
        snippet: str,
        success: bool,
        detection: str,
    ) -> SingleAttackResult:
        """Helper to create a :class:`SingleAttackResult`."""
        return SingleAttackResult(
            vector_id=vector.id,
            payload_used=payload,
            target_endpoint=vector.target_endpoint,
            http_status=status,
            response_snippet=snippet[:200] if snippet else "",
            success=success,
            detection_method=detection,
        )
