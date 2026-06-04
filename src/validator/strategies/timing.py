"""Timing-based validation strategy for blind injection confirmation.

Applies only to time-based payloads (those containing keywords like
``SLEEP``, ``WAITFOR``, ``pg_sleep``, ``BENCHMARK``).  Measures the
response-time difference between the attack payload and a benign
baseline to detect genuine blind injection.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import requests

from src.infra.config import settings
from src.infra.logging import get_logger

from .base import ValidationStrategy

if TYPE_CHECKING:
    from src.models import SingleAttackResult

logger = get_logger(__name__)

_TIME_KEYWORDS = frozenset(
    {
        "sleep",
        "waitfor",
        "pg_sleep",
        "benchmark",
        "delay",
        "dbms_pipe",
    }
)
"""Keywords that identify time-based injection payloads."""

_BENIGN_VALUE = "test123"
"""Innocuous value used for the baseline request."""

_SLOWDOWN_FACTOR = 3.0
"""If attack response is >=3x slower than baseline, it is considered confirmed."""


class TimingStrategy(ValidationStrategy):
    """Timing-based validation for blind injection payloads.

    Only applicable when the payload contains time-based keywords
    (``sleep``, ``WAITFOR``, etc.).

    * Attack response >= 3x slower than baseline -> confirmed (score 0.9)
    * Otherwise -> likely false positive (score 0.2)
    """

    name: str = "timing"

    def validate(
        self,
        vector_id: str,
        payload: str,
        target_endpoint: str,
        base_url: str,
        original_result: SingleAttackResult,
        session: requests.Session | None = None,
    ) -> tuple[float, str]:
        # Only apply to time-based payloads
        payload_lower = payload.lower()
        if not any(kw in payload_lower for kw in _TIME_KEYWORDS):
            return -1, "Timing strategy not applicable (no time-based keywords in payload)."

        url = f"{base_url.rstrip('/')}{target_endpoint}"
        http_session = session or requests.Session()
        timeout = settings.executor_timeout

        try:
            # Measure baseline (benign) response time
            start_benign = time.perf_counter()
            http_session.get(
                url,
                params={"q": _BENIGN_VALUE},
                timeout=timeout,
                verify=False,
            )
            benign_time = time.perf_counter() - start_benign

            # Measure attack payload response time
            start_attack = time.perf_counter()
            http_session.get(
                url,
                params={"q": payload},
                timeout=timeout,
                verify=False,
            )
            attack_time = time.perf_counter() - start_attack

        except requests.RequestException as exc:
            logger.warning(
                "Timing validation request failed for %s: %s",
                vector_id,
                exc,
            )
            return -1, f"Timing request failed: {exc}"

        # Avoid division by zero
        if benign_time <= 0:
            benign_time = 0.001

        slowdown_ratio = attack_time / benign_time

        logger.debug(
            "Timing validation for %s: benign=%.3fs, attack=%.3fs, ratio=%.2fx",
            vector_id,
            benign_time,
            attack_time,
            slowdown_ratio,
        )

        if slowdown_ratio >= _SLOWDOWN_FACTOR:
            return (
                0.9,
                f"Attack response {slowdown_ratio:.1f}x slower than baseline "
                f"(attack={attack_time:.3f}s, benign={benign_time:.3f}s). "
                "Confirmed blind injection.",
            )

        return (
            0.2,
            f"Attack response only {slowdown_ratio:.1f}x vs baseline "
            f"(attack={attack_time:.3f}s, benign={benign_time:.3f}s). "
            "Likely false positive.",
        )
