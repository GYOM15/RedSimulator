"""Differential validation strategy.

Compares the attack response against a benign baseline request to the
same endpoint.  If both responses are materially identical (same status
code, similar body length), the attack likely had no special effect and
the finding is probably a false positive.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import requests

from src.infra.config import settings
from src.infra.logging import get_logger

from .base import ValidationStrategy

if TYPE_CHECKING:
    from src.models import SingleAttackResult

logger = get_logger(__name__)

_BENIGN_VALUE = "test123"
"""Innocuous value sent instead of the attack payload."""

_LENGTH_TOLERANCE = 0.10
"""Fraction by which response lengths may differ and still be considered similar."""


class DifferentialStrategy(ValidationStrategy):
    """Compare attack response to a benign baseline.

    Sends the same request with a harmless value instead of the
    payload and compares status codes and body lengths.

    * Responses materially identical -> likely FP (score 0.2)
    * Responses significantly different -> likely real (score 0.8)
    """

    name: str = "differential"

    def validate(
        self,
        vector_id: str,
        payload: str,
        target_endpoint: str,
        base_url: str,
        original_result: SingleAttackResult,
        session: requests.Session | None = None,
    ) -> tuple[float, str]:
        url = f"{base_url.rstrip('/')}{target_endpoint}"

        http_session = session or requests.Session()
        timeout = settings.executor_timeout

        try:
            # Send a benign request to establish a baseline
            benign_resp = http_session.get(
                url,
                params={"q": _BENIGN_VALUE},
                timeout=timeout,
                verify=False,
            )

            original_status = original_result.http_status
            original_body_len = len(original_result.response_snippet)
            benign_status = benign_resp.status_code
            benign_body_len = len(benign_resp.text)

            # Compare status codes
            status_match = original_status == benign_status

            # Compare body lengths with tolerance
            if original_body_len == 0 and benign_body_len == 0:
                length_similar = True
            elif max(original_body_len, benign_body_len) == 0:
                length_similar = False
            else:
                larger = max(original_body_len, benign_body_len)
                diff_ratio = abs(original_body_len - benign_body_len) / larger
                length_similar = diff_ratio <= _LENGTH_TOLERANCE

            # Check for key indicators in the original response
            snippet_lower = original_result.response_snippet.lower()
            has_error_indicators = any(
                kw in snippet_lower for kw in ["error", "syntax", "sql", "stack trace", "exception"]
            )

            if status_match and length_similar and not has_error_indicators:
                return (
                    0.2,
                    f"Responses are similar (status {original_status}={benign_status}, "
                    f"body lengths within {_LENGTH_TOLERANCE:.0%}). Likely false positive.",
                )

            if not status_match:
                return (
                    0.8,
                    f"Status codes differ (attack={original_status}, benign={benign_status}). "
                    "Likely true positive.",
                )

            # Status matches but lengths differ meaningfully
            return (
                0.6,
                f"Same status ({original_status}) but body lengths differ "
                f"(attack={original_body_len}, benign={benign_body_len}). "
                "Moderately likely true positive.",
            )

        except requests.RequestException as exc:
            logger.warning(
                "Differential validation failed for %s: %s",
                vector_id,
                exc,
            )
            return -1, f"Differential request failed: {exc}"
