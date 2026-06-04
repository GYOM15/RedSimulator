"""Multi-payload validation strategy.

Re-tests the same endpoint with several different payloads from the
payload database.  If multiple distinct payloads succeed, the finding
is very likely real; if none succeed on retry, the original was
probably a fluke.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import requests

from src.generator.payload_db import payload_db
from src.infra.config import settings
from src.infra.logging import get_logger

from .base import ValidationStrategy

if TYPE_CHECKING:
    from src.models import SingleAttackResult

logger = get_logger(__name__)

_MAX_ALTERNATE_PAYLOADS = 5
"""Number of alternate payloads to try during validation."""


class MultiPayloadStrategy(ValidationStrategy):
    """Re-test with different payloads from the payload database.

    * 2+ alternate payloads succeed -> high confidence (score 0.9)
    * Exactly 1 succeeds -> medium confidence (score 0.5)
    * None succeed -> original was likely FP (score 0.1)
    """

    name: str = "multi_payload"

    def validate(
        self,
        vector_id: str,
        payload: str,
        target_endpoint: str,
        base_url: str,
        original_result: SingleAttackResult,
        session: requests.Session | None = None,
    ) -> tuple[float, str]:
        # Determine the attack type from the vector_id prefix or fall back
        # to inferring from the original result detection method.
        attack_type = self._infer_attack_type(original_result)
        if not attack_type:
            return -1, "Could not determine attack type for multi-payload validation."

        # Fetch alternate payloads from the database
        all_payloads = payload_db.get_texts(attack_type, limit=_MAX_ALTERNATE_PAYLOADS * 3)

        # Filter out the original payload and pick up to N alternates
        alternates = [p for p in all_payloads if p != payload][:_MAX_ALTERNATE_PAYLOADS]

        if not alternates:
            logger.debug(
                "No alternate payloads available for %s/%s",
                attack_type,
                vector_id,
            )
            return -1, "No alternate payloads available for re-testing."

        url = f"{base_url.rstrip('/')}{target_endpoint}"
        http_session = session or requests.Session()
        timeout = settings.executor_timeout
        delay = settings.attack_delay

        success_count = 0
        tested = 0

        for alt_payload in alternates:
            tested += 1
            time.sleep(delay)
            try:
                resp = http_session.get(
                    url,
                    params={"q": alt_payload},
                    timeout=timeout,
                    verify=False,
                )
                if self._looks_successful(resp, attack_type, alt_payload):
                    success_count += 1
            except requests.RequestException as exc:
                logger.debug(
                    "Multi-payload request failed for %s: %s",
                    vector_id,
                    exc,
                )

        if success_count >= 2:
            return (
                0.9,
                f"{success_count}/{tested} alternate payloads succeeded. "
                "High confidence this is a true positive.",
            )
        if success_count == 1:
            return (
                0.5,
                f"1/{tested} alternate payload succeeded. "
                "Medium confidence — may be a true positive.",
            )
        return (
            0.1,
            f"0/{tested} alternate payloads succeeded. "
            "Original finding is likely a false positive.",
        )

    @staticmethod
    def _infer_attack_type(result: SingleAttackResult) -> str | None:
        """Best-effort inference of the attack type from the result.

        Uses the ``vector_id`` prefix convention (e.g. ``VEC-SQLI-001``)
        or falls back to keyword matching on the detection method.
        """
        vid = result.vector_id.upper()
        detection = result.detection_method.lower()

        mapping = {
            "sqli": ["sqli", "sql", "injection"],
            "xss": ["xss", "cross-site", "script"],
            "idor": ["idor", "insecure direct"],
            "path_traversal": ["path_traversal", "traversal", "lfi"],
            "command_injection": ["command_injection", "rce", "command"],
            "auth_bypass": ["auth_bypass", "authentication"],
            "info_disclosure": ["info_disclosure", "information"],
            "csrf": ["csrf", "cross-site request"],
            "open_redirect": ["open_redirect", "redirect"],
        }

        for attack_type, keywords in mapping.items():
            for kw in keywords:
                if kw in vid or kw in detection:
                    return attack_type
        return None

    @staticmethod
    def _looks_successful(
        response: requests.Response,
        attack_type: str,
        payload: str,
    ) -> bool:
        """Heuristic check for whether a response indicates success.

        This is intentionally conservative to avoid inflating the
        multi-payload confirmation count.
        """
        body = response.text.lower()
        status = response.status_code

        # Common success indicators per attack type
        if attack_type == "sqli":
            return status == 200 and any(
                kw in body for kw in ["token", "admin", "error in your sql", "syntax"]
            )
        if attack_type == "xss":
            return payload.lower() in body
        if attack_type == "path_traversal":
            return any(kw in body for kw in ["root:", "/etc/", "boot.ini", "[extensions]"])
        if attack_type == "command_injection":
            return any(kw in body for kw in ["root:", "uid=", "volume serial"])

        # Generic: non-error 2xx with payload reflection
        return status == 200 and payload[:20].lower() in body
