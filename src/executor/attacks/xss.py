"""Cross-Site Scripting (XSS) attack handler.

Implements three detection strategies:
  1. **Reflected XSS** -- POST the payload and check if it appears
     verbatim in the response body (not sanitised).
  2. **Stored XSS** -- POST the payload, then GET the same endpoint
     and verify the payload persists.
  3. **Partial sanitisation** -- check if the payload was modified but
     not fully removed (e.g. ``<script>`` stripped but ``onerror=`` kept).
"""

from __future__ import annotations

import html

import requests

from src.executor.base import AttackHandler
from src.infra.decorators import retry
from src.infra.logging import get_logger
from src.models import AttackVector, SingleAttackResult

logger = get_logger(__name__)

# Fragments that, if present after sanitisation, indicate an incomplete
# filtering attempt and still represent an XSS risk.
_DANGEROUS_FRAGMENTS = (
    "onerror=",
    "onload=",
    "onclick=",
    "onmouseover=",
    "onfocus=",
    "javascript:",
    "eval(",
    "document.cookie",
    "alert(",
)


class XssHandler(AttackHandler):
    """XSS handler with reflected, stored, and partial-sanitisation detection."""

    attack_type = "xss"

    @retry(max_attempts=2, base_delay=0.5, exceptions=(requests.ConnectionError, requests.Timeout))
    def test(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Test an XSS payload against the target endpoint.

        Args:
            vector: Attack vector describing the endpoint and fields.
            payload: XSS payload string (e.g. ``<script>alert(1)</script>``).

        Returns:
            Result indicating whether the XSS succeeded.
        """
        url = vector.target_endpoint
        logger.debug("[XSS] %s%s <- %s", self.base_url, url, payload)

        # Build POST body with the payload in each target field.
        body: dict[str, str] = {field: payload for field in vector.target_fields}

        try:
            resp = self.session.post(url, json=body)

            if resp is None:
                return self._make_result(
                    vector,
                    payload,
                    status=0,
                    snippet="No response (connection error)",
                    success=False,
                    detection="Connection failed -- no HTTP response received",
                )

            snippet = resp.text[:200]
            text_lower = resp.text.lower()

            # ----------------------------------------------------------------
            # WAF / firewall blocking detection
            # ----------------------------------------------------------------
            if resp.status_code == 403 or "blocked" in text_lower or "forbidden" in text_lower:
                logger.debug("[XSS] Request blocked (possible WAF)")
                return self._make_result(
                    vector,
                    payload,
                    status=resp.status_code,
                    snippet=snippet,
                    success=False,
                    detection=(
                        f"WAF/firewall detected: request blocked "
                        f"(HTTP {resp.status_code}, 'blocked'/'forbidden' in response)"
                    ),
                )

            # ----------------------------------------------------------------
            # Strategy 1: Reflected XSS
            # The exact payload appears verbatim in the response body.
            # ----------------------------------------------------------------
            if payload in resp.text:
                logger.debug("[XSS] Reflected: payload found verbatim in response")
                return self._make_result(
                    vector,
                    payload,
                    status=resp.status_code,
                    snippet=snippet,
                    success=True,
                    detection=(
                        "Reflected XSS: payload appears verbatim in the HTTP "
                        f"response (HTTP {resp.status_code}), no sanitisation applied"
                    ),
                )

            # ----------------------------------------------------------------
            # Strategy 2: Stored XSS
            # POST the payload, then GET the same endpoint and check if the
            # payload was persisted and is served back.
            # ----------------------------------------------------------------
            get_resp = self.session.get(url)
            if get_resp is not None and payload in get_resp.text:
                logger.debug("[XSS] Stored: payload persists on GET after POST")
                return self._make_result(
                    vector,
                    payload,
                    status=get_resp.status_code,
                    snippet=get_resp.text[:200],
                    success=True,
                    detection=(
                        "Stored XSS: payload persists in the page after a "
                        "subsequent GET request, indicating server-side storage "
                        "without sanitisation"
                    ),
                )

            # ----------------------------------------------------------------
            # Strategy 3: Partial sanitisation
            # The exact payload was modified (e.g. <script> stripped) but
            # dangerous fragments still remain, or the payload appears in
            # its HTML-encoded form (meaning it was encoded but not removed).
            # ----------------------------------------------------------------
            # Check for HTML-encoded version of the payload.
            encoded_payload = html.escape(payload)
            if encoded_payload != payload and encoded_payload in resp.text:
                logger.debug("[XSS] Partial: HTML-encoded payload found in response")
                return self._make_result(
                    vector,
                    payload,
                    status=resp.status_code,
                    snippet=snippet,
                    success=False,
                    detection=(
                        "Partial sanitisation: payload was HTML-encoded in "
                        "the response (not exploitable as-is, but input is "
                        "reflected — encoding bypass may be possible)"
                    ),
                )

            # Check for dangerous event-handler fragments surviving sanitisation.
            surviving = [frag for frag in _DANGEROUS_FRAGMENTS if frag.lower() in text_lower]
            if surviving:
                frags_str = ", ".join(surviving)
                logger.debug("[XSS] Partial: dangerous fragments survived: %s", frags_str)
                return self._make_result(
                    vector,
                    payload,
                    status=resp.status_code,
                    snippet=snippet,
                    success=True,
                    detection=(
                        f"Partial sanitisation: dangerous fragments [{frags_str}] "
                        "survived in the response despite other filtering, "
                        "indicating incomplete XSS protection"
                    ),
                )

            # No XSS detected.
            return self._make_result(
                vector,
                payload,
                status=resp.status_code,
                snippet=snippet,
                success=False,
                detection=(
                    f"No XSS detected (HTTP {resp.status_code}): payload not "
                    "reflected, not stored, and no dangerous fragments found"
                ),
            )

        except requests.RequestException as exc:
            logger.error("Request error during XSS test: %s", exc)
            return self._make_result(
                vector,
                payload,
                status=0,
                snippet=str(exc)[:200],
                success=False,
                detection=f"Connection error: {exc}",
            )
