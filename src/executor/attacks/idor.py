"""Insecure Direct Object Reference (IDOR) attack handler.

Implements three detection strategies:
  1. **ID enumeration** -- replace numeric IDs in the URL path with the
     payload value and request the modified endpoint.
  2. **Response comparison** -- compare status codes and body lengths
     between the original and modified URLs.
  3. **Unauthorised access** -- if the server returns 200 with JSON data
     for a different user's resource, IDOR is confirmed.
"""

from __future__ import annotations

import re

import requests

from src.executor.base import AttackHandler
from src.infra.decorators import retry
from src.infra.logging import get_logger
from src.models import AttackVector, SingleAttackResult

logger = get_logger(__name__)

# Matches one or more digits in a URL path segment (e.g. /rest/basket/1).
_NUMERIC_ID_PATTERN = re.compile(r"/(\d+)(?=/|$)")


class IdorHandler(AttackHandler):
    """IDOR handler with ID enumeration, response comparison, and unauthorised-access detection."""

    attack_type = "idor"

    @retry(max_attempts=2, base_delay=0.5, exceptions=(requests.ConnectionError, requests.Timeout))
    def test(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Test an IDOR payload against the target endpoint.

        The payload is expected to be an alternate ID value (e.g. ``"2"``).
        The handler finds the numeric ID in the URL, replaces it with the
        payload, and compares the two responses.

        Args:
            vector: Attack vector with a target_endpoint containing a numeric ID.
            payload: Replacement ID value to test access controls.

        Returns:
            Result indicating whether the IDOR succeeded.
        """
        url = vector.target_endpoint
        logger.debug("[IDOR] %s%s <- payload=%s", self.base_url, url, payload)

        # Find numeric IDs in the URL path.
        id_match = _NUMERIC_ID_PATTERN.search(url)
        if not id_match:
            logger.debug("[IDOR] No numeric ID found in URL: %s", url)
            return self._make_result(
                vector,
                payload,
                status=0,
                snippet="",
                success=False,
                detection=(
                    f"No numeric ID found in endpoint path '{url}' — cannot perform ID substitution"
                ),
            )

        original_id = id_match.group(1)
        modified_url = url[: id_match.start(1)] + str(payload) + url[id_match.end(1) :]

        try:
            # ----------------------------------------------------------------
            # Step 1: Fetch the original endpoint (baseline).
            # ----------------------------------------------------------------
            original_resp = self.session.get(url)
            if original_resp is None:
                return self._make_result(
                    vector,
                    payload,
                    status=0,
                    snippet="No response for original URL (connection error)",
                    success=False,
                    detection="Connection failed on baseline request",
                )

            # ----------------------------------------------------------------
            # Step 2: Fetch the modified endpoint (with substituted ID).
            # ----------------------------------------------------------------
            modified_resp = self.session.get(modified_url)
            if modified_resp is None:
                return self._make_result(
                    vector,
                    payload,
                    status=0,
                    snippet="No response for modified URL (connection error)",
                    success=False,
                    detection="Connection failed on modified-ID request",
                )

            snippet = modified_resp.text[:200]

            # ----------------------------------------------------------------
            # Access denied: the server correctly blocked the request.
            # ----------------------------------------------------------------
            if modified_resp.status_code in (401, 403, 404):
                logger.debug(
                    "[IDOR] Access denied for ID %s (HTTP %d)",
                    payload,
                    modified_resp.status_code,
                )
                return self._make_result(
                    vector,
                    payload,
                    status=modified_resp.status_code,
                    snippet=snippet,
                    success=False,
                    detection=(
                        f"Access correctly denied: HTTP {modified_resp.status_code} "
                        f"when requesting ID {payload} (original ID was {original_id})"
                    ),
                )

            # ----------------------------------------------------------------
            # Strategy 3: Unauthorised access detection
            # HTTP 200 with a JSON body for a different ID indicates IDOR.
            # ----------------------------------------------------------------
            if modified_resp.status_code == 200:
                content_type = modified_resp.headers.get("Content-Type", "")
                has_json = "application/json" in content_type

                # Try to determine if the response contains user-specific data.
                text_lower = modified_resp.text.lower()
                has_user_data = any(
                    marker in text_lower
                    for marker in (
                        "email",
                        "username",
                        "name",
                        "address",
                        "phone",
                        "basket",
                        "order",
                    )
                )

                # ----------------------------------------------------------------
                # Strategy 2: Response comparison
                # Compare body lengths to detect meaningful data being returned.
                # ----------------------------------------------------------------
                original_len = len(original_resp.text)
                modified_len = len(modified_resp.text)

                if has_json and has_user_data:
                    logger.debug("[IDOR] Confirmed: ID %s returned JSON with user data", payload)
                    return self._make_result(
                        vector,
                        payload,
                        status=modified_resp.status_code,
                        snippet=snippet,
                        success=True,
                        detection=(
                            f"IDOR confirmed: replacing ID {original_id} with "
                            f"{payload} returned HTTP 200 with JSON body containing "
                            "user-specific data (missing access control)"
                        ),
                    )

                if modified_len > 50 and has_json:
                    logger.debug(
                        "[IDOR] Probable: ID %s returned JSON data (%d chars)",
                        payload,
                        modified_len,
                    )
                    return self._make_result(
                        vector,
                        payload,
                        status=modified_resp.status_code,
                        snippet=snippet,
                        success=True,
                        detection=(
                            f"IDOR probable: ID {payload} returned HTTP 200 "
                            f"with JSON body ({modified_len} chars vs "
                            f"{original_len} chars for original ID {original_id})"
                        ),
                    )

                # Non-JSON 200 response — may still be an IDOR for HTML endpoints.
                if modified_len > 100:
                    logger.debug(
                        "[IDOR] Possible: ID %s returned HTTP 200 with %d chars",
                        payload,
                        modified_len,
                    )
                    return self._make_result(
                        vector,
                        payload,
                        status=modified_resp.status_code,
                        snippet=snippet,
                        success=True,
                        detection=(
                            f"IDOR possible: ID {payload} returned HTTP 200 "
                            f"with body ({modified_len} chars) — access control "
                            "may be missing on this endpoint"
                        ),
                    )

            # No IDOR detected.
            return self._make_result(
                vector,
                payload,
                status=modified_resp.status_code,
                snippet=snippet,
                success=False,
                detection=(
                    f"No IDOR detected: ID {payload} returned HTTP "
                    f"{modified_resp.status_code} with {len(modified_resp.text)} "
                    f"chars (original ID {original_id})"
                ),
            )

        except requests.RequestException as exc:
            logger.error("Request error during IDOR test: %s", exc)
            return self._make_result(
                vector,
                payload,
                status=0,
                snippet=str(exc)[:200],
                success=False,
                detection=f"Connection error: {exc}",
            )
