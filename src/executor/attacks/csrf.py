"""CSRF (Cross-Site Request Forgery) attack handler.

Tests whether form endpoints are protected against CSRF by checking
for token presence, token validation, SameSite cookie attributes, and
Referer header enforcement.
"""

from __future__ import annotations

import re

from src.executor.base import AttackHandler
from src.infra.logging import get_logger
from src.models import AttackVector, SingleAttackResult

logger = get_logger(__name__)

# Known CSRF token field names across popular frameworks.
_CSRF_FIELD_NAMES = (
    "csrf",
    "csrf_token",
    "_csrf",
    "_token",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "__RequestVerificationToken",
    "XSRF-TOKEN",
)

# Regex that matches an HTML <input> whose name is a known CSRF token field.
_CSRF_INPUT_RE = re.compile(
    r'<input[^>]+name=["\']('
    + "|".join(re.escape(n) for n in _CSRF_FIELD_NAMES)
    + r')["\'][^>]*value=["\']([^"\']*)["\']',
    re.IGNORECASE,
)


class CsrfHandler(AttackHandler):
    """Test CSRF protections on form endpoints.

    The handler runs several sub-checks sequentially:

    1. **Token absence** -- GET the target endpoint, parse the HTML, and
       verify that at least one recognised CSRF token field exists.
    2. **Token validation** -- If a token is found, re-submit the form
       *without* the token.  A ``200`` response means the server does not
       actually validate the token.
    3. **SameSite cookie check** -- Inspect ``Set-Cookie`` headers for the
       ``SameSite`` attribute.
    4. **Referer validation** -- Submit the form with a spoofed
       ``Referer: https://evil.com`` header.  Acceptance indicates
       missing Referer enforcement.
    """

    attack_type = "csrf"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def test(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Execute the full CSRF test suite for *vector*.

        *payload* is largely unused for CSRF checks but is forwarded to
        ``_make_result`` for traceability.
        """
        endpoint = vector.target_endpoint

        # Step 1 -- Fetch the form page and look for a CSRF token.
        page_resp = self._get_page(endpoint)
        if page_resp is None:
            return self._make_result(
                vector,
                payload,
                status=0,
                snippet="",
                success=False,
                detection="Connection error: could not reach target endpoint",
            )

        page_body = page_resp.text
        token_match = _CSRF_INPUT_RE.search(page_body)

        if token_match is None:
            # No CSRF token found at all -- vulnerable.
            logger.info("[CSRF] No CSRF token found on %s", endpoint)
            return self._make_result(
                vector,
                payload,
                status=page_resp.status_code,
                snippet=page_body[:200],
                success=True,
                detection="No CSRF token field found in form HTML",
            )

        token_field_name = token_match.group(1)
        token_value = token_match.group(2)
        logger.debug(
            "[CSRF] Found token field '%s' on %s",
            token_field_name,
            endpoint,
        )

        # Step 2 -- Submit the form WITHOUT the CSRF token.
        bypass_result = self._test_token_validation(
            vector,
            payload,
            token_field_name,
        )
        if bypass_result is not None and bypass_result.success:
            return bypass_result

        # Step 3 -- Check SameSite attribute on cookies.
        samesite_result = self._check_samesite(vector, payload, page_resp)
        if samesite_result is not None and samesite_result.success:
            return samesite_result

        # Step 4 -- Spoofed Referer header.
        referer_result = self._test_referer_validation(
            vector,
            payload,
            token_field_name,
            token_value,
        )
        if referer_result is not None and referer_result.success:
            return referer_result

        # All checks passed -- endpoint appears protected.
        return self._make_result(
            vector,
            payload,
            status=page_resp.status_code,
            snippet=page_body[:200],
            success=False,
            detection="CSRF protections appear adequate (token present, validated, SameSite set, Referer checked)",
        )

    # ------------------------------------------------------------------
    # Sub-checks
    # ------------------------------------------------------------------

    def _get_page(self, endpoint: str):
        """GET the target endpoint via the shared session."""
        if self.session is None:
            logger.warning("[CSRF] No session available for HTTP calls")
            return None
        return self.session.get(endpoint)

    def _test_token_validation(
        self,
        vector: AttackVector,
        payload: str,
        token_field_name: str,
    ) -> SingleAttackResult | None:
        """Submit the form without the CSRF token.

        If the server returns a ``200``, the token is not validated --
        the endpoint is vulnerable.
        """
        if self.session is None:
            return None

        # Build a form body using target_fields but omit the token field.
        body: dict[str, str] = {}
        for field in vector.target_fields:
            if field.lower() != token_field_name.lower():
                body[field] = payload

        resp = self.session.post(vector.target_endpoint, data=body)
        if resp is None:
            return None

        if resp.status_code == 200:
            logger.info(
                "[CSRF] Token validation bypassed on %s (submitted without token, got 200)",
                vector.target_endpoint,
            )
            return self._make_result(
                vector,
                payload,
                status=resp.status_code,
                snippet=resp.text[:200],
                success=True,
                detection="CSRF token validation bypassed: form accepted without token",
            )

        logger.debug(
            "[CSRF] Token validation OK on %s (status %d without token)",
            vector.target_endpoint,
            resp.status_code,
        )
        return None

    def _check_samesite(
        self,
        vector: AttackVector,
        payload: str,
        page_resp,
    ) -> SingleAttackResult | None:
        """Check whether cookies returned by the page have the SameSite attribute."""
        set_cookie_headers = page_resp.headers.get("Set-Cookie", "")
        if not set_cookie_headers:
            # No cookies set -- nothing to check here, not a vulnerability
            # on its own.
            return None

        # ``Set-Cookie`` may appear multiple times; ``requests`` concatenates
        # them with commas in the raw header.  We check each fragment.
        has_samesite = "samesite" in set_cookie_headers.lower()

        if not has_samesite:
            logger.info(
                "[CSRF] Cookies on %s lack SameSite attribute",
                vector.target_endpoint,
            )
            return self._make_result(
                vector,
                payload,
                status=page_resp.status_code,
                snippet=set_cookie_headers[:200],
                success=True,
                detection="Session cookies lack SameSite attribute, increasing CSRF risk",
            )

        return None

    def _test_referer_validation(
        self,
        vector: AttackVector,
        payload: str,
        token_field_name: str,
        token_value: str,
    ) -> SingleAttackResult | None:
        """Submit the form with a spoofed ``Referer`` header.

        If the server accepts the request with ``Referer: https://evil.com``,
        it does not enforce Referer validation.
        """
        if self.session is None:
            return None

        body: dict[str, str] = {token_field_name: token_value}
        for field in vector.target_fields:
            if field.lower() != token_field_name.lower():
                body[field] = payload

        resp = self.session.post(
            vector.target_endpoint,
            data=body,
            headers={"Referer": "https://evil.com"},
        )
        if resp is None:
            return None

        if resp.status_code == 200:
            logger.info(
                "[CSRF] Referer validation missing on %s (accepted Referer: evil.com)",
                vector.target_endpoint,
            )
            return self._make_result(
                vector,
                payload,
                status=resp.status_code,
                snippet=resp.text[:200],
                success=True,
                detection="Referer validation missing: form accepted request with Referer https://evil.com",
            )

        logger.debug(
            "[CSRF] Referer validation OK on %s (status %d with evil Referer)",
            vector.target_endpoint,
            resp.status_code,
        )
        return None
