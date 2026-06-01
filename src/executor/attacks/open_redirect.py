"""Open Redirect attack handler.

Injects attacker-controlled URLs into redirect-related parameters and
checks whether the application redirects users to arbitrary external
destinations.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from src.executor.base import AttackHandler
from src.infra.logging import get_logger
from src.models import AttackVector, SingleAttackResult

logger = get_logger(__name__)

# Common parameter names used by applications for redirect destinations.
_REDIRECT_PARAMS = (
    "redirect",
    "redirect_uri",
    "redirect_url",
    "next",
    "url",
    "return",
    "returnTo",
    "return_url",
    "continue",
    "dest",
    "destination",
    "go",
    "target",
    "rurl",
    "out",
    "view",
    "ref",
    "redir",
)

# Default payloads when the vector does not supply any.
_DEFAULT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2F%2F",
    "/\\evil.com",
    "https://evil.com/.example.com",
]

# Regex for detecting JavaScript-based redirects in response bodies.
_JS_REDIRECT_RE = re.compile(
    r"(window\.location|document\.location|location\.href)\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

# The attacker-controlled domain we look for in the redirect target.
_EVIL_DOMAIN = "evil.com"


class OpenRedirectHandler(AttackHandler):
    """Test for open redirect vulnerabilities.

    Strategy:
    1. Identify redirect-related parameters from ``vector.target_fields``
       or by scanning the URL for common redirect parameter names.
    2. For each parameter, inject each payload and send a GET request
       with ``allow_redirects=False`` to capture the raw redirect.
    3. Check the ``Location`` header for the attacker-controlled domain.
    4. Also inspect the response body for JavaScript-based redirects.
    """

    attack_type = "open_redirect"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def test(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Test a single open-redirect payload against the vector endpoint."""
        if self.session is None:
            return self._make_result(
                vector,
                payload,
                status=0,
                snippet="",
                success=False,
                detection="No HTTP session available",
            )

        redirect_params = self._identify_redirect_params(vector)
        if not redirect_params:
            logger.debug(
                "[OPEN_REDIRECT] No redirect parameters identified for %s",
                vector.target_endpoint,
            )
            return self._make_result(
                vector,
                payload,
                status=0,
                snippet="",
                success=False,
                detection="No redirect-related parameters found to test",
            )

        # Test each redirect parameter with the given payload.
        for param in redirect_params:
            result = self._test_redirect(vector, payload, param)
            if result.success:
                return result

        # None of the parameters resulted in an open redirect.
        return self._make_result(
            vector,
            payload,
            status=0,
            snippet="",
            success=False,
            detection=f"Payload not redirected for params: {', '.join(redirect_params)}",
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _identify_redirect_params(self, vector: AttackVector) -> list[str]:
        """Determine which URL parameters to inject the payload into.

        Prefers ``vector.target_fields`` if populated; otherwise falls
        back to scanning the endpoint URL for common redirect parameter
        names.
        """
        if vector.target_fields:
            return list(vector.target_fields)

        # Parse existing query parameters from the endpoint URL.
        parsed = urlparse(vector.target_endpoint)
        existing_params = parse_qs(parsed.query)

        # Check if any existing parameter has a redirect-like name.
        found = [p for p in existing_params if p.lower() in _REDIRECT_PARAMS]
        if found:
            return found

        # Fallback: inject into the most common redirect parameter name.
        return ["redirect"]

    def _build_url_with_payload(
        self,
        endpoint: str,
        param: str,
        payload: str,
    ) -> str:
        """Construct the full path with the payload injected into *param*."""
        parsed = urlparse(endpoint)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]

        new_query = urlencode(qs, doseq=True)
        new_url = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            )
        )
        return new_url

    def _test_redirect(
        self,
        vector: AttackVector,
        payload: str,
        param: str,
    ) -> SingleAttackResult:
        """Send a GET with the payload and check for an open redirect."""
        target_path = self._build_url_with_payload(
            vector.target_endpoint,
            param,
            payload,
        )
        logger.debug(
            "[OPEN_REDIRECT] Testing %s with param=%s payload=%s", target_path, param, payload
        )

        resp = self.session.get(target_path, allow_redirects=False)  # type: ignore[union-attr]
        if resp is None:
            return self._make_result(
                vector,
                payload,
                status=0,
                snippet="",
                success=False,
                detection=f"Connection error testing param '{param}'",
            )

        status = resp.status_code
        snippet = resp.text[:200] if resp.text else ""

        # Check 1: HTTP 3xx with Location pointing to the evil domain.
        if 300 <= status < 400:
            location = resp.headers.get("Location", "")
            if self._is_evil_redirect(location):
                logger.info(
                    "[OPEN_REDIRECT] Confirmed redirect via Location header on %s (param=%s)",
                    vector.target_endpoint,
                    param,
                )
                return self._make_result(
                    vector,
                    payload,
                    status=status,
                    snippet=f"Location: {location}",
                    success=True,
                    detection=f"Open redirect confirmed: {status} with Location header pointing to {_EVIL_DOMAIN}",
                )

        # Check 2: 200 but the evil URL appears reflected in the body.
        if status == 200 and _EVIL_DOMAIN in resp.text:
            # Look for JS-based redirects specifically.
            js_match = _JS_REDIRECT_RE.search(resp.text)
            if js_match and _EVIL_DOMAIN in js_match.group(2):
                logger.info(
                    "[OPEN_REDIRECT] JS redirect detected on %s (param=%s)",
                    vector.target_endpoint,
                    param,
                )
                return self._make_result(
                    vector,
                    payload,
                    status=status,
                    snippet=js_match.group(0)[:200],
                    success=True,
                    detection=f"JavaScript redirect to {_EVIL_DOMAIN} detected in response body",
                )

            # The evil URL is reflected but not necessarily a redirect.
            logger.info(
                "[OPEN_REDIRECT] Evil URL reflected in body on %s (param=%s)",
                vector.target_endpoint,
                param,
            )
            return self._make_result(
                vector,
                payload,
                status=status,
                snippet=snippet,
                success=True,
                detection=f"Evil URL ({_EVIL_DOMAIN}) reflected in response body (potential redirect)",
            )

        return self._make_result(
            vector,
            payload,
            status=status,
            snippet=snippet,
            success=False,
            detection=f"No redirect detected for param '{param}' (status {status})",
        )

    @staticmethod
    def _is_evil_redirect(location: str) -> bool:
        """Return True if *location* resolves to the attacker domain."""
        if not location:
            return False

        # Handle protocol-relative URLs (//evil.com).
        normalized = location
        if normalized.startswith("//"):
            normalized = "https:" + normalized

        try:
            parsed = urlparse(normalized)
            host = parsed.hostname or ""
            return host == _EVIL_DOMAIN or host.endswith(f".{_EVIL_DOMAIN}")
        except Exception:
            # Malformed URL -- check raw string as fallback.
            return _EVIL_DOMAIN in location
