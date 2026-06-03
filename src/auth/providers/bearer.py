"""Bearer token / JWT authentication provider.

Sets the ``Authorization: Bearer <token>`` header on the session.  If
the token looks like a JWT (three dot-separated base64 segments), the
provider decodes the payload (without signature verification) to check
the ``exp`` claim and auto-refreshes when expired.
"""

from __future__ import annotations

import base64
import json
import time

import requests

from src.auth.models import AuthConfig, AuthState
from src.auth.providers.base import AuthProvider
from src.infra.config import settings
from src.infra.decorators import logged, retry
from src.infra.exceptions import AuthenticationFailedError, TokenExpiredError
from src.infra.logging import get_logger

logger = get_logger(__name__)


def _decode_jwt_payload(token: str) -> dict | None:
    """Decode the payload of a JWT *without* verifying the signature.

    Returns ``None`` if the token does not look like a valid JWT or
    cannot be decoded.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        # JWT base64url encoding: add padding and replace URL-safe chars.
        payload_b64 = parts[1]
        # Add padding if needed.
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        decoded = base64.urlsafe_b64decode(payload_b64)
        return json.loads(decoded)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


class BearerAuthProvider(AuthProvider):
    """Provider for Bearer token / JWT authentication."""

    name = "bearer"

    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        self._expires_at: float | None = None

    @logged
    @retry(max_attempts=2, exceptions=(requests.RequestException,))
    def authenticate(self, session: requests.Session, base_url: str) -> AuthState:
        """Set the Bearer token header on the session."""
        token = self.config.token
        if not token:
            raise AuthenticationFailedError("Bearer auth requires a token but none was provided.")

        session.headers["Authorization"] = f"Bearer {token}"

        # Try to extract expiration from JWT payload.
        expires_at: float | None = None
        jwt_payload = _decode_jwt_payload(token)
        if jwt_payload and "exp" in jwt_payload:
            try:
                expires_at = float(jwt_payload["exp"])
                remaining = expires_at - time.time()
                if remaining <= 0:
                    logger.warning("Bearer token is already expired (exp=%s)", expires_at)
                    raise TokenExpiredError(
                        "Bearer token has already expired",
                        details={"exp": expires_at},
                    )
                logger.info("Bearer token expires in %.0f seconds", remaining)
            except (TypeError, ValueError):
                logger.debug("Could not parse 'exp' claim from JWT payload")

        self._expires_at = expires_at

        # Optionally verify the token with a test request.
        try:
            resp = session.get(
                base_url,
                timeout=settings.executor_timeout,
                allow_redirects=True,
            )
            if resp.status_code in (401, 403):
                session.headers.pop("Authorization", None)
                raise AuthenticationFailedError(
                    f"Bearer token rejected by {base_url} (HTTP {resp.status_code})",
                    details={"status_code": resp.status_code},
                )
        except requests.RequestException:
            logger.warning("Test request to %s failed during Bearer auth setup", base_url)
            raise

        logger.info("Bearer auth configured successfully")
        return AuthState(
            authenticated=True,
            token=token,
            expires_at=expires_at,
            method_used=self.name,
        )

    def is_authenticated(self, session: requests.Session) -> bool:
        """Check that the Authorization header is set and the token is not expired."""
        auth_header = session.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False

        # If we have an expiration time, check it.
        if self._expires_at is not None and time.time() >= self._expires_at:
            logger.info("Bearer token has expired")
            return False

        return True

    def refresh(self, session: requests.Session, base_url: str) -> AuthState:
        """Refresh the Bearer token.

        If a ``token_url`` is configured, attempts to obtain a new token
        from it.  Otherwise falls back to re-authentication with the
        original token.
        """
        if self.config.token_url:
            token_url = self.config.token_url
            if token_url.startswith("/"):
                token_url = f"{base_url.rstrip('/')}{token_url}"

            try:
                resp = session.post(
                    token_url,
                    json={
                        "token": self.config.token,
                        **self.config.extra,
                    },
                    timeout=settings.executor_timeout,
                )
                if resp.ok:
                    data = resp.json()
                    new_token = data.get("access_token") or data.get("token", "")
                    if new_token:
                        self.config.token = new_token
                        logger.info("Bearer token refreshed via %s", token_url)
            except (requests.RequestException, ValueError, KeyError):
                logger.warning("Token refresh via %s failed; re-authenticating", token_url)

        return self.authenticate(session, base_url)
