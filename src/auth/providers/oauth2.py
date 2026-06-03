"""OAuth2 client_credentials flow authentication provider.

Implements the OAuth2 ``client_credentials`` grant type: POSTs
``client_id`` and ``client_secret`` to the ``token_url`` to obtain an
access token, then sets the ``Authorization: Bearer <token>`` header.
Automatically refreshes the token before it expires.
"""

from __future__ import annotations

import time

import requests

from src.auth.models import AuthConfig, AuthState
from src.auth.providers.base import AuthProvider
from src.infra.config import settings
from src.infra.decorators import logged, retry
from src.infra.exceptions import AuthenticationFailedError
from src.infra.logging import get_logger

logger = get_logger(__name__)


class OAuth2Provider(AuthProvider):
    """Provider for OAuth2 client_credentials flow."""

    name = "oauth2"

    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        self._expires_at: float | None = None

    @logged
    @retry(max_attempts=2, exceptions=(requests.RequestException,))
    def authenticate(self, session: requests.Session, base_url: str) -> AuthState:
        """Obtain an access token via the client_credentials grant."""
        token_url = self.config.token_url
        if not token_url:
            raise AuthenticationFailedError(
                "OAuth2 auth requires a token_url but none was provided."
            )

        if not self.config.client_id or not self.config.client_secret:
            raise AuthenticationFailedError("OAuth2 auth requires client_id and client_secret.")

        # Resolve relative token URLs against the base URL.
        if token_url.startswith("/"):
            token_url = f"{base_url.rstrip('/')}{token_url}"

        # POST the client credentials.
        try:
            resp = session.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    **self.config.extra,
                },
                timeout=settings.executor_timeout,
            )
        except requests.RequestException:
            logger.warning("OAuth2 token request to %s failed", token_url)
            raise

        if not resp.ok:
            raise AuthenticationFailedError(
                f"OAuth2 token request failed (HTTP {resp.status_code})",
                details={
                    "status_code": resp.status_code,
                    "body": resp.text[:500],
                },
            )

        # Parse the token response.
        try:
            data = resp.json()
        except ValueError as exc:
            raise AuthenticationFailedError(
                "OAuth2 token response is not valid JSON",
                details={"body": resp.text[:500]},
            ) from exc

        access_token = data.get("access_token", "")
        if not access_token:
            raise AuthenticationFailedError(
                "OAuth2 token response does not contain 'access_token'",
                details={"response_keys": list(data.keys())},
            )

        # Calculate expiration.
        expires_at: float | None = None
        expires_in = data.get("expires_in")
        if expires_in is not None:
            try:
                expires_at = time.time() + float(expires_in)
                logger.info("OAuth2 token expires in %s seconds", expires_in)
            except (TypeError, ValueError):
                logger.debug("Could not parse 'expires_in' from OAuth2 response")

        self._expires_at = expires_at

        # Set the Bearer header.
        session.headers["Authorization"] = f"Bearer {access_token}"

        logger.info("OAuth2 client_credentials auth successful via %s", token_url)
        return AuthState(
            authenticated=True,
            token=access_token,
            expires_at=expires_at,
            method_used=self.name,
        )

    def is_authenticated(self, session: requests.Session) -> bool:
        """Check that the Bearer header is present and the token is not expired."""
        auth_header = session.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False

        # Proactively refresh if the token expires within 30 seconds.
        if self._expires_at is not None and time.time() >= self._expires_at - 30:
            logger.info("OAuth2 token is expired or about to expire")
            return False

        return True

    def refresh(self, session: requests.Session, base_url: str) -> AuthState:
        """Refresh by re-running the client_credentials flow."""
        logger.info("Refreshing OAuth2 token")
        return self.authenticate(session, base_url)
