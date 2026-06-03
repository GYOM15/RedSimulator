"""HTTP Basic authentication provider.

Sets ``session.auth`` to the ``(username, password)`` tuple and verifies
that the credentials are accepted by making a test request to the
target's base URL.
"""

from __future__ import annotations

import requests

from src.auth.models import AuthConfig, AuthState
from src.auth.providers.base import AuthProvider
from src.infra.config import settings
from src.infra.decorators import logged, retry
from src.infra.exceptions import AuthenticationFailedError
from src.infra.logging import get_logger

logger = get_logger(__name__)


class BasicAuthProvider(AuthProvider):
    """Provider for HTTP Basic authentication (RFC 7617)."""

    name = "basic"

    def __init__(self, config: AuthConfig) -> None:
        self.config = config

    @logged
    @retry(max_attempts=2, exceptions=(requests.RequestException,))
    def authenticate(self, session: requests.Session, base_url: str) -> AuthState:
        """Set Basic auth credentials and verify with a test request."""
        session.auth = (self.config.username, self.config.password)

        # Verify credentials with a lightweight HEAD/GET to the base URL.
        try:
            resp = session.get(
                base_url,
                timeout=settings.executor_timeout,
                allow_redirects=True,
            )
        except requests.RequestException:
            logger.warning("Test request to %s failed during Basic auth setup", base_url)
            raise

        if resp.status_code in (401, 403):
            session.auth = None
            raise AuthenticationFailedError(
                f"Basic auth rejected by {base_url} (HTTP {resp.status_code})",
                details={"status_code": resp.status_code},
            )

        logger.info(
            "Basic auth successful for user '%s' (HTTP %d)",
            self.config.username,
            resp.status_code,
        )
        return AuthState(
            authenticated=True,
            method_used=self.name,
        )

    def is_authenticated(self, session: requests.Session) -> bool:
        """Check that the session still carries Basic auth credentials."""
        return session.auth is not None
