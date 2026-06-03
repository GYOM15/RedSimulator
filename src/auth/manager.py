"""Authentication orchestrator.

The :class:`AuthManager` is the single entry point used by the executor
layer.  It selects the correct provider based on configuration, drives
the authenticate/refresh lifecycle, and handles automatic
re-authentication when a response comes back with 401/403.
"""

from __future__ import annotations

import requests

from src.auth.models import AuthConfig, AuthState, AuthType
from src.auth.providers.base import AuthProvider
from src.auth.providers.basic import BasicAuthProvider
from src.auth.providers.bearer import BearerAuthProvider
from src.auth.providers.cookie import CookieAuthProvider
from src.auth.providers.oauth2 import OAuth2Provider
from src.infra.decorators import logged
from src.infra.logging import get_logger

logger = get_logger(__name__)

_PROVIDER_MAP: dict[AuthType, type[AuthProvider]] = {
    AuthType.BASIC: BasicAuthProvider,
    AuthType.COOKIE: CookieAuthProvider,
    AuthType.BEARER: BearerAuthProvider,
    AuthType.OAUTH2: OAuth2Provider,
}


class AuthManager:
    """Manages authentication for the executor.

    Selects and drives the correct :class:`AuthProvider` based on the
    supplied :class:`AuthConfig`.  When ``auth_type`` is ``"none"``,
    the manager is effectively a no-op and all methods return immediately.
    """

    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        self.provider = self._create_provider()
        self.state = AuthState()

    def _create_provider(self) -> AuthProvider | None:
        """Factory: create the right provider based on config."""
        if self.config.auth_type == AuthType.NONE:
            logger.debug("Auth type is 'none'; no provider created")
            return None

        provider_cls = _PROVIDER_MAP.get(self.config.auth_type)
        if provider_cls is None:
            logger.warning(
                "Unknown auth type '%s'; authentication disabled",
                self.config.auth_type,
            )
            return None

        logger.info("Created auth provider: %s", provider_cls.name)
        return provider_cls(self.config)

    @logged
    def ensure_authenticated(
        self,
        session: requests.Session,
        base_url: str,
    ) -> AuthState:
        """Authenticate if needed, refresh if expired.

        This method is safe to call repeatedly.  It only performs actual
        network requests when the session is not yet authenticated or
        when the current credentials have expired.
        """
        if self.provider is None:
            return self.state

        # Already authenticated and still valid?
        if self.state.authenticated and self.provider.is_authenticated(session):
            return self.state

        # Need to authenticate or refresh.
        if self.state.authenticated:
            logger.info("Auth expired or invalid; refreshing")
            self.state = self.provider.refresh(session, base_url)
        else:
            logger.info("Performing initial authentication")
            self.state = self.provider.authenticate(session, base_url)

        return self.state

    def on_response(
        self,
        response: requests.Response,
        session: requests.Session,
        base_url: str,
    ) -> None:
        """Called after each request.  Re-authenticates on 401/403.

        This provides a safety net: if the server rejects a request
        despite a previously successful authentication, the manager
        forces a full re-authentication so the next retry has fresh
        credentials.
        """
        if self.provider is None:
            return

        if response.status_code in (401, 403):
            logger.info(
                "Received HTTP %d; forcing re-authentication",
                response.status_code,
            )
            # Mark as unauthenticated so ensure_authenticated will do a fresh login.
            self.state.authenticated = False
            self.state = self.provider.authenticate(session, base_url)
