"""Abstract base class for authentication providers.

Every concrete provider (Basic, Cookie, Bearer, OAuth2) inherits from
:class:`AuthProvider` and implements at least :meth:`authenticate` and
:meth:`is_authenticated`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import requests

from src.auth.models import AuthState


class AuthProvider(ABC):
    """Abstract authentication provider.

    Subclasses implement a specific authentication strategy (HTTP Basic,
    cookie-based login, bearer token, OAuth2 client-credentials, etc.).
    """

    name: str

    @abstractmethod
    def authenticate(self, session: requests.Session, base_url: str) -> AuthState:
        """Perform authentication and return the resulting state."""

    @abstractmethod
    def is_authenticated(self, session: requests.Session) -> bool:
        """Return ``True`` if the session is still authenticated."""

    def refresh(self, session: requests.Session, base_url: str) -> AuthState:
        """Refresh authentication.

        The default implementation simply re-authenticates from scratch.
        Subclasses may override this to perform a lightweight token
        refresh instead.
        """
        return self.authenticate(session, base_url)
