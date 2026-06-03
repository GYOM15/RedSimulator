"""Authentication framework for RedSimulator.

Provides a pluggable auth provider system so the executor can
authenticate before testing.  Supports HTTP Basic, cookie/form-based
login (with CSRF), Bearer/JWT tokens, and OAuth2 client_credentials.

Quick reference::

    from src.auth import AuthManager, AuthConfig, AuthType

    config = AuthConfig(auth_type=AuthType.BASIC, username="admin", password="s3cret")
    manager = AuthManager(config)
    manager.ensure_authenticated(session, base_url)
"""

from src.auth.manager import AuthManager
from src.auth.models import AuthConfig, AuthState, AuthType
from src.auth.providers import (
    AuthProvider,
    BasicAuthProvider,
    BearerAuthProvider,
    CookieAuthProvider,
    OAuth2Provider,
)

__all__ = [
    "AuthConfig",
    "AuthManager",
    "AuthProvider",
    "AuthState",
    "AuthType",
    "BasicAuthProvider",
    "BearerAuthProvider",
    "CookieAuthProvider",
    "OAuth2Provider",
]
