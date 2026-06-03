"""Data models for the authentication framework.

Defines the configuration and runtime state types used by all auth
providers and the :class:`~src.auth.manager.AuthManager` orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class AuthType(StrEnum):
    """Supported authentication strategies."""

    NONE = "none"
    BASIC = "basic"
    COOKIE = "cookie"
    BEARER = "bearer"
    OAUTH2 = "oauth2"


@dataclass
class AuthConfig:
    """Authentication configuration supplied by the user.

    Only the fields relevant to the chosen :attr:`auth_type` need to be
    populated; the rest can stay at their defaults.
    """

    auth_type: AuthType = AuthType.NONE
    username: str = ""
    password: str = ""
    token: str = ""
    login_url: str = ""
    token_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    csrf_field: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class AuthState:
    """Runtime authentication state.

    Tracks whether the session is authenticated, what method was used,
    and any tokens/cookies that were obtained.
    """

    authenticated: bool = False
    token: str | None = None
    expires_at: float | None = None  # unix timestamp
    cookies: dict = field(default_factory=dict)
    method_used: str = ""
