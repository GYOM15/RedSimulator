"""Authentication providers package.

Exports all concrete :class:`~src.auth.providers.base.AuthProvider`
implementations.
"""

from src.auth.providers.base import AuthProvider
from src.auth.providers.basic import BasicAuthProvider
from src.auth.providers.bearer import BearerAuthProvider
from src.auth.providers.cookie import CookieAuthProvider
from src.auth.providers.oauth2 import OAuth2Provider

__all__ = [
    "AuthProvider",
    "BasicAuthProvider",
    "BearerAuthProvider",
    "CookieAuthProvider",
    "OAuth2Provider",
]
