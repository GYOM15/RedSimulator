"""Attack handler implementations.

Each module in this package implements an :class:`AttackHandler` subclass
for a specific attack type (SQLi, XSS, IDOR, ...).
"""

from .auth_bypass import AuthBypassHandler
from .command_injection import CommandInjectionHandler
from .csrf import CsrfHandler
from .idor import IdorHandler
from .info_disclosure import InfoDisclosureHandler
from .open_redirect import OpenRedirectHandler
from .path_traversal import PathTraversalHandler
from .sqli import SqliHandler
from .xss import XssHandler

__all__ = [
    "AuthBypassHandler",
    "CommandInjectionHandler",
    "CsrfHandler",
    "IdorHandler",
    "InfoDisclosureHandler",
    "OpenRedirectHandler",
    "PathTraversalHandler",
    "SqliHandler",
    "XssHandler",
    "get_all_handlers",
]


def get_all_handlers() -> dict[str, type]:
    """Return a mapping of attack_type string to handler class."""
    handlers = [
        AuthBypassHandler,
        CommandInjectionHandler,
        CsrfHandler,
        IdorHandler,
        InfoDisclosureHandler,
        OpenRedirectHandler,
        PathTraversalHandler,
        SqliHandler,
        XssHandler,
    ]
    return {h.attack_type: h for h in handlers}
