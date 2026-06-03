"""Auto-discovery of all passive checks.

Registers every concrete PassiveCheck subclass so the analyzer can
iterate over them without manual wiring.
"""

from src.passive.checks.base import PassiveCheck
from src.passive.checks.cookies import CookieCheck
from src.passive.checks.cors import CorsCheck
from src.passive.checks.headers import HeaderCheck
from src.passive.checks.information import InformationCheck
from src.passive.checks.sensitive_urls import SensitiveUrlCheck
from src.passive.checks.transport import TransportCheck


def get_all_checks() -> list[PassiveCheck]:
    """Return an instance of every registered passive check."""
    return [
        HeaderCheck(),
        CookieCheck(),
        InformationCheck(),
        TransportCheck(),
        SensitiveUrlCheck(),
        CorsCheck(),
    ]


__all__ = [
    "CookieCheck",
    "CorsCheck",
    "HeaderCheck",
    "InformationCheck",
    "PassiveCheck",
    "SensitiveUrlCheck",
    "TransportCheck",
    "get_all_checks",
]
