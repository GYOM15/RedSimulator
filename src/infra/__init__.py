"""
Infrastructure layer for cross-cutting concerns.

Provides AOP decorators, centralized configuration, structured logging,
and a typed exception hierarchy.

Quick reference::

    from src.infra.decorators import logged, retry, timed, safe
    from src.infra.config import settings
    from src.infra.logging import setup_logging, get_logger
    from src.infra.exceptions import ScanError, ToolError
"""

from src.infra.decorators import logged, retry, safe, timed

__all__ = [
    "logged",
    "retry",
    "safe",
    "timed",
]
