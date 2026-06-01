"""
Structured logging setup for RedSimulator.

Provides two output formats:
  - text: colored, human-readable lines for local development.
  - json: one JSON object per line for production log aggregation.

Usage at application startup::

    from src.infra.logging import setup_logging
    setup_logging(level="DEBUG", fmt="text")

Usage inside any module::

    from src.infra.logging import get_logger
    logger = get_logger(__name__)
    logger.info("Starting scan", extra={"target": url})

If ``setup_logging`` is never called, ``get_logger`` still returns a
standard :class:`logging.Logger` that writes to stderr at WARNING level
(the Python default), so library code is never broken by the absence of
an explicit setup step.
"""

from __future__ import annotations

import json as _json
import logging
import os
import sys
import traceback
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ROOT_NAMESPACE = "src"
"""All application loggers live under this namespace."""

_NOISY_LOGGERS = (
    "urllib3",
    "httpx",
    "chromadb",
    "langchain",
    "langchain_core",
    "langchain_community",
    "httpcore",
)
"""Third-party loggers that are suppressed to WARNING."""

_SETUP_DONE = False
"""Module-level flag used to make ``setup_logging`` idempotent."""

# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

_RESET = "\033[0m"

_LEVEL_COLORS: dict[int, str] = {
    logging.DEBUG: "\033[37m",  # gray / white
    logging.INFO: "\033[32m",  # green
    logging.WARNING: "\033[33m",  # yellow
    logging.ERROR: "\033[31m",  # red
    logging.CRITICAL: "\033[1;31m",  # red bold
}


def _supports_color() -> bool:
    """Return True when stdout is a TTY that likely supports ANSI colors."""
    if os.getenv("NO_COLOR"):
        return False
    if os.getenv("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


# ---------------------------------------------------------------------------
# Text formatter
# ---------------------------------------------------------------------------


class TextFormatter(logging.Formatter):
    """Human-readable single-line formatter with optional ANSI colors.

    Output format::

        [2025-03-29 14:30:00] INFO scanner.agent | Starting ReAct agent ...

    Colors are applied to the level name when the output stream is a TTY
    (or when the ``FORCE_COLOR`` environment variable is set).  Set the
    ``NO_COLOR`` environment variable to disable colors unconditionally.
    """

    def __init__(self, use_color: bool | None = None) -> None:
        super().__init__()
        self._use_color = use_color if use_color is not None else _supports_color()

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")
        level = record.levelname.ljust(8)

        if self._use_color:
            color = _LEVEL_COLORS.get(record.levelno, "")
            level = f"{color}{level}{_RESET}"

        msg = record.getMessage()
        line = f"[{ts}] {level} {record.name} | {msg}"

        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            line = f"{line}\n{record.exc_text}"

        return line


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


class JsonFormatter(logging.Formatter):
    """Outputs one JSON object per log record (JSON Lines).

    Guaranteed fields: ``timestamp``, ``level``, ``module``, ``message``.

    Any *extra* keyword arguments passed to the logging call are merged
    into the top-level object.  If the record carries exception info, an
    ``exception`` field is added containing the formatted traceback.
    """

    # Keys that belong to the stdlib LogRecord and should not be treated
    # as user-supplied extras.
    _BUILTIN_ATTRS: frozenset[str] = frozenset(
        logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
    ) | {"message", "asctime"}

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
        }

        # Merge user-supplied extras.
        for key, value in record.__dict__.items():
            if key not in self._BUILTIN_ATTRS:
                payload[key] = value

        # Attach traceback when present.
        if record.exc_info:
            payload["exception"] = "".join(traceback.format_exception(*record.exc_info))

        return _json.dumps(payload, default=str, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def setup_logging(
    level: str = "INFO",
    fmt: str = "text",
) -> None:
    """Configure the application root logger.

    This should be called once, early in the application's startup sequence
    (e.g. in ``main()``).  Repeated calls are safe and have no effect.

    Parameters
    ----------
    level:
        Log level name such as ``"DEBUG"``, ``"INFO"``, ``"WARNING"``.
        Passed directly to :meth:`logging.Logger.setLevel`.
    fmt:
        ``"text"`` for colored human-readable output, ``"json"`` for
        structured JSON Lines.
    """
    global _SETUP_DONE

    if _SETUP_DONE:
        return
    _SETUP_DONE = True

    # Resolve the numeric level (accepts both "INFO" and "info").
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    # Choose formatter.
    if fmt == "json":
        formatter: logging.Formatter = JsonFormatter()
    else:
        formatter = TextFormatter()

    # Set up a single StreamHandler writing to stdout.
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)

    # Configure the application root logger.
    root = logging.getLogger(_ROOT_NAMESPACE)
    root.setLevel(numeric_level)
    root.addHandler(handler)

    # Prevent log records from propagating to the default root logger,
    # which would duplicate output.
    root.propagate = False

    # Suppress chatty third-party loggers.
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a logger for the given module name.

    This is a thin convenience wrapper around :func:`logging.getLogger`.
    Typical usage inside a module::

        from src.infra.logging import get_logger
        logger = get_logger(__name__)

    The returned logger works even if :func:`setup_logging` has not been
    called -- it simply falls back to Python's default logging behaviour
    (WARNING level, stderr output).
    """
    return logging.getLogger(name)
