"""
Aspect-Oriented Programming (AOP) decorators for cross-cutting concerns.

This module centralizes logging, retry logic, timing, and error handling
so that business logic stays clean and free of infrastructure boilerplate.

All decorators:
    - Preserve the original function's signature via functools.wraps.
    - Work transparently with both synchronous and asynchronous functions.
    - Are composable: they can be stacked in any order.
    - Use Python's logging module exclusively (no print statements).

Typical usage::

    @logged
    @retry(max_attempts=3, exceptions=(ConnectionError,))
    def call_external_api(url: str) -> dict:
        ...

    @safe(fallback=[])
    async def fetch_optional_metadata(target: str) -> list:
        ...
"""

from __future__ import annotations

import asyncio
import functools
import logging
import random
import time
from typing import Any, Callable, Tuple, Type, TypeVar, Union

F = TypeVar("F", bound=Callable[..., Any])

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MAX_ARG_REPR_LENGTH = 200


def _truncated_repr(value: Any, max_length: int = _MAX_ARG_REPR_LENGTH) -> str:
    """Return a repr of *value*, truncated with an ellipsis if too long."""
    text = repr(value)
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text


def _format_args(args: tuple, kwargs: dict) -> str:
    """Build a human-readable, truncated summary of call arguments."""
    parts: list[str] = [_truncated_repr(a) for a in args]
    parts.extend(f"{k}={_truncated_repr(v)}" for k, v in kwargs.items())
    return ", ".join(parts)


def _get_logger(func: Callable) -> logging.Logger:
    """Return a logger named after the module that defines *func*."""
    module = getattr(func, "__module__", None) or __name__
    return logging.getLogger(module)


# ---------------------------------------------------------------------------
# @logged
# ---------------------------------------------------------------------------


def logged(
    _func: Callable | None = None,
    *,
    level: int = logging.INFO,
) -> Callable:
    """Structured entry/exit logging with timing.

    Can be used bare (``@logged``) or with parameters
    (``@logged(level=logging.DEBUG)``).

    Logs:
        - Function entry with (truncated) arguments.
        - Function exit with wall-clock duration in milliseconds.
        - Any exception with full context before re-raising.

    Parameters
    ----------
    level:
        The logging level for entry/exit messages.  Exceptions are always
        logged at ``ERROR`` level regardless of this setting.
    """

    def decorator(func: F) -> F:
        logger = _get_logger(func)
        qualname = func.__qualname__

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            call_args = _format_args(args, kwargs)
            logger.log(level, "[ENTER] %s(%s)", qualname, call_args)
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
            except Exception:
                elapsed_ms = (time.perf_counter() - start) * 1000
                logger.exception(
                    "[ERROR] %s raised after %.2f ms", qualname, elapsed_ms
                )
                raise
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.log(
                level,
                "[EXIT]  %s completed in %.2f ms",
                qualname,
                elapsed_ms,
            )
            return result

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            call_args = _format_args(args, kwargs)
            logger.log(level, "[ENTER] %s(%s)", qualname, call_args)
            start = time.perf_counter()
            try:
                result = await func(*args, **kwargs)
            except Exception:
                elapsed_ms = (time.perf_counter() - start) * 1000
                logger.exception(
                    "[ERROR] %s raised after %.2f ms", qualname, elapsed_ms
                )
                raise
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.log(
                level,
                "[EXIT]  %s completed in %.2f ms",
                qualname,
                elapsed_ms,
            )
            return result

        if asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    # Allow bare ``@logged`` (no parentheses) as well as ``@logged(...)``.
    if _func is not None:
        return decorator(_func)
    return decorator


# ---------------------------------------------------------------------------
# @retry
# ---------------------------------------------------------------------------


def retry(
    _func: Callable | None = None,
    *,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exceptions: Tuple[Type[BaseException], ...] = (Exception,),
) -> Callable:
    """Configurable retry with exponential backoff and jitter.

    Can be used bare (``@retry``) or with parameters
    (``@retry(max_attempts=5, exceptions=(ConnectionError, TimeoutError))``).

    On each failed attempt the decorator sleeps for::

        min(base_delay * 2^attempt + random_jitter, max_delay)

    If all attempts are exhausted the **last** exception is re-raised.

    Parameters
    ----------
    max_attempts:
        Total number of tries (including the first).
    base_delay:
        Base delay in seconds before the first retry.
    max_delay:
        Upper bound on the delay between retries.
    exceptions:
        Tuple of exception types that trigger a retry.  Exceptions not
        listed here propagate immediately.
    """

    def decorator(func: F) -> F:
        logger = _get_logger(func)
        qualname = func.__qualname__

        def _compute_delay(attempt: int) -> float:
            """Exponential backoff with full jitter."""
            exp_delay = base_delay * (2 ** attempt)
            jitter = random.uniform(0, exp_delay)
            return min(jitter, max_delay)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exc: BaseException | None = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt < max_attempts - 1:
                        delay = _compute_delay(attempt)
                        logger.warning(
                            "[RETRY] %s attempt %d/%d failed (%s: %s). "
                            "Retrying in %.2f s ...",
                            qualname,
                            attempt + 1,
                            max_attempts,
                            type(exc).__name__,
                            exc,
                            delay,
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            "[RETRY] %s failed after %d attempts. "
                            "Last error: %s: %s",
                            qualname,
                            max_attempts,
                            type(exc).__name__,
                            exc,
                        )
            raise last_exc  # type: ignore[misc]

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exc: BaseException | None = None
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except exceptions as exc:
                    last_exc = exc
                    if attempt < max_attempts - 1:
                        delay = _compute_delay(attempt)
                        logger.warning(
                            "[RETRY] %s attempt %d/%d failed (%s: %s). "
                            "Retrying in %.2f s ...",
                            qualname,
                            attempt + 1,
                            max_attempts,
                            type(exc).__name__,
                            exc,
                            delay,
                        )
                        await asyncio.sleep(delay)
                    else:
                        logger.error(
                            "[RETRY] %s failed after %d attempts. "
                            "Last error: %s: %s",
                            qualname,
                            max_attempts,
                            type(exc).__name__,
                            exc,
                        )
            raise last_exc  # type: ignore[misc]

        if asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    if _func is not None:
        return decorator(_func)
    return decorator


# ---------------------------------------------------------------------------
# @timed
# ---------------------------------------------------------------------------


def timed(func: F) -> F:
    """Measure and log execution time in milliseconds.

    Always logs at ``INFO`` level.  The log message is structured so that
    it can be parsed by log-aggregation tooling::

        [TIMED] my_module.my_func took 42.17 ms

    When stacked with ``@logged``, ``@timed`` adds a dedicated timing line
    but does **not** duplicate the entry/exit messages produced by
    ``@logged``.  Place ``@timed`` closer to the function (i.e. below
    ``@logged``) for the most accurate measurement.
    """
    logger = _get_logger(func)
    qualname = func.__qualname__

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        try:
            return func(*args, **kwargs)
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.info("[TIMED] %s took %.2f ms", qualname, elapsed_ms)

    @functools.wraps(func)
    async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        try:
            return await func(*args, **kwargs)
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.info("[TIMED] %s took %.2f ms", qualname, elapsed_ms)

    if asyncio.iscoroutinefunction(func):
        return async_wrapper  # type: ignore[return-value]
    return sync_wrapper  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# @safe
# ---------------------------------------------------------------------------


def safe(
    _func: Callable | None = None,
    *,
    fallback: Any = None,
    exceptions: Tuple[Type[BaseException], ...] = (Exception,),
) -> Callable:
    """Catch exceptions and return a fallback value instead.

    Can be used bare (``@safe``) or with parameters
    (``@safe(fallback=[], exceptions=(KeyError, ValueError))``).

    Caught exceptions are logged at ``WARNING`` level.  This decorator is
    intended for **non-critical** operations where a failure should not
    crash the pipeline.

    Parameters
    ----------
    fallback:
        The value to return when an exception is caught.
    exceptions:
        Tuple of exception types to catch.  Any exception not in this
        tuple will propagate normally.
    """

    def decorator(func: F) -> F:
        logger = _get_logger(func)
        qualname = func.__qualname__

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except exceptions as exc:
                logger.warning(
                    "[SAFE]  %s caught %s: %s — returning fallback %r",
                    qualname,
                    type(exc).__name__,
                    exc,
                    fallback,
                )
                return fallback

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return await func(*args, **kwargs)
            except exceptions as exc:
                logger.warning(
                    "[SAFE]  %s caught %s: %s — returning fallback %r",
                    qualname,
                    type(exc).__name__,
                    exc,
                    fallback,
                )
                return fallback

        if asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    if _func is not None:
        return decorator(_func)
    return decorator
