"""Adaptive rate limiter for attack execution.

Dynamically adjusts the delay between requests based on server responses.
Slows down when the server shows signs of stress, speeds up when healthy.

Thread-safe: all mutable state is protected by a lock so the limiter
can safely be shared across threads.
"""

from __future__ import annotations

import threading
import time

from src.infra.logging import get_logger

logger = get_logger(__name__)


class AdaptiveRateLimiter:
    """Adjusts request delay based on server behavior.

    Parameters
    ----------
    base_delay:
        Starting delay between requests (seconds).
    min_delay:
        Floor for the delay — the limiter will never go below this.
    max_delay:
        Ceiling for the delay — the limiter will never exceed this.
    backoff_factor:
        Multiplicative factor when backing off (delay *= backoff_factor).
    recovery_factor:
        Multiplicative factor when recovering (delay *= recovery_factor).
        Must be < 1.0 to actually decrease the delay.
    """

    def __init__(
        self,
        base_delay: float = 0.2,
        min_delay: float = 0.05,
        max_delay: float = 5.0,
        backoff_factor: float = 1.5,
        recovery_factor: float = 0.9,
    ):
        self.base_delay = base_delay
        self.current_delay = base_delay
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.recovery_factor = recovery_factor

        self._consecutive_errors: int = 0
        self._consecutive_success: int = 0
        self._total_requests: int = 0
        self._total_backoffs: int = 0

        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def wait(self) -> None:
        """Sleep for the current adaptive delay."""
        with self._lock:
            delay = self.current_delay
        time.sleep(delay)

    def record_response(self, status_code: int, response_time_ms: float) -> None:
        """Adjust delay based on the server's response.

        Back off when:
        - 429 Too Many Requests
        - 503 Service Unavailable
        - Response time > 3000 ms (server is slow)
        - 5 consecutive server errors (5xx)

        Speed up when:
        - 10 consecutive successful responses (2xx)
        - Response time < 500 ms
        """
        with self._lock:
            self._total_requests += 1

            should_backoff = False
            should_recover = False

            # --- Back-off triggers ---

            if status_code == 429:
                # Rate limited — significant backoff.
                should_backoff = True
                self._consecutive_errors += 1
                self._consecutive_success = 0
                logger.debug(
                    "Rate limiter: 429 received, backing off (delay=%.3fs)",
                    self.current_delay,
                )

            elif status_code == 503:
                # Service unavailable — significant backoff.
                should_backoff = True
                self._consecutive_errors += 1
                self._consecutive_success = 0
                logger.debug(
                    "Rate limiter: 503 received, backing off (delay=%.3fs)",
                    self.current_delay,
                )

            elif 500 <= status_code < 600:
                # Other server error — track consecutive count.
                self._consecutive_errors += 1
                self._consecutive_success = 0
                if self._consecutive_errors >= 5:
                    should_backoff = True
                    logger.debug(
                        "Rate limiter: %d consecutive server errors, backing off",
                        self._consecutive_errors,
                    )

            elif 200 <= status_code < 300:
                # Success.
                self._consecutive_success += 1
                self._consecutive_errors = 0

                if response_time_ms > 3000:
                    # Server responded OK but very slowly.
                    should_backoff = True
                    logger.debug(
                        "Rate limiter: slow response (%.0fms), backing off",
                        response_time_ms,
                    )
                elif self._consecutive_success >= 10 and response_time_ms < 500:
                    should_recover = True
                    self._consecutive_success = 0  # Reset after recovery.

            else:
                # 3xx, 4xx (other than 429) — treat as neutral.
                self._consecutive_errors = 0
                self._consecutive_success = 0

            # --- Apply adjustment ---

            if should_backoff:
                self._apply_backoff()
            elif should_recover:
                self._apply_recovery()

    def record_error(self) -> None:
        """Record a connection error (timeout, DNS failure, etc.).

        Connection errors trigger a more aggressive backoff than HTTP
        errors because they suggest the server may be down.
        """
        with self._lock:
            self._total_requests += 1
            self._consecutive_errors += 1
            self._consecutive_success = 0

            # Double backoff for connection errors.
            self.current_delay = min(
                self.current_delay * self.backoff_factor * self.backoff_factor,
                self.max_delay,
            )
            self._total_backoffs += 1
            logger.debug(
                "Rate limiter: connection error, aggressive backoff (delay=%.3fs)",
                self.current_delay,
            )

    @property
    def stats(self) -> dict:
        """Return a snapshot of rate limiter statistics."""
        with self._lock:
            return {
                "current_delay_ms": round(self.current_delay * 1000, 1),
                "base_delay_ms": round(self.base_delay * 1000, 1),
                "min_delay_ms": round(self.min_delay * 1000, 1),
                "max_delay_ms": round(self.max_delay * 1000, 1),
                "consecutive_errors": self._consecutive_errors,
                "consecutive_success": self._consecutive_success,
                "total_requests": self._total_requests,
                "total_backoffs": self._total_backoffs,
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_backoff(self) -> None:
        """Increase delay. Must be called while holding ``_lock``."""
        self.current_delay = min(
            self.current_delay * self.backoff_factor,
            self.max_delay,
        )
        self._total_backoffs += 1

    def _apply_recovery(self) -> None:
        """Decrease delay. Must be called while holding ``_lock``."""
        self.current_delay = max(
            self.current_delay * self.recovery_factor,
            self.min_delay,
        )
