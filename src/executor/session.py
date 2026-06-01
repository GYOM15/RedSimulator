"""HTTP session manager for attack execution.

Manages cookies, authentication state, and default headers across all
attack handlers so that multi-step attack sequences (e.g. login then
exploit) share the same transport session.
"""

from __future__ import annotations

import requests

from src.infra.config import settings
from src.infra.logging import get_logger

logger = get_logger(__name__)


class SessionManager:
    """Manages HTTP sessions, cookies, and auth state across attacks.

    All handlers receive the same ``SessionManager`` instance, which
    lets authenticated attacks reuse tokens/cookies obtained by earlier
    handlers in the same execution run.
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "RedSimulator/1.0",
                "Accept": "application/json, text/html, */*",
            }
        )
        self.auth_token: str | None = None
        self.cookies: dict = {}

    def get(self, path: str, **kwargs) -> requests.Response | None:
        """Send GET request through the session."""
        kwargs.setdefault("timeout", settings.executor_timeout)
        try:
            return self.session.get(f"{self.base_url}{path}", **kwargs)
        except requests.RequestException as e:
            logger.debug("GET %s failed: %s", path, e)
            return None

    def post(self, path: str, **kwargs) -> requests.Response | None:
        """Send POST request through the session."""
        kwargs.setdefault("timeout", settings.executor_timeout)
        try:
            return self.session.post(f"{self.base_url}{path}", **kwargs)
        except requests.RequestException as e:
            logger.debug("POST %s failed: %s", path, e)
            return None

    def request(self, method: str, path: str, **kwargs) -> requests.Response | None:
        """Send arbitrary method request."""
        kwargs.setdefault("timeout", settings.executor_timeout)
        try:
            return self.session.request(method, f"{self.base_url}{path}", **kwargs)
        except requests.RequestException as e:
            logger.debug("%s %s failed: %s", method, path, e)
            return None
