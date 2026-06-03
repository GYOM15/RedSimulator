"""HTTP session manager for attack execution.

Manages cookies, authentication state, and default headers across all
attack handlers so that multi-step attack sequences (e.g. login then
exploit) share the same transport session.
"""

from __future__ import annotations

import requests

from src.auth.manager import AuthManager
from src.auth.models import AuthConfig
from src.infra.config import settings
from src.infra.logging import get_logger

logger = get_logger(__name__)


class SessionManager:
    """Manages HTTP sessions, cookies, and auth state across attacks.

    All handlers receive the same ``SessionManager`` instance, which
    lets authenticated attacks reuse tokens/cookies obtained by earlier
    handlers in the same execution run.

    Parameters
    ----------
    base_url:
        The base URL of the target application.
    auth_config:
        Optional authentication configuration.  When provided, the
        session will authenticate automatically before each request
        and retry on 401/403 responses.
    """

    def __init__(
        self,
        base_url: str,
        auth_config: AuthConfig | None = None,
    ):
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
        self.auth_manager = AuthManager(auth_config) if auth_config else None

    def ensure_auth(self) -> None:
        """Ensure the session is authenticated before requests.

        This is a no-op when no :class:`AuthManager` is configured or
        when the auth type is ``"none"``.
        """
        if self.auth_manager:
            self.auth_manager.ensure_authenticated(self.session, self.base_url)

    def _handle_auth_failure(self, resp: requests.Response) -> None:
        """Notify the auth manager of a 401/403 so it can re-authenticate."""
        if resp is not None and resp.status_code in (401, 403) and self.auth_manager:
            self.auth_manager.on_response(resp, self.session, self.base_url)

    def get(self, path: str, **kwargs) -> requests.Response | None:
        """Send GET request through the session."""
        self.ensure_auth()
        kwargs.setdefault("timeout", settings.executor_timeout)
        try:
            resp = self.session.get(f"{self.base_url}{path}", **kwargs)
        except requests.RequestException as e:
            logger.debug("GET %s failed: %s", path, e)
            return None

        # Retry once after re-authentication on 401/403.
        if resp.status_code in (401, 403) and self.auth_manager:
            self._handle_auth_failure(resp)
            try:
                resp = self.session.get(f"{self.base_url}{path}", **kwargs)
            except requests.RequestException as e:
                logger.debug("GET %s retry failed: %s", path, e)
                return None

        return resp

    def post(self, path: str, **kwargs) -> requests.Response | None:
        """Send POST request through the session."""
        self.ensure_auth()
        kwargs.setdefault("timeout", settings.executor_timeout)
        try:
            resp = self.session.post(f"{self.base_url}{path}", **kwargs)
        except requests.RequestException as e:
            logger.debug("POST %s failed: %s", path, e)
            return None

        # Retry once after re-authentication on 401/403.
        if resp.status_code in (401, 403) and self.auth_manager:
            self._handle_auth_failure(resp)
            try:
                resp = self.session.post(f"{self.base_url}{path}", **kwargs)
            except requests.RequestException as e:
                logger.debug("POST %s retry failed: %s", path, e)
                return None

        return resp

    def request(self, method: str, path: str, **kwargs) -> requests.Response | None:
        """Send arbitrary method request."""
        self.ensure_auth()
        kwargs.setdefault("timeout", settings.executor_timeout)
        try:
            resp = self.session.request(method, f"{self.base_url}{path}", **kwargs)
        except requests.RequestException as e:
            logger.debug("%s %s failed: %s", method, path, e)
            return None

        # Retry once after re-authentication on 401/403.
        if resp.status_code in (401, 403) and self.auth_manager:
            self._handle_auth_failure(resp)
            try:
                resp = self.session.request(method, f"{self.base_url}{path}", **kwargs)
            except requests.RequestException as e:
                logger.debug("%s %s retry failed: %s", method, path, e)
                return None

        return resp
