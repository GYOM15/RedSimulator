"""Cookie / form-based login authentication provider.

Handles the common web-application pattern where the client POSTs
credentials to a login URL and receives session cookies. Includes
automatic CSRF token extraction from the login page, which is
essential for frameworks like Django, Rails, Laravel, and Express
(e.g. OWASP Juice Shop).
"""

from __future__ import annotations

import re

import requests

from src.auth.models import AuthConfig, AuthState
from src.auth.providers.base import AuthProvider
from src.infra.config import settings
from src.infra.decorators import logged, retry
from src.infra.exceptions import AuthenticationFailedError
from src.infra.logging import get_logger

logger = get_logger(__name__)

# Common CSRF field names found across web frameworks.
_CSRF_FIELD_NAMES = (
    "csrf",
    "csrf_token",
    "_csrf",
    "_token",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "__RequestVerificationToken",
    "XSRF-TOKEN",
)

# Regex to extract hidden input fields from HTML.
_HIDDEN_INPUT_RE = re.compile(
    r'<input[^>]+type=["\']hidden["\'][^>]*'
    r'name=["\']([^"\']+)["\'][^>]*'
    r'value=["\']([^"\']*)["\']',
    re.IGNORECASE,
)

# Also match inputs where value comes before name.
_HIDDEN_INPUT_RE_ALT = re.compile(
    r'<input[^>]+type=["\']hidden["\'][^>]*'
    r'value=["\']([^"\']*)["\'][^>]*'
    r'name=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def _extract_csrf_token(html: str, csrf_field: str = "") -> tuple[str, str]:
    """Extract CSRF token name and value from HTML.

    Parameters
    ----------
    html:
        Raw HTML of the login page.
    csrf_field:
        If provided, look for this specific field name.  Otherwise scan
        for any of the common CSRF field names.

    Returns
    -------
    tuple[str, str]
        ``(field_name, field_value)`` or ``("", "")`` if not found.
    """
    # Collect all hidden inputs.
    hidden_fields: dict[str, str] = {}

    for match in _HIDDEN_INPUT_RE.finditer(html):
        hidden_fields[match.group(1)] = match.group(2)

    for match in _HIDDEN_INPUT_RE_ALT.finditer(html):
        # Groups are reversed: value first, then name.
        hidden_fields[match.group(2)] = match.group(1)

    if not hidden_fields:
        return "", ""

    # If a specific field was requested, look for it.
    if csrf_field and csrf_field in hidden_fields:
        return csrf_field, hidden_fields[csrf_field]

    # Otherwise try each known CSRF field name.
    for name in _CSRF_FIELD_NAMES:
        if name in hidden_fields:
            return name, hidden_fields[name]

    # Last resort: return the first hidden field that looks CSRF-ish.
    for name, value in hidden_fields.items():
        if "csrf" in name.lower() or "token" in name.lower():
            return name, value

    return "", ""


class CookieAuthProvider(AuthProvider):
    """Provider for cookie/form-based login with CSRF handling."""

    name = "cookie"

    def __init__(self, config: AuthConfig) -> None:
        self.config = config

    @logged
    @retry(max_attempts=2, exceptions=(requests.RequestException,))
    def authenticate(self, session: requests.Session, base_url: str) -> AuthState:
        """POST credentials to the login URL and capture session cookies."""
        login_url = self.config.login_url
        if not login_url:
            raise AuthenticationFailedError(
                "Cookie auth requires a login_url but none was provided."
            )

        # Resolve relative login URLs against the base URL.
        if login_url.startswith("/"):
            login_url = f"{base_url.rstrip('/')}{login_url}"

        # Step 1: GET the login page to pick up CSRF token and initial cookies.
        csrf_name, csrf_value = "", ""
        try:
            page_resp = session.get(
                login_url,
                timeout=settings.executor_timeout,
                allow_redirects=True,
            )
            if page_resp.ok:
                csrf_name, csrf_value = _extract_csrf_token(
                    page_resp.text,
                    csrf_field=self.config.csrf_field,
                )
                if csrf_name:
                    logger.debug(
                        "Found CSRF field '%s' on login page",
                        csrf_name,
                    )
        except requests.RequestException:
            logger.debug("Failed to GET login page for CSRF extraction; proceeding anyway")

        # Step 2: Build the form payload.
        form_data: dict[str, str] = {
            "username": self.config.username,
            "password": self.config.password,
        }
        # Also include common alternative field names in the extras.
        form_data.update(self.config.extra)

        if csrf_name and csrf_value:
            form_data[csrf_name] = csrf_value

        # Step 3: POST credentials.
        try:
            resp = session.post(
                login_url,
                data=form_data,
                timeout=settings.executor_timeout,
                allow_redirects=True,
            )
        except requests.RequestException:
            logger.warning("POST to login URL %s failed", login_url)
            raise

        # A redirect to a non-login page or a 2xx is typically success.
        if resp.status_code in (401, 403):
            raise AuthenticationFailedError(
                f"Cookie auth rejected by {login_url} (HTTP {resp.status_code})",
                details={"status_code": resp.status_code},
            )

        # Capture cookies from the session.
        cookies = dict(session.cookies)
        logger.info(
            "Cookie auth successful via %s (%d cookie(s) captured)",
            login_url,
            len(cookies),
        )

        return AuthState(
            authenticated=True,
            cookies=cookies,
            method_used=self.name,
        )

    def is_authenticated(self, session: requests.Session) -> bool:
        """Check that the session still holds cookies."""
        return len(session.cookies) > 0
