"""Passive check for sensitive data in URLs.

Detects tokens, API keys, session IDs, passwords, and credentials
exposed in URL query parameters or path segments.
"""

import re
from urllib.parse import parse_qs, urlparse

from src.infra.decorators import logged
from src.infra.logging import get_logger
from src.passive.checks.base import PassiveCheck
from src.passive.models import FindingSeverity, PassiveFinding

logger = get_logger(__name__)

# Query parameter names that likely contain secrets
_SECRET_PARAM_NAMES = frozenset(
    {
        "token",
        "api_key",
        "apikey",
        "api-key",
        "access_token",
        "auth_token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "private_key",
        "client_secret",
    }
)

# Session-related parameter names
_SESSION_PARAM_NAMES = frozenset(
    {
        "sessionid",
        "session_id",
        "sid",
        "jsessionid",
        "phpsessid",
        "sess",
        "session",
    }
)

# Pattern for credentials in URL authority (user:pass@host)
_CREDENTIALS_IN_URL = re.compile(r"://([^:]+):([^@]+)@")


class SensitiveUrlCheck(PassiveCheck):
    """Detect sensitive data exposed in URLs."""

    name = "sensitive_url_check"
    description = "Checks for tokens, keys, session IDs, and credentials in URL parameters."

    @logged
    def check(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
        cookies: list[dict] | None = None,
    ) -> list[PassiveFinding]:
        findings: list[PassiveFinding] = []

        findings.extend(self._check_secret_params(url))
        findings.extend(self._check_session_in_url(url))
        findings.extend(self._check_credentials_in_url(url))

        return findings

    def _check_secret_params(self, url: str) -> list[PassiveFinding]:
        """Check for tokens/keys/passwords in query parameters."""
        findings: list[PassiveFinding] = []

        parsed = urlparse(url)
        if not parsed.query:
            return findings

        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            if param_name.lower() in _SECRET_PARAM_NAMES:
                values = params[param_name]
                # Only flag if the value is non-empty (actual data present)
                if any(v.strip() for v in values):
                    findings.append(
                        PassiveFinding(
                            check_name="secret_in_url",
                            severity=FindingSeverity.HIGH,
                            title=f"Sensitive parameter '{param_name}' in URL",
                            description=(
                                f"The URL contains a '{param_name}' query parameter "
                                "with a value. Secrets in URLs are logged by proxies, "
                                "stored in browser history, and visible in Referer headers."
                            ),
                            url=url,
                            evidence=f"?{param_name}=<redacted>",
                            cwe_id="CWE-598",
                            remediation=(
                                f"Move the '{param_name}' parameter from the URL to "
                                "a request header (e.g. Authorization) or POST body."
                            ),
                        )
                    )

        return findings

    def _check_session_in_url(self, url: str) -> list[PassiveFinding]:
        """Check for session IDs in URL query parameters."""
        findings: list[PassiveFinding] = []

        parsed = urlparse(url)
        if not parsed.query:
            return findings

        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            if param_name.lower() in _SESSION_PARAM_NAMES:
                values = params[param_name]
                if any(v.strip() for v in values):
                    findings.append(
                        PassiveFinding(
                            check_name="session_id_in_url",
                            severity=FindingSeverity.HIGH,
                            title=f"Session ID '{param_name}' in URL",
                            description=(
                                f"The URL contains a session identifier '{param_name}'. "
                                "Session IDs in URLs can be leaked through Referer headers, "
                                "browser history, and server logs, enabling session fixation "
                                "and hijacking attacks."
                            ),
                            url=url,
                            evidence=f"?{param_name}=<redacted>",
                            cwe_id="CWE-598",
                            remediation=(
                                "Use cookies with HttpOnly and Secure flags to manage "
                                "session IDs instead of URL parameters."
                            ),
                        )
                    )

        return findings

    def _check_credentials_in_url(self, url: str) -> list[PassiveFinding]:
        """Check for user:password credentials in URL authority."""
        findings: list[PassiveFinding] = []

        match = _CREDENTIALS_IN_URL.search(url)
        if match:
            findings.append(
                PassiveFinding(
                    check_name="credentials_in_url",
                    severity=FindingSeverity.CRITICAL,
                    title="Credentials embedded in URL",
                    description=(
                        "The URL contains embedded credentials in the format user:password@host. "
                        "These credentials are visible in logs, browser history, Referer headers, "
                        "and network monitoring tools."
                    ),
                    url=url,
                    evidence="<user>:<password>@<host> pattern detected",
                    cwe_id="CWE-598",
                    remediation=(
                        "Remove credentials from URLs. Use HTTP authentication headers "
                        "or secure session management instead."
                    ),
                )
            )

        return findings
