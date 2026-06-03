"""Passive check for transport security issues.

Detects mixed content, insecure form actions, and HTTPS-to-HTTP redirects
by analyzing response bodies and headers.
"""

import re

from src.infra.decorators import logged
from src.infra.logging import get_logger
from src.passive.checks.base import PassiveCheck
from src.passive.models import FindingSeverity, PassiveFinding

logger = get_logger(__name__)

# Pattern for HTTP resources embedded in the page
_MIXED_CONTENT_PATTERN = re.compile(
    r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']',
    re.IGNORECASE,
)

# Pattern for form elements posting to HTTP
_INSECURE_FORM_PATTERN = re.compile(
    r'<form[^>]*action\s*=\s*["\']http://[^"\']+["\']',
    re.IGNORECASE,
)


class TransportCheck(PassiveCheck):
    """Detect transport security issues (mixed content, insecure redirects)."""

    name = "transport_check"
    description = "Checks for mixed content, insecure form actions, and HTTPS-to-HTTP redirects."

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

        is_https = url.lower().startswith("https://")

        # Only relevant for HTTPS pages
        if is_https and body:
            findings.extend(self._check_mixed_content(url, body))
            findings.extend(self._check_insecure_forms(url, body))

        # Check redirect from HTTPS to HTTP
        findings.extend(self._check_insecure_redirect(url, status_code, headers))

        return findings

    def _check_mixed_content(self, url: str, body: str) -> list[PassiveFinding]:
        """Detect HTTP resources loaded from an HTTPS page."""
        findings: list[PassiveFinding] = []
        matches = _MIXED_CONTENT_PATTERN.findall(body)
        if matches:
            # Deduplicate and limit
            unique = sorted(set(matches))[:5]
            findings.append(
                PassiveFinding(
                    check_name="mixed_content",
                    severity=FindingSeverity.MEDIUM,
                    title="Mixed content: HTTP resources on HTTPS page",
                    description=(
                        f"Found {len(matches)} reference(s) to HTTP resources on an HTTPS page. "
                        "Mixed content degrades the security of the encrypted connection "
                        "and may be blocked by modern browsers."
                    ),
                    url=url,
                    evidence="; ".join(unique),
                    remediation=(
                        "Replace all http:// resource URLs with https:// or use "
                        "protocol-relative URLs (//). Set a CSP upgrade-insecure-requests directive."
                    ),
                )
            )
        return findings

    def _check_insecure_forms(self, url: str, body: str) -> list[PassiveFinding]:
        """Detect forms posting to HTTP from an HTTPS page."""
        findings: list[PassiveFinding] = []
        matches = _INSECURE_FORM_PATTERN.findall(body)
        if matches:
            unique = sorted(set(matches))[:3]
            findings.append(
                PassiveFinding(
                    check_name="insecure_form_action",
                    severity=FindingSeverity.HIGH,
                    title="Form submits to HTTP from HTTPS page",
                    description=(
                        f"Found {len(matches)} form(s) with an HTTP action URL on an HTTPS page. "
                        "Form data (potentially including credentials) will be sent "
                        "over an unencrypted connection."
                    ),
                    url=url,
                    evidence="; ".join(unique),
                    remediation=(
                        "Change all form action URLs to use https://. "
                        "Ensure form submissions are always encrypted."
                    ),
                )
            )
        return findings

    def _check_insecure_redirect(
        self, url: str, status_code: int, headers: dict
    ) -> list[PassiveFinding]:
        """Detect redirects from HTTPS to HTTP."""
        findings: list[PassiveFinding] = []

        if not url.lower().startswith("https://"):
            return findings

        if status_code not in (301, 302, 303, 307, 308):
            return findings

        location = headers.get("Location", "") or headers.get("location", "")
        if location.lower().startswith("http://"):
            findings.append(
                PassiveFinding(
                    check_name="https_to_http_redirect",
                    severity=FindingSeverity.HIGH,
                    title="HTTPS to HTTP redirect",
                    description=(
                        f"The HTTPS URL redirects to an HTTP location: {location}. "
                        "This downgrades the connection security, exposing "
                        "subsequent requests to interception."
                    ),
                    url=url,
                    evidence=f"Location: {location}",
                    remediation=(
                        "Ensure all redirects stay on HTTPS. "
                        "Configure the web server to redirect HTTP to HTTPS, not the reverse."
                    ),
                )
            )

        return findings
