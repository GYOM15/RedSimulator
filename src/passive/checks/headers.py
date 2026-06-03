"""Passive check for missing or misconfigured security headers.

Verifies the presence of standard security headers and detects
information leakage through Server, X-Powered-By, and similar headers.
"""

import re

from src.infra.decorators import logged
from src.infra.logging import get_logger
from src.passive.checks.base import PassiveCheck
from src.passive.models import FindingSeverity, PassiveFinding

logger = get_logger(__name__)


class HeaderCheck(PassiveCheck):
    """Analyze HTTP response headers for security issues."""

    name = "header_check"
    description = "Checks for missing or misconfigured security headers."

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
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # --- Missing security headers ---

        if "strict-transport-security" not in lower_headers:
            findings.append(
                PassiveFinding(
                    check_name="missing_hsts",
                    severity=FindingSeverity.MEDIUM,
                    title="Missing Strict-Transport-Security (HSTS)",
                    description=(
                        "The response does not include a Strict-Transport-Security header. "
                        "Without HSTS, browsers may connect over unencrypted HTTP, exposing "
                        "users to man-in-the-middle attacks."
                    ),
                    url=url,
                    cwe_id="CWE-523",
                    remediation=(
                        "Add the header: Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload"
                    ),
                )
            )

        if "content-security-policy" not in lower_headers:
            findings.append(
                PassiveFinding(
                    check_name="missing_csp",
                    severity=FindingSeverity.MEDIUM,
                    title="Missing Content-Security-Policy (CSP)",
                    description=(
                        "The response does not include a Content-Security-Policy header. "
                        "Without CSP, the application is more vulnerable to XSS and "
                        "data injection attacks."
                    ),
                    url=url,
                    cwe_id="CWE-1021",
                    remediation=(
                        "Add a Content-Security-Policy header with a restrictive policy. "
                        "Start with: Content-Security-Policy: default-src 'self'"
                    ),
                )
            )

        if "x-content-type-options" not in lower_headers:
            findings.append(
                PassiveFinding(
                    check_name="missing_xcto",
                    severity=FindingSeverity.LOW,
                    title="Missing X-Content-Type-Options",
                    description=(
                        "The response does not include X-Content-Type-Options: nosniff. "
                        "Browsers may MIME-sniff the response, potentially treating "
                        "non-executable content as executable."
                    ),
                    url=url,
                    cwe_id="CWE-16",
                    remediation="Add the header: X-Content-Type-Options: nosniff",
                )
            )

        if "x-frame-options" not in lower_headers:
            findings.append(
                PassiveFinding(
                    check_name="missing_xfo",
                    severity=FindingSeverity.MEDIUM,
                    title="Missing X-Frame-Options",
                    description=(
                        "The response does not include X-Frame-Options. "
                        "The page may be embedded in an iframe, enabling clickjacking attacks."
                    ),
                    url=url,
                    cwe_id="CWE-1021",
                    remediation="Add the header: X-Frame-Options: DENY (or SAMEORIGIN)",
                )
            )

        if "referrer-policy" not in lower_headers:
            findings.append(
                PassiveFinding(
                    check_name="missing_referrer_policy",
                    severity=FindingSeverity.LOW,
                    title="Missing Referrer-Policy",
                    description=(
                        "The response does not include a Referrer-Policy header. "
                        "The browser may leak the full URL in the Referer header "
                        "when navigating to external sites."
                    ),
                    url=url,
                    remediation=(
                        "Add the header: Referrer-Policy: strict-origin-when-cross-origin"
                    ),
                )
            )

        if "permissions-policy" not in lower_headers:
            findings.append(
                PassiveFinding(
                    check_name="missing_permissions_policy",
                    severity=FindingSeverity.LOW,
                    title="Missing Permissions-Policy",
                    description=(
                        "The response does not include a Permissions-Policy header. "
                        "Browser features like camera, microphone, and geolocation "
                        "are not explicitly restricted."
                    ),
                    url=url,
                    remediation=(
                        "Add the header: Permissions-Policy: camera=(), microphone=(), "
                        "geolocation=()"
                    ),
                )
            )

        # --- Information leakage via headers ---

        server = lower_headers.get("server", "")
        if server and re.search(r"[\d.]", server):
            findings.append(
                PassiveFinding(
                    check_name="server_version_leak",
                    severity=FindingSeverity.LOW,
                    title="Server header reveals version information",
                    description=(
                        f"The Server header exposes version details: '{server}'. "
                        "This helps attackers identify known vulnerabilities for "
                        "this specific software version."
                    ),
                    url=url,
                    evidence=f"Server: {server}",
                    cwe_id="CWE-200",
                    remediation=(
                        "Remove or genericize the Server header. "
                        "Avoid exposing software names and version numbers."
                    ),
                )
            )

        powered_by = lower_headers.get("x-powered-by", "")
        if powered_by:
            findings.append(
                PassiveFinding(
                    check_name="x_powered_by_leak",
                    severity=FindingSeverity.LOW,
                    title="X-Powered-By header present",
                    description=(
                        f"The X-Powered-By header reveals technology details: '{powered_by}'. "
                        "This aids attackers in fingerprinting the application stack."
                    ),
                    url=url,
                    evidence=f"X-Powered-By: {powered_by}",
                    cwe_id="CWE-200",
                    remediation="Remove the X-Powered-By header entirely.",
                )
            )

        aspnet_version = lower_headers.get("x-aspnet-version", "")
        if aspnet_version:
            findings.append(
                PassiveFinding(
                    check_name="aspnet_version_leak",
                    severity=FindingSeverity.LOW,
                    title="X-AspNet-Version header present",
                    description=(
                        f"The X-AspNet-Version header reveals: '{aspnet_version}'. "
                        "This exposes the exact ASP.NET runtime version."
                    ),
                    url=url,
                    evidence=f"X-AspNet-Version: {aspnet_version}",
                    cwe_id="CWE-200",
                    remediation=(
                        "Remove the X-AspNet-Version header. In web.config: "
                        '<httpRuntime enableVersionHeader="false" />'
                    ),
                )
            )

        aspnetmvc_version = lower_headers.get("x-aspnetmvc-version", "")
        if aspnetmvc_version:
            findings.append(
                PassiveFinding(
                    check_name="aspnetmvc_version_leak",
                    severity=FindingSeverity.LOW,
                    title="X-AspNetMvc-Version header present",
                    description=(
                        f"The X-AspNetMvc-Version header reveals: '{aspnetmvc_version}'. "
                        "This exposes the exact ASP.NET MVC version."
                    ),
                    url=url,
                    evidence=f"X-AspNetMvc-Version: {aspnetmvc_version}",
                    cwe_id="CWE-200",
                    remediation=(
                        "Remove the X-AspNetMvc-Version header. "
                        "In Global.asax: MvcHandler.DisableMvcResponseHeader = true"
                    ),
                )
            )

        return findings
