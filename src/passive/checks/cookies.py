"""Passive check for cookie security issues.

Analyzes Set-Cookie headers for missing security flags
(Secure, HttpOnly, SameSite) and other misconfigurations.
"""

from src.infra.decorators import logged
from src.infra.logging import get_logger
from src.passive.checks.base import PassiveCheck
from src.passive.models import FindingSeverity, PassiveFinding

logger = get_logger(__name__)

# Cookie names that typically carry session identifiers.
_SESSION_COOKIE_NAMES = frozenset(
    {
        "sessionid",
        "session_id",
        "sid",
        "jsessionid",
        "phpsessid",
        "aspsessionid",
        "asp.net_sessionid",
        "connect.sid",
        "token",
        "auth_token",
        "access_token",
    }
)


class CookieCheck(PassiveCheck):
    """Analyze cookies for missing security attributes."""

    name = "cookie_check"
    description = "Checks cookies for missing Secure, HttpOnly, and SameSite flags."

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

        if not cookies:
            return findings

        for cookie in cookies:
            name = cookie.get("name", "unknown")
            raw = cookie.get("raw", "")
            secure = cookie.get("secure", False)
            httponly = cookie.get("httponly", False)
            samesite = cookie.get("samesite", "")
            is_session = name.lower() in _SESSION_COOKIE_NAMES

            # Missing Secure flag
            if not secure:
                findings.append(
                    PassiveFinding(
                        check_name="insecure_cookie",
                        severity=FindingSeverity.MEDIUM,
                        title=f"Cookie '{name}' missing Secure flag",
                        description=(
                            f"The cookie '{name}' does not have the Secure flag set. "
                            "It may be transmitted over unencrypted HTTP connections."
                        ),
                        url=url,
                        evidence=raw or f"Cookie: {name}",
                        cwe_id="CWE-614",
                        remediation=f"Set the Secure flag on cookie '{name}'.",
                    )
                )

            # Missing HttpOnly flag
            if not httponly:
                severity = FindingSeverity.HIGH if is_session else FindingSeverity.MEDIUM
                title_suffix = " (session cookie — hijacking risk)" if is_session else ""
                findings.append(
                    PassiveFinding(
                        check_name="cookie_no_httponly",
                        severity=severity,
                        title=f"Cookie '{name}' missing HttpOnly flag{title_suffix}",
                        description=(
                            f"The cookie '{name}' does not have the HttpOnly flag. "
                            "Client-side JavaScript can read this cookie, enabling "
                            "theft via XSS attacks."
                        ),
                        url=url,
                        evidence=raw or f"Cookie: {name}",
                        cwe_id="CWE-1004",
                        remediation=f"Set the HttpOnly flag on cookie '{name}'.",
                    )
                )

            # Missing SameSite attribute
            if not samesite:
                findings.append(
                    PassiveFinding(
                        check_name="cookie_no_samesite",
                        severity=FindingSeverity.LOW,
                        title=f"Cookie '{name}' missing SameSite attribute",
                        description=(
                            f"The cookie '{name}' does not specify a SameSite attribute. "
                            "Browsers default to Lax, but explicit configuration is "
                            "recommended for CSRF protection."
                        ),
                        url=url,
                        evidence=raw or f"Cookie: {name}",
                        cwe_id="CWE-352",
                        remediation=(f"Set SameSite=Strict or SameSite=Lax on cookie '{name}'."),
                    )
                )

            # SameSite=None without Secure
            if samesite.lower() == "none" and not secure:
                findings.append(
                    PassiveFinding(
                        check_name="samesite_none_no_secure",
                        severity=FindingSeverity.HIGH,
                        title=f"Cookie '{name}' has SameSite=None without Secure",
                        description=(
                            f"The cookie '{name}' sets SameSite=None but lacks the "
                            "Secure flag. Modern browsers will reject this cookie. "
                            "Additionally, it is sent on all cross-site requests "
                            "without transport encryption."
                        ),
                        url=url,
                        evidence=raw or f"Cookie: {name}",
                        cwe_id="CWE-614",
                        remediation=(
                            f"Either add the Secure flag to cookie '{name}' "
                            "or change SameSite to Lax/Strict."
                        ),
                    )
                )

            # __Secure- prefix without Secure flag
            if name.startswith("__Secure-") and not secure:
                findings.append(
                    PassiveFinding(
                        check_name="secure_prefix_no_flag",
                        severity=FindingSeverity.MEDIUM,
                        title=f"Cookie '{name}' uses __Secure- prefix but lacks Secure flag",
                        description=(
                            f"The cookie '{name}' uses the __Secure- prefix, which "
                            "requires the Secure flag. Browsers will reject this cookie."
                        ),
                        url=url,
                        evidence=raw or f"Cookie: {name}",
                        remediation=f"Add the Secure flag to cookie '{name}'.",
                    )
                )

        return findings
