"""Passive check for CORS misconfiguration.

Analyzes Access-Control-Allow-Origin and related headers to detect
overly permissive or dangerous CORS policies.
"""

from src.infra.decorators import logged
from src.infra.logging import get_logger
from src.passive.checks.base import PassiveCheck
from src.passive.models import FindingSeverity, PassiveFinding

logger = get_logger(__name__)


class CorsCheck(PassiveCheck):
    """Detect CORS misconfigurations in response headers."""

    name = "cors_check"
    description = "Checks Access-Control-Allow-Origin and related CORS headers."

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

        acao = lower_headers.get("access-control-allow-origin", "")
        acac = lower_headers.get("access-control-allow-credentials", "")

        if not acao:
            return findings

        credentials_allowed = acac.lower() == "true"

        # Wildcard origin with credentials = critical
        if acao == "*" and credentials_allowed:
            findings.append(
                PassiveFinding(
                    check_name="cors_wildcard_credentials",
                    severity=FindingSeverity.CRITICAL,
                    title="CORS: wildcard origin with credentials allowed",
                    description=(
                        "Access-Control-Allow-Origin is set to '*' while "
                        "Access-Control-Allow-Credentials is 'true'. "
                        "This combination allows any website to make authenticated "
                        "cross-origin requests and read the responses, enabling "
                        "full account takeover via CSRF-like attacks."
                    ),
                    url=url,
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    remediation=(
                        "Never use Access-Control-Allow-Origin: * with "
                        "Access-Control-Allow-Credentials: true. "
                        "Whitelist specific trusted origins instead."
                    ),
                )
            )
            return findings  # Most critical, skip lesser findings

        # Wildcard origin (without credentials)
        if acao == "*":
            findings.append(
                PassiveFinding(
                    check_name="cors_wildcard_origin",
                    severity=FindingSeverity.MEDIUM,
                    title="CORS: wildcard Access-Control-Allow-Origin",
                    description=(
                        "Access-Control-Allow-Origin is set to '*'. "
                        "Any website can make cross-origin requests to this endpoint "
                        "and read the responses. This is acceptable for public APIs "
                        "but risky for endpoints that return user-specific data."
                    ),
                    url=url,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation=(
                        "If the endpoint returns user-specific data, restrict "
                        "Access-Control-Allow-Origin to trusted origins only."
                    ),
                )
            )

        # Null origin allowed
        if acao.lower() == "null":
            findings.append(
                PassiveFinding(
                    check_name="cors_null_origin",
                    severity=FindingSeverity.MEDIUM,
                    title="CORS: null origin allowed",
                    description=(
                        "Access-Control-Allow-Origin is set to 'null'. "
                        "The null origin is sent by sandboxed iframes, local files, "
                        "and redirects. Allowing it may enable attackers to bypass "
                        "CORS restrictions."
                    ),
                    url=url,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation=(
                        "Do not allow the 'null' origin. "
                        "Whitelist specific trusted origins instead."
                    ),
                )
            )

        # Origin reflection (ACAO matches a non-standard/arbitrary origin)
        # We detect this heuristically: if ACAO is not *, not null, and
        # looks like a full origin, it might be reflecting the request Origin.
        if (
            acao not in ("*", "null")
            and acao.startswith(("http://", "https://"))
            and credentials_allowed
        ):
            findings.append(
                PassiveFinding(
                    check_name="cors_origin_reflection",
                    severity=FindingSeverity.HIGH,
                    title="CORS: possible origin reflection with credentials",
                    description=(
                        f"Access-Control-Allow-Origin is set to '{acao}' with "
                        "credentials allowed. If the server reflects any requested "
                        "Origin header, an attacker's site can make authenticated "
                        "cross-origin requests and read responses."
                    ),
                    url=url,
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    remediation=(
                        "Validate the Origin header against a strict allowlist. "
                        "Never reflect arbitrary origins when credentials are allowed."
                    ),
                )
            )

        return findings
