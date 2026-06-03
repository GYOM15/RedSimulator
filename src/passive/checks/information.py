"""Passive check for information leakage in response bodies.

Scans response content for stack traces, internal IPs, email addresses,
file paths, API keys, SQL errors, and debug mode indicators.
"""

import re

from src.infra.decorators import logged
from src.infra.logging import get_logger
from src.passive.checks.base import PassiveCheck
from src.passive.models import FindingSeverity, PassiveFinding

logger = get_logger(__name__)

# --- Compiled regex patterns ---

# Stack trace patterns for common languages
_STACK_TRACE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE), "Python"),
    (re.compile(r"at\s+[\w$.]+\([\w]+\.java:\d+\)"), "Java"),
    (re.compile(r"at\s+[\w$.]+\s+\([\w/\\]+\.(?:js|ts):\d+:\d+\)"), "Node.js"),
    (re.compile(r"(?:Fatal error|Warning|Notice):.*in\s+/[\w/]+\.php\s+on line\s+\d+"), "PHP"),
    (
        re.compile(
            r"(?:System\.(?:NullReferenceException|ArgumentException|InvalidOperationException)"
            r"|at\s+[\w.]+\s+in\s+[\w:\\/.]+\.cs:line\s+\d+)"
        ),
        ".NET",
    ),
]

# Internal/private IP address pattern
_INTERNAL_IP_PATTERN = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r")\b"
)

# Email address pattern
_EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

# File path patterns
_FILE_PATH_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:/home/|/var/|/usr/|/etc/|/opt/|/tmp/)[\w/.+-]+"), "Unix"),
    (re.compile(r"[A-Z]:\\(?:Users|Windows|Program Files|inetpub)\\[\w\\.+-]+"), "Windows"),
]

# API key / token patterns
_API_KEY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bsk-[a-zA-Z0-9]{20,}"), "OpenAI API key (sk-)"),
    (re.compile(r"\bAKIA[A-Z0-9]{16}"), "AWS Access Key (AKIA)"),
    (re.compile(r"\bghp_[a-zA-Z0-9]{36}"), "GitHub personal access token (ghp_)"),
    (re.compile(r"Bearer\s+[a-zA-Z0-9._~+/=-]{20,}"), "Bearer token"),
]

# SQL error messages
_SQL_ERROR_PATTERNS: list[re.Pattern] = [
    re.compile(
        r"(?:SQL syntax|mysql_|ORA-\d{5}|PG::Error|sqlite3\.OperationalError"
        r"|SQLSTATE\[|Unclosed quotation mark|syntax error at or near)",
        re.IGNORECASE,
    ),
    re.compile(r"(?:You have an error in your SQL syntax)", re.IGNORECASE),
]

# Debug mode indicators
_DEBUG_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bDEBUG\s*=\s*True\b", re.IGNORECASE), "DEBUG=True"),
    (re.compile(r"\bFLASK_DEBUG\s*=\s*[\"']?1[\"']?", re.IGNORECASE), "FLASK_DEBUG=1"),
    (re.compile(r"\bAPP_DEBUG\s*=\s*[\"']?true[\"']?", re.IGNORECASE), "APP_DEBUG=true"),
    (re.compile(r"\bDjango\s+Debug\s+Toolbar", re.IGNORECASE), "Django Debug Toolbar"),
    (re.compile(r"\bLaravel.*debug\s+mode\s+is\s+enabled", re.IGNORECASE), "Laravel debug mode"),
]


class InformationCheck(PassiveCheck):
    """Detect information leakage in HTTP response bodies."""

    name = "information_check"
    description = "Scans response bodies for stack traces, IPs, keys, and debug indicators."

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

        if not body:
            return findings

        # Limit analysis to first 10 KB to avoid performance issues
        content = body[:10240]

        findings.extend(self._check_stack_traces(url, content))
        findings.extend(self._check_internal_ips(url, content))
        findings.extend(self._check_emails(url, content))
        findings.extend(self._check_file_paths(url, content))
        findings.extend(self._check_api_keys(url, content))
        findings.extend(self._check_sql_errors(url, content))
        findings.extend(self._check_debug_mode(url, content))

        return findings

    def _check_stack_traces(self, url: str, content: str) -> list[PassiveFinding]:
        findings: list[PassiveFinding] = []
        for pattern, language in _STACK_TRACE_PATTERNS:
            match = pattern.search(content)
            if match:
                findings.append(
                    PassiveFinding(
                        check_name="stack_trace_leak",
                        severity=FindingSeverity.HIGH,
                        title=f"{language} stack trace in response",
                        description=(
                            f"A {language} stack trace was found in the response body. "
                            "Stack traces reveal internal implementation details, file paths, "
                            "and library versions to potential attackers."
                        ),
                        url=url,
                        evidence=match.group(0)[:200],
                        cwe_id="CWE-209",
                        remediation=(
                            "Disable detailed error messages in production. "
                            "Use a custom error handler that returns generic messages."
                        ),
                    )
                )
        return findings

    def _check_internal_ips(self, url: str, content: str) -> list[PassiveFinding]:
        findings: list[PassiveFinding] = []
        matches = _INTERNAL_IP_PATTERN.findall(content)
        if matches:
            unique_ips = sorted(set(matches))
            findings.append(
                PassiveFinding(
                    check_name="internal_ip_leak",
                    severity=FindingSeverity.MEDIUM,
                    title="Internal IP address(es) in response",
                    description=(
                        f"Found {len(unique_ips)} internal IP address(es) in the response body. "
                        "This reveals internal network topology to attackers."
                    ),
                    url=url,
                    evidence=", ".join(unique_ips[:5]),
                    cwe_id="CWE-200",
                    remediation=(
                        "Remove internal IP addresses from responses. "
                        "Use reverse proxies to mask backend infrastructure."
                    ),
                )
            )
        return findings

    def _check_emails(self, url: str, content: str) -> list[PassiveFinding]:
        findings: list[PassiveFinding] = []
        matches = _EMAIL_PATTERN.findall(content)
        # Filter out common false positives
        real_emails = [
            e for e in matches if not e.endswith((".example.com", ".test", ".invalid")) and "@" in e
        ]
        if real_emails:
            unique_emails = sorted(set(real_emails))
            findings.append(
                PassiveFinding(
                    check_name="email_leak",
                    severity=FindingSeverity.LOW,
                    title="Email address(es) in response",
                    description=(
                        f"Found {len(unique_emails)} email address(es) in the response body. "
                        "These can be used for phishing or social engineering attacks."
                    ),
                    url=url,
                    evidence=", ".join(unique_emails[:5]),
                    remediation=(
                        "Avoid exposing email addresses in public-facing pages. "
                        "Use contact forms instead of displaying email addresses."
                    ),
                )
            )
        return findings

    def _check_file_paths(self, url: str, content: str) -> list[PassiveFinding]:
        findings: list[PassiveFinding] = []
        for pattern, os_type in _FILE_PATH_PATTERNS:
            matches = pattern.findall(content)
            if matches:
                unique_paths = sorted(set(matches))
                findings.append(
                    PassiveFinding(
                        check_name="file_path_leak",
                        severity=FindingSeverity.MEDIUM,
                        title=f"{os_type} file path(s) in response",
                        description=(
                            f"Found {len(unique_paths)} {os_type} file path(s) "
                            "in the response body. This reveals the server's filesystem "
                            "structure to attackers."
                        ),
                        url=url,
                        evidence=", ".join(unique_paths[:3]),
                        cwe_id="CWE-200",
                        remediation=(
                            "Remove absolute file paths from responses. "
                            "Use generic error messages in production."
                        ),
                    )
                )
        return findings

    def _check_api_keys(self, url: str, content: str) -> list[PassiveFinding]:
        findings: list[PassiveFinding] = []
        for pattern, key_type in _API_KEY_PATTERNS:
            match = pattern.search(content)
            if match:
                # Redact the key in the evidence (show first 8 chars only)
                raw = match.group(0)
                redacted = raw[:8] + "..." if len(raw) > 8 else raw
                findings.append(
                    PassiveFinding(
                        check_name="api_key_leak",
                        severity=FindingSeverity.CRITICAL,
                        title=f"Potential {key_type} exposed in response",
                        description=(
                            f"A pattern matching a {key_type} was detected "
                            "in the response body. Exposed API keys allow unauthorized "
                            "access to external services."
                        ),
                        url=url,
                        evidence=redacted,
                        cwe_id="CWE-200",
                        remediation=(
                            "Immediately rotate the exposed key. "
                            "Never embed secrets in HTML/JS — use server-side "
                            "environment variables and backend proxying."
                        ),
                    )
                )
        return findings

    def _check_sql_errors(self, url: str, content: str) -> list[PassiveFinding]:
        findings: list[PassiveFinding] = []
        for pattern in _SQL_ERROR_PATTERNS:
            match = pattern.search(content)
            if match:
                findings.append(
                    PassiveFinding(
                        check_name="sql_error_leak",
                        severity=FindingSeverity.HIGH,
                        title="SQL error message in response",
                        description=(
                            "An SQL error message was found in the response body. "
                            "This reveals the database engine and query structure, "
                            "making SQL injection attacks easier to craft."
                        ),
                        url=url,
                        evidence=match.group(0)[:200],
                        cwe_id="CWE-209",
                        remediation=(
                            "Disable detailed database error messages in production. "
                            "Log errors server-side and return generic error pages to users."
                        ),
                    )
                )
                break  # One SQL error finding is enough
        return findings

    def _check_debug_mode(self, url: str, content: str) -> list[PassiveFinding]:
        findings: list[PassiveFinding] = []
        for pattern, indicator in _DEBUG_PATTERNS:
            match = pattern.search(content)
            if match:
                findings.append(
                    PassiveFinding(
                        check_name="debug_mode_enabled",
                        severity=FindingSeverity.HIGH,
                        title=f"Debug mode indicator: {indicator}",
                        description=(
                            f"The response contains a debug mode indicator ({indicator}). "
                            "Debug mode exposes detailed error pages, stack traces, "
                            "and internal application state to anyone."
                        ),
                        url=url,
                        evidence=match.group(0),
                        remediation=(
                            "Disable debug mode in production. "
                            "Ensure environment configuration sets DEBUG=False "
                            "and equivalent flags for your framework."
                        ),
                    )
                )
        return findings
