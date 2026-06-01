"""Information disclosure attack handler.

Probes the target for leaked server metadata, verbose error pages,
exposed sensitive data, and directory listings.
"""

from __future__ import annotations

import re

import requests

from src.executor.base import AttackHandler
from src.infra.decorators import retry
from src.infra.logging import get_logger
from src.models import AttackVector, SingleAttackResult

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_VERSION_HEADER_KEYS = ("Server", "X-Powered-By", "X-Debug", "X-AspNet-Version")

_STACK_TRACE_PATTERNS: list[re.Pattern] = [
    re.compile(r"Traceback \(most recent call", re.IGNORECASE),
    re.compile(r"at [\w.]+\([\w.]+:\d+\)"),  # Java / C#
    re.compile(r"File \"[^\"]+\", line \d+"),  # Python
    re.compile(r"(Fatal error|Warning):.*in .+on line \d+"),  # PHP
    re.compile(r"Exception in thread"),  # Java
]

_SENSITIVE_KEYWORDS = re.compile(
    r"(password|secret|token|api[_-]?key|private[_-]?key|credentials|"
    r"aws[_-]?access|database[_-]?url|db[_-]?password)",
    re.IGNORECASE,
)

_DIRECTORY_LISTING_PATTERNS: list[re.Pattern] = [
    re.compile(r"<title>\s*Index of\s*/", re.IGNORECASE),
    re.compile(r"Directory listing for", re.IGNORECASE),
    re.compile(r"<h1>Directory Listing", re.IGNORECASE),
    re.compile(r"Parent Directory</a>", re.IGNORECASE),
]


class InfoDisclosureHandler(AttackHandler):
    """Test for information disclosure vulnerabilities.

    Strategies:

    1. **Header analysis** -- Inspect response headers for server
       version strings and debug flags.
    2. **Error probing** -- Send a malformed request to trigger error
       pages with stack traces or internal paths.
    3. **Sensitive endpoint access** -- GET the target endpoint and
       scan for config data, environment variables, API keys, and
       tokens.
    4. **Directory listing** -- Check if the response contains HTML
       patterns typical of auto-generated directory indexes.
    """

    attack_type = "info_disclosure"

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_version_headers(headers: dict) -> str | None:
        """Return a detection string if version info leaks via headers."""
        leaked: list[str] = []
        for key in _VERSION_HEADER_KEYS:
            value = headers.get(key)
            if value:
                leaked.append(f"{key}: {value}")
        if leaked:
            return f"Server version leak via headers: {'; '.join(leaked)}"
        return None

    @staticmethod
    def _check_stack_trace(body: str) -> str | None:
        """Return a detection string if a stack trace is found."""
        for pat in _STACK_TRACE_PATTERNS:
            if pat.search(body):
                return "Error page reveals stack trace or internal file paths"
        return None

    @staticmethod
    def _check_sensitive_data(body: str) -> str | None:
        """Return a detection string if sensitive keywords appear."""
        matches = _SENSITIVE_KEYWORDS.findall(body)
        if matches:
            unique = sorted(set(m.lower() for m in matches))
            return f"Response contains sensitive keywords: {', '.join(unique[:5])}"
        return None

    @staticmethod
    def _check_directory_listing(body: str) -> str | None:
        """Return a detection string if a directory listing is detected."""
        for pat in _DIRECTORY_LISTING_PATTERNS:
            if pat.search(body):
                return "Directory listing detected in response"
        return None

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    @retry(max_attempts=2, base_delay=0.5, exceptions=(requests.ConnectionError, requests.Timeout))
    def test(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Execute information disclosure tests against the target."""
        endpoint = vector.target_endpoint
        logger.debug("[INFO_DISCLOSURE] %s <- %s", endpoint, payload)

        # --- Strategy 1 & 3: GET target endpoint, analyse headers + body ---
        try:
            resp = self.session.get(endpoint)
        except requests.RequestException as exc:
            logger.error("Request failed for info disclosure: %s", exc)
            return self._make_result(
                vector,
                payload,
                status=0,
                snippet=str(exc),
                success=False,
                detection=f"Connection error: {exc}",
            )

        if resp is None:
            return self._make_result(
                vector,
                payload,
                status=0,
                snippet="No response received",
                success=False,
                detection="Connection error: no response from target",
            )

        body = resp.text
        headers = dict(resp.headers)

        # Header version leak
        header_detection = self._check_version_headers(headers)
        if header_detection:
            logger.info(
                "[INFO_DISCLOSURE] SUCCESS (headers) on %s | %s", endpoint, header_detection
            )
            return self._make_result(
                vector,
                payload,
                status=resp.status_code,
                snippet=body[:200],
                success=True,
                detection=header_detection,
            )

        # Sensitive data in body
        sensitive_detection = self._check_sensitive_data(body)
        if sensitive_detection:
            logger.info(
                "[INFO_DISCLOSURE] SUCCESS (sensitive data) on %s | %s",
                endpoint,
                sensitive_detection,
            )
            return self._make_result(
                vector,
                payload,
                status=resp.status_code,
                snippet=body[:200],
                success=True,
                detection=sensitive_detection,
            )

        # Directory listing
        dir_detection = self._check_directory_listing(body)
        if dir_detection:
            logger.info(
                "[INFO_DISCLOSURE] SUCCESS (directory listing) on %s | %s",
                endpoint,
                dir_detection,
            )
            return self._make_result(
                vector,
                payload,
                status=resp.status_code,
                snippet=body[:200],
                success=True,
                detection=dir_detection,
            )

        # --- Strategy 2: Error probing with malformed request ---
        malformed_paths = [
            f"{endpoint}/{payload}",
            f"{endpoint}/%00",
            f"{endpoint}/'",
        ]

        for mal_path in malformed_paths:
            try:
                resp_err = self.session.get(mal_path)
            except requests.RequestException:
                continue

            if resp_err is None:
                continue

            err_body = resp_err.text

            # Stack trace in error page
            trace_detection = self._check_stack_trace(err_body)
            if trace_detection:
                logger.info(
                    "[INFO_DISCLOSURE] SUCCESS (error probe) on %s | %s",
                    mal_path,
                    trace_detection,
                )
                return self._make_result(
                    vector,
                    payload,
                    status=resp_err.status_code,
                    snippet=err_body[:200],
                    success=True,
                    detection=trace_detection,
                )

            # Sensitive data in error page
            err_sensitive = self._check_sensitive_data(err_body)
            if err_sensitive:
                logger.info(
                    "[INFO_DISCLOSURE] SUCCESS (error probe) on %s | %s",
                    mal_path,
                    err_sensitive,
                )
                return self._make_result(
                    vector,
                    payload,
                    status=resp_err.status_code,
                    snippet=err_body[:200],
                    success=True,
                    detection=err_sensitive,
                )

        # --- No disclosure detected ---
        logger.debug("[INFO_DISCLOSURE] FAIL on %s", endpoint)
        return self._make_result(
            vector,
            payload,
            status=resp.status_code,
            snippet=body[:200],
            success=False,
            detection="No information disclosure detected",
        )
