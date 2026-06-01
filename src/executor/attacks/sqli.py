"""SQL Injection attack handler.

Implements three detection strategies:
  1. **Error-based** -- look for SQL error messages in the response.
  2. **Auth bypass** -- check if an authentication token is returned
     without valid credentials.
  3. **UNION-based** -- when the payload contains ``UNION``, check if
     extra data appears in the response.
"""

from __future__ import annotations

import re

import requests

from src.executor.base import AttackHandler
from src.infra.decorators import retry
from src.infra.logging import get_logger
from src.models import AttackVector, SingleAttackResult

logger = get_logger(__name__)

# Patterns that indicate a SQL error was exposed in the response body.
_SQL_ERROR_PATTERNS: re.Pattern = re.compile(
    r"sqlite|mysql|syntax\s+error|sql\s+error|ORA-\d|pg_|Microsoft\s+SQL|"
    r"unclosed\s+quotation|quoted\s+string|SQLSTATE|unterminated",
    re.IGNORECASE,
)


class SqliHandler(AttackHandler):
    """SQL Injection handler with error-based, auth-bypass, and UNION detection."""

    attack_type = "sqli"

    @retry(max_attempts=2, base_delay=0.5, exceptions=(requests.ConnectionError, requests.Timeout))
    def test(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Test a SQL injection payload against the target endpoint.

        Args:
            vector: Attack vector describing the endpoint and fields.
            payload: SQL injection payload string.

        Returns:
            Result indicating whether the injection succeeded.
        """
        url = vector.target_endpoint
        logger.debug("[SQLI] %s%s <- %s", self.base_url, url, payload)

        # Build POST body: inject the payload into every target field.
        body: dict[str, str] = {field: payload for field in vector.target_fields}

        try:
            resp = self.session.post(url, json=body)

            # SessionManager returns None on network errors.
            if resp is None:
                return self._make_result(
                    vector,
                    payload,
                    status=0,
                    snippet="No response (connection error)",
                    success=False,
                    detection="Connection failed — no HTTP response received",
                )

            snippet = resp.text[:200]
            text_lower = resp.text.lower()

            # ------------------------------------------------------------------
            # Strategy 1: Auth bypass
            # A 200 response containing an authentication token means the
            # login was bypassed without valid credentials.
            # ------------------------------------------------------------------
            if resp.status_code == 200 and (
                "authentication" in text_lower or "token" in text_lower
            ):
                logger.debug("[SQLI] Auth bypass detected for payload: %s", payload)
                return self._make_result(
                    vector,
                    payload,
                    status=resp.status_code,
                    snippet=snippet,
                    success=True,
                    detection=(
                        "Auth bypass: authentication token returned without valid "
                        "credentials (HTTP 200 with 'authentication'/'token' in body)"
                    ),
                )

            # ------------------------------------------------------------------
            # Strategy 2: Error-based detection
            # SQL error messages leaked in the response indicate that user
            # input reaches the database layer without proper sanitisation.
            # ------------------------------------------------------------------
            error_match = _SQL_ERROR_PATTERNS.search(resp.text)
            if error_match:
                matched_text = error_match.group()
                # If the error message is accompanied by a non-error status,
                # it means the backend processed the injection and leaked info.
                is_success = "error" not in text_lower or resp.status_code == 200
                logger.debug("[SQLI] SQL error pattern found: %s", matched_text)
                return self._make_result(
                    vector,
                    payload,
                    status=resp.status_code,
                    snippet=snippet,
                    success=is_success,
                    detection=(
                        f"Error-based: SQL error pattern '{matched_text}' found "
                        f"in response (HTTP {resp.status_code})"
                    ),
                )

            # ------------------------------------------------------------------
            # Strategy 3: UNION-based detection
            # When the payload contains UNION, check if the response is larger
            # than typical error responses — extra data suggests the UNION
            # query returned additional rows.
            # ------------------------------------------------------------------
            if "union" in payload.lower() and resp.status_code == 200 and len(resp.text) > 100:
                logger.debug("[SQLI] UNION injection may have returned extra data")
                return self._make_result(
                    vector,
                    payload,
                    status=resp.status_code,
                    snippet=snippet,
                    success=True,
                    detection=(
                        "UNION-based: payload with UNION returned HTTP 200 "
                        f"with substantial body ({len(resp.text)} chars), "
                        "indicating extra data from injected query"
                    ),
                )

            # No injection detected.
            return self._make_result(
                vector,
                payload,
                status=resp.status_code,
                snippet=snippet,
                success=False,
                detection=(
                    f"No SQL injection detected (HTTP {resp.status_code}, "
                    f"no error patterns or auth tokens in response)"
                ),
            )

        except requests.RequestException as exc:
            logger.error("Request error during SQLi test: %s", exc)
            return self._make_result(
                vector,
                payload,
                status=0,
                snippet=str(exc)[:200],
                success=False,
                detection=f"Connection error: {exc}",
            )
