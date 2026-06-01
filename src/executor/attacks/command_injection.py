"""Command injection attack handler.

Injects OS command payloads via parameter values and detects execution
through direct output analysis and time-based blind techniques.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlencode

import requests

from src.executor.base import AttackHandler
from src.infra.decorators import retry
from src.infra.logging import get_logger
from src.models import AttackVector, SingleAttackResult

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_COMMAND_OUTPUT_PATTERNS: list[re.Pattern] = [
    re.compile(r"uid=\d+\(\w+\)"),  # id command
    re.compile(r"root:.*:0:0:"),  # /etc/passwd leak via cat
    re.compile(r"Linux\s+\S+\s+\d+\.\d+"),  # uname output
    re.compile(r"Windows\s+(NT|IP)", re.IGNORECASE),
    re.compile(r"Directory of\s+[A-Z]:\\", re.IGNORECASE),  # dir output
    re.compile(r"total\s+\d+\s*\n.*drwx"),  # ls -la output
    re.compile(r"(Volume Serial Number|Volume in drive)"),  # Windows vol
]

_TIME_BASED_KEYWORDS = re.compile(r"(sleep|ping\s+-[cn])", re.IGNORECASE)

# Threshold in seconds: if the response takes longer than this with a
# time-based payload, we consider blind injection confirmed.
_BLIND_THRESHOLD_SECONDS = 3.0


class CommandInjectionHandler(AttackHandler):
    """Test for OS command injection vulnerabilities.

    Strategies:

    1. **Separator injection** -- Inject the payload (which contains OS
       command separators like ``;``, ``|``, ``&&``) into query parameters
       and form fields, then check the response for command output.
    2. **Time-based blind** -- If the payload contains ``sleep`` or
       ``ping``, measure the response time.  A delay exceeding 3 seconds
       indicates blind command execution.
    3. **Output-based** -- Scan the response for well-known OS command
       outputs (``uid=``, ``root:``, ``Linux``, ``Windows``, etc.).
    """

    attack_type = "command_injection"

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_command_output(body: str) -> tuple[bool, str]:
        """Check the response body for OS command output patterns."""
        for pat in _COMMAND_OUTPUT_PATTERNS:
            if pat.search(body):
                return True, "OS command output detected in response"
        return False, "No command output indicators found in response"

    @staticmethod
    def _is_time_based_payload(payload: str) -> bool:
        """Return True if the payload is designed for time-based detection."""
        return bool(_TIME_BASED_KEYWORDS.search(payload))

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    @retry(max_attempts=2, base_delay=0.5, exceptions=(requests.ConnectionError, requests.Timeout))
    def test(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Execute a command injection test against the target."""
        endpoint = vector.target_endpoint
        fields = vector.target_fields
        is_time_based = self._is_time_based_payload(payload)

        logger.debug(
            "[CMD_INJECTION] %s <- %s (time_based=%s)",
            endpoint,
            payload,
            is_time_based,
        )

        # --- Strategy 1: Inject payload into query parameters ---
        params = {f: payload for f in fields} if fields else {"cmd": payload}
        target_url = f"{endpoint}?{urlencode(params)}" if "?" not in endpoint else endpoint

        # If the endpoint already has a query string, append
        if "?" in endpoint and target_url == endpoint:
            target_url = f"{endpoint}&{urlencode(params)}"

        start_time = time.time()

        try:
            resp = self.session.get(target_url)
        except requests.RequestException as exc:
            logger.error("GET request failed for command injection: %s", exc)
            return self._make_result(
                vector,
                payload,
                status=0,
                snippet=str(exc),
                success=False,
                detection=f"Connection error: {exc}",
            )

        elapsed = time.time() - start_time

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
        snippet = body[:200]

        # --- Strategy 3: Output-based detection on GET response ---
        success, detection = self._detect_command_output(body)
        if success:
            logger.info("[CMD_INJECTION] SUCCESS (output) on %s | %s", endpoint, detection)
            return self._make_result(
                vector,
                payload,
                status=resp.status_code,
                snippet=snippet,
                success=True,
                detection=detection,
            )

        # --- Strategy 2: Time-based blind detection on GET ---
        if is_time_based and elapsed > _BLIND_THRESHOLD_SECONDS:
            detection = (
                f"Blind command injection confirmed: response took "
                f"{elapsed:.1f}s with time-based payload (threshold: "
                f"{_BLIND_THRESHOLD_SECONDS}s)"
            )
            logger.info("[CMD_INJECTION] SUCCESS (blind/GET) on %s | %s", endpoint, detection)
            return self._make_result(
                vector,
                payload,
                status=resp.status_code,
                snippet=snippet,
                success=True,
                detection=detection,
            )

        # --- Also try POST with payload in form fields ---
        post_body = {f: payload for f in fields} if fields else {"input": payload}

        start_time_post = time.time()

        try:
            resp_post = self.session.post(endpoint, json=post_body)
        except requests.RequestException as exc:
            logger.debug("POST request failed for command injection: %s", exc)
            resp_post = None

        elapsed_post = time.time() - start_time_post

        if resp_post is not None:
            post_text = resp_post.text

            # Output-based on POST
            success_post, detection_post = self._detect_command_output(post_text)
            if success_post:
                logger.info(
                    "[CMD_INJECTION] SUCCESS (output/POST) on %s | %s",
                    endpoint,
                    detection_post,
                )
                return self._make_result(
                    vector,
                    payload,
                    status=resp_post.status_code,
                    snippet=post_text[:200],
                    success=True,
                    detection=detection_post,
                )

            # Time-based blind on POST
            if is_time_based and elapsed_post > _BLIND_THRESHOLD_SECONDS:
                detection = (
                    f"Blind command injection confirmed: POST response took "
                    f"{elapsed_post:.1f}s with time-based payload (threshold: "
                    f"{_BLIND_THRESHOLD_SECONDS}s)"
                )
                logger.info(
                    "[CMD_INJECTION] SUCCESS (blind/POST) on %s | %s",
                    endpoint,
                    detection,
                )
                return self._make_result(
                    vector,
                    payload,
                    status=resp_post.status_code,
                    snippet=post_text[:200],
                    success=True,
                    detection=detection,
                )

            # Check if error reveals command execution context
            if resp_post.status_code >= 500:
                err_patterns = re.compile(
                    r"(sh:|bash:|cmd\.exe|/bin/|command not found|"
                    r"is not recognized as an internal)",
                    re.IGNORECASE,
                )
                if err_patterns.search(post_text):
                    detection = "Error message reveals command execution context"
                    logger.info(
                        "[CMD_INJECTION] PARTIAL on %s | %s",
                        endpoint,
                        detection,
                    )
                    return self._make_result(
                        vector,
                        payload,
                        status=resp_post.status_code,
                        snippet=post_text[:200],
                        success=False,
                        detection=detection,
                    )

        # --- No injection detected ---
        logger.debug("[CMD_INJECTION] FAIL on %s", endpoint)
        return self._make_result(
            vector,
            payload,
            status=resp.status_code,
            snippet=snippet,
            success=False,
            detection="No command injection indicators found",
        )
