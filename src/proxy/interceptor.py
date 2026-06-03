"""Mitmproxy addon that captures HTTP flows.

This addon is loaded into the mitmproxy instance and captures
every request/response pair, converting them to CapturedFlow
objects and storing them in the FlowStore.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from fnmatch import fnmatch
from urllib.parse import urlparse

# Conditional import -- mitmproxy may not be installed
try:
    from mitmproxy import http

    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False

from src.infra.logging import get_logger

from .models import CapturedFlow, ProxyConfig
from .store import FlowStore

logger = get_logger(__name__)


class RequestInterceptor:
    """Mitmproxy addon that captures flows into the FlowStore.

    Also supports an optional callback for real-time SSE streaming
    to the frontend.
    """

    def __init__(
        self,
        store: FlowStore,
        config: ProxyConfig,
        on_flow: Callable[[CapturedFlow], None] | None = None,
    ):
        self.store = store
        self.config = config
        self.on_flow = on_flow
        self._pending: dict[str, float] = {}  # flow_id -> start_time

    # ------------------------------------------------------------------
    # Mitmproxy event hooks
    # ------------------------------------------------------------------

    def request(self, flow: http.HTTPFlow) -> None:
        """Called when a request is received (before forwarding)."""
        # Generate flow ID and record start time
        flow_id = str(uuid.uuid4())[:8]
        flow.id = flow_id  # type: ignore[attr-defined]
        self._pending[flow_id] = time.time()

        # Check if URL matches exclude patterns -- if so, tag it to skip
        url = flow.request.url
        if not self._matches_patterns(url):
            flow.metadata["rs_skip"] = True  # type: ignore[union-attr]

    def response(self, flow: http.HTTPFlow) -> None:
        """Called when a response is received."""
        # Skip flows that don't match our patterns
        if getattr(flow, "metadata", None) and flow.metadata.get("rs_skip"):
            self._pending.pop(flow.id, None)
            return

        # Calculate duration
        start = self._pending.pop(flow.id, time.time())
        duration_ms = (time.time() - start) * 1000

        # Convert to CapturedFlow
        captured = self._flow_to_captured(flow, duration_ms)

        # Store
        self.store.add(captured)

        # Notify callback (for SSE)
        if self.on_flow:
            try:
                self.on_flow(captured)
            except Exception:
                logger.exception("on_flow callback failed")

        logger.debug(
            "Captured: %s %s -> %d (%.0fms)",
            flow.request.method,
            flow.request.url,
            flow.response.status_code,
            duration_ms,
        )

    def error(self, flow: http.HTTPFlow) -> None:
        """Called on connection errors."""
        self._pending.pop(getattr(flow, "id", ""), None)
        logger.warning(
            "Flow error: %s %s -> %s",
            flow.request.method,
            flow.request.url,
            flow.error.msg if flow.error else "unknown",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _flow_to_captured(self, flow: http.HTTPFlow, duration_ms: float) -> CapturedFlow:
        """Convert a mitmproxy flow to our CapturedFlow model."""
        parsed = urlparse(flow.request.url)
        max_body = self.config.max_body_size

        # Extract and truncate request body
        req_body = ""
        if flow.request.content:
            try:
                req_body = flow.request.content.decode("utf-8", errors="replace")
            except Exception:
                req_body = "<binary>"
            if len(req_body) > max_body:
                req_body = req_body[:max_body] + "... [truncated]"

        # Extract and truncate response body
        resp_body = ""
        if flow.response and flow.response.content:
            try:
                resp_body = flow.response.content.decode("utf-8", errors="replace")
            except Exception:
                resp_body = "<binary>"
            if len(resp_body) > max_body:
                resp_body = resp_body[:max_body] + "... [truncated]"

        # Convert headers to dict (mitmproxy headers are multi-valued)
        req_headers = {k: v for k, v in flow.request.headers.items(multi=False)}
        resp_headers = {}
        resp_status = 0
        resp_content_type = ""
        if flow.response:
            resp_headers = {k: v for k, v in flow.response.headers.items(multi=False)}
            resp_status = flow.response.status_code
            resp_content_type = flow.response.headers.get("content-type", "")

        return CapturedFlow(
            id=flow.id,
            timestamp=datetime.now(UTC).isoformat(),
            request_method=flow.request.method,
            request_url=flow.request.url,
            request_host=parsed.hostname or "",
            request_path=parsed.path or "/",
            request_headers=req_headers,
            request_body=req_body,
            response_status=resp_status,
            response_headers=resp_headers,
            response_body=resp_body,
            response_content_type=resp_content_type,
            duration_ms=round(duration_ms, 2),
        )

    def _matches_patterns(self, url: str) -> bool:
        """Check if URL should be captured based on intercept/exclude patterns.

        Returns True if the URL should be captured, False otherwise.

        Logic:
        - If exclude_patterns match, the URL is skipped.
        - If intercept_patterns is non-empty, the URL must match at least one.
        - If intercept_patterns is empty, all non-excluded URLs are captured.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Check exclude patterns first
        for pattern in self.config.exclude_patterns:
            if fnmatch(hostname, pattern) or fnmatch(url, pattern):
                return False

        # If no intercept patterns, capture everything not excluded
        if not self.config.intercept_patterns:
            return True

        # Must match at least one intercept pattern
        for pattern in self.config.intercept_patterns:
            if fnmatch(hostname, pattern) or fnmatch(url, pattern):
                return True

        return False
