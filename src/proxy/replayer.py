"""Replay captured flows with optional modifications.

Replays are executed via the ``requests`` library (not through the proxy)
so they behave like direct HTTP calls to the target server.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests as _requests

from src.infra.decorators import logged
from src.infra.logging import get_logger

from .models import CapturedFlow
from .store import FlowStore

logger = get_logger(__name__)


class FlowReplayer:
    """Replays captured HTTP flows.

    Loads a previously-captured flow from the :class:`FlowStore`, optionally
    modifies it, then sends the request via ``requests`` and captures the
    new response as a fresh :class:`CapturedFlow`.
    """

    def __init__(self, store: FlowStore, timeout: int = 30):
        self.store = store
        self.timeout = timeout

    @logged
    def replay(
        self,
        flow_id: str,
        modify_headers: dict[str, str] | None = None,
        modify_body: str | None = None,
        modify_method: str | None = None,
    ) -> CapturedFlow | None:
        """Replay a captured flow, optionally with modifications.

        Sends the request and captures the new response.
        Returns a new CapturedFlow with the replay results, or *None*
        if the original flow cannot be found.
        """
        original = self.store.get(flow_id)
        if original is None:
            logger.warning("Flow %s not found for replay", flow_id)
            return None

        return self._send_request(
            original=original,
            modify_url=None,
            modify_headers=modify_headers,
            modify_body=modify_body,
            modify_method=modify_method,
            tags=["replay", f"original:{flow_id}"],
        )

    @logged
    def replay_with_payload(
        self,
        flow_id: str,
        payload: str,
        inject_into: str = "body",
    ) -> CapturedFlow | None:
        """Replay a flow with a payload injected.

        Args:
            flow_id: Original flow to replay.
            payload: Payload string to inject.
            inject_into: Where to inject -- ``"body"``, ``"url"``, or
                ``"header"``.

        Returns:
            A new :class:`CapturedFlow` with the replay results, or *None*
            if the original flow cannot be found.
        """
        original = self.store.get(flow_id)
        if original is None:
            logger.warning("Flow %s not found for payload replay", flow_id)
            return None

        modify_headers: dict[str, str] | None = None
        modify_body: str | None = None
        modify_url: str | None = None

        if inject_into == "body":
            modify_body = payload
        elif inject_into == "url":
            parsed = urlparse(original.request_url)
            params = parse_qs(parsed.query)
            params["payload"] = [payload]
            new_query = urlencode(params, doseq=True)
            modify_url = urlunparse(parsed._replace(query=new_query))
        elif inject_into == "header":
            modify_headers = {"X-Payload": payload}
        else:
            logger.warning("Unknown inject_into value: %s", inject_into)
            return None

        return self._send_request(
            original=original,
            modify_url=modify_url,
            modify_headers=modify_headers,
            modify_body=modify_body,
            modify_method=None,
            tags=["replay", f"original:{flow_id}", f"payload:{inject_into}"],
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _send_request(
        self,
        original: CapturedFlow,
        *,
        modify_url: str | None = None,
        modify_headers: dict[str, str] | None = None,
        modify_body: str | None = None,
        modify_method: str | None = None,
        tags: list[str] | None = None,
    ) -> CapturedFlow | None:
        """Build, send, and capture a replayed request.

        This is the shared implementation used by both :meth:`replay` and
        :meth:`replay_with_payload`.
        """
        method = modify_method or original.request_method
        url = modify_url or original.request_url
        headers = dict(original.request_headers)
        body = modify_body if modify_body is not None else original.request_body

        # Apply header modifications
        if modify_headers:
            headers.update(modify_headers)

        # Remove hop-by-hop headers that should not be replayed
        for hop_header in (
            "host",
            "transfer-encoding",
            "connection",
            "proxy-connection",
            "keep-alive",
        ):
            headers.pop(hop_header, None)
            headers.pop(hop_header.title(), None)

        # Send the request
        start = time.time()
        try:
            resp = _requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body.encode("utf-8") if body else None,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )
        except _requests.RequestException as exc:
            logger.error("Replay request failed: %s", exc)
            return None

        duration_ms = (time.time() - start) * 1000
        parsed = urlparse(url)

        # Truncate response body to a reasonable size
        resp_body = resp.text
        if len(resp_body) > 51200:
            resp_body = resp_body[:51200] + "... [truncated]"

        captured = CapturedFlow(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now(UTC).isoformat(),
            request_method=method,
            request_url=url,
            request_host=parsed.hostname or "",
            request_path=parsed.path or "/",
            request_headers=headers,
            request_body=body,
            response_status=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=resp_body,
            response_content_type=resp.headers.get("content-type", ""),
            duration_ms=round(duration_ms, 2),
            tags=tags or [],
        )

        self.store.add(captured)
        logger.info(
            "Replayed %s %s -> %d (%.0fms)",
            method,
            url,
            resp.status_code,
            duration_ms,
        )
        return captured
