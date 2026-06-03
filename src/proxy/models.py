"""Proxy data models.

Pure-Python dataclasses for representing captured HTTP flows and proxy
configuration.  These models have **no dependency on mitmproxy** and can
be used anywhere in the codebase.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CapturedFlow:
    """A captured HTTP request/response pair.

    Attributes:
        id:                  Unique flow identifier (UUID4 hex string).
        timestamp:           ISO 8601 timestamp of the capture.
        request_method:      HTTP method (GET, POST, ...).
        request_url:         Full request URL including scheme.
        request_host:        Hostname extracted from the URL.
        request_path:        Path component of the URL.
        request_headers:     Request header name -> value mapping.
        request_body:        Request body (truncated to 10 KB).
        response_status:     HTTP response status code.
        response_headers:    Response header name -> value mapping.
        response_body:       Response body (truncated to 50 KB).
        response_content_type: Content-Type of the response.
        duration_ms:         Round-trip time in milliseconds.
        tags:                User-defined tags for categorisation.
    """

    id: str
    timestamp: str
    request_method: str
    request_url: str
    request_host: str
    request_path: str
    request_headers: dict[str, str]
    request_body: str = ""
    response_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_content_type: str = ""
    duration_ms: float = 0.0
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to a plain dict suitable for JSON / SSE transport."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "request_method": self.request_method,
            "request_url": self.request_url,
            "request_host": self.request_host,
            "request_path": self.request_path,
            "request_headers": dict(self.request_headers),
            "request_body": self.request_body,
            "response_status": self.response_status,
            "response_headers": dict(self.response_headers),
            "response_body": self.response_body,
            "response_content_type": self.response_content_type,
            "duration_ms": self.duration_ms,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, data: dict) -> CapturedFlow:
        """Deserialize from a plain dict."""
        return cls(
            id=data["id"],
            timestamp=data["timestamp"],
            request_method=data["request_method"],
            request_url=data["request_url"],
            request_host=data["request_host"],
            request_path=data["request_path"],
            request_headers=data.get("request_headers", {}),
            request_body=data.get("request_body", ""),
            response_status=data.get("response_status", 0),
            response_headers=data.get("response_headers", {}),
            response_body=data.get("response_body", ""),
            response_content_type=data.get("response_content_type", ""),
            duration_ms=data.get("duration_ms", 0.0),
            tags=data.get("tags", []),
        )


@dataclass
class ProxyConfig:
    """Proxy server configuration.

    Attributes:
        listen_host:         Address the proxy binds to.
        listen_port:         TCP port the proxy listens on.
        ssl_insecure:        If *True*, skip upstream SSL certificate
                             verification (useful for self-signed targets).
        intercept_patterns:  URL glob patterns to capture.  An empty list
                             means "capture everything".
        exclude_patterns:    URL glob patterns to exclude from capture.
        max_body_size:       Maximum response body size (bytes) to store.
    """

    listen_host: str = "127.0.0.1"
    listen_port: int = 8888
    ssl_insecure: bool = False
    intercept_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(
        default_factory=lambda: [
            "*.google.com",
            "*.gstatic.com",
            "*.googleapis.com",
            "*.mozilla.org",
            "*.firefox.com",
        ]
    )
    max_body_size: int = 51200  # 50 KB
