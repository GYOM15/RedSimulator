"""Convert captured proxy flows into pipeline input.

This adapter bridges the proxy module and the scanner/expert pipeline
by transforming captured HTTP flows into a :class:`ScanResult` that the
Expert system and downstream modules can consume.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import urlparse

from src.infra.decorators import logged, timed
from src.infra.logging import get_logger
from src.models.scan_result import (
    EndpointInfo,
    FieldInfo,
    FormInfo,
    HeaderAnalysis,
    ScanResult,
)

from .models import CapturedFlow
from .store import FlowStore

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Simple HTML form parser
# ---------------------------------------------------------------------------


class _FormParser(HTMLParser):
    """Minimal HTML parser that extracts ``<form>`` elements and their fields."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": (attr_dict.get("method", "GET")).upper(),
                "fields": [],
            }
        elif tag == "input" and self._current_form is not None:
            name = attr_dict.get("name", "")
            if name:
                self._current_form["fields"].append(
                    {
                        "name": name,
                        "type": attr_dict.get("type", "text"),
                        "placeholder": attr_dict.get("placeholder", ""),
                    }
                )
        elif tag == "textarea" and self._current_form is not None:
            name = attr_dict.get("name", "")
            if name:
                self._current_form["fields"].append(
                    {
                        "name": name,
                        "type": "textarea",
                        "placeholder": attr_dict.get("placeholder", ""),
                    }
                )
        elif tag == "select" and self._current_form is not None:
            name = attr_dict.get("name", "")
            if name:
                self._current_form["fields"].append(
                    {
                        "name": name,
                        "type": "select",
                        "placeholder": "",
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            if self._current_form["fields"]:
                self.forms.append(self._current_form)
            self._current_form = None


# ---------------------------------------------------------------------------
# Security headers to check
# ---------------------------------------------------------------------------

_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Headers that leak server information
_SERVER_INFO_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")

# Known technology patterns in headers
_TECH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Express", re.compile(r"express", re.IGNORECASE)),
    ("Node.js", re.compile(r"node", re.IGNORECASE)),
    ("nginx", re.compile(r"nginx", re.IGNORECASE)),
    ("Apache", re.compile(r"apache", re.IGNORECASE)),
    ("PHP", re.compile(r"php", re.IGNORECASE)),
    ("ASP.NET", re.compile(r"asp\.?net", re.IGNORECASE)),
    ("Django", re.compile(r"django", re.IGNORECASE)),
    ("Flask", re.compile(r"flask", re.IGNORECASE)),
    ("Spring", re.compile(r"spring", re.IGNORECASE)),
    ("Ruby on Rails", re.compile(r"rails|phusion", re.IGNORECASE)),
    ("Tomcat", re.compile(r"tomcat", re.IGNORECASE)),
    ("IIS", re.compile(r"microsoft-iis", re.IGNORECASE)),
]


class ProxyFeedAdapter:
    """Converts captured flows into ScanResult for the pipeline.

    Groups flows by endpoint, extracts technologies from headers,
    detects missing security headers, and parses HTML forms.
    """

    def __init__(self, store: FlowStore):
        self.store = store

    @logged
    @timed
    def to_scan_result(self, host_filter: str = "") -> ScanResult:
        """Convert stored flows into a ScanResult.

        Groups flows by endpoint, extracts:
        - Endpoints (path, method, status, parameters)
        - Technologies (from response headers)
        - Headers (security analysis)
        - Forms (from HTML responses with form tags)

        Args:
            host_filter: Only include flows for this host.
                If empty, all flows are included.

        Returns:
            ScanResult that can feed into the Expert system.
        """
        if host_filter:
            flows = self.store.search(url_pattern=host_filter, limit=10000)
        else:
            flows = self.store.search(limit=10000)

        if not flows:
            logger.warning("No captured flows to convert (host_filter=%r)", host_filter)
            target = f"http://{host_filter}" if host_filter else "unknown"
            return ScanResult(
                target=target,
                scan_timestamp=datetime.now(UTC).isoformat(),
            )

        # Determine target from the first flow
        first_flow = flows[0]
        parsed_first = urlparse(first_flow.request_url)
        target = f"{parsed_first.scheme}://{parsed_first.netloc}"

        # Group flows by (method, path)
        grouped: dict[tuple[str, str], list[CapturedFlow]] = defaultdict(list)
        for flow in flows:
            key = (flow.request_method, flow.request_path)
            grouped[key].append(flow)

        endpoints = self._extract_endpoints(grouped)
        technologies = self._detect_technologies(flows)
        headers = self._analyze_headers(flows)
        forms = self._extract_forms(flows)

        return ScanResult(
            target=target,
            scan_timestamp=datetime.now(UTC).isoformat(),
            endpoints=endpoints,
            technologies=sorted(technologies),
            headers=headers,
            forms=forms,
        )

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    def _extract_endpoints(
        self, grouped: dict[tuple[str, str], list[CapturedFlow]]
    ) -> list[EndpointInfo]:
        """Extract unique endpoints from grouped flows."""
        endpoints: list[EndpointInfo] = []

        for (method, path), group_flows in grouped.items():
            # Use the most common status code for this endpoint
            status_codes = [f.response_status for f in group_flows if f.response_status]
            most_common_status = (
                max(set(status_codes), key=status_codes.count) if status_codes else 0
            )

            # Collect parameters from request bodies and query strings
            parameters: set[str] = set()
            for flow in group_flows:
                # Extract from query string
                parsed = urlparse(flow.request_url)
                if parsed.query:
                    for param in parsed.query.split("&"):
                        name = param.split("=", 1)[0]
                        if name:
                            parameters.add(name)

                # Extract from JSON-like body (simple key extraction)
                if (
                    flow.request_body
                    and flow.response_content_type
                    and (
                        "json" in flow.response_content_type.lower()
                        or flow.request_body.startswith("{")
                    )
                ):
                    # Simple regex extraction of top-level JSON keys
                    keys = re.findall(r'"(\w+)"\s*:', flow.request_body)
                    parameters.update(keys)

            # Check if any flow returned 401/403 (suggests auth required)
            auth_required = any(f.response_status in (401, 403) for f in group_flows)

            endpoints.append(
                EndpointInfo(
                    path=path,
                    method=method,
                    status_code=most_common_status,
                    auth_required=auth_required,
                    parameters=sorted(parameters),
                )
            )

        return endpoints

    def _detect_technologies(self, flows: list[CapturedFlow]) -> set[str]:
        """Detect technologies from response headers."""
        technologies: set[str] = set()

        for flow in flows:
            # Check Server and X-Powered-By headers
            for header_name in _SERVER_INFO_HEADERS:
                value = ""
                for k, v in flow.response_headers.items():
                    if k.lower() == header_name:
                        value = v
                        break
                if value:
                    for tech_name, pattern in _TECH_PATTERNS:
                        if pattern.search(value):
                            technologies.add(tech_name)

            # Check content type for technology hints
            ct = flow.response_content_type.lower()
            if "json" in ct:
                technologies.add("JSON API")
            if "xml" in ct:
                technologies.add("XML API")

        return technologies

    def _analyze_headers(self, flows: list[CapturedFlow]) -> HeaderAnalysis:
        """Analyze security headers across all flows."""
        # Collect all seen response header names (case-insensitive)
        seen_headers: set[str] = set()
        server_info_leaked = False

        for flow in flows:
            for header_name in flow.response_headers:
                seen_headers.add(header_name.lower())

            # Check for server info leakage
            for info_header in _SERVER_INFO_HEADERS:
                for k in flow.response_headers:
                    if k.lower() == info_header:
                        server_info_leaked = True
                        break

        # Determine which security headers are missing
        missing: list[str] = []
        for sec_header in _SECURITY_HEADERS:
            if sec_header.lower() not in seen_headers:
                missing.append(sec_header)

        return HeaderAnalysis(
            missing_security_headers=missing,
            server_info_leaked=server_info_leaked,
        )

    def _extract_forms(self, flows: list[CapturedFlow]) -> list[FormInfo]:
        """Extract forms from HTML responses."""
        forms: list[FormInfo] = []
        seen_actions: set[str] = set()  # Deduplicate forms

        for flow in flows:
            # Only parse HTML responses
            if "text/html" not in flow.response_content_type.lower():
                continue
            if not flow.response_body:
                continue

            parser = _FormParser()
            try:
                parser.feed(flow.response_body)
            except Exception:
                logger.debug("HTML parse error for %s", flow.request_url)
                continue

            for form_data in parser.forms:
                action = form_data.get("action", "") or flow.request_path
                # Deduplicate by action
                if action in seen_actions:
                    continue
                seen_actions.add(action)

                fields = [
                    FieldInfo(
                        name=f["name"],
                        type=f.get("type", "text"),
                        placeholder=f.get("placeholder", ""),
                    )
                    for f in form_data.get("fields", [])
                ]

                forms.append(
                    FormInfo(
                        endpoint=flow.request_path,
                        fields=fields,
                        method=form_data.get("method", "POST"),
                        action=action,
                        source="proxy",
                    )
                )

        return forms
