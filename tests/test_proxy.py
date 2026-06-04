"""Tests for the proxy module (no mitmproxy dependency needed).

Verifies CapturedFlow serialization, ProxyConfig defaults,
and FlowStore CRUD/search/export operations using a temporary
SQLite database. All tests run without Docker, mitmproxy, or API keys.
"""

import os
import tempfile

from src.proxy.models import CapturedFlow, ProxyConfig
from src.proxy.store import FlowStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store() -> FlowStore:
    """Create a FlowStore backed by a temporary SQLite database."""
    db_path = os.path.join(tempfile.mkdtemp(), "test_flows.db")
    return FlowStore(db_path)


def _make_flow(
    flow_id: str = "f1",
    method: str = "GET",
    path: str = "/test",
    host: str = "localhost",
    status: int = 200,
    body: str = "ok",
    content_type: str = "",
    duration_ms: float = 0.0,
    tags: list[str] | None = None,
) -> CapturedFlow:
    """Create a CapturedFlow with sensible defaults."""
    return CapturedFlow(
        id=flow_id,
        timestamp="2025-01-01T00:00:00Z",
        request_method=method,
        request_url=f"http://{host}{path}",
        request_host=host,
        request_path=path,
        request_headers={},
        response_status=status,
        response_headers={},
        response_body=body,
        response_content_type=content_type,
        duration_ms=duration_ms,
        tags=tags or [],
    )


# ---------------------------------------------------------------------------
# TestCapturedFlow
# ---------------------------------------------------------------------------


class TestCapturedFlow:
    """Test CapturedFlow data model and serialization."""

    def test_to_dict_roundtrip(self):
        flow = CapturedFlow(
            id="test-1",
            timestamp="2025-01-01T00:00:00Z",
            request_method="GET",
            request_url="http://localhost/test",
            request_host="localhost",
            request_path="/test",
            request_headers={"Accept": "text/html"},
            response_status=200,
            response_headers={"Content-Type": "text/html"},
            response_body="<html>test</html>",
        )
        d = flow.to_dict()
        restored = CapturedFlow.from_dict(d)
        assert restored.id == flow.id
        assert restored.request_method == flow.request_method
        assert restored.request_url == flow.request_url
        assert restored.request_host == flow.request_host
        assert restored.request_path == flow.request_path
        assert restored.request_headers == flow.request_headers
        assert restored.response_status == flow.response_status
        assert restored.response_headers == flow.response_headers
        assert restored.response_body == flow.response_body

    def test_to_dict_contains_all_fields(self):
        flow = _make_flow(tags=["auth", "api"])
        d = flow.to_dict()
        expected_keys = {
            "id",
            "timestamp",
            "request_method",
            "request_url",
            "request_host",
            "request_path",
            "request_headers",
            "request_body",
            "response_status",
            "response_headers",
            "response_body",
            "response_content_type",
            "duration_ms",
            "tags",
        }
        assert set(d.keys()) == expected_keys

    def test_from_dict_handles_missing_optional_fields(self):
        """from_dict should handle missing optional fields gracefully."""
        minimal = {
            "id": "m1",
            "timestamp": "2025-01-01T00:00:00Z",
            "request_method": "GET",
            "request_url": "http://localhost/",
            "request_host": "localhost",
            "request_path": "/",
        }
        flow = CapturedFlow.from_dict(minimal)
        assert flow.id == "m1"
        assert flow.request_body == ""
        assert flow.response_status == 0
        assert flow.response_headers == {}
        assert flow.tags == []

    def test_defaults(self):
        flow = CapturedFlow(
            id="d1",
            timestamp="2025-01-01T00:00:00Z",
            request_method="POST",
            request_url="http://localhost/api",
            request_host="localhost",
            request_path="/api",
            request_headers={"Content-Type": "application/json"},
        )
        assert flow.request_body == ""
        assert flow.response_status == 0
        assert flow.response_body == ""
        assert flow.response_content_type == ""
        assert flow.duration_ms == 0.0
        assert flow.tags == []


# ---------------------------------------------------------------------------
# TestProxyConfig
# ---------------------------------------------------------------------------


class TestProxyConfig:
    """Test ProxyConfig data model."""

    def test_defaults(self):
        config = ProxyConfig()
        assert config.listen_host == "127.0.0.1"
        assert config.listen_port == 8888
        assert config.ssl_insecure is False
        assert config.intercept_patterns == []
        assert len(config.exclude_patterns) > 0
        assert config.max_body_size == 51200

    def test_custom_values(self):
        config = ProxyConfig(
            listen_host="0.0.0.0",
            listen_port=9090,
            ssl_insecure=True,
            intercept_patterns=["*.api.com"],
            exclude_patterns=[],
            max_body_size=102400,
        )
        assert config.listen_host == "0.0.0.0"
        assert config.listen_port == 9090
        assert config.ssl_insecure is True
        assert config.intercept_patterns == ["*.api.com"]
        assert config.exclude_patterns == []
        assert config.max_body_size == 102400

    def test_default_exclude_patterns(self):
        config = ProxyConfig()
        assert "*.google.com" in config.exclude_patterns
        assert "*.gstatic.com" in config.exclude_patterns

    def test_exclude_patterns_independent(self):
        """Each ProxyConfig should have its own exclude_patterns list."""
        c1 = ProxyConfig()
        c2 = ProxyConfig()
        c1.exclude_patterns.append("*.extra.com")
        assert "*.extra.com" not in c2.exclude_patterns


# ---------------------------------------------------------------------------
# TestFlowStore
# ---------------------------------------------------------------------------


class TestFlowStore:
    """Test FlowStore CRUD, search, and export operations."""

    def test_add_and_count(self):
        store = _make_store()
        store.add(_make_flow())
        assert store.count() == 1

    def test_add_multiple(self):
        store = _make_store()
        for i in range(5):
            store.add(_make_flow(f"f{i}"))
        assert store.count() == 5

    def test_add_replace(self):
        """Adding a flow with the same ID should replace, not duplicate."""
        store = _make_store()
        store.add(_make_flow("same-id", body="original"))
        store.add(_make_flow("same-id", body="updated"))
        assert store.count() == 1
        flow = store.get("same-id")
        assert flow is not None
        assert flow.response_body == "updated"

    def test_get_by_id(self):
        store = _make_store()
        store.add(_make_flow("abc"))
        flow = store.get("abc")
        assert flow is not None
        assert flow.id == "abc"

    def test_get_nonexistent(self):
        store = _make_store()
        flow = store.get("does-not-exist")
        assert flow is None

    def test_search_by_url(self):
        store = _make_store()
        store.add(_make_flow("f1", path="/api/users"))
        store.add(_make_flow("f2", path="/api/login"))
        store.add(_make_flow("f3", path="/static/css"))
        results = store.search(url_pattern="api")
        assert len(results) == 2

    def test_search_by_method(self):
        store = _make_store()
        store.add(_make_flow("f1", method="GET"))
        store.add(_make_flow("f2", method="POST"))
        results = store.search(method="POST")
        assert len(results) == 1
        assert results[0].request_method == "POST"

    def test_search_by_method_case_insensitive(self):
        store = _make_store()
        store.add(_make_flow("f1", method="POST"))
        results = store.search(method="post")
        assert len(results) == 1

    def test_search_by_status(self):
        store = _make_store()
        store.add(_make_flow("f1", status=200))
        store.add(_make_flow("f2", status=404))
        store.add(_make_flow("f3", status=500))
        results = store.search(status_min=400, status_max=599)
        assert len(results) == 2

    def test_search_by_content_type(self):
        store = _make_store()
        store.add(_make_flow("f1", content_type="text/html"))
        store.add(_make_flow("f2", content_type="application/json"))
        results = store.search(content_type="json")
        assert len(results) == 1

    def test_search_with_limit(self):
        store = _make_store()
        for i in range(10):
            store.add(_make_flow(f"f{i}"))
        results = store.search(limit=3)
        assert len(results) == 3

    def test_search_with_offset(self):
        store = _make_store()
        for i in range(5):
            store.add(_make_flow(f"f{i}"))
        all_results = store.search(limit=100)
        offset_results = store.search(limit=100, offset=2)
        assert len(offset_results) == len(all_results) - 2

    def test_search_no_filters(self):
        """Search with no filters returns all flows."""
        store = _make_store()
        for i in range(3):
            store.add(_make_flow(f"f{i}"))
        results = store.search()
        assert len(results) == 3

    def test_search_combined_filters(self):
        store = _make_store()
        store.add(_make_flow("f1", method="POST", path="/api/login", status=200))
        store.add(_make_flow("f2", method="POST", path="/api/users", status=404))
        store.add(_make_flow("f3", method="GET", path="/api/login", status=200))
        results = store.search(method="POST", url_pattern="api", status_min=200, status_max=299)
        assert len(results) == 1
        assert results[0].id == "f1"

    def test_delete(self):
        store = _make_store()
        store.add(_make_flow("del-me"))
        assert store.delete("del-me") is True
        assert store.count() == 0

    def test_delete_nonexistent(self):
        store = _make_store()
        assert store.delete("nonexistent") is False

    def test_clear(self):
        store = _make_store()
        for i in range(5):
            store.add(_make_flow(f"f{i}"))
        deleted = store.clear()
        assert deleted == 5
        assert store.count() == 0

    def test_clear_empty(self):
        store = _make_store()
        deleted = store.clear()
        assert deleted == 0

    def test_get_hosts(self):
        store = _make_store()
        store.add(_make_flow("f1", host="localhost"))
        store.add(_make_flow("f2", host="example.com"))
        store.add(_make_flow("f3", host="localhost"))
        hosts = store.get_hosts()
        assert "localhost" in hosts
        assert "example.com" in hosts
        assert len(hosts) == 2

    def test_get_hosts_sorted(self):
        store = _make_store()
        store.add(_make_flow("f1", host="zebra.com"))
        store.add(_make_flow("f2", host="alpha.com"))
        hosts = store.get_hosts()
        assert hosts == sorted(hosts)

    def test_export_har(self):
        store = _make_store()
        store.add(_make_flow())
        har = store.export_har()
        assert har["log"]["version"] == "1.2"
        assert har["log"]["creator"]["name"] == "RedSimulator"
        assert len(har["log"]["entries"]) == 1

    def test_export_har_entry_structure(self):
        store = _make_store()
        store.add(_make_flow(method="POST", path="/api", status=201, body="created"))
        har = store.export_har()
        entry = har["log"]["entries"][0]
        assert entry["request"]["method"] == "POST"
        assert entry["request"]["url"] == "http://localhost/api"
        assert entry["response"]["status"] == 201
        assert entry["response"]["content"]["text"] == "created"

    def test_export_har_empty(self):
        store = _make_store()
        har = store.export_har()
        assert har["log"]["entries"] == []

    def test_export_har_multiple_entries(self):
        store = _make_store()
        for i in range(3):
            store.add(_make_flow(f"f{i}"))
        har = store.export_har()
        assert len(har["log"]["entries"]) == 3

    def test_flow_store_preserves_headers(self):
        """Headers should survive the JSON serialization roundtrip via SQLite."""
        store = _make_store()
        flow = CapturedFlow(
            id="hdr-test",
            timestamp="2025-01-01T00:00:00Z",
            request_method="GET",
            request_url="http://localhost/",
            request_host="localhost",
            request_path="/",
            request_headers={"Authorization": "Bearer tok", "Accept": "application/json"},
            response_status=200,
            response_headers={"Content-Type": "application/json", "X-Custom": "value"},
            response_body='{"ok": true}',
        )
        store.add(flow)
        restored = store.get("hdr-test")
        assert restored is not None
        assert restored.request_headers["Authorization"] == "Bearer tok"
        assert restored.response_headers["Content-Type"] == "application/json"

    def test_flow_store_preserves_tags(self):
        """Tags should survive the JSON serialization roundtrip via SQLite."""
        store = _make_store()
        store.add(_make_flow("tag-test", tags=["auth", "api", "admin"]))
        restored = store.get("tag-test")
        assert restored is not None
        assert restored.tags == ["auth", "api", "admin"]

    def test_close(self):
        """Closing the store should not raise."""
        store = _make_store()
        store.close()
