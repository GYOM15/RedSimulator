"""Tests du module executor.

Verifie le systeme de plugins (handlers), le gestionnaire de session,
et l'executeur d'attaques. Tous les tests fonctionnent sans Docker
ni API keys grace aux fixtures et aux mocks.
"""

from unittest.mock import MagicMock, patch

from src.executor import AttackExecutor, AttackHandler, SessionManager
from src.executor.attacks import get_all_handlers

# ---------------------------------------------------------------------------
# TestHandlerDiscovery
# ---------------------------------------------------------------------------


class TestHandlerDiscovery:
    """Test that all 9 handlers are auto-discovered."""

    def test_all_handlers_loaded(self):
        handlers = get_all_handlers()
        assert len(handlers) == 9

    def test_handler_types(self):
        """Verify each expected attack_type has a handler."""
        handlers = get_all_handlers()
        expected = {
            "sqli",
            "xss",
            "idor",
            "path_traversal",
            "auth_bypass",
            "info_disclosure",
            "command_injection",
            "csrf",
            "open_redirect",
        }
        assert set(handlers.keys()) == expected

    def test_handlers_are_classes(self):
        """Each handler value should be a class (not an instance)."""
        handlers = get_all_handlers()
        for attack_type, handler_cls in handlers.items():
            assert isinstance(handler_cls, type), (
                f"Handler for {attack_type} should be a class, got {type(handler_cls)}"
            )

    def test_handlers_subclass_attack_handler(self):
        """Each handler should be a subclass of AttackHandler."""
        handlers = get_all_handlers()
        for _attack_type, handler_cls in handlers.items():
            assert issubclass(handler_cls, AttackHandler), (
                f"{handler_cls.__name__} should subclass AttackHandler"
            )

    def test_handlers_have_attack_type_attribute(self):
        """Each handler class should have an attack_type class attribute."""
        handlers = get_all_handlers()
        for attack_type, handler_cls in handlers.items():
            assert hasattr(handler_cls, "attack_type")
            assert handler_cls.attack_type == attack_type

    def test_handlers_have_test_method(self):
        """Each handler class should have a test() method."""
        handlers = get_all_handlers()
        for _attack_type, handler_cls in handlers.items():
            assert hasattr(handler_cls, "test"), f"{handler_cls.__name__} missing test() method"
            assert callable(handler_cls.test)


# ---------------------------------------------------------------------------
# TestSessionManager
# ---------------------------------------------------------------------------


class TestSessionManager:
    """Test session manager initialization."""

    def test_session_created(self):
        sm = SessionManager("http://localhost:3000")
        assert sm.base_url == "http://localhost:3000"
        assert sm.session is not None

    def test_base_url_trailing_slash_stripped(self):
        sm = SessionManager("http://localhost:3000/")
        assert sm.base_url == "http://localhost:3000"

    def test_default_headers_set(self):
        sm = SessionManager("http://localhost:3000")
        headers = sm.session.headers
        assert "User-Agent" in headers
        assert "RedSimulator" in headers["User-Agent"]

    def test_auth_token_initially_none(self):
        sm = SessionManager("http://localhost:3000")
        assert sm.auth_token is None

    def test_cookies_initially_empty(self):
        sm = SessionManager("http://localhost:3000")
        assert sm.cookies == {}

    def test_get_returns_none_on_connection_error(self):
        """GET on unreachable host should return None, not raise."""
        sm = SessionManager("http://192.0.2.1:1")  # RFC 5737 TEST-NET, unreachable
        result = sm.get("/test", timeout=0.1)
        assert result is None

    def test_post_returns_none_on_connection_error(self):
        """POST on unreachable host should return None, not raise."""
        sm = SessionManager("http://192.0.2.1:1")
        result = sm.post("/test", timeout=0.1)
        assert result is None

    def test_request_returns_none_on_connection_error(self):
        """Arbitrary method on unreachable host should return None, not raise."""
        sm = SessionManager("http://192.0.2.1:1")
        result = sm.request("PUT", "/test", timeout=0.1)
        assert result is None


# ---------------------------------------------------------------------------
# TestAttackExecutor
# ---------------------------------------------------------------------------


class TestAttackExecutor:
    """Test executor with fixtures and mocks."""

    def test_from_fixtures(self):
        """from_fixtures() should load the attack_result.json fixture."""
        result = AttackExecutor.from_fixtures()
        assert result.total_attempts > 0
        assert result.successful_attacks >= 0
        assert len(result.results) >= 1

    def test_from_fixtures_results_have_fields(self):
        """Fixture results should have required fields."""
        result = AttackExecutor.from_fixtures()
        for r in result.results:
            assert r.vector_id.startswith("VEC-")
            assert r.payload_used
            assert r.target_endpoint.startswith("/")
            assert isinstance(r.success, bool)

    def test_executor_discovers_handlers(self):
        """AttackExecutor should instantiate all handlers on init."""
        with patch("src.executor.runner.settings") as mock_settings:
            mock_settings.attack_delay = 0
            mock_settings.executor_timeout = 1
            executor = AttackExecutor("http://localhost:3000")
            assert len(executor._handlers) == 9

    def test_executor_handler_keys_match_attack_types(self):
        """Handler keys should match expected attack type strings."""
        with patch("src.executor.runner.settings") as mock_settings:
            mock_settings.attack_delay = 0
            mock_settings.executor_timeout = 1
            executor = AttackExecutor("http://localhost:3000")
            expected = {
                "sqli",
                "xss",
                "idor",
                "path_traversal",
                "auth_bypass",
                "info_disclosure",
                "command_injection",
                "csrf",
                "open_redirect",
            }
            assert set(executor._handlers.keys()) == expected

    def test_executor_base_url_stored(self):
        with patch("src.executor.runner.settings") as mock_settings:
            mock_settings.attack_delay = 0
            mock_settings.executor_timeout = 1
            executor = AttackExecutor("http://localhost:3000/")
            assert executor.base_url == "http://localhost:3000"


# ---------------------------------------------------------------------------
# TestAttackHandlerBase
# ---------------------------------------------------------------------------


class TestAttackHandlerBase:
    """Test the AttackHandler base class contract."""

    def test_handler_instantiation(self):
        """Concrete handlers should be instantiable with base_url."""
        handlers = get_all_handlers()
        for _attack_type, handler_cls in handlers.items():
            handler = handler_cls(base_url="http://localhost:3000")
            assert handler.base_url == "http://localhost:3000"

    def test_handler_with_session(self):
        """Handlers should accept a session parameter."""
        sm = SessionManager("http://localhost:3000")
        handlers = get_all_handlers()
        for _attack_type, handler_cls in handlers.items():
            handler = handler_cls(base_url="http://localhost:3000", session=sm)
            assert handler.session is sm

    def test_make_result_helper(self):
        """The _make_result helper should produce a valid SingleAttackResult."""
        handlers = get_all_handlers()
        handler_cls = handlers["sqli"]
        handler = handler_cls(base_url="http://localhost:3000")

        # Create a minimal mock vector
        mock_vector = MagicMock()
        mock_vector.id = "VEC-001"
        mock_vector.target_endpoint = "/test"

        result = handler._make_result(
            vector=mock_vector,
            payload="test_payload",
            status=200,
            snippet="response body",
            success=True,
            detection="test detection",
        )
        assert result.vector_id == "VEC-001"
        assert result.payload_used == "test_payload"
        assert result.target_endpoint == "/test"
        assert result.http_status == 200
        assert result.success is True
        assert result.detection_method == "test detection"

    def test_make_result_truncates_snippet(self):
        """The _make_result helper should truncate long snippets to 200 chars."""
        handlers = get_all_handlers()
        handler_cls = handlers["xss"]
        handler = handler_cls(base_url="http://localhost:3000")

        mock_vector = MagicMock()
        mock_vector.id = "VEC-001"
        mock_vector.target_endpoint = "/test"

        long_snippet = "x" * 500
        result = handler._make_result(
            vector=mock_vector,
            payload="test",
            status=200,
            snippet=long_snippet,
            success=False,
            detection="test",
        )
        assert len(result.response_snippet) <= 200
