"""Tests for the authentication framework.

Verifies auth models, the AuthManager orchestrator, and individual
providers (Basic, Bearer, Cookie, OAuth2). All tests run without
Docker, mitmproxy, or API keys.
"""

import base64
import json
import time

import pytest
import requests

from src.auth.models import AuthConfig, AuthState, AuthType
from src.auth.providers.base import AuthProvider
from src.auth.providers.basic import BasicAuthProvider
from src.auth.providers.bearer import BearerAuthProvider, _decode_jwt_payload
from src.auth.providers.cookie import CookieAuthProvider, _extract_csrf_token
from src.auth.providers.oauth2 import OAuth2Provider
from src.infra.exceptions import AuthenticationFailedError

# ---------------------------------------------------------------------------
# TestAuthModels
# ---------------------------------------------------------------------------


class TestAuthModels:
    """Test authentication data models."""

    def test_auth_config_defaults(self):
        config = AuthConfig()
        assert config.auth_type == AuthType.NONE
        assert config.username == ""
        assert config.password == ""
        assert config.token == ""
        assert config.login_url == ""
        assert config.token_url == ""
        assert config.client_id == ""
        assert config.client_secret == ""
        assert config.csrf_field == ""
        assert config.extra == {}

    def test_auth_config_with_values(self):
        config = AuthConfig(
            auth_type=AuthType.BASIC,
            username="admin",
            password="secret",
        )
        assert config.auth_type == AuthType.BASIC
        assert config.username == "admin"
        assert config.password == "secret"

    def test_auth_state_defaults(self):
        state = AuthState()
        assert state.authenticated is False
        assert state.token is None
        assert state.expires_at is None
        assert state.cookies == {}
        assert state.method_used == ""

    def test_auth_state_authenticated(self):
        state = AuthState(
            authenticated=True,
            token="my-token",
            expires_at=9999999999.0,
            method_used="bearer",
        )
        assert state.authenticated is True
        assert state.token == "my-token"
        assert state.expires_at == 9999999999.0
        assert state.method_used == "bearer"

    def test_auth_type_enum_values(self):
        assert AuthType.NONE == "none"
        assert AuthType.BASIC == "basic"
        assert AuthType.COOKIE == "cookie"
        assert AuthType.BEARER == "bearer"
        assert AuthType.OAUTH2 == "oauth2"

    def test_auth_config_extra_is_independent(self):
        """Each AuthConfig should have its own extra dict."""
        c1 = AuthConfig()
        c2 = AuthConfig()
        c1.extra["key"] = "value"
        assert "key" not in c2.extra


# ---------------------------------------------------------------------------
# TestAuthManager
# ---------------------------------------------------------------------------


class TestAuthManager:
    """Test the AuthManager orchestrator."""

    def test_none_auth_creates_no_provider(self):
        from src.auth.manager import AuthManager

        manager = AuthManager(AuthConfig())
        assert manager.provider is None

    def test_basic_auth_creates_provider(self):
        from src.auth.manager import AuthManager

        config = AuthConfig(auth_type=AuthType.BASIC, username="admin", password="pass")
        manager = AuthManager(config)
        assert manager.provider is not None
        assert isinstance(manager.provider, BasicAuthProvider)

    def test_bearer_auth_creates_provider(self):
        from src.auth.manager import AuthManager

        config = AuthConfig(auth_type=AuthType.BEARER, token="test-token")
        manager = AuthManager(config)
        assert manager.provider is not None
        assert isinstance(manager.provider, BearerAuthProvider)

    def test_cookie_auth_creates_provider(self):
        from src.auth.manager import AuthManager

        config = AuthConfig(
            auth_type=AuthType.COOKIE, username="user", password="pass", login_url="/login"
        )
        manager = AuthManager(config)
        assert manager.provider is not None
        assert isinstance(manager.provider, CookieAuthProvider)

    def test_oauth2_auth_creates_provider(self):
        from src.auth.manager import AuthManager

        config = AuthConfig(
            auth_type=AuthType.OAUTH2,
            client_id="id",
            client_secret="secret",
            token_url="/token",
        )
        manager = AuthManager(config)
        assert manager.provider is not None
        assert isinstance(manager.provider, OAuth2Provider)

    def test_initial_state_unauthenticated(self):
        from src.auth.manager import AuthManager

        manager = AuthManager(AuthConfig(auth_type=AuthType.BASIC, username="u", password="p"))
        assert manager.state.authenticated is False

    def test_ensure_authenticated_noop_when_none(self):
        from src.auth.manager import AuthManager

        manager = AuthManager(AuthConfig())
        session = requests.Session()
        state = manager.ensure_authenticated(session, "http://localhost")
        assert state.authenticated is False

    def test_on_response_noop_when_none(self):
        from src.auth.manager import AuthManager

        manager = AuthManager(AuthConfig())
        resp = requests.Response()
        resp.status_code = 401
        session = requests.Session()
        # Should not raise
        manager.on_response(resp, session, "http://localhost")


# ---------------------------------------------------------------------------
# TestBasicAuthProvider
# ---------------------------------------------------------------------------


class TestBasicAuthProvider:
    """Test the HTTP Basic auth provider."""

    def test_provider_name(self):
        config = AuthConfig(auth_type=AuthType.BASIC, username="u", password="p")
        provider = BasicAuthProvider(config)
        assert provider.name == "basic"

    def test_is_authenticated_checks_session_auth(self):
        config = AuthConfig(auth_type=AuthType.BASIC, username="u", password="p")
        provider = BasicAuthProvider(config)
        session = requests.Session()
        assert provider.is_authenticated(session) is False
        session.auth = ("u", "p")
        assert provider.is_authenticated(session) is True

    def test_subclasses_auth_provider(self):
        config = AuthConfig(auth_type=AuthType.BASIC, username="u", password="p")
        provider = BasicAuthProvider(config)
        assert isinstance(provider, AuthProvider)


# ---------------------------------------------------------------------------
# TestBearerAuthProvider
# ---------------------------------------------------------------------------


class TestBearerAuthProvider:
    """Test the Bearer token / JWT auth provider."""

    def test_provider_name(self):
        config = AuthConfig(auth_type=AuthType.BEARER, token="tok")
        provider = BearerAuthProvider(config)
        assert provider.name == "bearer"

    def test_is_authenticated_false_without_header(self):
        config = AuthConfig(auth_type=AuthType.BEARER, token="tok")
        provider = BearerAuthProvider(config)
        session = requests.Session()
        assert provider.is_authenticated(session) is False

    def test_is_authenticated_true_with_header(self):
        config = AuthConfig(auth_type=AuthType.BEARER, token="tok")
        provider = BearerAuthProvider(config)
        session = requests.Session()
        session.headers["Authorization"] = "Bearer tok"
        assert provider.is_authenticated(session) is True

    def test_is_authenticated_detects_expiry(self):
        config = AuthConfig(auth_type=AuthType.BEARER, token="tok")
        provider = BearerAuthProvider(config)
        provider._expires_at = time.time() - 100  # expired 100 seconds ago
        session = requests.Session()
        session.headers["Authorization"] = "Bearer tok"
        assert provider.is_authenticated(session) is False

    def test_subclasses_auth_provider(self):
        config = AuthConfig(auth_type=AuthType.BEARER, token="tok")
        provider = BearerAuthProvider(config)
        assert isinstance(provider, AuthProvider)


# ---------------------------------------------------------------------------
# TestJWTDecoding
# ---------------------------------------------------------------------------


class TestJWTDecoding:
    """Test the _decode_jwt_payload helper."""

    def _make_jwt(self, payload: dict) -> str:
        """Build a fake JWT with the given payload (no signature verification)."""
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=")
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
        sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=")
        return f"{header.decode()}.{body.decode()}.{sig.decode()}"

    def test_decodes_valid_jwt(self):
        token = self._make_jwt({"sub": "user", "exp": 9999999999})
        payload = _decode_jwt_payload(token)
        assert payload is not None
        assert payload["sub"] == "user"
        assert payload["exp"] == 9999999999

    def test_returns_none_for_non_jwt(self):
        assert _decode_jwt_payload("not-a-jwt") is None

    def test_returns_none_for_two_parts(self):
        assert _decode_jwt_payload("a.b") is None

    def test_returns_none_for_invalid_base64(self):
        # Four parts = invalid JWT structure
        assert _decode_jwt_payload("a.b.c.d") is None

    def test_expired_jwt_payload(self):
        expired_time = int(time.time()) - 3600
        token = self._make_jwt({"sub": "user", "exp": expired_time})
        payload = _decode_jwt_payload(token)
        assert payload is not None
        assert payload["exp"] < time.time()


# ---------------------------------------------------------------------------
# TestCookieAuthProvider
# ---------------------------------------------------------------------------


class TestCookieAuthProvider:
    """Test the cookie/form-based auth provider."""

    def test_provider_name(self):
        config = AuthConfig(auth_type=AuthType.COOKIE, login_url="/login")
        provider = CookieAuthProvider(config)
        assert provider.name == "cookie"

    def test_is_authenticated_false_without_cookies(self):
        config = AuthConfig(auth_type=AuthType.COOKIE, login_url="/login")
        provider = CookieAuthProvider(config)
        session = requests.Session()
        assert provider.is_authenticated(session) is False

    def test_is_authenticated_true_with_cookies(self):
        config = AuthConfig(auth_type=AuthType.COOKIE, login_url="/login")
        provider = CookieAuthProvider(config)
        session = requests.Session()
        session.cookies.set("session", "abc123")
        assert provider.is_authenticated(session) is True

    def test_authenticate_requires_login_url(self):
        config = AuthConfig(auth_type=AuthType.COOKIE)
        provider = CookieAuthProvider(config)
        session = requests.Session()
        with pytest.raises(AuthenticationFailedError, match="login_url"):
            provider.authenticate(session, "http://localhost")

    def test_subclasses_auth_provider(self):
        config = AuthConfig(auth_type=AuthType.COOKIE, login_url="/login")
        provider = CookieAuthProvider(config)
        assert isinstance(provider, AuthProvider)


# ---------------------------------------------------------------------------
# TestCSRFExtraction
# ---------------------------------------------------------------------------


class TestCSRFExtraction:
    """Test the _extract_csrf_token helper."""

    def test_extracts_csrf_token(self):
        html = '<input type="hidden" name="csrf_token" value="abc123">'
        name, value = _extract_csrf_token(html)
        assert name == "csrf_token"
        assert value == "abc123"

    def test_extracts_django_csrf(self):
        html = '<input type="hidden" name="csrfmiddlewaretoken" value="django-csrf-val">'
        name, value = _extract_csrf_token(html)
        assert name == "csrfmiddlewaretoken"
        assert value == "django-csrf-val"

    def test_extracts_rails_authenticity_token(self):
        html = '<input type="hidden" name="authenticity_token" value="rails-tok">'
        name, value = _extract_csrf_token(html)
        assert name == "authenticity_token"
        assert value == "rails-tok"

    def test_specific_field_name(self):
        html = (
            '<input type="hidden" name="csrf_token" value="general">'
            '<input type="hidden" name="my_csrf" value="specific">'
        )
        name, value = _extract_csrf_token(html, csrf_field="my_csrf")
        assert name == "my_csrf"
        assert value == "specific"

    def test_no_hidden_fields(self):
        html = "<form><input type='text' name='username'></form>"
        name, value = _extract_csrf_token(html)
        assert name == ""
        assert value == ""

    def test_empty_html(self):
        name, value = _extract_csrf_token("")
        assert name == ""
        assert value == ""

    def test_value_before_name_order(self):
        """Test the alternate regex where value attribute precedes name."""
        html = '<input type="hidden" value="tok-val" name="_token">'
        name, value = _extract_csrf_token(html)
        assert name == "_token"
        assert value == "tok-val"


# ---------------------------------------------------------------------------
# TestOAuth2Provider
# ---------------------------------------------------------------------------


class TestOAuth2Provider:
    """Test the OAuth2 client_credentials provider."""

    def test_provider_name(self):
        config = AuthConfig(
            auth_type=AuthType.OAUTH2,
            client_id="id",
            client_secret="secret",
            token_url="/token",
        )
        provider = OAuth2Provider(config)
        assert provider.name == "oauth2"

    def test_is_authenticated_false_without_header(self):
        config = AuthConfig(
            auth_type=AuthType.OAUTH2,
            client_id="id",
            client_secret="secret",
            token_url="/token",
        )
        provider = OAuth2Provider(config)
        session = requests.Session()
        assert provider.is_authenticated(session) is False

    def test_is_authenticated_true_with_bearer_header(self):
        config = AuthConfig(
            auth_type=AuthType.OAUTH2,
            client_id="id",
            client_secret="secret",
            token_url="/token",
        )
        provider = OAuth2Provider(config)
        session = requests.Session()
        session.headers["Authorization"] = "Bearer access-tok"
        assert provider.is_authenticated(session) is True

    def test_is_authenticated_detects_expiry(self):
        config = AuthConfig(
            auth_type=AuthType.OAUTH2,
            client_id="id",
            client_secret="secret",
            token_url="/token",
        )
        provider = OAuth2Provider(config)
        provider._expires_at = time.time() - 100
        session = requests.Session()
        session.headers["Authorization"] = "Bearer access-tok"
        assert provider.is_authenticated(session) is False

    def test_is_authenticated_detects_near_expiry(self):
        """OAuth2 proactively refreshes within 30 seconds of expiration."""
        config = AuthConfig(
            auth_type=AuthType.OAUTH2,
            client_id="id",
            client_secret="secret",
            token_url="/token",
        )
        provider = OAuth2Provider(config)
        provider._expires_at = time.time() + 10  # expires in 10 seconds (< 30s threshold)
        session = requests.Session()
        session.headers["Authorization"] = "Bearer access-tok"
        assert provider.is_authenticated(session) is False

    def test_authenticate_requires_token_url(self):
        config = AuthConfig(auth_type=AuthType.OAUTH2, client_id="id", client_secret="secret")
        provider = OAuth2Provider(config)
        session = requests.Session()
        with pytest.raises(AuthenticationFailedError, match="token_url"):
            provider.authenticate(session, "http://localhost")

    def test_authenticate_requires_client_id(self):
        config = AuthConfig(auth_type=AuthType.OAUTH2, client_secret="secret", token_url="/token")
        provider = OAuth2Provider(config)
        session = requests.Session()
        with pytest.raises(AuthenticationFailedError, match="client_id"):
            provider.authenticate(session, "http://localhost")

    def test_authenticate_requires_client_secret(self):
        config = AuthConfig(auth_type=AuthType.OAUTH2, client_id="id", token_url="/token")
        provider = OAuth2Provider(config)
        session = requests.Session()
        with pytest.raises(AuthenticationFailedError, match="client_secret"):
            provider.authenticate(session, "http://localhost")

    def test_subclasses_auth_provider(self):
        config = AuthConfig(
            auth_type=AuthType.OAUTH2,
            client_id="id",
            client_secret="secret",
            token_url="/token",
        )
        provider = OAuth2Provider(config)
        assert isinstance(provider, AuthProvider)
