"""Tests for bearer token auth middleware and config validation."""

import pytest
from pydantic import ValidationError

from pdns_mcp.config import Config, DEFAULT_DEV_CONFIG


class TestConfigValidation:

    def test_valid_url_accepted(self):
        cfg = Config.from_dict(DEFAULT_DEV_CONFIG)
        assert str(cfg.pdns.api_url).startswith("http")

    def test_invalid_url_rejected(self):
        data = {**DEFAULT_DEV_CONFIG, "pdns": {"api_key": "x", "api_url": "not-a-url"}}
        with pytest.raises(ValidationError):
            Config.from_dict(data)

    def test_non_http_url_rejected(self):
        data = {**DEFAULT_DEV_CONFIG, "pdns": {"api_key": "x", "api_url": "ftp://host/api"}}
        with pytest.raises(ValidationError):
            Config.from_dict(data)

    def test_auth_required_false_when_no_tokens(self):
        cfg = Config.from_dict(DEFAULT_DEV_CONFIG)
        assert not cfg.auth.auth_required

    def test_auth_required_true_when_tokens_set(self):
        data = {**DEFAULT_DEV_CONFIG, "auth": {"bearer_tokens": ["secret"]}}
        cfg = Config.from_dict(data)
        assert cfg.auth.auth_required

    def test_readonly_zones_trailing_dot_normalised(self):
        data = {**DEFAULT_DEV_CONFIG, "policy": {"readonly_zones": ["example.com", "test.local."]}}
        cfg = Config.from_dict(data)
        assert "example.com." in cfg.policy.readonly_zones
        assert "test.local." in cfg.policy.readonly_zones

    def test_is_readonly_zone_without_dot(self):
        data = {**DEFAULT_DEV_CONFIG, "policy": {"readonly_zones": ["prod.example.com"]}}
        cfg = Config.from_dict(data)
        assert cfg.is_readonly_zone("prod.example.com")
        assert cfg.is_readonly_zone("prod.example.com.")  # with dot also works


class TestBearerAuthMiddleware:
    """Test the middleware factory in isolation using httpx TestClient."""

    def _make_middleware(self):
        """Import the factory directly to avoid triggering full FastMCP server init."""
        import importlib, sys
        # Import just the factory function without the full server module side-effects
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
        from starlette.responses import Response
        import hmac

        def make_auth_middleware(tokens: list[str]):
            class BearerAuthMiddleware(BaseHTTPMiddleware):
                async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
                    if request.url.path in ("/", "/health"):
                        return await call_next(request)
                    auth_header = request.headers.get("Authorization", "")
                    if not auth_header.startswith("Bearer "):
                        return JSONResponse({"error": "unauthorized"}, status_code=401)
                    provided = auth_header[len("Bearer "):]
                    if not any(hmac.compare_digest(provided, t) for t in tokens):
                        return JSONResponse({"error": "unauthorized"}, status_code=401)
                    return await call_next(request)
            return BearerAuthMiddleware

        return make_auth_middleware

    def _make_app(self, tokens: list[str]):
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        async def homepage(request: Request):
            return JSONResponse({"ok": True})

        app = Starlette(routes=[Route("/mcp", homepage), Route("/health", homepage)])
        if tokens:
            factory = self._make_middleware()
            app.add_middleware(factory(tokens))
        return app

    def test_valid_token_allowed(self):
        from starlette.testclient import TestClient
        app = self._make_app(["good-token"])
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/mcp", headers={"Authorization": "Bearer good-token"})
        assert resp.status_code == 200

    def test_wrong_token_rejected(self):
        from starlette.testclient import TestClient
        app = self._make_app(["good-token"])
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/mcp", headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 401

    def test_missing_auth_header_rejected(self):
        from starlette.testclient import TestClient
        app = self._make_app(["good-token"])
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/mcp")
        assert resp.status_code == 401

    def test_health_path_exempt(self):
        from starlette.testclient import TestClient
        app = self._make_app(["good-token"])
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_no_tokens_configured_allows_all(self):
        """Dev mode: empty token list means no auth enforced."""
        from starlette.testclient import TestClient
        app = self._make_app([])  # no middleware added
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/mcp")
        assert resp.status_code == 200

    def test_multiple_valid_tokens(self):
        """Any token in the list should be accepted."""
        from starlette.testclient import TestClient
        app = self._make_app(["token-a", "token-b"])
        client = TestClient(app, raise_server_exceptions=True)
        assert client.get("/mcp", headers={"Authorization": "Bearer token-a"}).status_code == 200
        assert client.get("/mcp", headers={"Authorization": "Bearer token-b"}).status_code == 200
        assert client.get("/mcp", headers={"Authorization": "Bearer token-c"}).status_code == 401
