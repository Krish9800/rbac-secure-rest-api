"""Unit tests for RateLimitMiddleware and SecurityHeadersMiddleware."""

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from starlette.testclient import TestClient

from rbacapi.middleware.rate_limiter import (
    RateLimitMiddleware,
    SlidingWindowRateLimiter,
)
from rbacapi.middleware.security_headers import SecurityHeadersMiddleware


def test_security_headers_middleware() -> None:
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/ping")
    def ping() -> PlainTextResponse:
        return PlainTextResponse("pong")

    client = TestClient(app)
    response = client.get("/ping")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-XSS-Protection"] == "0"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert "Strict-Transport-Security" in response.headers


def test_rate_limiter_sliding_window_and_lockout() -> None:
    limiter = SlidingWindowRateLimiter(
        max_requests=3,
        window_seconds=10,
        lockout_duration_seconds=50,
        lockout_threshold=2,
    )
    key = "ip:10.0.0.1"

    # 3 allowed requests
    for _ in range(3):
        limited, _ = limiter.is_rate_limited(key)
        assert limited is False

    # 4th request: rate limited (1st violation)
    limited, retry_after = limiter.is_rate_limited(key)
    assert limited is True
    assert retry_after <= 10

    # 5th request: rate limited (2nd violation -> triggers lockout)
    limited, retry_after = limiter.is_rate_limited(key)
    assert limited is True
    assert retry_after >= 50


def test_rate_limiter_middleware_http_integration() -> None:
    limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=5)
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, limiter=limiter)

    @app.get("/data")
    def get_data() -> PlainTextResponse:
        return PlainTextResponse("ok")

    client = TestClient(app)

    # 2 requests pass
    r1 = client.get("/data", headers={"X-Forwarded-For": "1.2.3.4"})
    assert r1.status_code == 200

    r2 = client.get("/data", headers={"X-Forwarded-For": "1.2.3.4"})
    assert r2.status_code == 200

    # 3rd request rejected with 429
    r3 = client.get("/data", headers={"X-Forwarded-For": "1.2.3.4"})
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers
    assert r3.json()["detail"] == "Too many requests. Rate limit exceeded."

    # Different IP is not limited
    r4 = client.get("/data", headers={"X-Forwarded-For": "5.6.7.8"})
    assert r4.status_code == 200
