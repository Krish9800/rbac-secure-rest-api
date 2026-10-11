"""OWASP recommended security headers middleware."""

from typing import Any

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforces strict OWASP defense-in-depth security headers."""

    def __init__(
        self,
        app: Any,
        content_security_policy: str = "default-src 'none'; frame-ancestors 'none';",
        enable_hsts: bool = True,
    ) -> None:
        super().__init__(app)
        self.csp = content_security_policy
        self.enable_hsts = enable_hsts

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        # Enforce security response headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = self.csp
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        if self.enable_hsts:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        return response
