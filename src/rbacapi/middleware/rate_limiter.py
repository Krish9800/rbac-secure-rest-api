"""Sliding-window rate limiter with per-IP / per-user buckets and exponential lockout."""

import time
from collections import defaultdict
from threading import Lock
from typing import Any

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding window rate limiter."""

    def __init__(
        self,
        max_requests: int = 100,
        window_seconds: int = 60,
        lockout_duration_seconds: int = 300,
        lockout_threshold: int = 3,
    ) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.lockout_duration_seconds = lockout_duration_seconds
        self.lockout_threshold = lockout_threshold

        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lockouts: dict[str, float] = {}
        self._violations: dict[str, int] = defaultdict(int)
        self._lock = Lock()

    def _clean_window(self, key: str, now: float) -> None:
        cutoff = now - self.window_seconds
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]

    def is_rate_limited(self, key: str) -> tuple[bool, int]:
        """Check if key is rate limited or locked out.

        Returns (is_limited, retry_after_seconds).
        """
        now = time.time()
        with self._lock:
            # Check lockout
            if key in self._lockouts:
                lockout_end = self._lockouts[key]
                if now < lockout_end:
                    return True, max(1, int(lockout_end - now))
                # Lockout expired
                del self._lockouts[key]

            self._clean_window(key, now)

            if len(self._requests[key]) >= self.max_requests:
                self._violations[key] += 1
                if self._violations[key] >= self.lockout_threshold:
                    # Exponential lockout calculation
                    multiplier = 2 ** min(self._violations[key] - self.lockout_threshold, 4)
                    duration = self.lockout_duration_seconds * multiplier
                    self._lockouts[key] = now + duration
                    return True, duration

                # Regular window rate limit
                oldest = self._requests[key][0]
                retry_after = max(1, int(self.window_seconds - (now - oldest)))
                return True, retry_after

            # Permit request
            self._requests[key].append(now)
            return False, 0

    def reset(self) -> None:
        """Clear all rate limit buckets."""
        with self._lock:
            self._requests.clear()
            self._lockouts.clear()
            self._violations.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware applying sliding window rate limits on incoming HTTP requests."""

    def __init__(
        self,
        app: Any,
        limiter: SlidingWindowRateLimiter | None = None,
    ) -> None:
        super().__init__(app)
        self.limiter = limiter or SlidingWindowRateLimiter()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Determine client key: forwarded IP or client host
        client_ip = request.client.host if request.client else "127.0.0.1"
        if "x-forwarded-for" in request.headers:
            client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()

        key = f"ip:{client_ip}"
        is_limited, retry_after = self.limiter.is_rate_limited(key)

        if is_limited:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Rate limit exceeded.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        response = await call_next(request)
        return response
