"""FastAPI application factory and middleware configuration."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from rbacapi.api.routes.audit import router as audit_router
from rbacapi.api.routes.auth import router as auth_router
from rbacapi.api.routes.resources import router as resources_router
from rbacapi.api.routes.roles import router as roles_router
from rbacapi.api.routes.users import router as users_router
from rbacapi.audit.hash_chain import AuditLedger
from rbacapi.config.settings import Settings
from rbacapi.config.settings import settings as global_settings
from rbacapi.db.database import DatabaseManager
from rbacapi.middleware.rate_limiter import RateLimitMiddleware, SlidingWindowRateLimiter
from rbacapi.middleware.security_headers import SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan managing DB and ledger lifecycle."""
    settings: Settings = app.state.settings
    db = DatabaseManager(settings.db_path)
    db.init_db()

    audit_ledger = AuditLedger(db)

    app.state.db = db
    app.state.audit_ledger = audit_ledger

    yield


def create_app(
    settings: Settings | None = None,
    limiter: SlidingWindowRateLimiter | None = None,
) -> FastAPI:
    """Construct and configure the secure REST API FastAPI application."""
    app_settings: Settings = settings or global_settings

    app = FastAPI(
        title="RBAC/ABAC Zero Trust Security REST API",
        version="1.0.0",
        description=(
            "Production-grade FastAPI REST service enforcing hierarchical RBAC, "
            "contextual ABAC, cryptographic hash-chained audit logging, Argon2id, "
            "TOTP MFA, and refresh token rotation."
        ),
        lifespan=lifespan,
    )

    app.state.settings = app_settings

    # Initialize state instances immediately for TestClient direct usage
    db = DatabaseManager(app_settings.db_path)
    db.init_db()
    app.state.db = db
    app.state.audit_ledger = AuditLedger(db)

    # Security headers middleware
    app.add_middleware(
        SecurityHeadersMiddleware,
        content_security_policy=app_settings.content_security_policy,
        enable_hsts=app_settings.enable_hsts,
    )

    # Rate limiting middleware
    rate_limiter = limiter or SlidingWindowRateLimiter(
        max_requests=app_settings.rate_limit_requests,
        window_seconds=app_settings.rate_limit_window_seconds,
        lockout_duration_seconds=app_settings.lockout_duration_seconds,
    )
    app.add_middleware(RateLimitMiddleware, limiter=rate_limiter)

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Include route modules
    api_v1 = "/api/v1"
    app.include_router(auth_router, prefix=api_v1)
    app.include_router(users_router, prefix=api_v1)
    app.include_router(roles_router, prefix=api_v1)
    app.include_router(resources_router, prefix=api_v1)
    app.include_router(audit_router, prefix=api_v1)

    @app.get("/health", tags=["Health"])
    def health_check() -> dict[str, Any]:
        return {
            "status": "healthy",
            "app_name": app_settings.app_name,
            "version": "1.0.0",
            "environment": app_settings.environment,
        }

    return app
