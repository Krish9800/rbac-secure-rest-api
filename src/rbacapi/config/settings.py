"""Configuration settings for RBAC Secure REST API service."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application runtime security and system settings."""

    model_config = SettingsConfigDict(
        env_prefix="RBACAPI_",
        env_file=".env",
        extra="ignore",
    )

    # Cryptographic keys
    secret_key: str = "super-secret-rbac-jwt-key-minimum-32-chars-long"  # nosec B105
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7

    # Storage settings
    db_path: Path = Path("data/rbacapi.db")

    # Argon2id parameters
    argon2_time_cost: int = 2
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 2

    # Rate limiting & account lockout
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    max_failed_logins: int = 5
    lockout_duration_seconds: int = 900

    # Multi-factor authentication
    mfa_issuer: str = "RBAC-Secure-API"

    # Security headers & CORS
    cors_origins: list[str] = ["*"]
    content_security_policy: str = "default-src 'none'; frame-ancestors 'none';"
    enable_hsts: bool = True
    app_name: str = "RBAC Secure REST API"
    environment: str = "production"


settings = Settings()
