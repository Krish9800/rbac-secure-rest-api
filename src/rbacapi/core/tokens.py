"""JWT access tokens and opaque refresh token lifecycle management."""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from pydantic import BaseModel, Field

from rbacapi.config.settings import settings
from rbacapi.core.exceptions import InvalidTokenError


class TokenPayload(BaseModel):
    """Claims embedded within validated JWT access tokens."""

    sub: str
    username: str
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    tenant_id: str = "default"
    mfa_authenticated: bool = False
    exp: int
    iat: int
    jti: str


class RefreshTokenRecord(BaseModel):
    """Storage representation for tracking refresh token rotation and revocation."""

    token_id: str
    user_id: str
    token_hash: str
    family_id: str
    is_revoked: bool = False
    expires_at: datetime


def create_access_token(
    user_id: str,
    username: str,
    roles: list[str],
    permissions: list[str],
    tenant_id: str = "default",
    mfa_authenticated: bool = False,
    expires_delta: timedelta | None = None,
    secret_key: str | None = None,
) -> str:
    """Generate a signed cryptographic JWT access token with user claims."""
    now = datetime.now(UTC)
    delta = expires_delta or timedelta(minutes=settings.jwt_access_token_expire_minutes)
    expire = now + delta

    payload = {
        "sub": user_id,
        "username": username,
        "roles": roles,
        "permissions": permissions,
        "tenant_id": tenant_id,
        "mfa_authenticated": mfa_authenticated,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": f"jwt-{uuid.uuid4().hex[:12]}",
    }

    key = secret_key or settings.secret_key
    return jwt.encode(payload, key, algorithm=settings.jwt_algorithm)


def decode_access_token(
    token: str,
    secret_key: str | None = None,
) -> TokenPayload:
    """Validate and decode a signed JWT access token."""
    key = secret_key or settings.secret_key
    try:
        decoded: dict[str, Any] = jwt.decode(
            token,
            key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "exp", "iat"]},
        )
        return TokenPayload(**decoded)
    except jwt.ExpiredSignatureError as exc:
        raise InvalidTokenError("Access token has expired.") from exc
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(f"Access token validation failed: {exc}") from exc


def generate_refresh_token() -> tuple[str, str]:
    """Generate an opaque high-entropy refresh token and its SHA-256 storage hash."""
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return raw_token, token_hash


def hash_refresh_token(raw_token: str) -> str:
    """Compute SHA-256 hash of a submitted raw refresh token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
