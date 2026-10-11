"""Unit tests for JWT access tokens and refresh token hashing."""

from datetime import timedelta

import pytest

from rbacapi.core.exceptions import InvalidTokenError
from rbacapi.core.tokens import (
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_refresh_token,
)


def test_create_and_decode_access_token() -> None:
    """Verify creating a valid JWT access token and decoding all claims."""
    token = create_access_token(
        user_id="u-100",
        username="alice",
        roles=["Admin"],
        permissions=["users:read", "users:write"],
        tenant_id="tenant-alpha",
        mfa_authenticated=True,
    )

    claims = decode_access_token(token)
    assert claims.sub == "u-100"
    assert claims.username == "alice"
    assert claims.roles == ["Admin"]
    assert "users:read" in claims.permissions
    assert claims.tenant_id == "tenant-alpha"
    assert claims.mfa_authenticated is True
    assert claims.exp > claims.iat


def test_expired_access_token() -> None:
    """Verify expired JWT access token raises InvalidTokenError."""
    token = create_access_token(
        user_id="u-101",
        username="bob",
        roles=["Viewer"],
        permissions=["reports:read"],
        expires_delta=timedelta(seconds=-10),  # Expired in past
    )

    with pytest.raises(InvalidTokenError, match="expired"):
        decode_access_token(token)


def test_tampered_access_token() -> None:
    """Verify tampered signature raises InvalidTokenError."""
    token = create_access_token(
        user_id="u-102",
        username="charlie",
        roles=["Analyst"],
        permissions=[],
    )

    # Tamper with payload
    parts = token.split(".")
    tampered_token = f"{parts[0]}.eyJhZG1pbiI6IHRydWV9.{parts[2]}"

    with pytest.raises(InvalidTokenError):
        decode_access_token(tampered_token)

    # Wrong secret key
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, secret_key="wrong-secret-key-32-bytes-long-now")


def test_refresh_token_generation_and_hashing() -> None:
    """Verify high-entropy refresh token generation and cryptographic hash matching."""
    raw_token, token_hash = generate_refresh_token()
    assert len(raw_token) > 20
    assert len(token_hash) == 64

    # Verify re-hashing yields exact match
    assert hash_refresh_token(raw_token) == token_hash
    assert hash_refresh_token("altered_token") != token_hash
