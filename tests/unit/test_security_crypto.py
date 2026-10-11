"""Unit tests for Argon2id password hashing and TOTP MFA."""

import pyotp

from rbacapi.core.security import (
    generate_mfa_secret,
    get_mfa_provisioning_uri,
    hash_password,
    needs_rehash,
    verify_password,
    verify_totp_code,
)


def test_argon2id_hashing_and_verification() -> None:
    """Verify password hashing, correct verification, and wrong password rejection."""
    password = "CorrectHorseBatteryStaple123!"
    hashed = hash_password(password, time_cost=1, memory_cost=1024, parallelism=1)

    assert hashed.startswith("$argon2id$")
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False


def test_needs_rehash() -> None:
    """Verify checking whether a password hash requires upgrading."""
    password = "TestPassword123!"
    hashed = hash_password(password, time_cost=1, memory_cost=1024, parallelism=1)
    # Check returns boolean without raising
    assert isinstance(needs_rehash(hashed), bool)


def test_totp_mfa_generation_and_validation() -> None:
    """Verify TOTP secret generation, URI format, and code verification."""
    secret = generate_mfa_secret()
    assert len(secret) >= 16

    uri = get_mfa_provisioning_uri("alice", secret, issuer="TestIssuer")
    assert uri.startswith("otpauth://totp/")
    assert "alice" in uri
    assert "TestIssuer" in uri

    # Generate current valid code using pyotp
    totp = pyotp.TOTP(secret)
    current_code = totp.now()

    assert verify_totp_code(secret, current_code) is True
    assert verify_totp_code(secret, "000000") is False
    assert verify_totp_code(secret, "invalid") is False
    assert verify_totp_code(secret, "123") is False
