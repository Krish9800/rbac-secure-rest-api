"""Cryptographic password hashing (Argon2id) and TOTP MFA utilities."""

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from rbacapi.config.settings import settings


def get_password_hasher(
    time_cost: int | None = None,
    memory_cost: int | None = None,
    parallelism: int | None = None,
) -> PasswordHasher:
    """Instantiate an Argon2id password hasher with configured parameters."""
    return PasswordHasher(
        time_cost=time_cost or settings.argon2_time_cost,
        memory_cost=memory_cost or settings.argon2_memory_cost,
        parallelism=parallelism or settings.argon2_parallelism,
    )


def hash_password(
    password: str,
    time_cost: int | None = None,
    memory_cost: int | None = None,
    parallelism: int | None = None,
) -> str:
    """Hash plaintext password using Argon2id."""
    hasher = get_password_hasher(time_cost, memory_cost, parallelism)
    return hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Cryptographically verify password against stored Argon2id hash."""
    hasher = get_password_hasher()
    try:
        return hasher.verify(password_hash, password)
    except (VerifyMismatchError, Exception):
        return False


def needs_rehash(password_hash: str) -> bool:
    """Check if hash parameters are outdated and require re-hashing."""
    hasher = get_password_hasher()
    try:
        return hasher.check_needs_rehash(password_hash)
    except Exception:
        return True


def generate_mfa_secret() -> str:
    """Generate a random Base32 TOTP shared secret."""
    return pyotp.random_base32()


def get_mfa_provisioning_uri(
    username: str,
    secret: str,
    issuer: str | None = None,
) -> str:
    """Generate an otpauth:// provisioning URI for QR code generation."""
    issuer_name = issuer or settings.mfa_issuer
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer_name)


def verify_totp_code(secret: str, code: str, valid_window: int = 1) -> bool:
    """Verify a 6-digit TOTP code against the shared secret."""
    clean_code = code.strip().replace(" ", "")
    if not clean_code.isdigit() or len(clean_code) != 6:
        return False
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(clean_code, valid_window=valid_window))
