"""Foundation and settings test suite for RBAC Secure REST API."""

from rbacapi import __version__
from rbacapi.config.settings import Settings, settings


def test_package_metadata() -> None:
    """Verify package version is defined."""
    assert __version__ == "1.0.0"


def test_default_settings() -> None:
    """Verify default security configuration parameters."""
    assert settings.jwt_algorithm == "HS256"
    assert settings.jwt_access_token_expire_minutes == 15
    assert settings.jwt_refresh_token_expire_days == 7
    assert settings.max_failed_logins == 5
    assert settings.lockout_duration_seconds == 900
    assert settings.mfa_issuer == "RBAC-Secure-API"


def test_custom_settings(test_settings: Settings) -> None:
    """Verify custom test settings override Argon2 and storage parameters."""
    assert test_settings.argon2_time_cost == 1
    assert test_settings.argon2_memory_cost == 1024
    assert test_settings.argon2_parallelism == 1
