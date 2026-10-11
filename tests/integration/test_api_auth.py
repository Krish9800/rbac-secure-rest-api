"""Integration tests for authentication, MFA, and refresh token rotation routes."""

from pathlib import Path

import pytest
from starlette.testclient import TestClient

from rbacapi.api.app import create_app
from rbacapi.config.settings import Settings
from rbacapi.core.security import generate_mfa_secret, hash_password
from rbacapi.db.database import DatabaseManager
from rbacapi.models.enums import RoleType
from rbacapi.models.user import User


@pytest.fixture
def api_test_bed(tmp_path: Path) -> tuple[TestClient, DatabaseManager]:
    db_file = tmp_path / "integration_auth.db"
    settings = Settings(
        db_path=db_file,
        secret_key="test-integration-secret-key-at-least-32-chars",  # nosec B105
        rate_limit_requests=1000,
    )
    app = create_app(settings=settings)
    db: DatabaseManager = app.state.db

    # Create admin user
    admin_role = db.get_role_by_name("Admin")
    admin_user = User(
        user_id="usr-admin",
        username="admin",
        email="admin@sec.internal",
        password_hash=hash_password("AdminSecurePassword123!"),
        roles=[admin_role] if admin_role else [],
    )
    db.create_user(admin_user)

    client = TestClient(app)
    return client, db


def test_auth_login_success_and_me(api_test_bed: tuple[TestClient, DatabaseManager]) -> None:
    client, _ = api_test_bed

    # 1. Login with admin
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "AdminSecurePassword123!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data

    access_token = data["access_token"]
    refresh_token = data["refresh_token"]

    # 2. Access /me
    me_resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_resp.status_code == 200
    user_data = me_resp.json()
    assert user_data["username"] == "admin"

    # 3. Refresh token
    ref_resp = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert ref_resp.status_code == 200
    new_tokens = ref_resp.json()
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens
    assert new_tokens["refresh_token"] != refresh_token


def test_auth_refresh_token_reuse_detection(
    api_test_bed: tuple[TestClient, DatabaseManager],
) -> None:
    client, _ = api_test_bed

    # Login
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "AdminSecurePassword123!"},
    )
    original_refresh = resp.json()["refresh_token"]

    # First rotation succeeds
    ref1 = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original_refresh},
    )
    assert ref1.status_code == 200

    # Malicious replay attack using original_refresh again
    ref2 = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original_refresh},
    )
    assert ref2.status_code == 401
    assert "Token reuse detected" in ref2.json()["detail"]


def test_auth_login_mfa_challenge_and_verification(
    api_test_bed: tuple[TestClient, DatabaseManager],
) -> None:
    client, db = api_test_bed

    mfa_secret = generate_mfa_secret()
    analyst_role = db.get_role_by_name(RoleType.ANALYST.value)
    mfa_user = User(
        user_id="usr-mfa",
        username="mfa_user",
        email="mfa@sec.internal",
        password_hash=hash_password("MfaPassword123!"),
        mfa_enabled=True,
        mfa_secret=mfa_secret,
        roles=[analyst_role] if analyst_role else [],
    )
    db.create_user(mfa_user)

    # 1. Login triggers MFA challenge
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "mfa_user", "password": "MfaPassword123!"},
    )
    assert login_resp.status_code == 200
    challenge_data = login_resp.json()
    assert challenge_data.get("mfa_required") is True
    session_token = challenge_data["mfa_session_token"]

    # 2. MFA verify with bad TOTP fails
    bad_resp = client.post(
        "/api/v1/auth/mfa-verify",
        json={"mfa_session_token": session_token, "totp_code": "000000"},
    )
    assert bad_resp.status_code == 401

    # 3. MFA verify with valid TOTP succeeds
    import pyotp

    valid_code = pyotp.TOTP(mfa_secret).now()
    good_resp = client.post(
        "/api/v1/auth/mfa-verify",
        json={"mfa_session_token": session_token, "totp_code": valid_code},
    )
    assert good_resp.status_code == 200
    token_data = good_resp.json()
    assert "access_token" in token_data
