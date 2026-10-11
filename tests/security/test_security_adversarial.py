"""Adversarial and security compliance test suite."""

from pathlib import Path

import pytest
from starlette.testclient import TestClient

from rbacapi.api.app import create_app
from rbacapi.config.settings import Settings
from rbacapi.core.security import hash_password
from rbacapi.core.tokens import create_access_token
from rbacapi.db.database import DatabaseManager
from rbacapi.models.user import User


@pytest.fixture
def adversarial_env(tmp_path: Path) -> tuple[TestClient, DatabaseManager]:
    db_file = tmp_path / "adversarial.db"
    settings = Settings(
        db_path=db_file,
        secret_key="adversarial-test-secret-key-32-chars-at-least",  # nosec B105
        rate_limit_requests=5,
        rate_limit_window_seconds=10,
        max_failed_logins=3,
        lockout_duration_seconds=300,
    )
    app = create_app(settings=settings)
    db: DatabaseManager = app.state.db

    # Create target victim user
    victim_user = User(
        user_id="usr-victim",
        username="victim_user",
        email="victim@sec.internal",
        password_hash=hash_password("VictimPassword123!"),
    )
    db.create_user(victim_user)

    return TestClient(app), db


def test_brute_force_account_lockout(adversarial_env: tuple[TestClient, DatabaseManager]) -> None:
    client, db = adversarial_env

    # Attempt 3 failed logins to trigger account lockout
    for _ in range(3):
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "victim_user", "password": "WrongPassword!"},
        )
        assert resp.status_code == 401

    # 4th login attempt is blocked with 403 Account Locked
    resp4 = client.post(
        "/api/v1/auth/login",
        json={"username": "victim_user", "password": "VictimPassword123!"},
    )
    assert resp4.status_code == 403
    assert "Account is locked" in resp4.json()["detail"]


def test_privilege_escalation_jwt_tampering(
    adversarial_env: tuple[TestClient, DatabaseManager],
) -> None:
    client, db = adversarial_env

    # Forge token with arbitrary SuperAdmin role signed with an attacker key
    fake_token = create_access_token(
        user_id="usr-victim",
        username="victim_user",
        roles=["SuperAdmin"],
        permissions=["users:delete"],
        secret_key="attacker-tampered-secret-key-signature",  # nosec B105
    )

    # Attempt unauthorized deletion using forged signature
    resp = client.delete(
        "/api/v1/users/usr-victim",
        headers={"Authorization": f"Bearer {fake_token}"},
    )
    assert resp.status_code == 401
    assert "Invalid or expired access token" in resp.json()["detail"]


def test_rate_limiting_ddos_defense(
    adversarial_env: tuple[TestClient, DatabaseManager],
) -> None:
    client, _ = adversarial_env

    # Max requests is configured to 5
    for _ in range(5):
        r = client.get("/health")
        assert r.status_code == 200

    # 6th request is throttled
    r_throttled = client.get("/health")
    assert r_throttled.status_code == 429
    assert "Retry-After" in r_throttled.headers
