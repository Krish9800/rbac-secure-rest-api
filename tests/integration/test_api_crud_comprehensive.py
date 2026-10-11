"""Comprehensive integration tests covering users, roles, and audit endpoints."""

from pathlib import Path

import pytest
from starlette.testclient import TestClient

from rbacapi.api.app import create_app
from rbacapi.config.settings import Settings
from rbacapi.core.security import hash_password
from rbacapi.db.database import DatabaseManager
from rbacapi.models.enums import UserStatus
from rbacapi.models.user import User


@pytest.fixture
def test_suite(tmp_path: Path) -> dict[str, str | TestClient | DatabaseManager]:
    db_file = tmp_path / "comprehensive_test.db"
    settings = Settings(
        db_path=db_file,
        secret_key="comprehensive-test-secret-key-32-chars-long",  # nosec B105
        rate_limit_requests=1000,
    )
    app = create_app(settings=settings)
    client = TestClient(app)
    db: DatabaseManager = app.state.db

    # SuperAdmin
    superadmin_role = db.get_role_by_name("SuperAdmin")
    superadmin = User(
        user_id="usr-superadmin",
        username="superadmin",
        email="superadmin@sec.internal",
        password_hash=hash_password("SuperAdmin123!"),
        roles=[superadmin_role] if superadmin_role else [],
    )
    db.create_user(superadmin)

    # Admin
    admin_role = db.get_role_by_name("Admin")
    admin = User(
        user_id="usr-admin",
        username="admin",
        email="admin@sec.internal",
        password_hash=hash_password("AdminPass123!"),
        roles=[admin_role] if admin_role else [],
    )
    db.create_user(admin)

    # Tokens
    sa_token = client.post(
        "/api/v1/auth/login",
        json={"username": "superadmin", "password": "SuperAdmin123!"},
    ).json()["access_token"]

    adm_token = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "AdminPass123!"},
    ).json()["access_token"]

    return {
        "client": client,
        "db": db,
        "sa_token": sa_token,
        "adm_token": adm_token,
    }


def test_user_crud_operations(test_suite: dict[str, str | TestClient | DatabaseManager]) -> None:
    client = test_suite["client"]
    adm_token = test_suite["adm_token"]
    assert isinstance(client, TestClient)

    headers = {"Authorization": f"Bearer {adm_token}"}

    # 1. Create User
    create_payload = {
        "username": "alice_test",
        "email": "alice@sec.internal",
        "password": "AlicePassword123!",
        "tenant_id": "tenant_alice",
        "role_ids": ["role-viewer"],
    }
    r_create = client.post("/api/v1/users", json=create_payload, headers=headers)
    assert r_create.status_code == 201
    user_data = r_create.json()
    user_id = user_data["user_id"]
    assert user_data["username"] == "alice_test"

    # 2. Duplicate create fails 409
    r_dup = client.post("/api/v1/users", json=create_payload, headers=headers)
    assert r_dup.status_code == 409

    # 3. Get User by ID
    r_get = client.get(f"/api/v1/users/{user_id}", headers=headers)
    assert r_get.status_code == 200
    assert r_get.json()["email"] == "alice@sec.internal"

    # 4. Patch User (status, email, role)
    r_patch = client.patch(
        f"/api/v1/users/{user_id}",
        json={"email": "alice_new@sec.internal", "status": UserStatus.ACTIVE.value},
        headers=headers,
    )
    assert r_patch.status_code == 200
    assert r_patch.json()["email"] == "alice_new@sec.internal"

    # 5. List Users
    r_list = client.get("/api/v1/users?limit=10", headers=headers)
    assert r_list.status_code == 200
    assert len(r_list.json()) >= 3

    # 6. Delete User
    r_del = client.delete(f"/api/v1/users/{user_id}", headers=headers)
    assert r_del.status_code == 200

    # 7. Get deleted user fails 404
    r_notfound = client.get(f"/api/v1/users/{user_id}", headers=headers)
    assert r_notfound.status_code == 404


def test_roles_and_permissions_endpoints(
    test_suite: dict[str, str | TestClient | DatabaseManager],
) -> None:
    client = test_suite["client"]
    adm_token = test_suite["adm_token"]
    assert isinstance(client, TestClient)

    headers = {"Authorization": f"Bearer {adm_token}"}

    # 1. List roles
    r_roles = client.get("/api/v1/roles", headers=headers)
    assert r_roles.status_code == 200
    roles = r_roles.json()
    assert len(roles) >= 4

    # 2. List permissions
    r_perms = client.get("/api/v1/roles/permissions", headers=headers)
    assert r_perms.status_code == 200
    perms = r_perms.json()
    assert len(perms) > 0

    # 3. Assign role to user
    r_assign = client.post(
        "/api/v1/roles/assign",
        json={"user_id": "usr-admin", "role_id": "role-auditor"},
        headers=headers,
    )
    assert r_assign.status_code == 200

    # 4. Revoke role from user
    r_revoke = client.post(
        "/api/v1/roles/revoke",
        json={"user_id": "usr-admin", "role_id": "role-auditor"},
        headers=headers,
    )
    assert r_revoke.status_code == 200


def test_audit_entries_and_reports_endpoints(
    test_suite: dict[str, str | TestClient | DatabaseManager],
) -> None:
    client = test_suite["client"]
    adm_token = test_suite["adm_token"]
    assert isinstance(client, TestClient)

    headers = {"Authorization": f"Bearer {adm_token}"}

    # 1. Get reports
    r_rep = client.get("/api/v1/resources/reports", headers=headers)
    assert r_rep.status_code == 200
    assert "reports" in r_rep.json()

    # 2. Get audit entries
    r_audit = client.get("/api/v1/audit/entries?limit=50", headers=headers)
    assert r_audit.status_code == 200
    entries = r_audit.json()
    assert len(entries) > 0
    assert "entry_id" in entries[0]
    assert "current_hash" in entries[0]

    # 3. Health check
    r_health = client.get("/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "healthy"
