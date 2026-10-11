"""Integration tests for RBAC, ABAC tenant/owner boundaries, and audit verification."""

from pathlib import Path

import pytest
from starlette.testclient import TestClient

from rbacapi.api.app import create_app
from rbacapi.config.settings import Settings
from rbacapi.core.security import hash_password
from rbacapi.db.database import DatabaseManager
from rbacapi.models.user import User


@pytest.fixture
def auth_suite(tmp_path: Path) -> dict[str, str | TestClient]:
    db_file = tmp_path / "integration_rbac.db"
    settings = Settings(
        db_path=db_file,
        secret_key="test-integration-rbac-secret-key-32-chars",  # nosec B105
        rate_limit_requests=1000,
    )
    app = create_app(settings=settings)
    client = TestClient(app)
    db: DatabaseManager = app.state.db

    # Create admin
    admin_role = db.get_role_by_name("Admin")
    admin_user = User(
        user_id="usr-admin",
        username="admin",
        email="admin@sec.internal",
        password_hash=hash_password("AdminSecurePassword123!"),
        roles=[admin_role] if admin_role else [],
    )
    db.create_user(admin_user)

    # Create auditor (only has AUDIT_LOGS:READ, REPORTS:READ, USERS:READ)
    auditor_role = db.get_role_by_name("Auditor")
    auditor = User(
        user_id="usr-auditor",
        username="auditor_test",
        email="auditor@sec.internal",
        password_hash=hash_password("AuditorPass123!"),
        roles=[auditor_role] if auditor_role else [],
    )
    db.create_user(auditor)

    # Create Viewer (only has REPORTS:READ)
    viewer_role = db.get_role_by_name("Viewer")
    viewer = User(
        user_id="usr-viewer",
        username="viewer_test",
        email="viewer@sec.internal",
        password_hash=hash_password("ViewerPass123!"),
        roles=[viewer_role] if viewer_role else [],
    )
    db.create_user(viewer)

    # Tenant users
    usr_finance = User(
        user_id="usr_finance",
        username="finance_guy",
        email="finance@sec.internal",
        password_hash=hash_password("FinancePass123!"),
        tenant_id="tenant_a",
        roles=[viewer_role] if viewer_role else [],
    )
    db.create_user(usr_finance)

    usr_engineer = User(
        user_id="usr_engineer",
        username="engineer_guy",
        email="engineer@sec.internal",
        password_hash=hash_password("EngineerPass123!"),
        tenant_id="tenant_b",
        roles=[viewer_role] if viewer_role else [],
    )
    db.create_user(usr_engineer)

    # Login admin
    adm_token = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "AdminSecurePassword123!"},
    ).json()["access_token"]

    # Login viewer
    view_token = client.post(
        "/api/v1/auth/login",
        json={"username": "viewer_test", "password": "ViewerPass123!"},
    ).json()["access_token"]

    # Login finance
    fin_token = client.post(
        "/api/v1/auth/login",
        json={"username": "finance_guy", "password": "FinancePass123!"},
    ).json()["access_token"]

    # Login engineer
    eng_token = client.post(
        "/api/v1/auth/login",
        json={"username": "engineer_guy", "password": "EngineerPass123!"},
    ).json()["access_token"]

    return {
        "client": client,
        "admin_token": adm_token,
        "viewer_token": view_token,
        "fin_token": fin_token,
        "eng_token": eng_token,
    }


def test_rbac_endpoint_access_control(auth_suite: dict[str, str | TestClient]) -> None:
    client = auth_suite["client"]
    admin_token = auth_suite["admin_token"]
    viewer_token = auth_suite["viewer_token"]

    assert isinstance(client, TestClient)

    # Admin can list users (USERS:READ granted to Admin)
    r_adm = client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r_adm.status_code == 200

    # Viewer does NOT have USERS:READ permission (only REPORTS:READ)
    r_view = client.get(
        "/api/v1/users",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r_view.status_code == 403


def test_abac_ownership_and_tenant_isolation(auth_suite: dict[str, str | TestClient]) -> None:
    client = auth_suite["client"]
    fin_token = auth_suite["fin_token"]
    eng_token = auth_suite["eng_token"]

    assert isinstance(client, TestClient)

    # Finance user accesses their own document doc_101 in tenant_a -> 200
    r1 = client.get(
        "/api/v1/resources/documents/doc_101",
        headers={"Authorization": f"Bearer {fin_token}"},
    )
    assert r1.status_code == 200
    assert r1.json()["id"] == "doc_101"

    # Finance user tries to access Engineer's document doc_102 (BOLA/IDOR attempt) -> 403
    r2 = client.get(
        "/api/v1/resources/documents/doc_102",
        headers={"Authorization": f"Bearer {fin_token}"},
    )
    assert r2.status_code == 403
    assert (
        "Cross-tenant access forbidden" in r2.json()["detail"]
        or "Ownership mismatch" in r2.json()["detail"]
    )

    # Engineer accesses doc_102 -> 200
    r3 = client.get(
        "/api/v1/resources/documents/doc_102",
        headers={"Authorization": f"Bearer {eng_token}"},
    )
    assert r3.status_code == 200


def test_audit_ledger_api_verification(auth_suite: dict[str, str | TestClient]) -> None:
    client = auth_suite["client"]
    admin_token = auth_suite["admin_token"]

    assert isinstance(client, TestClient)

    # Verify audit chain via API
    resp = client.get(
        "/api/v1/audit/verify",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_valid"] is True
    assert data["total_entries"] > 0
    assert len(data["corrupted_entry_ids"]) == 0
