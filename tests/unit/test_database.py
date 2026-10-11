"""Unit tests for SQLite database manager, transactions, and seeding."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from rbacapi.core.tokens import RefreshTokenRecord
from rbacapi.db.database import DatabaseManager
from rbacapi.models.audit import AuditLogEntry
from rbacapi.models.enums import (
    AccessDecision,
    AuditEventType,
    UserStatus,
)
from rbacapi.models.user import User


def test_init_db_and_seeding(tmp_path: Path) -> None:
    """Verify database schema creation and default roles/permissions seeding."""
    db_file = tmp_path / "test_rbac.db"
    db = DatabaseManager(db_file)

    roles = db.list_roles()
    role_names = {r.name for r in roles}
    assert "SuperAdmin" in role_names
    assert "Admin" in role_names
    assert "Auditor" in role_names
    assert "Analyst" in role_names
    assert "Viewer" in role_names

    permissions = db.list_permissions()
    assert len(permissions) >= 30


def test_user_lifecycle(tmp_path: Path) -> None:
    """Verify user persistence, retrieval by id/username, updating, and deletion."""
    db_file = tmp_path / "test_rbac.db"
    db = DatabaseManager(db_file)

    admin_role = db.get_role_by_name("Admin")
    assert admin_role is not None

    user = User(
        user_id="u-001",
        username="alice",
        email="alice@corp.local",
        password_hash="argon2id$mock_hash",
        roles=[admin_role],
        status=UserStatus.ACTIVE,
    )
    db.create_user(user)

    fetched = db.get_user_by_id("u-001")
    assert fetched is not None
    assert fetched.username == "alice"
    assert len(fetched.roles) == 1
    assert fetched.roles[0].name == "Admin"

    by_username = db.get_user_by_username("alice")
    assert by_username is not None
    assert by_username.user_id == "u-001"

    # Update user status
    fetched.status = UserStatus.SUSPENDED
    fetched.failed_login_attempts = 3
    db.update_user(fetched)

    updated = db.get_user_by_id("u-001")
    assert updated is not None
    assert updated.status == UserStatus.SUSPENDED
    assert updated.failed_login_attempts == 3

    # List users
    users = db.list_users(limit=10)
    assert len(users) == 1

    # Delete user
    deleted = db.delete_user("u-001")
    assert deleted is True
    assert db.get_user_by_id("u-001") is None


def test_role_assignment_and_revocation(tmp_path: Path) -> None:
    """Verify role assignment to user and revocation."""
    db_file = tmp_path / "test_rbac.db"
    db = DatabaseManager(db_file)

    user = User(
        user_id="u-002",
        username="bob",
        email="bob@corp.local",
        password_hash="argon2id$mock_hash",
        roles=[],
        status=UserStatus.ACTIVE,
    )
    db.create_user(user)

    viewer_role = db.get_role_by_name("Viewer")
    assert viewer_role is not None

    db.assign_role_to_user("u-002", viewer_role.role_id)
    u_with_role = db.get_user_by_id("u-002")
    assert u_with_role is not None
    assert len(u_with_role.roles) == 1

    db.revoke_role_from_user("u-002", viewer_role.role_id)
    u_no_role = db.get_user_by_id("u-002")
    assert u_no_role is not None
    assert len(u_no_role.roles) == 0


def test_refresh_token_storage_and_family_revocation(tmp_path: Path) -> None:
    """Verify refresh token storage, hash lookup, and family revocation."""
    db_file = tmp_path / "test_rbac.db"
    db = DatabaseManager(db_file)

    user = User(
        user_id="u-003",
        username="charlie",
        email="charlie@corp.local",
        password_hash="argon2id$mock_hash",
        roles=[],
    )
    db.create_user(user)

    tok1 = RefreshTokenRecord(
        token_id="tok-1",
        user_id="u-003",
        token_hash="hash-1111",
        family_id="fam-alpha",
        is_revoked=False,
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    tok2 = RefreshTokenRecord(
        token_id="tok-2",
        user_id="u-003",
        token_hash="hash-2222",
        family_id="fam-alpha",
        is_revoked=False,
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    db.save_refresh_token(tok1)
    db.save_refresh_token(tok2)

    found = db.get_refresh_token_by_hash("hash-1111")
    assert found is not None
    assert found.family_id == "fam-alpha"
    assert found.is_revoked is False

    # Revoke family on compromise
    revoked_count = db.revoke_token_family("fam-alpha")
    assert revoked_count == 2

    rechecked = db.get_refresh_token_by_hash("hash-1111")
    assert rechecked is not None
    assert rechecked.is_revoked is True


def test_audit_log_persistence(tmp_path: Path) -> None:
    """Verify audit log entries are saved and retrieved in sequence."""
    db_file = tmp_path / "test_rbac.db"
    db = DatabaseManager(db_file)

    entry = AuditLogEntry(
        entry_id="audit-001",
        timestamp=datetime.now(UTC),
        event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
        user_id="u-001",
        role="Admin",
        resource="AUTH",
        action="LOGIN",
        decision=AccessDecision.PERMIT,
        ip_address="127.0.0.1",
        details={"status": "ok"},
        previous_hash="0000000000000000000000000000000000000000000000000000000000000000",
        current_hash="1111111111111111111111111111111111111111111111111111111111111111",
    )
    db.save_audit_entry(entry)

    last_entry = db.get_last_audit_entry()
    assert last_entry is not None
    assert last_entry.entry_id == "audit-001"

    entries = db.list_audit_entries(limit=10)
    assert len(entries) == 1
    assert entries[0].entry_id == "audit-001"
