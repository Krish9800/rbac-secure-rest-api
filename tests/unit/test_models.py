"""Unit tests for domain models, role resolution, and audit integrity."""

from datetime import UTC, datetime, timedelta

from rbacapi.models.audit import AuditLogEntry
from rbacapi.models.enums import (
    AccessDecision,
    AuditEventType,
    PermissionAction,
    ResourceType,
    RoleType,
    UserStatus,
)
from rbacapi.models.role import Permission, Role
from rbacapi.models.user import User, UserResponse


def test_permission_model() -> None:
    """Verify permission model string serialization."""
    perm = Permission(
        permission_id="p-1",
        resource=ResourceType.USERS,
        action=PermissionAction.READ,
        description="Read users",
    )
    assert perm.as_string() == "users:read"


def test_role_permission_matching() -> None:
    """Verify role permission resolution and wildcard MANAGE logic."""
    read_users = Permission(
        permission_id="p-1",
        resource=ResourceType.USERS,
        action=PermissionAction.READ,
    )
    manage_reports = Permission(
        permission_id="p-2",
        resource=ResourceType.REPORTS,
        action=PermissionAction.MANAGE,
    )

    analyst_role = Role(
        role_id="r-analyst",
        name="Analyst",
        role_type=RoleType.ANALYST,
        permissions=[read_users, manage_reports],
    )

    # Direct match
    assert analyst_role.has_permission(ResourceType.USERS, PermissionAction.READ) is True
    assert analyst_role.has_permission(ResourceType.USERS, PermissionAction.DELETE) is False

    # MANAGE gives full rights on REPORTS
    assert analyst_role.has_permission(ResourceType.REPORTS, PermissionAction.READ) is True
    assert analyst_role.has_permission(ResourceType.REPORTS, PermissionAction.DELETE) is True
    assert analyst_role.has_permission(ResourceType.REPORTS, PermissionAction.EXPORT) is True

    # SuperAdmin has all permissions
    super_admin_role = Role(
        role_id="r-super",
        name="SuperAdmin",
        role_type=RoleType.SUPER_ADMIN,
    )
    assert (
        super_admin_role.has_permission(ResourceType.SYSTEM_CONFIG, PermissionAction.DELETE) is True
    )
    assert len(super_admin_role.permission_strings()) > 20


def test_user_permissions_and_status() -> None:
    """Verify user permission aggregation and account lockout detection."""
    role = Role(
        role_id="r-viewer",
        name="Viewer",
        role_type=RoleType.VIEWER,
        permissions=[
            Permission(
                permission_id="p-view",
                resource=ResourceType.REPORTS,
                action=PermissionAction.READ,
            )
        ],
    )

    user = User(
        user_id="u-1",
        username="alice",
        email="alice@example.com",
        password_hash="hash-123",
        roles=[role],
        status=UserStatus.ACTIVE,
    )

    assert user.has_permission(ResourceType.REPORTS, PermissionAction.READ) is True
    assert user.has_permission(ResourceType.REPORTS, PermissionAction.DELETE) is False

    # Inactive / suspended status denies permission
    user.status = UserStatus.SUSPENDED
    assert user.has_permission(ResourceType.REPORTS, PermissionAction.READ) is False

    # Lockout check
    user.status = UserStatus.ACTIVE
    assert user.is_locked() is False

    user.locked_until = datetime.now(UTC) + timedelta(minutes=10)
    assert user.is_locked() is True

    user.locked_until = datetime.now(UTC) - timedelta(minutes=1)
    assert user.is_locked() is False


def test_user_response_credential_masking() -> None:
    """Verify UserResponse masks sensitive credentials like password hash and MFA secret."""
    user = User(
        user_id="u-2",
        username="bob",
        email="bob@example.com",
        password_hash="argon2id$sensitive_hash_secret",
        mfa_enabled=True,
        mfa_secret="JBSWY3DPEHPK3PXP",
    )

    dto = UserResponse.from_user(user)
    assert dto.username == "bob"
    assert not hasattr(dto, "password_hash")
    assert not hasattr(dto, "mfa_secret")


def test_audit_log_entry_cryptographic_integrity() -> None:
    """Verify SHA-256 hash chaining computation and tamper detection."""
    now = datetime.now(UTC)
    prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    current_hash = AuditLogEntry.compute_hash(
        previous_hash=prev_hash,
        timestamp=now,
        event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
        user_id="u-1",
        role="Admin",
        resource="AUTH",
        action="LOGIN",
        decision=AccessDecision.PERMIT,
        ip_address="192.168.1.100",
        details={"method": "password"},
    )

    entry = AuditLogEntry(
        entry_id="audit-1",
        timestamp=now,
        event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
        user_id="u-1",
        role="Admin",
        resource="AUTH",
        action="LOGIN",
        decision=AccessDecision.PERMIT,
        ip_address="192.168.1.100",
        details={"method": "password"},
        previous_hash=prev_hash,
        current_hash=current_hash,
    )

    assert entry.verify_integrity() is True

    # Tampering with IP address or decision violates integrity
    entry.ip_address = "10.0.0.99"
    assert entry.verify_integrity() is False
