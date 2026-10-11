"""Unit tests for RBAC, ABAC, and unified Policy Decision Point (PDP)."""

from datetime import UTC, datetime

from rbacapi.models.enums import (
    AccessDecision,
    PermissionAction,
    ResourceType,
    RoleType,
    UserStatus,
)
from rbacapi.models.role import Permission, Role
from rbacapi.models.user import User
from rbacapi.policy.abac import ABACContext, ABACEvaluator, ABACPolicy
from rbacapi.policy.pdp import PolicyDecisionPoint
from rbacapi.policy.rbac import RBACEvaluator


def _create_user(
    user_id: str = "u-01",
    roles: list[Role] | None = None,
    tenant_id: str = "tenant-a",
) -> User:
    return User(
        user_id=user_id,
        username="tester",
        email="tester@example.com",
        password_hash="hash",
        roles=roles or [],
        tenant_id=tenant_id,
        status=UserStatus.ACTIVE,
    )


def test_rbac_evaluator() -> None:
    """Verify RBAC role hierarchy and permission matching."""
    perm_read = Permission(
        permission_id="p-1",
        resource=ResourceType.USERS,
        action=PermissionAction.READ,
    )
    role_viewer = Role(
        role_id="r-1",
        name="UserViewer",
        role_type=RoleType.VIEWER,
        permissions=[perm_read],
    )

    assert RBACEvaluator.evaluate([role_viewer], ResourceType.USERS, PermissionAction.READ) is True
    assert (
        RBACEvaluator.evaluate([role_viewer], ResourceType.USERS, PermissionAction.DELETE) is False
    )

    role_super = Role(
        role_id="r-super",
        name="SuperAdmin",
        role_type=RoleType.SUPER_ADMIN,
    )
    assert (
        RBACEvaluator.evaluate([role_super], ResourceType.FINANCIAL_DATA, PermissionAction.DELETE)
        is True
    )


def test_abac_ip_network_filter() -> None:
    """Verify CIDR allowlist evaluation in ABAC."""
    user = _create_user()
    policy = ABACPolicy(allowed_ip_networks=["192.168.1.0/24", "127.0.0.1/32"])

    ctx_ok = ABACContext(client_ip="192.168.1.42")
    allowed, _ = ABACEvaluator.evaluate(user, ctx_ok, policy)
    assert allowed is True

    ctx_deny = ABACContext(client_ip="10.0.0.5")
    allowed, reason = ABACEvaluator.evaluate(user, ctx_deny, policy)
    assert allowed is False
    assert "not permitted by network policy" in (reason or "")

    # Invalid IP
    ctx_bad = ABACContext(client_ip="invalid-ip")
    allowed, reason = ABACEvaluator.evaluate(user, ctx_bad, policy)
    assert allowed is False
    assert "Invalid client IP" in (reason or "")


def test_abac_time_of_day_window() -> None:
    """Verify business hours time window enforcement."""
    user = _create_user()
    policy = ABACPolicy(allowed_hours=(8, 17))

    t_inside = datetime(2026, 10, 11, 14, 30, tzinfo=UTC)
    ctx_ok = ABACContext(client_ip="127.0.0.1", request_time=t_inside)
    allowed, _ = ABACEvaluator.evaluate(user, ctx_ok, policy)
    assert allowed is True

    t_outside = datetime(2026, 10, 11, 21, 0, tzinfo=UTC)
    ctx_deny = ABACContext(client_ip="127.0.0.1", request_time=t_outside)
    allowed, reason = ABACEvaluator.evaluate(user, ctx_deny, policy)
    assert allowed is False
    assert "outside permitted window" in (reason or "")


def test_abac_step_up_mfa_requirement() -> None:
    """Verify mandatory MFA requirement for high-risk policies."""
    user = _create_user()
    policy = ABACPolicy(require_mfa=True)

    ctx_no_mfa = ABACContext(client_ip="127.0.0.1", mfa_authenticated=False)
    allowed, reason = ABACEvaluator.evaluate(user, ctx_no_mfa, policy)
    assert allowed is False
    assert "MFA" in (reason or "")

    ctx_with_mfa = ABACContext(client_ip="127.0.0.1", mfa_authenticated=True)
    allowed, _ = ABACEvaluator.evaluate(user, ctx_with_mfa, policy)
    assert allowed is True


def test_abac_tenant_isolation_and_ownership() -> None:
    """Verify cross-tenant block and resource owner match."""
    user = _create_user(user_id="u-user", tenant_id="tenant-alpha")
    policy_tenant = ABACPolicy(require_tenant_match=True)

    # Different tenant denied
    ctx_other_tenant = ABACContext(client_ip="127.0.0.1", resource_tenant_id="tenant-beta")
    allowed, reason = ABACEvaluator.evaluate(user, ctx_other_tenant, policy_tenant)
    assert allowed is False
    assert "Cross-tenant access forbidden" in (reason or "")

    # Same tenant allowed
    ctx_same_tenant = ABACContext(client_ip="127.0.0.1", resource_tenant_id="tenant-alpha")
    allowed, _ = ABACEvaluator.evaluate(user, ctx_same_tenant, policy_tenant)
    assert allowed is True

    # Ownership check
    policy_owner = ABACPolicy(require_owner_match=True)
    ctx_other_owner = ABACContext(client_ip="127.0.0.1", resource_owner_id="u-stranger")
    allowed, reason = ABACEvaluator.evaluate(user, ctx_other_owner, policy_owner)
    assert allowed is False
    assert "Ownership mismatch" in (reason or "")

    ctx_own = ABACContext(client_ip="127.0.0.1", resource_owner_id="u-user")
    allowed, _ = ABACEvaluator.evaluate(user, ctx_own, policy_owner)
    assert allowed is True


def test_pdp_unified_decision() -> None:
    """Verify complete PolicyDecisionPoint pipeline logic."""
    perm = Permission(
        permission_id="p-reports",
        resource=ResourceType.REPORTS,
        action=PermissionAction.READ,
    )
    role = Role(
        role_id="r-rep",
        name="ReportReader",
        role_type=RoleType.ANALYST,
        permissions=[perm],
    )
    user = _create_user(roles=[role])
    context = ABACContext(client_ip="127.0.0.1")

    # Permitted request
    decision, msg = PolicyDecisionPoint.decide(
        user, ResourceType.REPORTS, PermissionAction.READ, context
    )
    assert decision == AccessDecision.PERMIT

    # Denied by RBAC
    decision, msg = PolicyDecisionPoint.decide(
        user, ResourceType.SYSTEM_CONFIG, PermissionAction.DELETE, context
    )
    assert decision == AccessDecision.DENY
    assert "lacks required role permission" in msg

    # Denied by locked account
    user.status = UserStatus.LOCKED
    decision, msg = PolicyDecisionPoint.decide(
        user, ResourceType.REPORTS, PermissionAction.READ, context
    )
    assert decision == AccessDecision.DENY
    assert "locked" in msg
