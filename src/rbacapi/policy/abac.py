"""Attribute-Based Access Control (ABAC) contextual predicates and policy evaluator."""

import ipaddress
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from rbacapi.models.enums import RoleType
from rbacapi.models.user import User


class ABACContext(BaseModel):
    """Runtime environmental and subject attributes for authorization."""

    client_ip: str
    request_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    resource_owner_id: str | None = None
    resource_tenant_id: str | None = None
    mfa_authenticated: bool = False


class ABACPolicy(BaseModel):
    """Contextual policy rules restricting access based on dynamic attributes."""

    allowed_ip_networks: list[str] = Field(default_factory=list)
    allowed_hours: tuple[int, int] | None = None
    require_mfa: bool = False
    require_tenant_match: bool = True
    require_owner_match: bool = False


class ABACEvaluator:
    """Evaluates contextual ABAC policy constraints."""

    @classmethod
    def _check_ip(cls, client_ip: str, allowed_networks: list[str]) -> tuple[bool, str | None]:
        try:
            client_addr = ipaddress.ip_address(client_ip)
            for net_str in allowed_networks:
                net = ipaddress.ip_network(net_str, strict=False)
                if client_addr in net:
                    return True, None
            return False, f"Client IP '{client_ip}' is not permitted by network policy."
        except ValueError:
            return False, f"Invalid client IP address format: '{client_ip}'"

    @classmethod
    def _check_time(
        cls, request_time: datetime, allowed_hours: tuple[int, int]
    ) -> tuple[bool, str | None]:
        start_hour, end_hour = allowed_hours
        req_hour = request_time.hour
        if not (start_hour <= req_hour < end_hour):
            return (
                False,
                f"Access denied: request at {req_hour}:00 is outside permitted window "
                f"[{start_hour}:00 - {end_hour}:00 UTC].",
            )
        return True, None

    @classmethod
    def evaluate(
        cls,
        user: User,
        context: ABACContext,
        policy: ABACPolicy,
    ) -> tuple[bool, str | None]:
        """Check all configured ABAC rules against request context."""
        is_super_admin = any(r.role_type == RoleType.SUPER_ADMIN for r in user.roles)

        # 1. IP / CIDR Network verification
        if policy.allowed_ip_networks:
            ok, err = cls._check_ip(context.client_ip, policy.allowed_ip_networks)
            if not ok:
                return False, err

        # 2. Time-of-day constraints
        if policy.allowed_hours is not None:
            ok, err = cls._check_time(context.request_time, policy.allowed_hours)
            if not ok:
                return False, err

        # 3. Mandatory Step-Up MFA
        if policy.require_mfa and not context.mfa_authenticated:
            return (
                False,
                "Multi-factor authentication (MFA) step-up verification required for this action.",
            )

        # 4. Multi-Tenant isolation
        if (
            policy.require_tenant_match
            and context.resource_tenant_id is not None
            and not is_super_admin
            and user.tenant_id != context.resource_tenant_id
        ):
            return (
                False,
                f"Cross-tenant access forbidden: User tenant '{user.tenant_id}' cannot "
                f"access resource belonging to tenant '{context.resource_tenant_id}'.",
            )

        # 5. Resource Ownership (BOLA / IDOR Defense)
        if (
            policy.require_owner_match
            and context.resource_owner_id is not None
            and not is_super_admin
            and user.user_id != context.resource_owner_id
        ):
            return (
                False,
                f"Ownership mismatch: User '{user.user_id}' is not the owner of "
                f"resource '{context.resource_owner_id}'.",
            )

        return True, None
