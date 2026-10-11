"""Policy Decision Point (PDP) orchestrating hybrid RBAC & ABAC evaluation."""

from rbacapi.models.enums import AccessDecision, PermissionAction, ResourceType, UserStatus
from rbacapi.models.user import User
from rbacapi.policy.abac import ABACContext, ABACEvaluator, ABACPolicy
from rbacapi.policy.rbac import RBACEvaluator


class PolicyDecisionPoint:
    """Central access control engine combining RBAC entitlements with ABAC contextual rules."""

    @classmethod
    def decide(
        cls,
        user: User,
        resource: ResourceType,
        action: PermissionAction,
        context: ABACContext,
        policy: ABACPolicy | None = None,
    ) -> tuple[AccessDecision, str]:
        """Perform authoritative access control decision evaluation."""
        # 1. Subject account hygiene & lockout verification
        if user.is_locked(context.request_time):
            return AccessDecision.DENY, "Account is locked due to security policy."

        if user.status != UserStatus.ACTIVE:
            return (
                AccessDecision.DENY,
                f"Account is not active (current status: {user.status.value}).",
            )

        # 2. RBAC Entitlement Evaluation
        rbac_ok = RBACEvaluator.evaluate(user.roles, resource, action)
        if not rbac_ok:
            return (
                AccessDecision.DENY,
                f"User '{user.username}' lacks required role permission: "
                f"'{resource.value.lower()}:{action.value.lower()}'.",
            )

        # 3. Contextual ABAC Policy Predicates
        if policy is not None:
            abac_ok, reason = ABACEvaluator.evaluate(user, context, policy)
            if not abac_ok:
                return AccessDecision.DENY, reason or "Denied by contextual policy constraint."

        # 4. Access Permitted
        return (
            AccessDecision.PERMIT,
            f"Authorized access to {resource.value}:{action.value} granted.",
        )
