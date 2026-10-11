"""Role-Based Access Control (RBAC) hierarchy and entitlement evaluator."""

from rbacapi.models.enums import PermissionAction, ResourceType, RoleType
from rbacapi.models.role import Role


class RoleHierarchy:
    """Manages role seniority and permission inheritance chains."""

    # Role level hierarchy: higher value inherits permissions of lower values
    HIERARCHY_LEVELS: dict[RoleType, int] = {
        RoleType.SUPER_ADMIN: 100,
        RoleType.ADMIN: 80,
        RoleType.AUDITOR: 60,
        RoleType.ANALYST: 40,
        RoleType.VIEWER: 20,
        RoleType.CUSTOM: 10,
    }

    @classmethod
    def get_effective_permissions(cls, roles: list[Role]) -> set[str]:
        """Aggregate all direct and inherited permissions granted across user roles."""
        permissions: set[str] = set()

        is_super = any(r.role_type == RoleType.SUPER_ADMIN for r in roles)
        if is_super:
            return {
                f"{res.value.lower()}:{act.value.lower()}"
                for res in ResourceType
                for act in PermissionAction
            }

        for role in roles:
            permissions.update(role.permission_strings())

        return permissions


class RBACEvaluator:
    """Evaluates whether assigned roles satisfy requested resource actions."""

    @classmethod
    def evaluate(
        cls,
        roles: list[Role],
        resource: ResourceType,
        action: PermissionAction,
    ) -> bool:
        """Check if any assigned role authorizes the requested resource action."""
        if any(r.role_type == RoleType.SUPER_ADMIN for r in roles):
            return True

        req_perm = f"{resource.value.lower()}:{action.value.lower()}"
        manage_perm = f"{resource.value.lower()}:{PermissionAction.MANAGE.value.lower()}"

        effective = RoleHierarchy.get_effective_permissions(roles)
        return req_perm in effective or manage_perm in effective
