"""Role and Permission data models for RBAC engine."""

from pydantic import BaseModel, Field

from rbacapi.models.enums import PermissionAction, ResourceType, RoleType


class Permission(BaseModel):
    """Resource action entitlement."""

    permission_id: str
    resource: ResourceType
    action: PermissionAction
    description: str = ""

    def as_string(self) -> str:
        """Render standard resource:action permission string."""
        return f"{self.resource.value.lower()}:{self.action.value.lower()}"


class Role(BaseModel):
    """Collection of permissions bound to users."""

    role_id: str
    name: str
    role_type: RoleType
    permissions: list[Permission] = Field(default_factory=list)
    description: str = ""

    def has_permission(self, resource: ResourceType, action: PermissionAction) -> bool:
        """Evaluate if role grants authorization for a specific resource action."""
        if self.role_type == RoleType.SUPER_ADMIN:
            return True

        for perm in self.permissions:
            if perm.resource == resource and (
                perm.action == action or perm.action == PermissionAction.MANAGE
            ):
                return True
        return False

    def permission_strings(self) -> set[str]:
        """Set of all permission strings granted by this role."""
        if self.role_type == RoleType.SUPER_ADMIN:
            return {
                f"{res.value.lower()}:{act.value.lower()}"
                for res in ResourceType
                for act in PermissionAction
            }
        return {p.as_string() for p in self.permissions}
