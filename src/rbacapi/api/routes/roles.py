"""Role and permission administration routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from rbacapi.api.dependencies import (
    get_audit_ledger,
    get_db,
    require_permission,
)
from rbacapi.audit.hash_chain import AuditLedger
from rbacapi.db.database import DatabaseManager
from rbacapi.models.enums import (
    AccessDecision,
    AuditEventType,
    PermissionAction,
    ResourceType,
    RoleType,
)
from rbacapi.models.role import Permission, Role

router = APIRouter(prefix="/roles", tags=["Roles"])


class RoleAssignmentRequest(BaseModel):
    user_id: str
    role_id: str


class CreateRoleRequest(BaseModel):
    role_id: str = Field(min_length=2, max_length=50)
    name: str = Field(min_length=2, max_length=50)
    role_type: RoleType = RoleType.CUSTOM
    description: str = ""
    permission_ids: list[str] = Field(default_factory=list)


@router.get(
    "",
    response_model=list[Role],
    dependencies=[Depends(require_permission(ResourceType.ROLES, PermissionAction.READ))],
)
def list_roles(db: Annotated[DatabaseManager, Depends(get_db)]) -> list[Role]:
    """List all configured system roles."""
    return db.list_roles()


@router.get(
    "/permissions",
    response_model=list[Permission],
    dependencies=[Depends(require_permission(ResourceType.ROLES, PermissionAction.READ))],
)
def list_permissions(db: Annotated[DatabaseManager, Depends(get_db)]) -> list[Permission]:
    """List all defined system permissions."""
    return db.list_permissions()


@router.post(
    "/assign",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_permission(ResourceType.ROLES, PermissionAction.MANAGE))],
)
def assign_role(
    req: RoleAssignmentRequest,
    db: Annotated[DatabaseManager, Depends(get_db)],
    audit_ledger: Annotated[AuditLedger, Depends(get_audit_ledger)],
) -> dict[str, str]:
    """Assign a role to a user."""
    user = db.get_user_by_id(req.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    role = db.get_role(req.role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found.")

    db.assign_role_to_user(req.user_id, req.role_id)

    audit_ledger.append(
        event_type=AuditEventType.ROLE_ASSIGNED,
        user_id=req.user_id,
        role=role.name,
        action=PermissionAction.MANAGE.value,
        decision=AccessDecision.PERMIT,
    )
    return {"message": f"Role '{role.name}' assigned to user '{user.username}'."}


@router.post(
    "/revoke",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_permission(ResourceType.ROLES, PermissionAction.MANAGE))],
)
def revoke_role(
    req: RoleAssignmentRequest,
    db: Annotated[DatabaseManager, Depends(get_db)],
    audit_ledger: Annotated[AuditLedger, Depends(get_audit_ledger)],
) -> dict[str, str]:
    """Revoke a role from a user."""
    user = db.get_user_by_id(req.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    db.revoke_role_from_user(req.user_id, req.role_id)

    audit_ledger.append(
        event_type=AuditEventType.ROLE_REVOKED,
        user_id=req.user_id,
        action=PermissionAction.MANAGE.value,
        decision=AccessDecision.PERMIT,
    )
    return {"message": f"Role '{req.role_id}' revoked from user '{user.username}'."}
