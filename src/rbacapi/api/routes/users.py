"""User administration routes protected by granular RBAC/ABAC."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from rbacapi.api.dependencies import (
    get_audit_ledger,
    get_db,
    require_permission,
)
from rbacapi.audit.hash_chain import AuditLedger
from rbacapi.core.security import hash_password
from rbacapi.db.database import DatabaseManager
from rbacapi.models.enums import (
    AccessDecision,
    AuditEventType,
    PermissionAction,
    ResourceType,
    UserStatus,
)
from rbacapi.models.user import User, UserCreate, UserResponse, UserUpdate

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "",
    response_model=list[UserResponse],
    dependencies=[Depends(require_permission(ResourceType.USERS, PermissionAction.READ))],
)
def list_users(
    db: Annotated[DatabaseManager, Depends(get_db)],
    limit: int = 50,
    offset: int = 0,
) -> list[UserResponse]:
    """List registered users (requires USERS:READ)."""
    users = db.list_users(limit=limit, offset=offset)
    return [UserResponse.from_user(u) for u in users]


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(ResourceType.USERS, PermissionAction.CREATE))],
)
def create_user(
    req: UserCreate,
    db: Annotated[DatabaseManager, Depends(get_db)],
    audit_ledger: Annotated[AuditLedger, Depends(get_audit_ledger)],
) -> UserResponse:
    """Create a new user (requires USERS:CREATE)."""
    existing = db.get_user_by_username(req.username)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{req.username}' already registered.",
        )

    # Resolve roles
    roles = []
    for r_id in req.role_ids:
        role = db.get_role(r_id) or db.get_role_by_name(r_id)
        if role:
            roles.append(role)

    # Default to Viewer role if none specified
    if not roles:
        viewer = db.get_role_by_name("Viewer")
        if viewer:
            roles.append(viewer)

    # Password hash
    pwd_hash = hash_password(req.password)
    user = User(
        user_id=f"usr-{uuid.uuid4().hex[:12]}",
        username=req.username,
        email=req.email,
        password_hash=pwd_hash,
        tenant_id=req.tenant_id,
        roles=roles,
    )
    db.create_user(user)

    audit_ledger.append(
        event_type=AuditEventType.USER_CREATED,
        user_id=user.user_id,
        resource=f"user:{user.user_id}",
        action=PermissionAction.CREATE.value,
        decision=AccessDecision.PERMIT,
    )

    return UserResponse.from_user(user)


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    dependencies=[Depends(require_permission(ResourceType.USERS, PermissionAction.READ))],
)
def get_user(
    user_id: str,
    db: Annotated[DatabaseManager, Depends(get_db)],
) -> UserResponse:
    """Retrieve specific user details by ID."""
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return UserResponse.from_user(user)


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    dependencies=[Depends(require_permission(ResourceType.USERS, PermissionAction.UPDATE))],
)
def update_user(
    user_id: str,
    req: UserUpdate,
    db: Annotated[DatabaseManager, Depends(get_db)],
    audit_ledger: Annotated[AuditLedger, Depends(get_audit_ledger)],
) -> UserResponse:
    """Update user state or assigned roles (requires USERS:UPDATE)."""
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if req.email is not None:
        user.email = req.email
    if req.status is not None:
        user.status = req.status
        if req.status == UserStatus.ACTIVE:
            user.failed_login_attempts = 0
            user.locked_until = None
    if req.tenant_id is not None:
        user.tenant_id = req.tenant_id

    if req.role_ids is not None:
        new_roles = []
        for r_id in req.role_ids:
            r = db.get_role(r_id) or db.get_role_by_name(r_id)
            if r:
                new_roles.append(r)
        user.roles = new_roles

    db.update_user(user)

    audit_ledger.append(
        event_type=AuditEventType.USER_UPDATED,
        user_id=user.user_id,
        resource=f"user:{user.user_id}",
        action=PermissionAction.UPDATE.value,
        decision=AccessDecision.PERMIT,
    )

    return UserResponse.from_user(user)


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_permission(ResourceType.USERS, PermissionAction.DELETE))],
)
def delete_user(
    user_id: str,
    db: Annotated[DatabaseManager, Depends(get_db)],
    audit_ledger: Annotated[AuditLedger, Depends(get_audit_ledger)],
) -> dict[str, str]:
    """Delete a user record (requires USERS:DELETE)."""
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    db.delete_user(user_id)

    audit_ledger.append(
        event_type=AuditEventType.USER_DELETED,
        user_id=user_id,
        resource=f"user:{user_id}",
        action=PermissionAction.DELETE.value,
        decision=AccessDecision.PERMIT,
    )

    return {"message": f"User '{user_id}' successfully deleted."}
