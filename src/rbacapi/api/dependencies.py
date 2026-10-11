"""FastAPI request dependencies for authentication, RBAC, and ABAC evaluation."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from rbacapi.audit.hash_chain import AuditLedger
from rbacapi.config.settings import Settings
from rbacapi.core.exceptions import InvalidTokenError
from rbacapi.core.tokens import TokenPayload, decode_access_token
from rbacapi.db.database import DatabaseManager
from rbacapi.models.enums import (
    AccessDecision,
    AuditEventType,
    PermissionAction,
    ResourceType,
    RoleType,
    UserStatus,
)
from rbacapi.models.user import User
from rbacapi.policy.abac import ABACContext, ABACPolicy
from rbacapi.policy.pdp import PolicyDecisionPoint

bearer_scheme = HTTPBearer(auto_error=False)


def get_db(request: Request) -> DatabaseManager:
    """Retrieve application database manager from state."""
    db: DatabaseManager = request.app.state.db
    return db


def get_app_settings(request: Request) -> Settings:
    """Retrieve application settings from state."""
    app_settings: Settings = request.app.state.settings
    return app_settings


def get_audit_ledger(request: Request) -> AuditLedger:
    """Retrieve audit ledger from state."""
    ledger: AuditLedger = request.app.state.audit_ledger
    return ledger


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[DatabaseManager, Depends(get_db)],
    audit_ledger: Annotated[AuditLedger, Depends(get_audit_ledger)],
) -> User:
    """Authenticate incoming request via JWT Bearer token."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        claims: TokenPayload = decode_access_token(token)
    except InvalidTokenError:
        client_ip = request.client.host if request.client else "unknown"
        audit_ledger.append(
            event_type=AuditEventType.AUTH_LOGIN_FAILURE,
            decision=AccessDecision.DENY,
            ip_address=client_ip,
            details={"reason": "Invalid or expired access token"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    user = db.get_user_by_id(claims.sub)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account is not active (current status: {user.status.value}).",
        )

    if user.is_locked():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is locked due to security policy.",
        )

    return user


def require_permission(
    resource: ResourceType,
    action: PermissionAction,
    abac_policy: ABACPolicy | None = None,
    extract_resource_owner: Callable[[Request], str | None] | None = None,
    extract_resource_tenant: Callable[[Request], str | None] | None = None,
) -> Callable[..., Any]:
    """Dependency factory enforcing unified RBAC + ABAC authorization."""

    def dependency(
        request: Request,
        user: Annotated[User, Depends(get_current_user)],
        audit_ledger: Annotated[AuditLedger, Depends(get_audit_ledger)],
        x_mfa_authenticated: Annotated[str | None, Header()] = None,
    ) -> User:
        client_ip = request.client.host if request.client else "127.0.0.1"
        if "x-forwarded-for" in request.headers:
            client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()

        mfa_verified = x_mfa_authenticated == "true" or any(
            r.role_type == RoleType.SUPER_ADMIN for r in user.roles
        )

        owner_id = extract_resource_owner(request) if extract_resource_owner else None
        tenant_id = extract_resource_tenant(request) if extract_resource_tenant else None

        abac_context = ABACContext(
            client_ip=client_ip,
            request_time=datetime.now(UTC),
            mfa_authenticated=mfa_verified,
            resource_owner_id=owner_id,
            resource_tenant_id=tenant_id,
        )

        decision_outcome, reason = PolicyDecisionPoint.decide(
            user=user,
            resource=resource,
            action=action,
            context=abac_context,
            policy=abac_policy,
        )

        # Record audit log
        audit_ledger.append(
            event_type=(
                AuditEventType.ACCESS_EVALUATION_PERMIT
                if decision_outcome == AccessDecision.PERMIT
                else AuditEventType.ACCESS_EVALUATION_DENY
            ),
            user_id=user.user_id,
            role=user.roles[0].name if user.roles else None,
            resource=f"{resource.value}:{action.value}",
            action=action.value,
            decision=decision_outcome,
            ip_address=client_ip,
            user_agent=request.headers.get("user-agent"),
            details={"reason": reason},
        )

        if decision_outcome != AccessDecision.PERMIT:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: {reason}",
            )

        return user

    return dependency
