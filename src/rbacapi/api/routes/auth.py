"""Authentication routes: login, mfa-verify, refresh, logout, me."""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from rbacapi.api.dependencies import (
    get_audit_ledger,
    get_current_user,
    get_db,
)
from rbacapi.audit.hash_chain import AuditLedger
from rbacapi.config.settings import settings
from rbacapi.core.exceptions import InvalidTokenError
from rbacapi.core.security import verify_password, verify_totp_code
from rbacapi.core.tokens import (
    RefreshTokenRecord,
    TokenPayload,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_refresh_token,
)
from rbacapi.db.database import DatabaseManager
from rbacapi.models.enums import AccessDecision, AuditEventType, UserStatus
from rbacapi.models.user import User, UserResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str
    password: str


class MFARequest(BaseModel):
    mfa_session_token: str
    totp_code: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # nosec B105
    expires_in: int


class MFARequiredResponse(BaseModel):
    mfa_required: bool = True
    mfa_session_token: str
    detail: str = "Multi-factor authentication required."


@router.post(
    "/login",
    response_model=TokenResponse | MFARequiredResponse,
    status_code=status.HTTP_200_OK,
)
def login(
    req: LoginRequest,
    request: Request,
    db: Annotated[DatabaseManager, Depends(get_db)],
    audit_ledger: Annotated[AuditLedger, Depends(get_audit_ledger)],
) -> Any:
    """Authenticate with username and password, returning tokens or MFA challenge."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    user = db.get_user_by_username(req.username)
    if not user:
        audit_ledger.append(
            event_type=AuditEventType.AUTH_LOGIN_FAILURE,
            decision=AccessDecision.DENY,
            ip_address=client_ip,
            details={"username": req.username, "reason": "User not found"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    if user.is_locked():
        audit_ledger.append(
            event_type=AuditEventType.AUTH_LOGIN_FAILURE,
            user_id=user.user_id,
            decision=AccessDecision.DENY,
            ip_address=client_ip,
            details={"reason": "Account is locked"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is locked due to security policy.",
        )

    # Verify password
    if not verify_password(req.password, user.password_hash):
        user.failed_login_attempts += 1
        locked = False
        if user.failed_login_attempts >= settings.max_failed_logins:
            user.status = UserStatus.LOCKED
            user.locked_until = datetime.now(UTC) + timedelta(
                seconds=settings.lockout_duration_seconds
            )
            locked = True

        db.update_user(user)

        audit_ledger.append(
            event_type=(
                AuditEventType.AUTH_ACCOUNT_LOCKED if locked else AuditEventType.AUTH_LOGIN_FAILURE
            ),
            user_id=user.user_id,
            decision=AccessDecision.DENY,
            ip_address=client_ip,
            details={
                "failed_attempts": user.failed_login_attempts,
                "locked": locked,
            },
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # Reset failed attempts
    if user.failed_login_attempts > 0:
        user.failed_login_attempts = 0
        db.update_user(user)

    # Check if MFA is required
    if user.mfa_enabled:
        session_token = create_access_token(
            user_id=user.user_id,
            username=user.username,
            roles=[],
            permissions=[],
            mfa_authenticated=False,
            expires_delta=timedelta(minutes=5),
        )
        audit_ledger.append(
            event_type=AuditEventType.AUTH_MFA_CHALLENGE,
            user_id=user.user_id,
            decision=AccessDecision.PERMIT,
            ip_address=client_ip,
        )
        return MFARequiredResponse(mfa_session_token=session_token)

    # Issue tokens
    role_names = [r.name for r in user.roles]
    permissions = list(user.all_permissions())
    access_token = create_access_token(
        user_id=user.user_id,
        username=user.username,
        roles=role_names,
        permissions=permissions,
        tenant_id=user.tenant_id,
        mfa_authenticated=False,
    )
    raw_refresh, token_hash = generate_refresh_token()
    family_id = f"fam-{user.user_id}-{int(datetime.now(UTC).timestamp())}"
    ref_record = RefreshTokenRecord(
        token_id=f"rt-{token_hash[:12]}",
        user_id=user.user_id,
        token_hash=token_hash,
        family_id=family_id,
        is_revoked=False,
        expires_at=datetime.now(UTC) + timedelta(days=settings.jwt_refresh_token_expire_days),
    )
    db.save_refresh_token(ref_record)

    audit_ledger.append(
        event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
        user_id=user.user_id,
        role=role_names[0] if role_names else None,
        decision=AccessDecision.PERMIT,
        ip_address=client_ip,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post("/mfa-verify", response_model=TokenResponse)
def verify_mfa(
    req: MFARequest,
    request: Request,
    db: Annotated[DatabaseManager, Depends(get_db)],
    audit_ledger: Annotated[AuditLedger, Depends(get_audit_ledger)],
) -> TokenResponse:
    """Complete MFA challenge and issue full credentials."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    try:
        claims: TokenPayload = decode_access_token(req.mfa_session_token)
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA session token.",
        ) from None

    user = db.get_user_by_id(claims.sub)
    if not user or not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User MFA is not configured.",
        )

    if not verify_totp_code(user.mfa_secret, req.totp_code):
        audit_ledger.append(
            event_type=AuditEventType.AUTH_MFA_FAILURE,
            user_id=user.user_id,
            decision=AccessDecision.DENY,
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code.",
        )

    # Success: issue authenticated access token with mfa_authenticated=True
    role_names = [r.name for r in user.roles]
    permissions = list(user.all_permissions())
    access_token = create_access_token(
        user_id=user.user_id,
        username=user.username,
        roles=role_names,
        permissions=permissions,
        tenant_id=user.tenant_id,
        mfa_authenticated=True,
    )
    raw_refresh, token_hash = generate_refresh_token()
    family_id = f"fam-{user.user_id}-{int(datetime.now(UTC).timestamp())}"
    ref_record = RefreshTokenRecord(
        token_id=f"rt-{token_hash[:12]}",
        user_id=user.user_id,
        token_hash=token_hash,
        family_id=family_id,
        is_revoked=False,
        expires_at=datetime.now(UTC) + timedelta(days=settings.jwt_refresh_token_expire_days),
    )
    db.save_refresh_token(ref_record)

    audit_ledger.append(
        event_type=AuditEventType.AUTH_MFA_SUCCESS,
        user_id=user.user_id,
        decision=AccessDecision.PERMIT,
        ip_address=client_ip,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(
    req: RefreshRequest,
    request: Request,
    db: Annotated[DatabaseManager, Depends(get_db)],
    audit_ledger: Annotated[AuditLedger, Depends(get_audit_ledger)],
) -> TokenResponse:
    """Rotate refresh token and issue a fresh access token."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    token_hash = hash_refresh_token(req.refresh_token)
    record = db.get_refresh_token_by_hash(token_hash)

    if not record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    # Check for reuse of revoked refresh token (replay attack)
    if record.is_revoked:
        db.revoke_token_family(record.family_id)
        audit_ledger.append(
            event_type=AuditEventType.AUTH_TOKEN_REVOKED,
            user_id=record.user_id,
            decision=AccessDecision.DENY,
            ip_address=client_ip,
            details={
                "reason": "Revoked refresh token reuse detected; entire token family invalidated",
                "family_id": record.family_id,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token reuse detected. All sessions in this chain have been revoked.",
        )

    # Revoke old token
    record.is_revoked = True
    db.save_refresh_token(record)

    # Verify user
    user = db.get_user_by_id(record.user_id)
    if not user or user.status != UserStatus.ACTIVE or user.is_locked():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive or locked.",
        )

    # Issue new rotated refresh token in the same family
    role_names = [r.name for r in user.roles]
    permissions = list(user.all_permissions())
    new_access = create_access_token(
        user_id=user.user_id,
        username=user.username,
        roles=role_names,
        permissions=permissions,
        tenant_id=user.tenant_id,
    )
    new_raw_refresh, new_token_hash = generate_refresh_token()
    new_record = RefreshTokenRecord(
        token_id=f"rt-{new_token_hash[:12]}",
        user_id=user.user_id,
        token_hash=new_token_hash,
        family_id=record.family_id,
        is_revoked=False,
        expires_at=datetime.now(UTC) + timedelta(days=settings.jwt_refresh_token_expire_days),
    )
    db.save_refresh_token(new_record)

    audit_ledger.append(
        event_type=AuditEventType.AUTH_TOKEN_REFRESH,
        user_id=user.user_id,
        decision=AccessDecision.PERMIT,
        ip_address=client_ip,
    )

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_raw_refresh,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(
    req: RefreshRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[DatabaseManager, Depends(get_db)],
    audit_ledger: Annotated[AuditLedger, Depends(get_audit_ledger)],
) -> dict[str, str]:
    """Revoke user's refresh token family upon logout."""
    token_hash = hash_refresh_token(req.refresh_token)
    record = db.get_refresh_token_by_hash(token_hash)
    if record:
        db.revoke_token_family(record.family_id)

    audit_ledger.append(
        event_type=AuditEventType.AUTH_LOGOUT,
        user_id=current_user.user_id,
        decision=AccessDecision.PERMIT,
    )
    return {"message": "Successfully logged out and session revoked."}


@router.get("/me", response_model=UserResponse)
def get_me(current_user: Annotated[User, Depends(get_current_user)]) -> UserResponse:
    """Return sanitized profile and assigned roles for currently authenticated user."""
    return UserResponse.from_user(current_user)
