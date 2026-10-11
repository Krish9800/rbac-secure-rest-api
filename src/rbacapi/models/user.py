"""User domain model and request/response transfer schemas."""

from datetime import UTC, datetime

from pydantic import BaseModel, EmailStr, Field

from rbacapi.models.enums import PermissionAction, ResourceType, UserStatus
from rbacapi.models.role import Role


class User(BaseModel):
    """Core user account entity."""

    user_id: str
    username: str
    email: str
    password_hash: str
    roles: list[Role] = Field(default_factory=list)
    status: UserStatus = UserStatus.ACTIVE
    failed_login_attempts: int = 0
    locked_until: datetime | None = None
    mfa_enabled: bool = False
    mfa_secret: str | None = None
    tenant_id: str = "default"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def is_locked(self, current_time: datetime | None = None) -> bool:
        """Determine whether user account is locked by status or temporary timeout."""
        if self.status == UserStatus.LOCKED:
            return True
        now = current_time or datetime.now(UTC)
        return bool(self.locked_until is not None and self.locked_until > now)

    def has_permission(self, resource: ResourceType, action: PermissionAction) -> bool:
        """Check if any assigned role grants the requested permission."""
        if self.status != UserStatus.ACTIVE:
            return False
        return any(role.has_permission(resource, action) for role in self.roles)

    def all_permissions(self) -> set[str]:
        """Aggregate all permission strings granted by active user roles."""
        perms: set[str] = set()
        for role in self.roles:
            perms.update(role.permission_strings())
        return perms


class UserResponse(BaseModel):
    """Sanitized user representation safe for API consumers."""

    user_id: str
    username: str
    email: str
    roles: list[Role]
    status: UserStatus
    mfa_enabled: bool
    tenant_id: str
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_user(cls, user: User) -> "UserResponse":
        """Instantiate response model masking sensitive credentials."""
        return cls(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            roles=user.roles,
            status=user.status,
            mfa_enabled=user.mfa_enabled,
            tenant_id=user.tenant_id,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )


class UserCreate(BaseModel):
    """Payload to register a new user."""

    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8)
    tenant_id: str = "default"
    role_ids: list[str] = Field(default_factory=list)


class UserUpdate(BaseModel):
    """Payload to modify existing user details."""

    email: EmailStr | None = None
    status: UserStatus | None = None
    tenant_id: str | None = None
    role_ids: list[str] | None = None


class PasswordChangeRequest(BaseModel):
    """Payload to update an authenticated user's password."""

    current_password: str
    new_password: str = Field(min_length=8)
