"""Domain enumerations for RBAC & ABAC authorization service."""

from enum import StrEnum


class UserStatus(StrEnum):
    """User account lifecycle status."""

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    LOCKED = "LOCKED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"


class RoleType(StrEnum):
    """System-defined and custom role types."""

    SUPER_ADMIN = "SUPER_ADMIN"
    ADMIN = "ADMIN"
    AUDITOR = "AUDITOR"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"
    CUSTOM = "CUSTOM"


class PermissionAction(StrEnum):
    """Granular action types executable on resources."""

    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"
    EXPORT = "EXPORT"
    MANAGE = "MANAGE"


class ResourceType(StrEnum):
    """Protected resource domain categories."""

    USERS = "USERS"
    ROLES = "ROLES"
    REPORTS = "REPORTS"
    AUDIT_LOGS = "AUDIT_LOGS"
    SYSTEM_CONFIG = "SYSTEM_CONFIG"
    FINANCIAL_DATA = "FINANCIAL_DATA"


class AccessDecision(StrEnum):
    """Policy Decision Point (PDP) evaluation outcome."""

    PERMIT = "PERMIT"
    DENY = "DENY"


class AuditEventType(StrEnum):
    """Categorized security event identifiers for audit trail."""

    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILURE = "AUTH_LOGIN_FAILURE"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    AUTH_MFA_CHALLENGE = "AUTH_MFA_CHALLENGE"
    AUTH_MFA_SUCCESS = "AUTH_MFA_SUCCESS"
    AUTH_MFA_FAILURE = "AUTH_MFA_FAILURE"
    AUTH_TOKEN_REFRESH = "AUTH_TOKEN_REFRESH"  # nosec B105
    AUTH_TOKEN_REVOKED = "AUTH_TOKEN_REVOKED"  # nosec B105
    AUTH_ACCOUNT_LOCKED = "AUTH_ACCOUNT_LOCKED"
    ACCESS_EVALUATION_PERMIT = "ACCESS_EVALUATION_PERMIT"
    ACCESS_EVALUATION_DENY = "ACCESS_EVALUATION_DENY"
    USER_CREATED = "USER_CREATED"
    USER_UPDATED = "USER_UPDATED"
    USER_DELETED = "USER_DELETED"
    ROLE_ASSIGNED = "ROLE_ASSIGNED"
    ROLE_REVOKED = "ROLE_REVOKED"
    SYSTEM_INTEGRITY_CHECK = "SYSTEM_INTEGRITY_CHECK"
