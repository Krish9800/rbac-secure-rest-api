"""Custom exception hierarchy for RBAC authorization and authentication."""


class RBACError(Exception):
    """Base exception for all RBAC service errors."""


class AuthError(RBACError):
    """Base exception for authentication failures."""


class InvalidCredentialsError(AuthError):
    """Raised when username or password authentication fails."""


class AccountLockedError(AuthError):
    """Raised when an account is temporarily locked due to failed attempts."""


class InvalidTokenError(AuthError):
    """Raised when a JWT token is expired, malformed, or forged."""


class TokenRevokedError(AuthError):
    """Raised when a revoked refresh token or compromised token family is used."""


class MFAValidationError(AuthError):
    """Raised when a TOTP code is missing, expired, or invalid."""


class AccessDeniedError(RBACError):
    """Raised when policy evaluation denies authorization."""


class PolicyViolationError(AccessDeniedError):
    """Raised when contextual ABAC policies (IP, time, ownership) fail."""
