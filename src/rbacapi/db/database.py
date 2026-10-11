"""SQLite thread-safe database manager with WAL journal mode."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from rbacapi.config.settings import settings
from rbacapi.core.tokens import RefreshTokenRecord
from rbacapi.models.audit import AuditLogEntry
from rbacapi.models.enums import (
    AccessDecision,
    AuditEventType,
    PermissionAction,
    ResourceType,
    RoleType,
    UserStatus,
)
from rbacapi.models.role import Permission, Role
from rbacapi.models.user import User


class DatabaseManager:
    """Manages SQLite storage for users, roles, tokens, and audit logs."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path is not None:
            self.db_path = Path(db_path)
        else:
            self.db_path = settings.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create and configure a SQLite connection."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def init_db(self) -> None:
        """Initialize database schema from schema.sql and seed default entities."""
        schema_path = Path(__file__).parent / "schema.sql"
        if not schema_path.exists():
            return
        with open(schema_path, encoding="utf-8") as f:
            schema_sql = f.read()
        with self._get_connection() as conn:
            conn.executescript(schema_sql)
        self.seed_defaults()

    def seed_defaults(self) -> None:
        """Populate baseline permissions and roles if empty."""
        with self._get_connection() as conn:
            # Seed permissions
            existing_perms = conn.execute("SELECT COUNT(*) FROM permissions").fetchone()[0]
            if existing_perms == 0:
                for res in ResourceType:
                    for act in PermissionAction:
                        perm_id = f"p-{res.value.lower()}-{act.value.lower()}"
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO permissions (
                                permission_id, resource, action, description
                            ) VALUES (?, ?, ?, ?)
                            """,
                            (
                                perm_id,
                                res.value,
                                act.value,
                                f"Allow {act.value} on {res.value}",
                            ),
                        )

            # Seed standard roles
            existing_roles = conn.execute("SELECT COUNT(*) FROM roles").fetchone()[0]
            if existing_roles == 0:
                roles_to_create = [
                    (
                        "role-superadmin",
                        "SuperAdmin",
                        RoleType.SUPER_ADMIN.value,
                        "Full system access",
                    ),
                    ("role-admin", "Admin", RoleType.ADMIN.value, "Administrative operations"),
                    ("role-auditor", "Auditor", RoleType.AUDITOR.value, "Audit inspection rights"),
                    ("role-analyst", "Analyst", RoleType.ANALYST.value, "Analytical operations"),
                    ("role-viewer", "Viewer", RoleType.VIEWER.value, "Read-only access"),
                ]
                for r_id, r_name, r_type, r_desc in roles_to_create:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO roles (role_id, name, role_type, description)
                        VALUES (?, ?, ?, ?)
                        """,
                        (r_id, r_name, r_type, r_desc),
                    )

                # Assign permissions to Admin
                admin_perms = conn.execute(
                    """
                    SELECT permission_id FROM permissions
                    WHERE resource IN ('USERS', 'ROLES', 'REPORTS', 'SYSTEM_CONFIG')
                    """
                ).fetchall()
                for p in admin_perms:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
                        VALUES (?, ?)
                        """,
                        ("role-admin", p[0]),
                    )

                # Assign permissions to Auditor
                auditor_perms = conn.execute(
                    """
                    SELECT permission_id FROM permissions
                    WHERE (resource = 'AUDIT_LOGS' AND action = 'READ')
                       OR (resource = 'REPORTS' AND action = 'READ')
                       OR (resource = 'USERS' AND action = 'READ')
                    """
                ).fetchall()
                for p in auditor_perms:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
                        VALUES (?, ?)
                        """,
                        ("role-auditor", p[0]),
                    )

                # Assign permissions to Viewer
                viewer_perms = conn.execute(
                    """
                    SELECT permission_id FROM permissions
                    WHERE resource = 'REPORTS' AND action = 'READ'
                    """
                ).fetchall()
                for p in viewer_perms:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
                        VALUES (?, ?)
                        """,
                        ("role-viewer", p[0]),
                    )

    def create_user(self, user: User) -> None:
        """Insert a new user record and map assigned roles."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users (
                    user_id, username, email, password_hash, status,
                    failed_login_attempts, locked_until, mfa_enabled, mfa_secret,
                    tenant_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user.user_id,
                    user.username,
                    user.email,
                    user.password_hash,
                    user.status.value,
                    user.failed_login_attempts,
                    user.locked_until.isoformat() if user.locked_until else None,
                    1 if user.mfa_enabled else 0,
                    user.mfa_secret,
                    user.tenant_id,
                    user.created_at.isoformat(),
                    user.updated_at.isoformat(),
                ),
            )
            for role in user.roles:
                conn.execute(
                    "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
                    (user.user_id, role.role_id),
                )

    def _load_user_roles(self, conn: sqlite3.Connection, user_id: str) -> list[Role]:
        """Fetch and populate all roles and permissions assigned to a user."""
        cursor = conn.execute(
            """
            SELECT r.* FROM roles r
            JOIN user_roles ur ON r.role_id = ur.role_id
            WHERE ur.user_id = ?
            """,
            (user_id,),
        )
        roles: list[Role] = []
        for r_row in cursor.fetchall():
            role_id = r_row["role_id"]
            perm_cursor = conn.execute(
                """
                SELECT p.* FROM permissions p
                JOIN role_permissions rp ON p.permission_id = rp.permission_id
                WHERE rp.role_id = ?
                """,
                (role_id,),
            )
            perms: list[Permission] = [
                Permission(
                    permission_id=p["permission_id"],
                    resource=ResourceType(p["resource"]),
                    action=PermissionAction(p["action"]),
                    description=p["description"] or "",
                )
                for p in perm_cursor.fetchall()
            ]
            roles.append(
                Role(
                    role_id=role_id,
                    name=r_row["name"],
                    role_type=RoleType(r_row["role_type"]),
                    permissions=perms,
                    description=r_row["description"] or "",
                )
            )
        return roles

    def get_user_by_id(self, user_id: str) -> User | None:
        """Fetch a user by ID along with their populated roles."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
            if not row:
                return None
            roles = self._load_user_roles(conn, user_id)
            return User(
                user_id=row["user_id"],
                username=row["username"],
                email=row["email"],
                password_hash=row["password_hash"],
                roles=roles,
                status=UserStatus(row["status"]),
                failed_login_attempts=row["failed_login_attempts"],
                locked_until=(
                    datetime.fromisoformat(row["locked_until"]) if row["locked_until"] else None
                ),
                mfa_enabled=bool(row["mfa_enabled"]),
                mfa_secret=row["mfa_secret"],
                tenant_id=row["tenant_id"],
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
            )

    def get_user_by_username(self, username: str) -> User | None:
        """Fetch a user by username along with their populated roles."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                return None
            roles = self._load_user_roles(conn, row["user_id"])
            return User(
                user_id=row["user_id"],
                username=row["username"],
                email=row["email"],
                password_hash=row["password_hash"],
                roles=roles,
                status=UserStatus(row["status"]),
                failed_login_attempts=row["failed_login_attempts"],
                locked_until=(
                    datetime.fromisoformat(row["locked_until"]) if row["locked_until"] else None
                ),
                mfa_enabled=bool(row["mfa_enabled"]),
                mfa_secret=row["mfa_secret"],
                tenant_id=row["tenant_id"],
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
            )

    def update_user(self, user: User) -> None:
        """Update user properties and synchronized roles."""
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE users SET
                    email = ?,
                    password_hash = ?,
                    status = ?,
                    failed_login_attempts = ?,
                    locked_until = ?,
                    mfa_enabled = ?,
                    mfa_secret = ?,
                    tenant_id = ?,
                    updated_at = ?
                WHERE user_id = ?
                """,
                (
                    user.email,
                    user.password_hash,
                    user.status.value,
                    user.failed_login_attempts,
                    user.locked_until.isoformat() if user.locked_until else None,
                    1 if user.mfa_enabled else 0,
                    user.mfa_secret,
                    user.tenant_id,
                    user.updated_at.isoformat(),
                    user.user_id,
                ),
            )
            # Synchronize roles
            conn.execute("DELETE FROM user_roles WHERE user_id = ?", (user.user_id,))
            for role in user.roles:
                conn.execute(
                    "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
                    (user.user_id, role.role_id),
                )

    def delete_user(self, user_id: str) -> bool:
        """Delete user account and cascade relationships."""
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
            return cursor.rowcount > 0

    def list_users(self, limit: int = 50, offset: int = 0) -> list[User]:
        """List user records ordered by created_at."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM users ORDER BY created_at ASC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            users: list[User] = []
            for row in rows:
                roles = self._load_user_roles(conn, row["user_id"])
                users.append(
                    User(
                        user_id=row["user_id"],
                        username=row["username"],
                        email=row["email"],
                        password_hash=row["password_hash"],
                        roles=roles,
                        status=UserStatus(row["status"]),
                        failed_login_attempts=row["failed_login_attempts"],
                        locked_until=(
                            datetime.fromisoformat(row["locked_until"])
                            if row["locked_until"]
                            else None
                        ),
                        mfa_enabled=bool(row["mfa_enabled"]),
                        mfa_secret=row["mfa_secret"],
                        tenant_id=row["tenant_id"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        updated_at=datetime.fromisoformat(row["updated_at"]),
                    )
                )
            return users

    def get_role(self, role_id: str) -> Role | None:
        """Fetch role by ID with permissions."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM roles WHERE role_id = ?", (role_id,)).fetchone()
            if not row:
                return None
            perm_cursor = conn.execute(
                """
                SELECT p.* FROM permissions p
                JOIN role_permissions rp ON p.permission_id = rp.permission_id
                WHERE rp.role_id = ?
                """,
                (role_id,),
            )
            perms = [
                Permission(
                    permission_id=p["permission_id"],
                    resource=ResourceType(p["resource"]),
                    action=PermissionAction(p["action"]),
                    description=p["description"] or "",
                )
                for p in perm_cursor.fetchall()
            ]
            return Role(
                role_id=row["role_id"],
                name=row["name"],
                role_type=RoleType(row["role_type"]),
                permissions=perms,
                description=row["description"] or "",
            )

    def get_role_by_name(self, name: str) -> Role | None:
        """Fetch role by unique name with permissions."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM roles WHERE name = ?", (name,)).fetchone()
            if not row:
                return None
            return self.get_role(row["role_id"])

    def list_roles(self) -> list[Role]:
        """List all defined roles."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT role_id FROM roles ORDER BY name ASC").fetchall()
            roles: list[Role] = []
            for r in rows:
                role = self.get_role(r["role_id"])
                if role:
                    roles.append(role)
            return roles

    def list_permissions(self) -> list[Permission]:
        """List all defined permissions."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM permissions ORDER BY resource, action").fetchall()
            return [
                Permission(
                    permission_id=r["permission_id"],
                    resource=ResourceType(r["resource"]),
                    action=PermissionAction(r["action"]),
                    description=r["description"] or "",
                )
                for r in rows
            ]

    def assign_role_to_user(self, user_id: str, role_id: str) -> None:
        """Assign a role to a user."""
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
                (user_id, role_id),
            )

    def revoke_role_from_user(self, user_id: str, role_id: str) -> None:
        """Revoke a role from a user."""
        with self._get_connection() as conn:
            conn.execute(
                "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
                (user_id, role_id),
            )

    # Refresh tokens
    def save_refresh_token(self, record: RefreshTokenRecord) -> None:
        """Store a refresh token record."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO refresh_tokens (
                    token_id, user_id, token_hash, family_id, is_revoked, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(token_id) DO UPDATE SET
                    is_revoked = excluded.is_revoked
                """,
                (
                    record.token_id,
                    record.user_id,
                    record.token_hash,
                    record.family_id,
                    1 if record.is_revoked else 0,
                    record.expires_at.isoformat(),
                ),
            )

    def get_refresh_token_by_hash(self, token_hash: str) -> RefreshTokenRecord | None:
        """Fetch a refresh token record by its SHA-256 hash."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM refresh_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if not row:
                return None
            return RefreshTokenRecord(
                token_id=row["token_id"],
                user_id=row["user_id"],
                token_hash=row["token_hash"],
                family_id=row["family_id"],
                is_revoked=bool(row["is_revoked"]),
                expires_at=datetime.fromisoformat(row["expires_at"]),
            )

    def revoke_token_family(self, family_id: str) -> int:
        """Revoke all refresh tokens in a family upon compromise/reuse detection."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE refresh_tokens SET is_revoked = 1 WHERE family_id = ?",
                (family_id,),
            )
            return cursor.rowcount

    # Audit log persistence
    def save_audit_entry(self, entry: AuditLogEntry) -> None:
        """Store an immutable audit log entry."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (
                    entry_id, timestamp, event_type, user_id, role,
                    resource, action, decision, ip_address, user_agent,
                    details, previous_hash, current_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.entry_id,
                    entry.timestamp.isoformat(),
                    entry.event_type.value,
                    entry.user_id,
                    entry.role,
                    entry.resource,
                    entry.action,
                    entry.decision.value,
                    entry.ip_address,
                    entry.user_agent,
                    json.dumps(entry.details),
                    entry.previous_hash,
                    entry.current_hash,
                ),
            )

    def get_last_audit_entry(self) -> AuditLogEntry | None:
        """Fetch the most recent audit entry to continue the cryptographic hash chain."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM audit_logs ORDER BY rowid DESC LIMIT 1").fetchone()
            if not row:
                return None
            return AuditLogEntry(
                entry_id=row["entry_id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                event_type=AuditEventType(row["event_type"]),
                user_id=row["user_id"],
                role=row["role"],
                resource=row["resource"],
                action=row["action"],
                decision=AccessDecision(row["decision"]),
                ip_address=row["ip_address"],
                user_agent=row["user_agent"],
                details=json.loads(row["details"]),
                previous_hash=row["previous_hash"],
                current_hash=row["current_hash"],
            )

    def list_audit_entries(self, limit: int = 100, offset: int = 0) -> list[AuditLogEntry]:
        """List audit entries ordered chronologically by rowid."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY rowid ASC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [
                AuditLogEntry(
                    entry_id=row["entry_id"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    event_type=AuditEventType(row["event_type"]),
                    user_id=row["user_id"],
                    role=row["role"],
                    resource=row["resource"],
                    action=row["action"],
                    decision=AccessDecision(row["decision"]),
                    ip_address=row["ip_address"],
                    user_agent=row["user_agent"],
                    details=json.loads(row["details"]),
                    previous_hash=row["previous_hash"],
                    current_hash=row["current_hash"],
                )
                for row in rows
            ]
