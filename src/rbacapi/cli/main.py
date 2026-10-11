"""RBAC & ABAC Administration and Verification CLI."""

import uuid
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from rbacapi.audit.hash_chain import AuditLedger
from rbacapi.config.settings import settings
from rbacapi.core.security import hash_password
from rbacapi.db.database import DatabaseManager
from rbacapi.models.enums import (
    AccessDecision,
    PermissionAction,
    ResourceType,
    UserStatus,
)
from rbacapi.models.user import User
from rbacapi.policy.abac import ABACContext, ABACPolicy
from rbacapi.policy.pdp import PolicyDecisionPoint

app = typer.Typer(
    name="rbac-admin",
    help="Zero Trust RBAC/ABAC Security REST API Administration CLI",
    add_completion=False,
)
console = Console()


def get_db(db_path: Path | None = None) -> DatabaseManager:
    path = db_path or settings.db_path
    db = DatabaseManager(path)
    db.init_db()
    return db


@app.command("bootstrap")
def bootstrap_cmd(
    db_path: Path = typer.Option(None, "--db-path", help="Custom SQLite database path"),
) -> None:
    """Initialize SQLite tables, default permissions, and baseline roles."""
    db = get_db(db_path)
    console.print(
        f"[bold green]✓[/] Database schema bootstrapped successfully at [cyan]{db.db_path}[/]"
    )


@app.command("users-list")
def list_users_cmd(
    db_path: Path = typer.Option(None, "--db-path", help="Custom SQLite database path"),
) -> None:
    """Display table of all registered users, roles, and account statuses."""
    db = get_db(db_path)
    users = db.list_users(limit=100)

    table = Table(title="Registered Users & Entitlements")
    table.add_column("User ID", style="dim")
    table.add_column("Username", style="cyan")
    table.add_column("Email", style="magenta")
    table.add_column("Roles", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Tenant", style="blue")

    for u in users:
        roles_str = ", ".join(r.name for r in u.roles) or "[dim]None[/]"
        table.add_row(u.user_id, u.username, u.email, roles_str, u.status.value, u.tenant_id)

    console.print(table)


@app.command("user-create")
def create_user_cmd(
    username: str = typer.Argument(..., help="New user unique username"),
    email: str = typer.Argument(..., help="New user email"),
    password: str = typer.Argument(..., help="Plaintext password to Argon2id hash"),
    role_name: str = typer.Option("Viewer", "--role", "-r", help="Initial role to bind"),
    tenant_id: str = typer.Option("default", "--tenant", "-t", help="Tenant ID"),
    db_path: Path = typer.Option(None, "--db-path", help="Custom SQLite database path"),
) -> None:
    """Register a new user account with Argon2id hashing."""
    db = get_db(db_path)
    if db.get_user_by_username(username):
        console.print(f"[bold red]Error:[/] Username '{username}' already exists.")
        raise typer.Exit(code=1)

    role = db.get_role_by_name(role_name)
    roles = [role] if role else []

    pwd_hash = hash_password(password)
    user = User(
        user_id=f"usr-{uuid.uuid4().hex[:12]}",
        username=username,
        email=email,
        password_hash=pwd_hash,
        tenant_id=tenant_id,
        roles=roles,
    )
    db.create_user(user)
    console.print(f"[bold green]✓[/] Created user [cyan]{username}[/] (ID: {user.user_id})")


@app.command("user-lock")
def lock_user_cmd(
    username: str = typer.Argument(..., help="Username of account to lock"),
    db_path: Path = typer.Option(None, "--db-path", help="Custom SQLite database path"),
) -> None:
    """Administrative security lock for suspicious or compromised user account."""
    db = get_db(db_path)
    user = db.get_user_by_username(username)
    if not user:
        console.print(f"[bold red]Error:[/] User '{username}' not found.")
        raise typer.Exit(code=1)

    user.status = UserStatus.LOCKED
    db.update_user(user)
    console.print(f"[bold yellow]✓[/] Account [cyan]{username}[/] successfully LOCKED.")


@app.command("audit-verify")
def audit_verify_cmd(
    db_path: Path = typer.Option(None, "--db-path", help="Custom SQLite database path"),
) -> None:
    """Execute mathematical SHA-256 hash chaining verification across all audit records."""
    db = get_db(db_path)
    ledger = AuditLedger(db)
    result = ledger.verify_ledger_integrity()

    if result.is_valid:
        console.print(
            f"[bold green]✓ AUDIT LEDGER VALID[/] Verified {result.verified_entries}/"
            f"{result.total_entries} cryptographic block entries."
        )
    else:
        console.print(
            f"[bold red]✗ TAMPER DETECTED![/] {len(result.corrupted_entry_ids)} corrupted "
            f"entries found out of {result.total_entries} total records."
        )
        for detail in result.tamper_details:
            console.print(f"  [red]• {detail}[/]")
        raise typer.Exit(code=2)


@app.command("simulate-policy")
def simulate_policy_cmd(
    username: str = typer.Argument(..., help="Subject username to test"),
    resource: str = typer.Argument(..., help="Resource name (e.g. USERS, REPORTS, AUDIT_LOGS)"),
    action: str = typer.Argument(..., help="Action name (e.g. READ, CREATE, UPDATE, DELETE)"),
    client_ip: str = typer.Option("127.0.0.1", "--ip", help="Simulated client IP"),
    mfa_verified: bool = typer.Option(False, "--mfa", help="Simulated MFA status"),
    db_path: Path = typer.Option(None, "--db-path", help="Custom SQLite database path"),
) -> None:
    """Dry-run test Policy Decision Point evaluation for user against resource and action."""
    db = get_db(db_path)
    user = db.get_user_by_username(username)
    if not user:
        console.print(f"[bold red]Error:[/] User '{username}' not found.")
        raise typer.Exit(code=1)

    try:
        res_enum = ResourceType(resource.upper())
        act_enum = PermissionAction(action.upper())
    except ValueError as exc:
        console.print(f"[bold red]Error:[/] Invalid resource or action enum value: {exc}")
        raise typer.Exit(code=1) from None

    context = ABACContext(
        client_ip=client_ip,
        mfa_authenticated=mfa_verified,
    )
    policy = ABACPolicy()

    decision, reason = PolicyDecisionPoint.decide(
        user=user,
        resource=res_enum,
        action=act_enum,
        context=context,
        policy=policy,
    )

    if decision == AccessDecision.PERMIT:
        console.print(f"[bold green]ACCESS PERMITTED[/]: {reason}")
    else:
        console.print(f"[bold red]ACCESS DENIED[/]: {reason}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
