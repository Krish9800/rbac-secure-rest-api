"""Integration tests for Typer CLI administration tool."""

from pathlib import Path

from typer.testing import CliRunner

from rbacapi.cli.main import app

runner = CliRunner()


def test_cli_bootstrap(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_test.db"
    res = runner.invoke(app, ["bootstrap", "--db-path", str(db_file)])
    assert res.exit_code == 0
    assert "Database schema bootstrapped successfully" in res.stdout


def test_cli_user_lifecycle_and_list(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_test2.db"
    # Bootstrap
    runner.invoke(app, ["bootstrap", "--db-path", str(db_file)])

    # Create user
    res_create = runner.invoke(
        app,
        [
            "user-create",
            "bob_cli",
            "bob@sec.internal",
            "BobPassword123!",
            "--role",
            "Viewer",
            "--tenant",
            "tenant_bob",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_create.exit_code == 0
    assert "Created user bob_cli" in res_create.stdout

    # List users
    res_list = runner.invoke(app, ["users-list", "--db-path", str(db_file)])
    assert res_list.exit_code == 0
    assert "bob_cli" in res_list.stdout

    # Lock user
    res_lock = runner.invoke(app, ["user-lock", "bob_cli", "--db-path", str(db_file)])
    assert res_lock.exit_code == 0
    assert "successfully LOCKED" in res_lock.stdout


def test_cli_audit_verify_and_simulate_policy(tmp_path: Path) -> None:
    db_file = tmp_path / "cli_test3.db"
    runner.invoke(app, ["bootstrap", "--db-path", str(db_file)])

    # Audit verify
    res_verify = runner.invoke(app, ["audit-verify", "--db-path", str(db_file)])
    assert res_verify.exit_code == 0
    assert "AUDIT LEDGER VALID" in res_verify.stdout

    # Create user for simulation
    runner.invoke(
        app,
        [
            "user-create",
            "sim_user",
            "sim@sec.internal",
            "SimPass123!",
            "--role",
            "Viewer",
            "--db-path",
            str(db_file),
        ],
    )

    # Simulate permitted policy
    res_sim_ok = runner.invoke(
        app,
        [
            "simulate-policy",
            "sim_user",
            "REPORTS",
            "READ",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_sim_ok.exit_code == 0
    assert "ACCESS PERMITTED" in res_sim_ok.stdout

    # Simulate denied policy
    res_sim_deny = runner.invoke(
        app,
        [
            "simulate-policy",
            "sim_user",
            "USERS",
            "DELETE",
            "--db-path",
            str(db_file),
        ],
    )
    assert res_sim_deny.exit_code == 0
    assert "ACCESS DENIED" in res_sim_deny.stdout
