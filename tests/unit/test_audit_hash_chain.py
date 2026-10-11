"""Unit tests for cryptographic audit hash chaining and tamper detection."""

import sqlite3
from pathlib import Path

import pytest

from rbacapi.audit.hash_chain import GENESIS_PREV_HASH, AuditLedger
from rbacapi.db.database import DatabaseManager
from rbacapi.models.enums import AccessDecision, AuditEventType


@pytest.fixture
def temp_ledger(tmp_path: Path) -> tuple[AuditLedger, DatabaseManager, Path]:
    db_file = tmp_path / "audit_test.db"
    db = DatabaseManager(db_file)
    db.init_db()
    ledger = AuditLedger(db)
    return ledger, db, db_file


def test_empty_ledger_verification(temp_ledger: tuple[AuditLedger, DatabaseManager, Path]) -> None:
    ledger, _, _ = temp_ledger
    res = ledger.verify_ledger_integrity()
    assert res.is_valid is True
    assert res.total_entries == 0
    assert res.verified_entries == 0
    assert len(res.corrupted_entry_ids) == 0


def test_append_and_verify_chain_integrity(
    temp_ledger: tuple[AuditLedger, DatabaseManager, Path],
) -> None:
    ledger, _, _ = temp_ledger

    e1 = ledger.append(
        event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
        user_id="usr_001",
        ip_address="192.168.1.10",
        decision=AccessDecision.PERMIT,
    )
    assert e1.previous_hash == GENESIS_PREV_HASH
    assert len(e1.current_hash) == 64

    e2 = ledger.append(
        event_type=AuditEventType.ACCESS_EVALUATION_PERMIT,
        user_id="usr_001",
        resource="/api/v1/users",
        action="read",
        decision=AccessDecision.PERMIT,
    )
    assert e2.previous_hash == e1.current_hash

    e3 = ledger.append(
        event_type=AuditEventType.ACCESS_EVALUATION_DENY,
        user_id="usr_001",
        resource="/api/v1/admin",
        action="write",
        decision=AccessDecision.DENY,
    )
    assert e3.previous_hash == e2.current_hash

    res = ledger.verify_ledger_integrity()
    assert res.is_valid is True
    assert res.total_entries == 3
    assert res.verified_entries == 3
    assert len(res.corrupted_entry_ids) == 0


def test_detect_record_content_tampering(
    temp_ledger: tuple[AuditLedger, DatabaseManager, Path],
) -> None:
    ledger, _, db_file = temp_ledger

    e1 = ledger.append(
        event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
        user_id="usr_001",
        decision=AccessDecision.PERMIT,
    )
    ledger.append(
        event_type=AuditEventType.ACCESS_EVALUATION_PERMIT,
        user_id="usr_001",
        decision=AccessDecision.PERMIT,
    )

    # Malicious attacker directly tampers with e1 in SQLite without recalculating hash
    conn = sqlite3.connect(db_file)
    with conn:
        conn.execute(
            "UPDATE audit_logs SET decision = 'DENY' WHERE entry_id = ?",
            (e1.entry_id,),
        )
    conn.close()

    res = ledger.verify_ledger_integrity()
    assert res.is_valid is False
    assert res.total_entries == 2
    assert e1.entry_id in res.corrupted_entry_ids
    assert any("Hash recalculation mismatch" in detail for detail in res.tamper_details)


def test_detect_chain_link_break(
    temp_ledger: tuple[AuditLedger, DatabaseManager, Path],
) -> None:
    ledger, _, db_file = temp_ledger

    ledger.append(event_type=AuditEventType.AUTH_LOGIN_SUCCESS, user_id="usr_001")
    e2 = ledger.append(event_type=AuditEventType.ACCESS_EVALUATION_PERMIT, user_id="usr_001")
    ledger.append(event_type=AuditEventType.ACCESS_EVALUATION_PERMIT, user_id="usr_001")

    # Attacker tampers with the previous_hash link of e2
    conn = sqlite3.connect(db_file)
    with conn:
        conn.execute(
            "UPDATE audit_logs SET previous_hash = 'badbeef' WHERE entry_id = ?",
            (e2.entry_id,),
        )
    conn.close()

    res = ledger.verify_ledger_integrity()
    assert res.is_valid is False
    assert e2.entry_id in res.corrupted_entry_ids
    assert any("Chain break" in detail for detail in res.tamper_details)
