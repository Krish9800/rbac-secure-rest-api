"""Cryptographic SHA-256 hash chaining audit engine and ledger integrity verifier."""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from rbacapi.db.database import DatabaseManager
from rbacapi.models.audit import AuditLogEntry
from rbacapi.models.enums import AccessDecision, AuditEventType

GENESIS_PREV_HASH = "0" * 64


class AuditChainVerificationResult(BaseModel):
    """Result of audit ledger hash chain verification."""

    is_valid: bool
    total_entries: int
    verified_entries: int
    corrupted_entry_ids: list[str] = Field(default_factory=list)
    tamper_details: list[str] = Field(default_factory=list)


class AuditLedger:
    """Manages appending tamper-evident records and verifying chain integrity."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def append(
        self,
        event_type: AuditEventType,
        user_id: str | None = None,
        role: str | None = None,
        resource: str | None = None,
        action: str | None = None,
        decision: AccessDecision = AccessDecision.PERMIT,
        ip_address: str | None = None,
        user_agent: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        """Append a newly hash-chained audit entry to the persistent ledger."""
        if details is None:
            details = {}

        # Fetch latest entry to find previous hash
        latest_entry = self.db.get_last_audit_entry()
        previous_hash = latest_entry.current_hash if latest_entry else GENESIS_PREV_HASH

        now = datetime.now(UTC)
        entry_id = str(uuid.uuid4())

        current_hash = AuditLogEntry.compute_hash(
            previous_hash=previous_hash,
            timestamp=now,
            event_type=event_type,
            user_id=user_id,
            role=role,
            resource=resource,
            action=action,
            decision=decision,
            ip_address=ip_address,
            details=details,
        )

        entry = AuditLogEntry(
            entry_id=entry_id,
            timestamp=now,
            event_type=event_type,
            user_id=user_id,
            role=role,
            resource=resource,
            action=action,
            decision=decision,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
            previous_hash=previous_hash,
            current_hash=current_hash,
        )

        self.db.save_audit_entry(entry)
        return entry

    def verify_ledger_integrity(self) -> AuditChainVerificationResult:
        """Scan the entire audit trail and mathematically verify hash chaining."""
        entries = self.db.list_audit_entries(limit=100_000)
        total_entries = len(entries)

        if total_entries == 0:
            return AuditChainVerificationResult(
                is_valid=True,
                total_entries=0,
                verified_entries=0,
            )

        corrupted_ids: list[str] = []
        tamper_details: list[str] = []
        verified_count = 0

        expected_prev_hash = GENESIS_PREV_HASH

        for i, entry in enumerate(entries):
            # Check 1: Chain continuity link
            if entry.previous_hash != expected_prev_hash:
                corrupted_ids.append(entry.entry_id)
                tamper_details.append(
                    f"Chain break at index {i} (entry_id={entry.entry_id}): "
                    f"expected previous_hash '{expected_prev_hash}', got '{entry.previous_hash}'."
                )

            # Check 2: Content hash recalculation
            if not entry.verify_integrity():
                if entry.entry_id not in corrupted_ids:
                    corrupted_ids.append(entry.entry_id)
                tamper_details.append(
                    f"Hash recalculation mismatch at index {i} (entry_id={entry.entry_id}): "
                    f"stored current_hash '{entry.current_hash}' does not match payload hash."
                )

            if entry.entry_id not in corrupted_ids:
                verified_count += 1

            # Update next expected link to this entry's recorded hash
            expected_prev_hash = entry.current_hash

        is_valid = len(corrupted_ids) == 0

        return AuditChainVerificationResult(
            is_valid=is_valid,
            total_entries=total_entries,
            verified_entries=verified_count,
            corrupted_entry_ids=corrupted_ids,
            tamper_details=tamper_details,
        )
