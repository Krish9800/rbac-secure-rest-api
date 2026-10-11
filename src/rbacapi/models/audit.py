"""Audit log entry domain model with cryptographic hash computation."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from rbacapi.models.enums import AccessDecision, AuditEventType


class AuditLogEntry(BaseModel):
    """Tamper-evident audit log ledger record."""

    entry_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: AuditEventType
    user_id: str | None = None
    role: str | None = None
    resource: str | None = None
    action: str | None = None
    decision: AccessDecision = AccessDecision.PERMIT
    ip_address: str | None = None
    user_agent: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str
    current_hash: str

    @classmethod
    def compute_hash(
        cls,
        previous_hash: str,
        timestamp: datetime,
        event_type: AuditEventType,
        user_id: str | None,
        role: str | None,
        resource: str | None,
        action: str | None,
        decision: AccessDecision,
        ip_address: str | None,
        details: dict[str, Any],
    ) -> str:
        """Compute cryptographic SHA-256 hash chaining across record properties."""
        details_serialized = json.dumps(details, sort_keys=True)
        raw_payload = (
            f"{previous_hash}|"
            f"{timestamp.isoformat()}|"
            f"{event_type.value}|"
            f"{user_id or ''}|"
            f"{role or ''}|"
            f"{resource or ''}|"
            f"{action or ''}|"
            f"{decision.value}|"
            f"{ip_address or ''}|"
            f"{details_serialized}"
        )
        return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify whether current_hash matches recalculation over entry fields."""
        expected = self.compute_hash(
            previous_hash=self.previous_hash,
            timestamp=self.timestamp,
            event_type=self.event_type,
            user_id=self.user_id,
            role=self.role,
            resource=self.resource,
            action=self.action,
            decision=self.decision,
            ip_address=self.ip_address,
            details=self.details,
        )
        return self.current_hash == expected
