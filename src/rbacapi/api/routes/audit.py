"""Audit ledger query and integrity verification routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from rbacapi.api.dependencies import (
    get_audit_ledger,
    require_permission,
)
from rbacapi.audit.hash_chain import AuditChainVerificationResult, AuditLedger
from rbacapi.models.audit import AuditLogEntry
from rbacapi.models.enums import PermissionAction, ResourceType

router = APIRouter(prefix="/audit", tags=["Audit Ledger"])


@router.get(
    "/entries",
    response_model=list[AuditLogEntry],
    dependencies=[Depends(require_permission(ResourceType.AUDIT_LOGS, PermissionAction.READ))],
)
def list_audit_entries(
    audit_ledger: Annotated[AuditLedger, Depends(get_audit_ledger)],
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[AuditLogEntry]:
    """Retrieve chronological audit trail records (requires AUDIT_LOGS:READ)."""
    return audit_ledger.db.list_audit_entries(limit=limit, offset=offset)


@router.get(
    "/verify",
    response_model=AuditChainVerificationResult,
    dependencies=[Depends(require_permission(ResourceType.AUDIT_LOGS, PermissionAction.READ))],
)
def verify_audit_chain(
    audit_ledger: Annotated[AuditLedger, Depends(get_audit_ledger)],
) -> AuditChainVerificationResult:
    """Perform mathematical SHA-256 hash chaining verification across all records."""
    return audit_ledger.verify_ledger_integrity()
