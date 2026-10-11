"""Protected multi-tenant and ownership resources demonstrating ABAC & BOLA defense."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from rbacapi.api.dependencies import (
    get_current_user,
    require_permission,
)
from rbacapi.models.enums import PermissionAction, ResourceType
from rbacapi.models.user import User
from rbacapi.policy.abac import ABACPolicy

router = APIRouter(prefix="/resources", tags=["Protected Resources"])

# In-memory mock resource store for BOLA/IDOR demonstration
_MOCK_RESOURCES: dict[str, dict[str, Any]] = {
    "doc_101": {
        "id": "doc_101",
        "title": "Quarterly Financial Analysis",
        "owner_id": "usr_finance",
        "tenant_id": "tenant_a",
        "content": "Confidential financial numbers.",
    },
    "doc_102": {
        "id": "doc_102",
        "title": "Engineering Architecture",
        "owner_id": "usr_engineer",
        "tenant_id": "tenant_b",
        "content": "Top secret microservice blueprint.",
    },
}


def _extract_doc_owner(request: Request) -> str | None:
    doc_id = request.path_params.get("doc_id")
    if doc_id and doc_id in _MOCK_RESOURCES:
        return str(_MOCK_RESOURCES[doc_id]["owner_id"])
    return None


def _extract_doc_tenant(request: Request) -> str | None:
    doc_id = request.path_params.get("doc_id")
    if doc_id and doc_id in _MOCK_RESOURCES:
        return str(_MOCK_RESOURCES[doc_id]["tenant_id"])
    return None


class DocumentCreate(BaseModel):
    title: str
    content: str


@router.get(
    "/reports",
    dependencies=[Depends(require_permission(ResourceType.REPORTS, PermissionAction.READ))],
)
def get_reports() -> dict[str, Any]:
    """Protected executive reports endpoint requiring REPORTS:READ."""
    return {
        "status": "success",
        "reports": [
            {"id": "rep_1", "name": "Annual Security Assessment", "status": "APPROVED"},
            {"id": "rep_2", "name": "SOC2 Compliance Readiness", "status": "IN_PROGRESS"},
        ],
    }


@router.get(
    "/documents/{doc_id}",
    dependencies=[
        Depends(
            require_permission(
                ResourceType.REPORTS,
                PermissionAction.READ,
                abac_policy=ABACPolicy(
                    require_owner_match=True,
                    require_tenant_match=True,
                ),
                extract_resource_owner=_extract_doc_owner,
                extract_resource_tenant=_extract_doc_tenant,
            )
        )
    ],
)
def get_document(
    doc_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Protected document endpoint with ABAC tenant isolation and ownership defense."""
    if doc_id not in _MOCK_RESOURCES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found.")

    return _MOCK_RESOURCES[doc_id]
