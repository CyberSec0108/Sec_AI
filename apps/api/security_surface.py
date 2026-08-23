"""IMP-046 scope-aware full-page, fragment, SSE and download surfaces."""

from __future__ import annotations

import json
from collections.abc import Iterator
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from apps.api.auth_support import (
    current_context,
    current_principal,
    get_auth_service,
    request_session_token,
)
from security_audit.security.rbac import (
    AuthorizationOutcome,
    Permission,
    authorize,
)

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")


def _authorize(
    request: Request,
    permission: Permission,
    organization_id: UUID,
    asset_id: UUID,
) -> None:
    principal = current_principal(request)
    decision = authorize(
        principal,
        permission,
        organization_id,
        asset_id,
    )
    get_auth_service().audit_authorization(
        request_session_token(request),
        principal,
        permission.value,
        decision.allowed,
        decision.reason_code,
    )
    if decision.outcome is AuthorizationOutcome.NOT_FOUND:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")
    if not decision.allowed:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Permission denied.")


@router.get(
    "/ui/security/organizations/{organization_id}/assets/{asset_id}",
    response_class=HTMLResponse,
)
def asset_security_page(
    request: Request,
    organization_id: UUID,
    asset_id: UUID,
) -> HTMLResponse:
    _authorize(request, Permission.ASSET_READ, organization_id, asset_id)
    context = current_context(request)
    return templates.TemplateResponse(
        request=request,
        name="pages/security_asset.html",
        context={
            "identity": context.principal,
            "csrf_token": context.csrf_token,
            "organization_id": organization_id,
            "asset_id": asset_id,
        },
    )


@router.get(
    "/ui/security/organizations/{organization_id}/assets/{asset_id}/fragment",
    response_class=HTMLResponse,
)
def asset_security_fragment(
    request: Request,
    organization_id: UUID,
    asset_id: UUID,
) -> HTMLResponse:
    _authorize(request, Permission.ASSET_READ, organization_id, asset_id)
    return templates.TemplateResponse(
        request=request,
        name="components/security_asset_fragment.html",
        context={"asset_id": asset_id},
    )


@router.get(
    "/api/v1/security/organizations/{organization_id}/assets/{asset_id}"
)
def asset_security_api(
    request: Request,
    organization_id: UUID,
    asset_id: UUID,
) -> dict[str, object]:
    _authorize(request, Permission.ASSET_READ, organization_id, asset_id)
    return {
        "resource": "asset-security-summary",
        "organization_id": str(organization_id),
        "asset_id": str(asset_id),
        "raw_evidence_included": False,
        "official_finding_created": False,
    }


@router.get(
    "/api/v1/security/organizations/{organization_id}/assets/{asset_id}/events"
)
def asset_security_events(
    request: Request,
    organization_id: UUID,
    asset_id: UUID,
) -> StreamingResponse:
    _authorize(request, Permission.ASSET_READ, organization_id, asset_id)

    def event_stream() -> Iterator[str]:
        payload = json.dumps(
            {
                "state": "AUTHORIZED",
                "asset_id": str(asset_id),
                "contains_evidence": False,
            },
            separators=(",", ":"),
        )
        yield f"event: security-status\ndata: {payload}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store"},
    )


@router.get(
    "/api/v1/security/organizations/{organization_id}/assets/{asset_id}/download",
    response_class=PlainTextResponse,
)
def asset_security_download(
    request: Request,
    organization_id: UUID,
    asset_id: UUID,
) -> PlainTextResponse:
    _authorize(
        request,
        Permission.EVIDENCE_DOWNLOAD,
        organization_id,
        asset_id,
    )
    return PlainTextResponse(
        "Sec_AI synthetic authorization check\n"
        "No original evidence is included.\n",
        headers={
            "Content-Disposition": 'attachment; filename="secai-auth-check.txt"',
            "Cache-Control": "no-store",
        },
    )
