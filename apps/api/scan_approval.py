"""원격 배치용 수집기 실행 승인 API.

수집기는 사이드카 토큰으로 실행을 등록하고, 사용자는 이미 로그인된 화면에서
대상 장비를 확인한 뒤 승인합니다. 일회용 코드를 입력하지 않습니다.
"""

from __future__ import annotations

import os
import re
import secrets
from datetime import UTC, datetime
from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Form, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field

from apps.api.auth_support import auth_enabled, current_principal
from apps.api.browser_csrf import browser_csrf_token, verify_browser_csrf
from apps.api.linux_oneshot import provision_linux_self_scan
from security_audit.collector.scan_approval import (
    InMemoryScanApprovalStore,
    ScanApprovalError,
    ScanApprovalService,
    ScanApprovalView,
)
from security_audit.collector.scan_session import (
    ScanSessionError,
    ScanSessionService,
)
from security_audit.collector.scan_sidecar import (
    SIDECAR_SUFFIX,
    ScanSidecarError,
    build_scan_sidecar,
)
from security_audit.collector.scan_token import (
    InMemoryScanTokenStore,
    ScanTokenError,
    ScanTokenService,
)
from security_audit.security.auth import AuthenticatedPrincipal

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")
MAX_TOKEN_BYTES = 128
_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]")


class IssueScanSidecarBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    artifact_filename: str = Field(min_length=1, max_length=128)


class RegisterScanSessionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=1, max_length=MAX_TOKEN_BYTES)
    device_name: str = Field(min_length=1, max_length=64)


class GrantScanCodeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=1, max_length=MAX_TOKEN_BYTES)


class _Runtime:
    def __init__(self) -> None:
        self.sessions = ScanSessionService(
            tokens=ScanTokenService(
                InMemoryScanTokenStore(),
                hash_key=secrets.token_bytes(32),
                hash_key_version="dev-process-ephemeral-v1",
            ),
            approvals=ScanApprovalService(InMemoryScanApprovalStore()),
        )


@lru_cache(maxsize=1)
def _runtime() -> _Runtime:
    return _Runtime()


def _feature_enabled() -> None:
    if os.getenv("SECAI_DEV_DEMO_ENABLED", "false").casefold() != "true":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")


def _require_user(request: Request) -> AuthenticatedPrincipal:
    _feature_enabled()
    if not auth_enabled():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Authentication required.")
    return current_principal(request)


def _server_origin(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def _safe_error(
    error: ScanTokenError | ScanApprovalError | ScanSessionError,
) -> HTTPException:
    return HTTPException(
        status.HTTP_400_BAD_REQUEST,
        {"code": str(error.code), "message": "점검 승인 요청을 확인할 수 없습니다."},
    )


def _approval_view_payload(view: ScanApprovalView) -> dict[str, object]:
    """수집기에는 결정 결과만 돌려주고 장비 이름은 노출하지 않습니다."""

    return {
        "request_id": view.request_id,
        "state": str(view.state),
        "elevated_consent": view.elevated_consent,
    }


def _sidecar_filename(artifact_filename: str) -> str:
    """서명된 실행 파일은 그대로 두고 옆에 놓일 이름만 만듭니다."""

    return f"{artifact_filename}{SIDECAR_SUFFIX}"


@router.post("/api/v1/scan/sidecar")
def issue_scan_sidecar(
    request: Request,
    body: IssueScanSidecarBody,
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> Response:
    """로그인한 사용자에게만 서버 주소와 실행 토큰을 담은 사이드카를 내려줍니다."""

    principal = _require_user(request)
    verify_browser_csrf(request, csrf_token)
    if _UNSAFE_FILENAME.search(body.artifact_filename) is not None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "실행 파일 이름이 올바르지 않습니다.",
        )
    issued = _runtime().sessions.issue_token(
        organization_id=str(principal.organization_id),
        subject_user_id=str(principal.user_id),
        server_origin=_server_origin(request),
        issued_at=datetime.now(UTC),
    )
    try:
        document = build_scan_sidecar(
            token=issued.token,
            server_origin=issued.server_origin,
            expires_at=issued.expires_at,
            max_runs=issued.max_runs,
        )
    except ScanSidecarError as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "사이드카 파일을 만들 수 없습니다.",
        ) from exc
    filename = _sidecar_filename(body.artifact_filename)
    return Response(
        content=document,
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/api/v1/scan/approvals", status_code=status.HTTP_201_CREATED)
def register_scan_session(
    request: Request,
    body: RegisterScanSessionBody,
) -> dict[str, object]:
    _feature_enabled()
    try:
        registered = _runtime().sessions.register(
            body.token,
            device_name=body.device_name,
            server_origin=_server_origin(request),
            received_at=datetime.now(UTC),
        )
    except (ScanTokenError, ScanApprovalError) as exc:
        raise _safe_error(exc) from exc
    return {
        "request_id": registered.request_id,
        "approve_url": registered.approve_url,
        "expires_at": registered.expires_at.isoformat().replace("+00:00", "Z"),
        "remaining_runs": registered.remaining_runs,
    }


@router.get("/api/v1/scan/approvals/{request_id}")
def poll_scan_approval(request: Request, request_id: str) -> dict[str, object]:
    _feature_enabled()
    try:
        view = _runtime().sessions.poll(request_id, received_at=datetime.now(UTC))
    except ScanApprovalError as exc:
        raise _safe_error(exc) from exc
    return _approval_view_payload(view)


@router.post("/api/v1/scan/approvals/{request_id}/grant")
def grant_scan_code(
    request: Request,
    request_id: str,
    body: GrantScanCodeBody,
) -> dict[str, object]:
    """승인된 요청의 일회용 코드를 같은 소유자의 수집기에만 건넵니다."""

    _feature_enabled()
    try:
        authorized = _runtime().sessions.authorize_exchange(
            request_id,
            token=body.token,
            server_origin=_server_origin(request),
            received_at=datetime.now(UTC),
        )
    except (ScanTokenError, ScanApprovalError, ScanSessionError) as exc:
        raise _safe_error(exc) from exc
    if authorized.grant_code is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {
                "code": "SCAN_GRANT_UNAVAILABLE",
                "message": "승인은 되었지만 실행 코드를 준비하지 못했습니다.",
            },
        )
    return {
        "request_id": authorized.request_id,
        "grant_code": authorized.grant_code,
        "elevated_consent": authorized.elevated_consent,
    }


@router.get("/ui/scan-approve", response_class=HTMLResponse)
def scan_approval_page(request: Request, req: str) -> HTMLResponse:
    principal = _require_user(request)
    try:
        view = _runtime().sessions.pending_view(
            req,
            viewer_user_id=str(principal.user_id),
            received_at=datetime.now(UTC),
            include_grant=False,
        )
    except ScanApprovalError as exc:
        raise _safe_error(exc) from exc
    return templates.TemplateResponse(
        request=request,
        name="pages/scan_approve.html",
        context={
            "csrf_token": browser_csrf_token(request),
            "request_id": view.request_id,
            "device_name": view.device_name,
            "state": str(view.state),
            "elevated_consent": view.elevated_consent,
        },
    )


@router.post("/ui/scan-approve/{request_id}/decision", response_class=HTMLResponse)
def decide_scan_approval(
    request: Request,
    request_id: str,
    decision: Annotated[str, Form(pattern="^(APPROVE|DECLINE)$")],
    csrf_token: Annotated[str, Form()],
    elevated_consent: Annotated[str | None, Form()] = None,
) -> HTMLResponse:
    principal = _require_user(request)
    verify_browser_csrf(request, csrf_token)
    sessions = _runtime().sessions
    decided_at = datetime.now(UTC)
    try:
        if decision == "APPROVE":
            # 승인 순간에 run과 일회용 코드를 만듭니다. 코드는 화면에 표시하지
            # 않고, 토큰을 제시한 수집기만 grant 요청으로 받아갑니다.
            provisioned = provision_linux_self_scan(
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                criteria_values=None,
                now=decided_at,
            )
            view = sessions.approve(
                request_id,
                approving_user_id=str(principal.user_id),
                elevated_consent=elevated_consent is not None,
                decided_at=decided_at,
                grant_code=str(provisioned["device_code"]),
            )
        else:
            view = sessions.decline(
                request_id,
                approving_user_id=str(principal.user_id),
                decided_at=decided_at,
            )
    except ScanApprovalError as exc:
        raise _safe_error(exc) from exc
    return templates.TemplateResponse(
        request=request,
        name="pages/scan_approve.html",
        context={
            "csrf_token": browser_csrf_token(request),
            "request_id": view.request_id,
            "device_name": view.device_name,
            "state": str(view.state),
            "elevated_consent": view.elevated_consent,
        },
    )
