"""관리자 전용 Linux SSH 서버 등록 화면과 명령 API."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from apps.api.auth_support import auth_enabled, require_administrator
from apps.api.browser_csrf import browser_csrf_token, verify_browser_csrf
from security_audit.application.linux_asset_management import (
    LinuxAssetContractError,
    LinuxAssetKeyStore,
    LinuxAssetManagementService,
)
from security_audit.application.linux_audit_service import verify_linux_connection
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.linux_asset_repository import (
    SqlLinuxAssetRepository,
)
from security_audit.security.auth import AuthenticatedPrincipal

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")


@lru_cache(maxsize=1)
def _engine() -> Engine:
    return create_engine(ServiceSettings.from_environment().postgres_url(), pool_pre_ping=True)


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


@lru_cache(maxsize=1)
def _service() -> LinuxAssetManagementService:
    allowed_ports = tuple(
        int(item)
        for item in _csv(os.getenv("SECAI_LINUX_ASSET_ALLOWED_PORTS", "22"))
    )
    return LinuxAssetManagementService(
        SqlLinuxAssetRepository(_engine()),
        LinuxAssetKeyStore(
            Path(
                os.getenv(
                    "SECAI_LINUX_ASSET_KEY_ROOT",
                    "/run/secai-linux-asset-keys",
                )
            )
        ),
        allowed_cidrs=_csv(
            os.getenv("SECAI_LINUX_ASSET_ALLOWED_CIDRS", "192.168.110.0/24")
        ),
        allowed_ports=allowed_ports,
        verifier=verify_linux_connection,
    )


def _require_admin_feature(request: Request) -> AuthenticatedPrincipal:
    if os.getenv("SECAI_DEV_DEMO_ENABLED", "false").casefold() != "true":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")
    if not auth_enabled():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Authentication required.")
    principal = require_administrator(request)
    if principal is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator access required.")
    return principal


def _page(
    request: Request,
    principal: AuthenticatedPrincipal,
    *,
    error_message: str | None = None,
    success_message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    assets: tuple[dict[str, object], ...] = ()
    try:
        assets = tuple(item.administrator_view() for item in _service().list(principal))
    except SQLAlchemyError:
        error_message = error_message or "Linux 서버 저장소에 연결하지 못했습니다."
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return templates.TemplateResponse(
        request=request,
        name="pages/admin_linux_servers.html",
        context={
            "identity": principal,
            "csrf_token": browser_csrf_token(request),
            "assets": assets,
            "error_message": error_message,
            "success_message": success_message,
            "allowed_cidrs": _csv(
                os.getenv("SECAI_LINUX_ASSET_ALLOWED_CIDRS", "192.168.110.0/24")
            ),
            "allowed_ports": _csv(
                os.getenv("SECAI_LINUX_ASSET_ALLOWED_PORTS", "22")
            ),
        },
        status_code=status_code,
    )


@router.get("/admin/linux-servers", response_class=HTMLResponse)
def linux_server_management_page(request: Request, notice: str | None = None) -> HTMLResponse:
    principal = _require_admin_feature(request)
    messages = {
        "registered": "SSH 공개키를 자동 발급했습니다. 서버에 설치한 뒤 연결 확인을 진행하세요.",
        "activated": "연결 확인에 성공했습니다. 이제 Linux 점검 화면에서 선택할 수 있습니다.",
        "suspended": "서버 사용을 중지했습니다. Linux 점검 목록에서 제외됩니다.",
    }
    return _page(request, principal, success_message=messages.get(notice or ""))


@router.post("/admin/linux-servers")
def register_linux_server(
    request: Request,
    alias: Annotated[str, Form(min_length=2, max_length=80)],
    host: Annotated[str, Form(min_length=2, max_length=64)],
    port: Annotated[int, Form(ge=1, le=65535)],
    ssh_username: Annotated[str, Form(min_length=1, max_length=32)],
    csrf_token: Annotated[str, Form()],
) -> Response:
    principal = _require_admin_feature(request)
    verify_browser_csrf(request, csrf_token)
    try:
        _service().register(
            principal,
            alias=alias,
            host=host,
            port=port,
            ssh_username=ssh_username,
        )
    except LinuxAssetContractError as exc:
        return _page(
            request,
            principal,
            error_message=str(exc),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    except IntegrityError:
        return _page(
            request,
            principal,
            error_message="같은 별칭 또는 접속 주소가 이미 등록되어 있습니다.",
            status_code=status.HTTP_409_CONFLICT,
        )
    except (OSError, SQLAlchemyError):
        return _page(
            request,
            principal,
            error_message="서버 등록 또는 SSH 키 발급을 완료하지 못했습니다.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return RedirectResponse(
        "/admin/linux-servers?notice=registered",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/admin/linux-servers/{asset_id}/activate")
def activate_linux_server(
    request: Request,
    asset_id: UUID,
    host_key: Annotated[str, Form(min_length=20, max_length=2048)],
    csrf_token: Annotated[str, Form()],
    fingerprint_confirmed: Annotated[bool, Form()] = False,
) -> Response:
    principal = _require_admin_feature(request)
    verify_browser_csrf(request, csrf_token)
    try:
        _service().activate(
            principal,
            asset_id=asset_id,
            host_key=host_key,
            fingerprint_confirmed=fingerprint_confirmed,
        )
    except LinuxAssetContractError as exc:
        return _page(
            request,
            principal,
            error_message=str(exc),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    except (OSError, RuntimeError, UnicodeError, SQLAlchemyError):
        return _page(
            request,
            principal,
            error_message=(
                "연결 확인에 실패했습니다. 공개키 설치, 점검 계정, 호스트 키와 "
                "네트워크 연결을 확인해 주세요."
            ),
            status_code=status.HTTP_409_CONFLICT,
        )
    return RedirectResponse(
        "/admin/linux-servers?notice=activated",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/admin/linux-servers/{asset_id}/suspend")
def suspend_linux_server(
    request: Request,
    asset_id: UUID,
    csrf_token: Annotated[str, Form()],
) -> Response:
    principal = _require_admin_feature(request)
    verify_browser_csrf(request, csrf_token)
    try:
        _service().suspend(principal, asset_id=asset_id)
    except LinuxAssetContractError as exc:
        return _page(
            request,
            principal,
            error_message=str(exc),
            status_code=status.HTTP_409_CONFLICT,
        )
    except SQLAlchemyError:
        return _page(
            request,
            principal,
            error_message="서버 사용 중지를 저장하지 못했습니다.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return RedirectResponse(
        "/admin/linux-servers?notice=suspended",
        status_code=status.HTTP_303_SEE_OTHER,
    )
