"""개인 기준과 관리자 조직 기본 기준 관리 UI/API."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import SQLAlchemyError

from apps.api.auth_support import current_principal, require_administrator
from apps.api.browser_csrf import browser_csrf_token, verify_browser_csrf
from security_audit.application.assessment_criteria import (
    DEFAULT_UNNECESSARY_SERVICE_IDS,
    AssessmentCriteriaService,
    CriteriaContractError,
    public_criteria_catalog,
)
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.assessment_criteria_repository import (
    SqlAssessmentCriteriaRepository,
)

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")
_DEFAULT_UNNECESSARY_SERVICES_FORM = "\n".join(
    DEFAULT_UNNECESSARY_SERVICE_IDS
)


@lru_cache(maxsize=1)
def _engine() -> Engine:
    return create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )


@lru_cache(maxsize=1)
def _service() -> AssessmentCriteriaService:
    return AssessmentCriteriaService(SqlAssessmentCriteriaRepository(_engine()))


def _require_feature() -> None:
    if os.getenv("SECAI_DEV_DEMO_ENABLED", "false").casefold() != "true":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")


def _values(
    *,
    password_maximum_age_days: int,
    password_minimum_length: int,
    password_complexity_required: bool,
    password_required: bool,
    approved_share_ids: str,
    unnecessary_service_ids: str,
    approved_messenger_products: str,
    security_update_maximum_age_days: int,
    antivirus_signature_maximum_age_hours: int,
    screensaver_timeout_maximum_minutes: int,
    wininet_current_user_scope_accepted: bool,
    screensaver_current_user_scope_accepted: bool,
    autoplay_disabled_required: bool,
    remote_assistance_disabled_required: bool,
) -> dict[str, object]:
    return {
        "password_maximum_age_days": password_maximum_age_days,
        "password_minimum_length": password_minimum_length,
        "password_complexity_required": password_complexity_required,
        "password_required": password_required,
        "approved_share_ids": approved_share_ids,
        "unnecessary_service_ids": unnecessary_service_ids,
        "approved_messenger_products": approved_messenger_products,
        "security_update_maximum_age_days": security_update_maximum_age_days,
        "antivirus_signature_maximum_age_hours": (
            antivirus_signature_maximum_age_hours
        ),
        "screensaver_timeout_maximum_minutes": screensaver_timeout_maximum_minutes,
        "wininet_current_user_scope_accepted": wininet_current_user_scope_accepted,
        "screensaver_current_user_scope_accepted": (
            screensaver_current_user_scope_accepted
        ),
        "autoplay_disabled_required": autoplay_disabled_required,
        "remote_assistance_disabled_required": remote_assistance_disabled_required,
    }


def _effective_by_key(options: dict[str, object]) -> dict[str, dict[str, object]]:
    raw_effective = options.get("effective")
    if not isinstance(raw_effective, list):
        return {}
    return {
        str(item["key"]): item
        for item in raw_effective
        if isinstance(item, dict) and "key" in item
    }


def _official_values() -> dict[str, object]:
    return {
        str(item["key"]): item["official_value"]
        for item in public_criteria_catalog()
    }


def _personal_page(
    request: Request,
    *,
    selected_profile_id: UUID | None = None,
    reset_profile_id: UUID | None = None,
    success_message: str | None = None,
    error_message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    principal = current_principal(request)
    options: dict[str, object] = {}
    try:
        options = _service().options(
            principal,
            personal_profile_id=selected_profile_id,
        )
    except (CriteriaContractError, SQLAlchemyError) as exc:
        if error_message is None:
            error_message = (
                exc.args[0]
                if isinstance(exc, CriteriaContractError)
                else "점검 기준 저장소에 연결하지 못했습니다."
            )
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    effective = _effective_by_key(options)
    return templates.TemplateResponse(
        request=request,
        name="pages/assessment_criteria.html",
        context={
            "identity": principal,
            "csrf_token": browser_csrf_token(request),
            "catalog": public_criteria_catalog(),
            "official_values": _official_values(),
            "options": options,
            "effective": effective,
            "reset_profile_id": reset_profile_id,
            "success_message": success_message,
            "error_message": error_message,
        },
        status_code=status_code,
    )


@router.get("/ui/criteria", response_class=HTMLResponse)
def personal_criteria_page(
    request: Request,
    profile_id: Annotated[UUID | None, Query()] = None,
) -> HTMLResponse:
    _require_feature()
    return _personal_page(request, selected_profile_id=profile_id)


@router.post("/ui/criteria/personal", response_class=HTMLResponse)
def save_personal_criteria(
    request: Request,
    name: Annotated[str, Form(min_length=1, max_length=80)],
    change_reason: Annotated[str, Form(min_length=1, max_length=256)],
    password_maximum_age_days: Annotated[int, Form(ge=1, le=365)],
    password_minimum_length: Annotated[int, Form(ge=8, le=64)],
    approved_share_ids: Annotated[str, Form(max_length=4096)] = "",
    unnecessary_service_ids: Annotated[str, Form(max_length=4096)] = (
        _DEFAULT_UNNECESSARY_SERVICES_FORM
    ),
    approved_messenger_products: Annotated[str, Form(max_length=4096)] = "",
    security_update_maximum_age_days: Annotated[int, Form(ge=1, le=180)] = 30,
    antivirus_signature_maximum_age_hours: Annotated[int, Form(ge=1, le=168)] = 24,
    screensaver_timeout_maximum_minutes: Annotated[int, Form(ge=1, le=60)] = 10,
    password_complexity_required: Annotated[bool, Form()] = False,
    password_required: Annotated[bool, Form()] = False,
    wininet_current_user_scope_accepted: Annotated[bool, Form()] = False,
    screensaver_current_user_scope_accepted: Annotated[bool, Form()] = False,
    autoplay_disabled_required: Annotated[bool, Form()] = False,
    remote_assistance_disabled_required: Annotated[bool, Form()] = False,
    csrf_token: Annotated[str, Form()] = "",
) -> HTMLResponse:
    _require_feature()
    verify_browser_csrf(request, csrf_token)
    principal = current_principal(request)
    try:
        profile = _service().save_personal(
            principal,
            name=name,
            values=_values(
                password_maximum_age_days=password_maximum_age_days,
                password_minimum_length=password_minimum_length,
                password_complexity_required=password_complexity_required,
                password_required=password_required,
                approved_share_ids=approved_share_ids,
                unnecessary_service_ids=unnecessary_service_ids,
                approved_messenger_products=approved_messenger_products,
                security_update_maximum_age_days=security_update_maximum_age_days,
                antivirus_signature_maximum_age_hours=(
                    antivirus_signature_maximum_age_hours
                ),
                screensaver_timeout_maximum_minutes=screensaver_timeout_maximum_minutes,
                wininet_current_user_scope_accepted=(
                    wininet_current_user_scope_accepted
                ),
                screensaver_current_user_scope_accepted=(
                    screensaver_current_user_scope_accepted
                ),
                autoplay_disabled_required=autoplay_disabled_required,
                remote_assistance_disabled_required=(
                    remote_assistance_disabled_required
                ),
            ),
            change_reason=change_reason,
        )
        _service().select(
            principal,
            selection_kind="PERSONAL",
            personal_profile_id=profile.id,
        )
    except CriteriaContractError as exc:
        return _personal_page(
            request,
            error_message=str(exc),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    except SQLAlchemyError:
        return _personal_page(
            request,
            error_message="개인 기준을 저장하지 못했습니다.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return _personal_page(
        request,
        selected_profile_id=profile.id,
        success_message=f"{profile.name} {profile.version}판을 저장했습니다.",
    )


@router.post("/ui/criteria/personal/reset", response_class=HTMLResponse)
def reset_personal_criteria(
    request: Request,
    csrf_token: Annotated[str, Form()],
) -> HTMLResponse:
    _require_feature()
    verify_browser_csrf(request, csrf_token)
    principal = current_principal(request)
    try:
        _service().select(
            principal,
            selection_kind="KISA_DEFAULT",
            source="RESET",
        )
    except CriteriaContractError as exc:
        return _personal_page(
            request,
            error_message=str(exc),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    except SQLAlchemyError:
        return _personal_page(
            request,
            error_message="개인 기준을 기본 점검값으로 되돌리지 못했습니다.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return _personal_page(
        request,
        success_message=(
            "KISA 기준과 SecAI 보조 기본 범위를 선택했습니다. "
            "다음 점검에 자동 적용됩니다."
        ),
    )


@router.post("/ui/criteria/select", response_class=HTMLResponse)
def select_personal_criteria(
    request: Request,
    selection_kind: Annotated[
        Literal["KISA_DEFAULT", "ORGANIZATION", "PERSONAL"], Form()
    ],
    csrf_token: Annotated[str, Form()],
    personal_profile_id: Annotated[UUID | None, Form()] = None,
) -> HTMLResponse:
    _require_feature()
    verify_browser_csrf(request, csrf_token)
    principal = current_principal(request)
    try:
        _service().select(
            principal,
            selection_kind=selection_kind,
            personal_profile_id=personal_profile_id,
        )
    except CriteriaContractError as exc:
        return _personal_page(
            request,
            error_message=str(exc),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    labels = {
        "KISA_DEFAULT": "KISA 기준과 SecAI 보조 기본 범위",
        "ORGANIZATION": "조직 기본 기준",
        "PERSONAL": "개인 기준",
    }
    return _personal_page(
        request,
        success_message=f"{labels[selection_kind]}을 다음 점검 기준으로 선택했습니다.",
    )


def _admin_page(
    request: Request,
    *,
    success_message: str | None = None,
    error_message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    principal = require_administrator(request)
    if principal is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator access required.")
    options: dict[str, object] = {}
    try:
        options = _service().options(principal)
    except SQLAlchemyError:
        error_message = error_message or "점검 기준 저장소에 연결하지 못했습니다."
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    effective = _effective_by_key(options)
    return templates.TemplateResponse(
        request=request,
        name="pages/admin_assessment_criteria.html",
        context={
            "identity": principal,
            "csrf_token": browser_csrf_token(request),
            "catalog": public_criteria_catalog(),
            "official_values": _official_values(),
            "options": options,
            "effective": effective,
            "success_message": success_message,
            "error_message": error_message,
        },
        status_code=status_code,
    )


@router.get("/admin/criteria", response_class=HTMLResponse)
def organization_criteria_page(request: Request) -> HTMLResponse:
    _require_feature()
    return _admin_page(request)


@router.post("/admin/criteria", response_class=HTMLResponse)
def save_organization_criteria(
    request: Request,
    change_reason: Annotated[str, Form(min_length=1, max_length=256)],
    password_maximum_age_days: Annotated[int, Form(ge=1, le=365)],
    password_minimum_length: Annotated[int, Form(ge=8, le=64)],
    approved_share_ids: Annotated[str, Form(max_length=4096)] = "",
    unnecessary_service_ids: Annotated[str, Form(max_length=4096)] = (
        _DEFAULT_UNNECESSARY_SERVICES_FORM
    ),
    approved_messenger_products: Annotated[str, Form(max_length=4096)] = "",
    security_update_maximum_age_days: Annotated[int, Form(ge=1, le=180)] = 30,
    antivirus_signature_maximum_age_hours: Annotated[int, Form(ge=1, le=168)] = 24,
    screensaver_timeout_maximum_minutes: Annotated[int, Form(ge=1, le=60)] = 10,
    password_complexity_required: Annotated[bool, Form()] = False,
    password_required: Annotated[bool, Form()] = False,
    wininet_current_user_scope_accepted: Annotated[bool, Form()] = False,
    screensaver_current_user_scope_accepted: Annotated[bool, Form()] = False,
    autoplay_disabled_required: Annotated[bool, Form()] = False,
    remote_assistance_disabled_required: Annotated[bool, Form()] = False,
    csrf_token: Annotated[str, Form()] = "",
) -> HTMLResponse:
    _require_feature()
    verify_browser_csrf(request, csrf_token)
    principal = require_administrator(request)
    if principal is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator access required.")
    try:
        profile = _service().save_organization_default(
            principal,
            values=_values(
                password_maximum_age_days=password_maximum_age_days,
                password_minimum_length=password_minimum_length,
                password_complexity_required=password_complexity_required,
                password_required=password_required,
                approved_share_ids=approved_share_ids,
                unnecessary_service_ids=unnecessary_service_ids,
                approved_messenger_products=approved_messenger_products,
                security_update_maximum_age_days=security_update_maximum_age_days,
                antivirus_signature_maximum_age_hours=(
                    antivirus_signature_maximum_age_hours
                ),
                screensaver_timeout_maximum_minutes=screensaver_timeout_maximum_minutes,
                wininet_current_user_scope_accepted=(
                    wininet_current_user_scope_accepted
                ),
                screensaver_current_user_scope_accepted=(
                    screensaver_current_user_scope_accepted
                ),
                autoplay_disabled_required=autoplay_disabled_required,
                remote_assistance_disabled_required=(
                    remote_assistance_disabled_required
                ),
            ),
            change_reason=change_reason,
        )
    except CriteriaContractError as exc:
        return _admin_page(
            request,
            error_message=str(exc),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    except SQLAlchemyError:
        return _admin_page(
            request,
            error_message="조직 기본 기준을 저장하지 못했습니다.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return _admin_page(
        request,
        success_message=f"조직 기본 기준 {profile.version}판을 발행했습니다.",
    )


@router.post("/admin/criteria/reset", response_class=HTMLResponse)
def reset_organization_criteria(
    request: Request,
    csrf_token: Annotated[str, Form()],
) -> HTMLResponse:
    _require_feature()
    verify_browser_csrf(request, csrf_token)
    principal = require_administrator(request)
    if principal is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator access required.")
    try:
        profile = _service().save_organization_default(
            principal,
            values=_official_values(),
            change_reason="관리자 요청으로 기본 점검값 복원",
        )
    except CriteriaContractError as exc:
        return _admin_page(
            request,
            error_message=str(exc),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    except SQLAlchemyError:
        return _admin_page(
            request,
            error_message="조직 기본 기준을 기본 점검값으로 되돌리지 못했습니다.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    return _admin_page(
        request,
        success_message=(
            f"조직 기본 기준 {profile.version}판을 KISA 기준과 SecAI 보조 기본 "
            "범위로 되돌렸습니다. "
            "다음 점검부터 자동 적용됩니다."
        ),
    )


@router.get("/api/v1/criteria/effective")
def effective_criteria(
    request: Request,
    personal_profile_id: Annotated[UUID | None, Query()] = None,
    selection_kind: Annotated[
        Literal["KISA_DEFAULT", "ORGANIZATION"] | None,
        Query(),
    ] = None,
) -> dict[str, object]:
    _require_feature()
    try:
        return _service().options(
            current_principal(request),
            personal_profile_id=personal_profile_id,
            selection_kind=selection_kind,
        )
    except CriteriaContractError as exc:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            {"code": "CRITERIA_PROFILE_NOT_FOUND", "message": str(exc)},
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            {
                "code": "CRITERIA_STORE_UNAVAILABLE",
                "message": "점검 기준을 불러오지 못했습니다.",
            },
        ) from exc


@router.post("/api/v1/criteria/scan-start")
def record_scan_start_criteria(
    request: Request,
    selection_kind: Annotated[
        Literal["KISA_DEFAULT", "ORGANIZATION", "PERSONAL"], Form()
    ],
    expected_criteria_sha256: Annotated[
        str,
        Form(pattern=r"^[a-f0-9]{64}$"),
    ],
    csrf_token: Annotated[str, Form()],
    personal_profile_id: Annotated[UUID | None, Form()] = None,
) -> dict[str, object]:
    """점검에 고정한 기준과 화면에서 확인한 기준이 같은 경우만 기록합니다."""

    _require_feature()
    verify_browser_csrf(request, csrf_token)
    principal = current_principal(request)
    try:
        selection = _service().select(
            principal,
            selection_kind=selection_kind,
            personal_profile_id=personal_profile_id,
            source="SCAN_START",
            expected_criteria_sha256=expected_criteria_sha256,
        )
    except CriteriaContractError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"code": "CRITERIA_SELECTION_INVALID", "message": str(exc)},
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            {
                "code": "CRITERIA_STORE_UNAVAILABLE",
                "message": "점검 기준 이력을 저장하지 못했습니다.",
            },
        ) from exc
    return {"selection": selection.public_view()}
