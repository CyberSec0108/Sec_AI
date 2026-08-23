"""소유자 전용 Windows 저장과 Windows·Linux·Switch 통합 이력 API입니다."""

from __future__ import annotations

import logging
import os
from dataclasses import replace
from datetime import UTC, date, datetime, time, timedelta
from functools import lru_cache
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from apps.api.auth_support import (
    auth_enabled,
    current_principal,
    require_administrator,
)
from apps.api.browser_csrf import browser_csrf_token, verify_browser_csrf
from security_audit.application.audit_history import (
    AuditHistoryContractError,
    AuditHistoryPolicy,
    audit_history_entry_view,
    default_audit_history_policy,
    validate_windows_audit_presentation,
    validate_windows_audit_snapshot,
)
from security_audit.application.device_ai_token_stream import public_linux_control
from security_audit.application.switch_ai_token_stream import public_switch_control
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.audit_history_repository import (
    StoredWindowsAuditPresentation,
    append_audit_history_policy,
    append_windows_audit_presentation,
    append_windows_audit_snapshot,
    effective_audit_history_policy,
    list_audit_history,
    load_audit_history_record,
    load_windows_audit_presentations,
)
from security_audit.persistence.database.linux_audit_repository import get_ai_outputs
from security_audit.persistence.database.switch_audit_repository import (
    get_switch_ai_outputs,
)
from security_audit.security.rbac import AuthorizationOutcome, Permission, authorize

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")
logger = logging.getLogger(__name__)


class WindowsAuditHistoryBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: dict[str, Any]
    test_environment_result: Literal[True]


class AuditHistoryPolicyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    retention_days: int = Field(ge=30, le=3_650)
    backup_required: bool
    deletion_mode: Literal["HOLD", "TOMBSTONE_AFTER_BACKUP"]


class WindowsAuditPresentationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result_id: str = Field(pattern=r"^[a-f0-9]{16}$")
    result_version: int = Field(ge=1, le=1_000_000)
    presentation_kind: Literal["ADMINISTRATOR", "AI_COMPLETED"]
    administrator_report: dict[str, Any] | None = None
    ai_screen: dict[str, Any] | None = None
    test_environment_result: Literal[True]


@lru_cache(maxsize=1)
def _engine() -> Engine:
    return create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )


def _require_history_feature() -> None:
    if os.getenv("SECAI_DEV_DEMO_ENABLED", "false").casefold() != "true":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")
    if not auth_enabled():
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            {
                "code": "AUDIT_HISTORY_AUTHENTICATION_REQUIRED",
                "message": "점검 이력은 로그인한 사용자만 확인할 수 있습니다.",
            },
        )


def _assigned_windows_asset(request: Request) -> UUID:
    principal = current_principal(request)
    if len(principal.asset_ids) != 1:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {
                "code": "AUDIT_HISTORY_ASSET_SELECTION_REQUIRED",
                "message": "점검 결과를 저장할 Windows PC를 하나 선택해야 합니다.",
            },
        )
    asset_id = next(iter(principal.asset_ids))
    decision = authorize(
        principal,
        Permission.ASSET_READ,
        principal.organization_id,
        asset_id,
    )
    if decision.allowed:
        return asset_id
    response_status = (
        status.HTTP_404_NOT_FOUND
        if decision.outcome is AuthorizationOutcome.NOT_FOUND
        else status.HTTP_403_FORBIDDEN
    )
    raise HTTPException(
        response_status,
        {
            "code": decision.reason_code,
            "message": "점검 이력 대상 PC를 찾을 수 없습니다.",
        },
    )


def _policy_or_default(session: Session, request: Request) -> AuditHistoryPolicy:
    principal = current_principal(request)
    return (
        effective_audit_history_policy(
            session,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
        )
        or default_audit_history_policy()
    )


def _history_storage_error() -> HTTPException:
    return HTTPException(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        {
            "code": "AUDIT_HISTORY_STORAGE_UNAVAILABLE",
            "message": "점검 이력 저장소를 사용할 수 없습니다. 잠시 후 다시 시도하세요.",
        },
    )


@router.post(
    "/api/v1/audit-history/windows",
    status_code=status.HTTP_201_CREATED,
)
def save_windows_audit_history(
    request: Request,
    body: WindowsAuditHistoryBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    _require_history_feature()
    verify_browser_csrf(request, csrf_token)
    principal = current_principal(request)
    asset_id = _assigned_windows_asset(request)
    try:
        snapshot = validate_windows_audit_snapshot(body.result)
        with Session(_engine()) as session, session.begin():
            record = append_windows_audit_snapshot(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                asset_id=asset_id,
                snapshot=snapshot,
            )
        return {
            "entry_id": str(record.id),
            "created": record.created,
            "result_sha256": record.result_sha256,
            "created_at": record.created_at.isoformat(),
            "owner_scope": "CURRENT_LOGIN_ONLY",
        }
    except AuditHistoryContractError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {"code": str(exc), "message": "Windows 점검 결과를 안전하게 저장할 수 없습니다."},
        ) from exc
    except SQLAlchemyError as exc:
        raise _history_storage_error() from exc


def _windows_presentations_view(
    records: dict[str, StoredWindowsAuditPresentation],
) -> dict[str, object]:
    administrator_report: object = None
    ai_screen: object = None
    versions: dict[str, object] = {}
    ordered = sorted(
        records.values(),
        key=lambda item: item.created_at,
    )
    for item in ordered:
        payload = item.payload_json
        if payload.get("administrator_report") is not None:
            administrator_report = payload["administrator_report"]
        if payload.get("ai_screen") is not None:
            ai_screen = payload["ai_screen"]
        versions[item.presentation_kind] = {
            "version": item.presentation_version,
            "payload_sha256": item.payload_sha256,
            "created_at": item.created_at.isoformat(),
        }
    return {
        "available": bool(records),
        "administrator_report": administrator_report,
        "ai_screen": ai_screen,
        "versions": versions,
        "owner_scope": "CURRENT_LOGIN_ONLY",
    }


def _device_result_with_history_context(
    platform: str,
    result_json: dict[str, Any],
) -> dict[str, Any]:
    """구버전 결과도 화면에서 같은 공식 설명·AI 입력 계약으로 읽습니다."""

    if (
        isinstance(result_json.get("official_explanations"), list)
        and isinstance(result_json.get("ai_explanation_inputs"), list)
    ):
        return result_json
    controls = result_json.get("controls")
    if not isinstance(controls, list):
        raise AuditHistoryContractError("DEVICE_CONTROL_COVERAGE_INVALID")
    try:
        if platform == "LINUX":
            official = [public_linux_control(item) for item in controls]
            ai_inputs = [
                {
                    key: value
                    for key, value in item.items()
                    if key not in {"rule_status", "status_authority"}
                }
                for item in official
            ]
        elif platform == "SWITCH":
            official = [
                {
                    **dict(item),
                    **{
                        key: value
                        for key, value in public_switch_control(item).items()
                        if key
                        in {
                            "observed_summary",
                            "expected_summary",
                            "judgement_explanation",
                            "action_guidance",
                        }
                    },
                    "status_authority": "RULE_ENGINE",
                }
                for item in controls
            ]
            ai_inputs = [public_switch_control(item) for item in controls]
        else:
            return result_json
    except (KeyError, TypeError, ValueError) as exc:
        raise AuditHistoryContractError("DEVICE_HISTORY_CONTEXT_INVALID") from exc
    enriched = dict(result_json)
    enriched["official_explanations"] = official
    enriched["ai_explanation_inputs"] = ai_inputs
    return enriched


def _completed_device_ai_screen(
    *,
    version: str,
    result_json: dict[str, Any],
    outputs: dict[str, str],
) -> dict[str, object] | None:
    summary = outputs.get(f"{version}:SUMMARY")
    controls = result_json.get("controls")
    ai_inputs = result_json.get("ai_explanation_inputs")
    if (
        not isinstance(summary, str)
        or not summary.strip()
        or not isinstance(controls, list)
        or not isinstance(ai_inputs, list)
    ):
        return None
    input_by_id = {
        str(item.get("control_id")): item
        for item in ai_inputs
        if isinstance(item, dict)
    }
    restored: list[dict[str, object]] = []
    for control in controls:
        if not isinstance(control, dict):
            return None
        control_id = str(control.get("control_id", ""))
        content = outputs.get(f"{version}:{control_id}")
        context = input_by_id.get(control_id)
        if not isinstance(content, str) or not content.strip() or context is None:
            return None
        sources = context.get("knowledge_sources")
        restored.append(
            {
                "control_id": control_id,
                "source": content,
                "knowledge_sources": sources if isinstance(sources, list) else [],
            }
        )
    return {
        "version": version,
        "summary_source": summary,
        "controls": restored,
    }


@router.post(
    "/api/v1/audit-history/windows/presentation",
    status_code=status.HTTP_201_CREATED,
)
def save_windows_audit_presentation(
    request: Request,
    body: WindowsAuditPresentationBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    _require_history_feature()
    verify_browser_csrf(request, csrf_token)
    principal = current_principal(request)
    try:
        presentation = validate_windows_audit_presentation(body.model_dump())
        with Session(_engine()) as session, session.begin():
            record = append_windows_audit_presentation(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                presentation=presentation,
            )
        return {
            "presentation_id": str(record.id),
            "presentation_kind": record.presentation_kind,
            "presentation_version": record.presentation_version,
            "payload_sha256": record.payload_sha256,
            "created_at": record.created_at.isoformat(),
            "created": record.created,
            "owner_scope": "CURRENT_LOGIN_ONLY",
        }
    except AuditHistoryContractError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {
                "code": str(exc),
                "message": "Windows 점검 화면을 안전하게 저장할 수 없습니다.",
            },
        ) from exc
    except SQLAlchemyError as exc:
        raise _history_storage_error() from exc


@router.get("/api/v1/audit-history/windows/presentation")
def get_windows_audit_presentation(
    request: Request,
    result_id: str = Query(pattern=r"^[a-f0-9]{16}$"),
    result_version: int = Query(ge=1, le=1_000_000),
) -> dict[str, object]:
    _require_history_feature()
    principal = current_principal(request)
    try:
        with Session(_engine()) as session, session.begin():
            records = load_windows_audit_presentations(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                result_id=result_id,
                result_version=result_version,
            )
        return _windows_presentations_view(records)
    except SQLAlchemyError as exc:
        raise _history_storage_error() from exc


@router.get("/api/v1/audit-history")
def get_audit_history(
    request: Request,
    platform: Literal["WINDOWS", "LINUX", "SWITCH"] | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10_000),
) -> dict[str, object]:
    _require_history_feature()
    principal = current_principal(request)
    if date_from is not None and date_to is not None and date_from > date_to:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid date range.")
    completed_from = (
        datetime.combine(date_from, time.min, tzinfo=UTC) if date_from else None
    )
    completed_before = (
        datetime.combine(date_to, time.min, tzinfo=UTC) + timedelta(days=1)
        if date_to
        else None
    )
    try:
        with Session(_engine()) as session, session.begin():
            policy = _policy_or_default(session, request)
            records = list_audit_history(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                platform=platform,
                completed_from=completed_from,
                completed_before=completed_before,
                limit=limit,
                offset=offset,
            )
        items = [
            audit_history_entry_view(
                entry_id=record.id,
                platform=record.platform,
                asset_label=record.asset_label,
                result_id=record.result_id,
                result_version=record.result_version,
                completed_at=record.completed_at,
                result_json=record.result_json,
                result_sha256=record.result_sha256,
                criteria_sha256=record.criteria_sha256,
                policy=policy,
            )
            for record in records
        ]
        return {
            "items": items,
            "total": records[0].total_count if records else 0,
            "limit": limit,
            "offset": offset,
            "owner_scope": "CURRENT_LOGIN_ONLY",
            "policy": policy.public_view(),
        }
    except (AuditHistoryContractError, SQLAlchemyError) as exc:
        raise _history_storage_error() from exc


@router.get("/api/v1/audit-history/policy")
def get_audit_history_policy(request: Request) -> dict[str, object]:
    _require_history_feature()
    try:
        with Session(_engine()) as session, session.begin():
            return _policy_or_default(session, request).public_view()
    except SQLAlchemyError as exc:
        raise _history_storage_error() from exc


@router.post("/api/v1/audit-history/policy", status_code=status.HTTP_201_CREATED)
def create_audit_history_policy(
    request: Request,
    body: AuditHistoryPolicyBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    _require_history_feature()
    principal = require_administrator(request)
    if principal is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Authentication required.")
    verify_browser_csrf(request, csrf_token)
    try:
        with Session(_engine()) as session, session.begin():
            policy = append_audit_history_policy(
                session,
                organization_id=principal.organization_id,
                created_by=principal.user_id,
                retention_days=body.retention_days,
                backup_required=body.backup_required,
                deletion_mode=body.deletion_mode,
            )
        return policy.public_view()
    except AuditHistoryContractError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"code": str(exc), "message": "점검 이력 정책이 올바르지 않습니다."},
        ) from exc
    except SQLAlchemyError as exc:
        raise _history_storage_error() from exc


def _load_history_detail(
    request: Request,
    platform: str,
    entry_id: UUID,
) -> dict[str, object]:
    principal = current_principal(request)
    presentation_view: dict[str, object] | None = None
    ai_screen: dict[str, object] | None = None
    try:
        with Session(_engine()) as session, session.begin():
            policy = _policy_or_default(session, request)
            record = load_audit_history_record(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                platform=platform,
                entry_id=entry_id,
            )
    except SQLAlchemyError as exc:
        raise _history_storage_error() from exc
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Audit history not found.")
    try:
        if platform == "WINDOWS":
            try:
                with Session(_engine()) as session, session.begin():
                    presentations = load_windows_audit_presentations(
                        session,
                        organization_id=principal.organization_id,
                        owner_user_id=principal.user_id,
                        result_id=record.result_id,
                        result_version=record.result_version,
                    )
                presentation_view = _windows_presentations_view(presentations)
                stored_ai_screen = presentation_view.get("ai_screen")
                if isinstance(stored_ai_screen, dict):
                    ai_screen = stored_ai_screen
            except SQLAlchemyError as exc:
                logger.warning(
                    "Windows presentation history read skipped: error_type=%s",
                    type(exc).__name__,
                )
        elif platform in {"LINUX", "SWITCH"}:
            result_json = _device_result_with_history_context(
                platform,
                dict(record.result_json),
            )
            record = replace(record, result_json=result_json)
            try:
                with Session(_engine()) as session, session.begin():
                    if platform == "LINUX":
                        outputs = get_ai_outputs(
                            session,
                            organization_id=principal.organization_id,
                            owner_user_id=principal.user_id,
                            run_id=record.id,
                            output_prefix="V4:",
                        )
                        ai_screen = _completed_device_ai_screen(
                            version="V4",
                            result_json=result_json,
                            outputs=outputs,
                        )
                    else:
                        outputs = get_switch_ai_outputs(
                            session,
                            organization_id=principal.organization_id,
                            owner_user_id=principal.user_id,
                            run_id=record.id,
                            output_prefix="V2:",
                        )
                        ai_screen = _completed_device_ai_screen(
                            version="V2",
                            result_json=result_json,
                            outputs=outputs,
                        )
            except SQLAlchemyError as exc:
                logger.warning(
                    "Device AI history read skipped: platform=%s error_type=%s",
                    platform,
                    type(exc).__name__,
                )
        return audit_history_entry_view(
            entry_id=record.id,
            platform=record.platform,
            asset_label=record.asset_label,
            result_id=record.result_id,
            result_version=record.result_version,
            completed_at=record.completed_at,
            result_json=record.result_json,
            result_sha256=record.result_sha256,
            criteria_sha256=record.criteria_sha256,
            policy=policy,
            include_controls=True,
            presentation=presentation_view,
            ai_screen=ai_screen,
        )
    except AuditHistoryContractError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "Audit history is invalid.") from exc


@router.get("/api/v1/audit-history/{platform}/{entry_id}")
def get_audit_history_detail(
    request: Request,
    platform: Literal["windows", "linux", "switch"],
    entry_id: UUID,
) -> dict[str, object]:
    _require_history_feature()
    return _load_history_detail(request, platform.upper(), entry_id)


@router.get("/ui/audit-history/{platform}/{entry_id}", response_class=HTMLResponse)
def audit_history_detail_page(
    request: Request,
    platform: Literal["windows", "linux", "switch"],
    entry_id: UUID,
) -> HTMLResponse:
    _require_history_feature()
    detail = _load_history_detail(request, platform.upper(), entry_id)
    return templates.TemplateResponse(
        request=request,
        name="pages/audit_history_detail.html",
        context={
            "csrf_token": browser_csrf_token(request),
            "history": detail,
        },
    )
