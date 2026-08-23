"""Aruba AOS-CX 등록 장비의 입력·실행·결과 Web/API."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from collections.abc import Iterator
from functools import lru_cache
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from apps.api.auth_support import (
    auth_enabled,
    current_principal,
    get_auth_service,
    request_session_token,
)
from apps.api.browser_csrf import browser_csrf_token, verify_browser_csrf
from security_audit.application.device_report import build_switch_report_document
from security_audit.application.result_report import render_pdf
from security_audit.application.switch_ai_token_stream import (
    SwitchAIContractError,
    SwitchAITokenStreamService,
    public_switch_control,
)
from security_audit.application.switch_audit_service import (
    SwitchLabTarget,
    present_switch_control,
    present_switch_controls,
    start_switch_audit_thread,
    switch_lab_targets,
    validate_stored_switch_result,
)
from security_audit.common.canonical_json import JsonValue
from security_audit.common.service_settings import ServiceSettings
from security_audit.llm import (
    InternalModelGatewayClient as InternalModelGatewayClient,
)
from security_audit.llm import ProviderRequestError
from security_audit.persistence.database.switch_audit_repository import (
    SwitchAuditRunRecord,
    active_switch_audit_run,
    append_switch_ai_output,
    create_switch_audit_run,
    get_switch_ai_output,
    get_switch_ai_outputs,
    latest_completed_switch_audit_run,
    load_switch_audit_run,
)
from security_audit.platforms.kisa_network import (
    KISA_NETWORK_CONTROLS,
    NETWORK_CRITERIA_FIELDS,
    NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS,
    KisaNetworkAssessmentProfile,
)
from security_audit.security.auth import AuthenticatedPrincipal
from security_audit.security.rbac import Permission, authorize

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")
logger = logging.getLogger(__name__)


class StartSwitchAuditBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_key: Literal["aruba-aos-cx-10.13.1170-lab"]
    username: str = Field(min_length=1, max_length=32, pattern=r"^[a-z_][a-z0-9_-]*$")
    password: SecretStr = Field(min_length=1, max_length=512)
    criteria: dict[str, JsonValue]


class SwitchAIStreamBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: Literal["FAST", "PRECISE"] = "FAST"
    result_context_processing_approved: Literal[True]


_AI_CANCELLATIONS: dict[UUID, threading.Event] = {}
_AI_LOCK = threading.Lock()
_AI_OUTPUT_VERSION = "V2"


@lru_cache(maxsize=1)
def _engine() -> Engine:
    return create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )


def _require_switch_access(request: Request) -> AuthenticatedPrincipal | None:
    if os.getenv("SECAI_DEV_DEMO_ENABLED", "false").casefold() != "true":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")
    if not auth_enabled():
        return None
    principal = current_principal(request)
    decision = authorize(principal, Permission.SWITCH_AUDIT_EXECUTE)
    if not decision.allowed:
        _audit_access(request, principal, False, decision.reason_code)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Switch audit access denied.")
    return principal


def _audit_access(
    request: Request,
    principal: AuthenticatedPrincipal,
    allowed: bool,
    reason_code: str,
) -> None:
    get_auth_service().audit_authorization(
        request_session_token(request),
        principal,
        Permission.SWITCH_AUDIT_EXECUTE.value,
        allowed,
        reason_code,
    )


def _begin_switch_run(
    *,
    principal: AuthenticatedPrincipal,
    target: SwitchLabTarget,
) -> tuple[UUID, bool]:
    try:
        with Session(_engine()) as session, session.begin():
            active = active_switch_audit_run(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                asset_key=target.key,
            )
            if active is not None:
                return active, True
            run_id = uuid4()
            create_switch_audit_run(
                session,
                run_id=run_id,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                asset_key=target.key,
                asset_id=target.asset_id,
                platform_version=target.platform_version,
            )
            return run_id, False
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Switch audit is already running.",
        ) from exc


def _load_run(
    principal: AuthenticatedPrincipal,
    run_id: UUID,
) -> SwitchAuditRunRecord:
    with Session(_engine()) as session:
        record = load_switch_audit_run(
            session,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
            run_id=run_id,
        )
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Switch audit not found.")
    return record


def _load_completed_run(
    principal: AuthenticatedPrincipal,
    run_id: UUID,
) -> SwitchAuditRunRecord:
    record = _load_run(principal, run_id)
    if (
        record.status != "COMPLETED"
        or record.result_json is None
        or record.result_sha256 is None
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "Switch audit is not completed.")
    try:
        validate_stored_switch_result(record.result_json, record.result_sha256)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Switch audit result integrity check failed.",
        ) from exc
    return record


def _event(event_type: str, payload: dict[str, object] | None = None) -> str:
    return (
        f"event: {event_type}\n"
        "data: "
        + json.dumps(payload or {}, ensure_ascii=False, separators=(",", ":"))
        + "\n\n"
    )


def _load_ai_output_best_effort(
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    output_key: str,
) -> str | None:
    try:
        with Session(_engine()) as session:
            return get_switch_ai_output(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                run_id=run_id,
                output_key=output_key,
            )
    except SQLAlchemyError as exc:
        logger.warning(
            "Switch AI cache read skipped: run_id=%s output_key=%s error_type=%s",
            run_id,
            output_key,
            type(exc).__name__,
        )
        return None


def _store_ai_output_best_effort(
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    output_key: str,
    content: str,
) -> bool:
    if not content.strip():
        return False
    try:
        with Session(_engine()) as session, session.begin():
            append_switch_ai_output(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                run_id=run_id,
                output_key=output_key,
                content=content,
                content_sha256=hashlib.sha256(content.encode()).hexdigest(),
            )
    except SQLAlchemyError as exc:
        logger.warning(
            "Switch AI cache write skipped: run_id=%s output_key=%s error_type=%s",
            run_id,
            output_key,
            type(exc).__name__,
        )
        return False
    return True


def _load_ai_outputs_best_effort(
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
) -> dict[str, str] | None:
    """완성 화면 복원용 AI 출력을 owner scope에서 일괄 조회합니다."""

    try:
        with Session(_engine()) as session:
            return get_switch_ai_outputs(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                run_id=run_id,
                output_prefix=f"{_AI_OUTPUT_VERSION}:",
            )
    except SQLAlchemyError as exc:
        logger.warning(
            "Switch AI snapshot read skipped: run_id=%s error_type=%s",
            run_id,
            type(exc).__name__,
        )
        return None


def _legacy_switch_observation_present(controls: list[object]) -> bool:
    return any(
        isinstance(item, dict)
        and present_switch_control(item).get("observed_summary")
        != item.get("observed_summary")
        for item in controls
    )


def _completed_switch_ai_snapshot(
    controls: list[object],
    outputs: dict[str, str],
) -> dict[str, object]:
    expected_ids = [f"N-{number:02d}" for number in range(1, 39)]
    controls_by_id = {
        str(control.get("control_id")): control
        for control in controls
        if isinstance(control, dict)
    }
    summary = outputs.get(f"{_AI_OUTPUT_VERSION}:SUMMARY")
    if (
        _legacy_switch_observation_present(controls)
        or not isinstance(summary, str)
        or not summary.strip()
        or len(summary) > 100_000
        or set(controls_by_id) != set(expected_ids)
    ):
        return {"available": False, "version": _AI_OUTPUT_VERSION}
    restored_controls: list[dict[str, object]] = []
    for control_id in expected_ids:
        content = outputs.get(f"{_AI_OUTPUT_VERSION}:{control_id}")
        if not isinstance(content, str) or not content.strip() or len(content) > 100_000:
            return {"available": False, "version": _AI_OUTPUT_VERSION}
        restored_controls.append(
            {
                "control": public_switch_control(controls_by_id[control_id]),
                "content": content,
            }
        )
    return {
        "available": True,
        "version": _AI_OUTPUT_VERSION,
        "summary": summary,
        "controls": restored_controls,
        "total_controls": len(restored_controls),
    }


@router.get("/api/v1/switch/audits/{run_id}/ai/snapshot")
def switch_ai_snapshot(
    request: Request,
    run_id: UUID,
    response: Response,
) -> dict[str, object]:
    """모델 호출 없이 완성된 Switch AI 설명 화면만 복원합니다."""

    response.headers["Cache-Control"] = "no-store"
    principal = _require_switch_access(request)
    if principal is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Authentication required.")
    record = _load_completed_run(principal, run_id)
    controls = (record.result_json or {}).get("controls")
    if not isinstance(controls, list):
        raise HTTPException(status.HTTP_409_CONFLICT, "Switch audit result is invalid.")
    outputs = _load_ai_outputs_best_effort(
        organization_id=principal.organization_id,
        owner_user_id=principal.user_id,
        run_id=run_id,
    )
    if outputs is None:
        return {
            "available": False,
            "version": _AI_OUTPUT_VERSION,
            "cache_read_error": True,
        }
    return _completed_switch_ai_snapshot(controls, outputs)


@router.get("/ui/switch-scan", response_class=HTMLResponse)
def switch_scan_page(request: Request) -> HTMLResponse:
    _require_switch_access(request)
    default_profile = KisaNetworkAssessmentProfile()
    return templates.TemplateResponse(
        request=request,
        name="pages/switch_scan.html",
        context={
            "csrf_token": browser_csrf_token(request),
            "assets": [target.public_view() for target in switch_lab_targets().values()],
            "controls": [item.control_id for item in KISA_NETWORK_CONTROLS],
            "criteria_fields": NETWORK_CRITERIA_FIELDS,
            "supplemental_assessment_fields": (
                NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS
            ),
            "default_criteria": default_profile.public_values(),
        },
    )


@router.get("/api/v1/switch/criteria/default")
def switch_default_criteria(request: Request) -> dict[str, object]:
    """명령어나 자유형 입력 없이 편집할 수 있는 Switch 안전 기준을 제공합니다."""

    _require_switch_access(request)
    return {
        "name": "KISA·SecAI Switch 안전 기본 기준",
        "values": KisaNetworkAssessmentProfile().public_values(),
        "supplemental_assessments": (
            KisaNetworkAssessmentProfile().supplemental_values()
        ),
        "supplemental_assessments_are_device_observations": False,
        "observed_values_overwritten": False,
        "missing_observed_values_require_explicit_organization_input": True,
    }


@router.get("/ui/switch-results", response_class=HTMLResponse)
def switch_results_page(
    request: Request,
    run_id: UUID | None = None,
) -> Response:
    principal = _require_switch_access(request)
    if principal is None:
        return RedirectResponse("/ui/switch-scan", status_code=status.HTTP_303_SEE_OTHER)
    selected_run_id = run_id
    if selected_run_id is None:
        with Session(_engine()) as session:
            selected_run_id = latest_completed_switch_audit_run(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
            )
        if selected_run_id is None:
            return RedirectResponse("/ui/switch-scan", status_code=status.HTTP_303_SEE_OTHER)
    record = _load_completed_run(principal, selected_run_id)
    result_json = record.result_json
    result_sha256 = record.result_sha256
    if result_json is None or result_sha256 is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Switch audit result is invalid.")
    controls = list(result_json.get("controls", []))
    status_counts = {
        value: sum(
            1 for item in controls if isinstance(item, dict) and item.get("status") == value
        )
        for value in ("PASS", "FAIL", "ERROR", "REVIEW", "N/A")
    }
    presented_controls = present_switch_controls(
        [item for item in controls if isinstance(item, dict)]
    )
    return templates.TemplateResponse(
        request=request,
        name="pages/switch_results.html",
        context={
            "csrf_token": browser_csrf_token(request),
            "run_id": str(record.id),
            "result": result_json,
            "result_sha256": result_sha256,
            "status_counts": status_counts,
            "presented_controls": presented_controls,
        },
    )


@router.post(
    "/api/v1/switch/audits",
    status_code=status.HTTP_202_ACCEPTED,
)
def start_switch_audit(
    request: Request,
    body: StartSwitchAuditBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    principal = _require_switch_access(request)
    if principal is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Authentication required.")
    verify_browser_csrf(request, csrf_token)
    target = switch_lab_targets()[body.asset_key]
    try:
        criteria_profile = KisaNetworkAssessmentProfile.from_values(body.criteria)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Switch criteria invalid.",
        ) from exc
    run_id, reused = _begin_switch_run(principal=principal, target=target)
    _audit_access(request, principal, True, "SWITCH_AUDIT_REQUEST_ALLOWED")
    if not reused:
        start_switch_audit_thread(
            engine=_engine(),
            run_id=run_id,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
            target=target,
            username=body.username,
            password=body.password.get_secret_value(),
            criteria_profile=criteria_profile,
        )
    return {"run_id": str(run_id), "reused": reused}


@router.get("/api/v1/switch/audits/{run_id}")
def switch_audit_status(request: Request, run_id: UUID) -> dict[str, object]:
    principal = _require_switch_access(request)
    if principal is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Authentication required.")
    record = _load_run(principal, run_id)
    return {
        "run_id": str(record.id),
        "status": record.status,
        "error_code": record.error_code,
        "result_ready": record.status == "COMPLETED",
        "result_url": (
            f"/ui/switch-results?run_id={record.id}"
            if record.status == "COMPLETED"
            else None
        ),
    }


@router.get("/api/v1/switch/audits/{run_id}/report.pdf")
def switch_audit_report(
    request: Request,
    run_id: UUID,
    kind: Literal["USER", "TECHNICAL"] = "USER",
) -> Response:
    principal = _require_switch_access(request)
    if principal is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Authentication required.")
    record = _load_completed_run(principal, run_id)
    if (
        kind == "TECHNICAL"
        and not authorize(
            principal,
            Permission.EVIDENCE_DOWNLOAD,
            principal.organization_id,
        ).allowed
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Technical report permission required.",
        )
    document = build_switch_report_document(
        record.result_json or {},
        technical=kind == "TECHNICAL",
    )
    filename = f"switch-n01-n38-{run_id}-{kind.casefold()}.pdf"
    return Response(
        render_pdf(document),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@router.post("/api/v1/switch/audits/{run_id}/ai/stream")
def switch_ai_stream(
    request: Request,
    run_id: UUID,
    body: SwitchAIStreamBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> StreamingResponse:
    principal = _require_switch_access(request)
    if principal is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Authentication required.")
    verify_browser_csrf(request, csrf_token)
    record = _load_completed_run(principal, run_id)
    result_json = record.result_json
    if result_json is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Switch audit result is invalid.")
    controls = result_json.get("controls")
    if not isinstance(controls, list) or len(controls) not in {6, 38}:
        raise HTTPException(status.HTTP_409_CONFLICT, "Switch audit result is invalid.")
    total_controls = len(controls)
    legacy_observation_present = _legacy_switch_observation_present(controls)
    cancel = threading.Event()
    with _AI_LOCK:
        if run_id in _AI_CANCELLATIONS:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "이 점검 결과의 AI 설명이 이미 생성되고 있습니다.",
            )
        _AI_CANCELLATIONS[run_id] = cancel

    def stream() -> Iterator[str]:
        successful_controls = 0
        failed_controls = 0
        consecutive_provider_failures = 0
        yield _event(
            "ANALYSIS_STARTED",
            {
                "total_controls": total_controls,
                "status_authority": "RULE_ENGINE",
                "criteria_status": "DEVELOPMENT_DRAFT",
            },
        )
        try:
            service = SwitchAITokenStreamService(
                InternalModelGatewayClient.from_environment()
            )
            yield _event("SUMMARY_STARTED")
            try:
                summary_key = f"{_AI_OUTPUT_VERSION}:SUMMARY"
                summary = None
                if not legacy_observation_present:
                    summary = _load_ai_output_best_effort(
                        organization_id=principal.organization_id,
                        owner_user_id=principal.user_id,
                        run_id=run_id,
                        output_key=summary_key,
                    )
                if summary is not None:
                    yield _event("SUMMARY_DELTA", {"delta": summary, "cached": True})
                else:
                    summary_parts: list[str] = []
                    for delta in service.stream_summary(controls, profile=body.profile):
                        if cancel.is_set():
                            yield _event("ANALYSIS_CANCELLED", {"completed_controls": 0})
                            return
                        summary_parts.append(delta)
                        yield _event("SUMMARY_DELTA", {"delta": delta, "cached": False})
                    summary = "".join(summary_parts).strip()
                    _store_ai_output_best_effort(
                        organization_id=principal.organization_id,
                        owner_user_id=principal.user_id,
                        run_id=run_id,
                        output_key=summary_key,
                        content=summary,
                    )
                yield _event("SUMMARY_COMPLETED")
            except (SwitchAIContractError, ProviderRequestError) as exc:
                code = exc.category if isinstance(exc, ProviderRequestError) else str(exc)
                yield _event(
                    "SUMMARY_FAILED",
                    {
                        "code": code,
                        "message": "종합 설명은 건너뛰고 첫 항목부터 설명을 계속합니다.",
                    },
                )

            for index, control in enumerate(controls, start=1):
                if cancel.is_set():
                    yield _event(
                        "ANALYSIS_CANCELLED",
                        {"completed_controls": index - 1},
                    )
                    return
                if not isinstance(control, dict):
                    raise SwitchAIContractError("SWITCH_CONTROL_INVALID")
                control_id = str(control.get("control_id", ""))
                yield _event(
                    "CONTROL_STARTED",
                    {
                        "control_index": index,
                        "total_controls": total_controls,
                        "control": public_switch_control(control),
                    },
                )
                try:
                    output_key = f"{_AI_OUTPUT_VERSION}:{control_id}"
                    cached = None
                    if not legacy_observation_present:
                        cached = _load_ai_output_best_effort(
                            organization_id=principal.organization_id,
                            owner_user_id=principal.user_id,
                            run_id=run_id,
                            output_key=output_key,
                        )
                    if cached is not None:
                        yield _event(
                            "CONTROL_DELTA",
                            {"control_id": control_id, "delta": cached, "cached": True},
                        )
                    else:
                        parts: list[str] = []
                        for delta in service.stream_control(control, profile=body.profile):
                            if cancel.is_set():
                                yield _event(
                                    "ANALYSIS_CANCELLED",
                                    {"completed_controls": index - 1},
                                )
                                return
                            parts.append(delta)
                            yield _event(
                                "CONTROL_DELTA",
                                {
                                    "control_id": control_id,
                                    "delta": delta,
                                    "cached": False,
                                },
                            )
                        cached = "".join(parts).strip()
                        _store_ai_output_best_effort(
                            organization_id=principal.organization_id,
                            owner_user_id=principal.user_id,
                            run_id=run_id,
                            output_key=output_key,
                            content=cached,
                        )
                    successful_controls += 1
                    consecutive_provider_failures = 0
                    yield _event(
                        "CONTROL_COMPLETED",
                        {
                            "control_id": control_id,
                            "completed_controls": index,
                            "successful_controls": successful_controls,
                            "failed_controls": failed_controls,
                            "total_controls": total_controls,
                        },
                    )
                except (SwitchAIContractError, ProviderRequestError) as exc:
                    failed_controls += 1
                    if isinstance(exc, ProviderRequestError):
                        consecutive_provider_failures += 1
                        code = exc.category
                    else:
                        consecutive_provider_failures = 0
                        code = str(exc)
                    yield _event(
                        "CONTROL_FAILED",
                        {
                            "control_id": control_id,
                            "code": code,
                            "completed_controls": index,
                            "successful_controls": successful_controls,
                            "failed_controls": failed_controls,
                            "total_controls": total_controls,
                            "message": (
                                "이 항목의 AI 설명만 만들지 못했습니다. "
                                "다음 항목을 계속합니다."
                            ),
                        },
                    )
                    if consecutive_provider_failures >= 3:
                        yield _event(
                            "FAILED",
                            {
                                "code": code,
                                "message": (
                                    "AI 제공자 연결이 연속으로 실패해 생성을 중단했습니다. "
                                    "완료된 설명과 규칙 판정은 그대로 확인할 수 있습니다."
                                ),
                            },
                        )
                        return
            yield _event(
                "ANALYSIS_COMPLETED",
                {
                    "completed_controls": total_controls,
                    "successful_controls": successful_controls,
                    "failed_controls": failed_controls,
                },
            )
        except (SwitchAIContractError, ProviderRequestError) as exc:
            code = exc.category if isinstance(exc, ProviderRequestError) else str(exc)
            yield _event(
                "FAILED",
                {
                    "code": code,
                    "message": (
                        "AI 설명 연결을 완료하지 못했습니다. "
                        "규칙 판정과 비식별 점검 결과는 그대로 확인할 수 있습니다."
                    ),
                },
            )
        except Exception:
            logger.exception("Switch AI stream failed: run_id=%s", run_id)
            yield _event(
                "FAILED",
                {
                    "code": "SWITCH_AI_FAILED",
                    "message": (
                        "AI 설명 연결을 완료하지 못했습니다. "
                        "규칙 판정과 비식별 점검 결과는 그대로 확인할 수 있습니다."
                    ),
                },
            )
        finally:
            with _AI_LOCK:
                _AI_CANCELLATIONS.pop(run_id, None)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.post("/api/v1/switch/audits/{run_id}/ai/cancel")
def cancel_switch_ai(
    request: Request,
    run_id: UUID,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, bool]:
    principal = _require_switch_access(request)
    if principal is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Authentication required.")
    verify_browser_csrf(request, csrf_token)
    _load_completed_run(principal, run_id)
    with _AI_LOCK:
        cancellation = _AI_CANCELLATIONS.get(run_id)
    if cancellation is not None:
        cancellation.set()
    return {"cancel_requested": cancellation is not None}
