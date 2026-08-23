"""지원 Linux 배포판 KISA U-01~U-67 점검, 결과, AI 및 PDF API."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from apps.api.auth_support import auth_enabled, current_principal
from apps.api.browser_csrf import browser_csrf_token, verify_browser_csrf
from security_audit.application.device_ai_token_stream import (
    DeviceAIContractError,
    DeviceAITokenStreamService,
    public_linux_control,
    validate_stored_device_result,
)
from security_audit.application.device_report import build_linux_report_document
from security_audit.application.linux_audit_service import (
    LinuxLabTarget,
    linux_lab_targets,
    request_running_linux_audit_cancel,
    start_linux_audit_thread,
)
from security_audit.application.result_report import render_pdf
from security_audit.common.service_settings import ServiceSettings
from security_audit.llm import InternalModelGatewayClient, ProviderRequestError
from security_audit.persistence.database.linux_asset_repository import (
    SqlLinuxAssetRepository,
)
from security_audit.persistence.database.linux_audit_repository import (
    LinuxAuditRunRecord,
    active_linux_audit_run,
    append_ai_output,
    create_linux_audit_run,
    get_ai_output,
    get_ai_outputs,
    latest_completed_linux_audit_run,
    list_linux_audit_events,
    load_linux_audit_run,
    request_linux_audit_cancellation,
)
from security_audit.platforms.linux_kisa import (
    KISA_2026_UNIX_CONTROLS,
    KisaUnixAssessmentProfile,
)
from security_audit.security.auth import AuthenticatedPrincipal
from security_audit.security.rbac import Permission, authorize

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")
logger = logging.getLogger(__name__)


class StartLinuxAuditBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_key: str = Field(min_length=1, max_length=64, pattern=r"^[0-9A-Za-z-]+$")
    criteria: dict[str, object] | None = None


class LinuxAIStreamBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: Literal["FAST", "PRECISE"] = "FAST"


class LinuxFollowUpBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=1_000)


@lru_cache(maxsize=1)
def _engine() -> Engine:
    return create_engine(ServiceSettings.from_environment().postgres_url(), pool_pre_ping=True)


def _require_feature(request: Request) -> AuthenticatedPrincipal:
    if os.getenv("SECAI_DEV_DEMO_ENABLED", "false").casefold() != "true":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")
    if not auth_enabled():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Authentication required.")
    return current_principal(request)


def _linux_targets(principal: AuthenticatedPrincipal) -> dict[str, LinuxLabTarget]:
    targets = linux_lab_targets()
    key_root = Path(os.getenv("SECAI_LINUX_ASSET_KEY_ROOT", "/run/secai-linux-asset-keys"))
    try:
        managed = SqlLinuxAssetRepository(_engine()).list_active(principal)
    except SQLAlchemyError:
        logger.exception("Managed Linux assets could not be loaded; static lab targets remain.")
        return targets
    for asset in managed:
        if asset.distribution is None:
            continue
        directory = key_root / str(asset.credential_ref)
        key = str(asset.asset_id)
        targets[key] = LinuxLabTarget(
            key=key,
            label=asset.alias,
            distribution=asset.distribution,
            host=asset.host,
            username=asset.ssh_username,
            private_key=directory / "identity",
            known_hosts=directory / "known_hosts",
            asset_id=asset.asset_id,
            port=asset.port,
        )
    return targets


def _load_result(
    request: Request, run_id: UUID
) -> tuple[AuthenticatedPrincipal, LinuxAuditRunRecord]:
    principal = _require_feature(request)
    with Session(_engine()) as session:
        record = load_linux_audit_run(
            session,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
            run_id=run_id,
        )
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Linux audit not found.")
    if record.status != "COMPLETED" or record.result_json is None or record.result_sha256 is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Linux audit is not completed.")
    validate_stored_device_result(record.result_json, record.result_sha256)
    return principal, record


def _event(
    event_type: str, payload: dict[str, object] | None = None, *, event_id: int | None = None
) -> str:
    lines = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event_type}")
    lines.append("data: " + json.dumps(payload or {}, ensure_ascii=False, separators=(",", ":")))
    return "\n".join(lines) + "\n\n"


@router.get("/ui/linux-scan", response_class=HTMLResponse)
def linux_scan_page(request: Request) -> HTMLResponse:
    principal = _require_feature(request)
    return templates.TemplateResponse(
        request=request,
        name="pages/linux_scan.html",
        context={
            "csrf_token": browser_csrf_token(request),
            "assets": [item.public_view() for item in _linux_targets(principal).values()],
            "default_criteria": KisaUnixAssessmentProfile().public_values(),
            "controls": [
                {"control_id": item.control_id, "title": item.title}
                for item in KISA_2026_UNIX_CONTROLS
            ],
        },
    )


@router.get("/ui/linux-results", response_class=HTMLResponse)
def linux_results_page(request: Request, run_id: UUID) -> HTMLResponse:
    _require_feature(request)
    return templates.TemplateResponse(
        request=request,
        name="pages/linux_results.html",
        context={"csrf_token": browser_csrf_token(request), "run_id": str(run_id)},
    )


@router.get("/ui/linux-results/latest")
def latest_linux_results_page(request: Request) -> RedirectResponse:
    principal = _require_feature(request)
    with Session(_engine()) as session:
        run_id = latest_completed_linux_audit_run(
            session,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
        )
    if run_id is None:
        return RedirectResponse("/ui/linux-scan", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(
        f"/ui/linux-results?run_id={run_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/ui/linux-ai", response_class=HTMLResponse)
def linux_ai_page(request: Request, run_id: UUID) -> HTMLResponse:
    _load_result(request, run_id)
    return templates.TemplateResponse(
        request=request,
        name="pages/linux_ai.html",
        context={"csrf_token": browser_csrf_token(request), "run_id": str(run_id)},
    )


@router.get("/api/v1/linux/assets")
def linux_assets(request: Request) -> dict[str, object]:
    principal = _require_feature(request)
    return {"items": [item.public_view() for item in _linux_targets(principal).values()]}


@router.get("/api/v1/linux/criteria/default")
def linux_default_criteria(request: Request) -> dict[str, object]:
    _require_feature(request)
    return {
        "name": "KISA·SecAI Linux 안전 기본 기준",
        "values": KisaUnixAssessmentProfile().public_values(),
        "collection_errors_remain_check_required": True,
    }


@router.post("/api/v1/linux/audits", status_code=status.HTTP_202_ACCEPTED)
def start_linux_audit(
    request: Request,
    body: StartLinuxAuditBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    principal = _require_feature(request)
    verify_browser_csrf(request, csrf_token)
    try:
        criteria_profile = KisaUnixAssessmentProfile.from_values(body.criteria)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Linux criteria invalid.",
        ) from exc
    target = _linux_targets(principal).get(body.asset_key)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Linux asset not found.")
    with Session(_engine()) as session, session.begin():
        active = active_linux_audit_run(
            session,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
            asset_key=body.asset_key,
        )
        if active is not None:
            return {"run_id": str(active), "reused": True}
        run_id = uuid4()
        create_linux_audit_run(
            session,
            run_id=run_id,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
            asset_key=body.asset_key,
            asset_id=target.asset_id,
            distribution=target.distribution.value,
        )
    start_linux_audit_thread(
        _engine(),
        run_id=run_id,
        organization_id=principal.organization_id,
        owner_user_id=principal.user_id,
        target=target,
        criteria_profile=criteria_profile,
    )
    return {"run_id": str(run_id), "reused": False}


@router.get("/api/v1/linux/audits/{run_id}")
def linux_audit_result(request: Request, run_id: UUID) -> dict[str, object]:
    principal = _require_feature(request)
    with Session(_engine()) as session:
        record = load_linux_audit_run(
            session,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
            run_id=run_id,
        )
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Linux audit not found.")
    return {
        "run_id": str(record.id),
        "asset_key": record.asset_key,
        "distribution": record.distribution,
        "status": record.status,
        "result": record.result_json,
        "result_sha256": record.result_sha256,
        "cancellation_requested": record.cancellation_requested,
        "created_at": record.created_at.isoformat(),
        "completed_at": record.completed_at.isoformat() if record.completed_at else None,
    }


@router.get("/api/v1/linux/audits/{run_id}/events")
def linux_audit_events(request: Request, run_id: UUID, after: int = 0) -> StreamingResponse:
    principal = _require_feature(request)
    last_header = request.headers.get("last-event-id")
    if last_header and last_header.isdigit():
        after = max(after, int(last_header))
    organization_id = principal.organization_id
    owner_user_id = principal.user_id

    def stream() -> Iterator[str]:
        cursor = after
        idle = 0
        while True:
            with Session(_engine()) as session:
                events = list_linux_audit_events(
                    session,
                    organization_id=organization_id,
                    owner_user_id=owner_user_id,
                    run_id=run_id,
                    after=cursor,
                )
                record = load_linux_audit_run(
                    session,
                    organization_id=organization_id,
                    owner_user_id=owner_user_id,
                    run_id=run_id,
                )
            if record is None:
                yield _event("FAILED", {"code": "LINUX_AUDIT_NOT_FOUND"})
                return
            for item in events:
                cursor = int(item["sequence"])
                yield _event(str(item["event_type"]), dict(item["payload"]), event_id=cursor)
                idle = 0
            if record.status in {"COMPLETED", "FAILED", "CANCELLED"} and not events:
                return
            idle += 1
            if idle % 30 == 0:
                yield ": keep-alive\n\n"
            time.sleep(0.35)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.post("/api/v1/linux/audits/{run_id}/cancel")
def cancel_linux_audit(
    request: Request,
    run_id: UUID,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, bool]:
    principal = _require_feature(request)
    verify_browser_csrf(request, csrf_token)
    with Session(_engine()) as session, session.begin():
        requested = request_linux_audit_cancellation(
            session,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
            run_id=run_id,
        )
    if requested:
        request_running_linux_audit_cancel(run_id)
    return {"cancel_requested": requested}


@router.get("/api/v1/linux/audits/{run_id}/report.pdf")
def linux_audit_report(
    request: Request,
    run_id: UUID,
    kind: Literal["USER", "TECHNICAL"] = "USER",
) -> Response:
    principal, record = _load_result(request, run_id)
    if (
        kind == "TECHNICAL"
        and not authorize(
            principal, Permission.EVIDENCE_DOWNLOAD, principal.organization_id
        ).allowed
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Technical report permission required.")
    document = build_linux_report_document(record.result_json or {}, technical=kind == "TECHNICAL")
    filename = f"linux-u01-u67-{run_id}-{kind.casefold()}.pdf"
    return Response(
        render_pdf(document),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


_AI_CANCELLATIONS: dict[UUID, threading.Event] = {}
_AI_LOCK = threading.Lock()
_AI_OUTPUT_VERSION = "V4"


def _load_ai_output_best_effort(
    *, organization_id: UUID, owner_user_id: UUID, run_id: UUID, output_key: str
) -> str | None:
    """캐시 조회 장애가 읽기 전용 AI 설명 스트림을 중단시키지 않게 합니다."""

    try:
        with Session(_engine()) as session:
            return get_ai_output(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                run_id=run_id,
                output_key=output_key,
            )
    except SQLAlchemyError as exc:
        logger.warning(
            "Linux AI cache read skipped: run_id=%s output_key=%s error_type=%s",
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
    """생성 결과를 우선 전달하고 캐시 저장 장애는 안전하게 분리합니다."""

    try:
        with Session(_engine()) as session, session.begin():
            append_ai_output(
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
            "Linux AI cache write skipped: run_id=%s output_key=%s error_type=%s",
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
            return get_ai_outputs(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                run_id=run_id,
                output_prefix=f"{_AI_OUTPUT_VERSION}:",
            )
    except SQLAlchemyError as exc:
        logger.warning(
            "Linux AI snapshot read skipped: run_id=%s error_type=%s",
            run_id,
            type(exc).__name__,
        )
        return None


def _completed_linux_ai_snapshot(
    controls: list[object],
    outputs: dict[str, str],
) -> dict[str, object]:
    expected_ids = [f"U-{number:02d}" for number in range(1, 68)]
    controls_by_id = {
        str(control.get("control_id")): control
        for control in controls
        if isinstance(control, dict)
    }
    summary = outputs.get(f"{_AI_OUTPUT_VERSION}:SUMMARY")
    if (
        not isinstance(summary, str)
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
                "control": public_linux_control(controls_by_id[control_id]),
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


@router.get("/api/v1/linux/audits/{run_id}/ai/snapshot")
def linux_ai_snapshot(
    request: Request,
    run_id: UUID,
    response: Response,
) -> dict[str, object]:
    """모델 호출 없이 완성된 Linux AI 설명 화면만 복원합니다."""

    response.headers["Cache-Control"] = "no-store"
    principal, record = _load_result(request, run_id)
    controls = (record.result_json or {}).get("controls")
    if not isinstance(controls, list):
        raise HTTPException(status.HTTP_409_CONFLICT, "Linux audit result is invalid.")
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
    return _completed_linux_ai_snapshot(controls, outputs)


@router.post("/api/v1/linux/audits/{run_id}/ai/stream")
def linux_ai_stream(
    request: Request,
    run_id: UUID,
    body: LinuxAIStreamBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> StreamingResponse:
    principal, record = _load_result(request, run_id)
    verify_browser_csrf(request, csrf_token)
    controls = (record.result_json or {}).get("controls")
    if not isinstance(controls, list):
        raise HTTPException(status.HTTP_409_CONFLICT, "Linux audit result is invalid.")
    cancel = threading.Event()
    with _AI_LOCK:
        if run_id in _AI_CANCELLATIONS:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "이 점검 결과의 AI 설명이 이미 생성되고 있습니다.",
            )
        _AI_CANCELLATIONS[run_id] = cancel

    def stream() -> Iterator[str]:
        service = DeviceAITokenStreamService(InternalModelGatewayClient.from_environment())
        yield _event("ANALYSIS_STARTED", {"total_controls": 67, "status_authority": "RULE_ENGINE"})
        try:
            yield _event("SUMMARY_STARTED")
            try:
                summary_key = f"{_AI_OUTPUT_VERSION}:SUMMARY"
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
            except (DeviceAIContractError, ProviderRequestError) as exc:
                code = exc.category if isinstance(exc, ProviderRequestError) else str(exc)
                yield _event(
                    "SUMMARY_FAILED",
                    {
                        "code": code,
                        "message": "종합 설명은 건너뛰고 U-01부터 항목별 설명을 계속합니다.",
                    },
                )

            successful_controls = 0
            failed_controls = 0
            consecutive_provider_failures = 0
            for index, control in enumerate(controls, start=1):
                if cancel.is_set():
                    yield _event("ANALYSIS_CANCELLED", {"completed_controls": index - 1})
                    return
                key = str(control["control_id"])
                yield _event(
                    "CONTROL_STARTED",
                    {
                        "control_index": index,
                        "total_controls": 67,
                        "control": public_linux_control(control),
                    },
                )
                try:
                    output_key = f"{_AI_OUTPUT_VERSION}:{key}"
                    cached = _load_ai_output_best_effort(
                        organization_id=principal.organization_id,
                        owner_user_id=principal.user_id,
                        run_id=run_id,
                        output_key=output_key,
                    )
                    if cached is not None:
                        yield _event(
                            "CONTROL_DELTA",
                            {"control_id": key, "delta": cached, "cached": True},
                        )
                    else:
                        control_parts: list[str] = []
                        for delta in service.stream_control(control, profile=body.profile):
                            if cancel.is_set():
                                yield _event(
                                    "ANALYSIS_CANCELLED",
                                    {"completed_controls": index - 1},
                                )
                                return
                            control_parts.append(delta)
                            yield _event(
                                "CONTROL_DELTA",
                                {"control_id": key, "delta": delta, "cached": False},
                            )
                        cached = "".join(control_parts).strip()
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
                            "control_id": key,
                            "completed_controls": index,
                            "successful_controls": successful_controls,
                            "failed_controls": failed_controls,
                            "total_controls": 67,
                        },
                    )
                except (DeviceAIContractError, ProviderRequestError) as exc:
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
                            "control_id": key,
                            "code": code,
                            "completed_controls": index,
                            "successful_controls": successful_controls,
                            "failed_controls": failed_controls,
                            "total_controls": 67,
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
                    "completed_controls": 67,
                    "successful_controls": successful_controls,
                    "failed_controls": failed_controls,
                },
            )
        except (DeviceAIContractError, ProviderRequestError) as exc:
            code = exc.category if isinstance(exc, ProviderRequestError) else str(exc)
            yield _event(
                "FAILED",
                {
                    "code": code,
                    "message": (
                        "AI 설명 연결을 완료하지 못했습니다. "
                        "규칙 판정과 증적은 그대로 확인할 수 있습니다."
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


@router.post("/api/v1/linux/audits/{run_id}/ai/cancel")
def cancel_linux_ai(
    request: Request,
    run_id: UUID,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, bool]:
    _require_feature(request)
    verify_browser_csrf(request, csrf_token)
    with _AI_LOCK:
        cancellation = _AI_CANCELLATIONS.get(run_id)
    if cancellation is not None:
        cancellation.set()
    return {"cancel_requested": cancellation is not None}


@router.post("/api/v1/linux/audits/{run_id}/follow-up/stream")
def linux_follow_up_stream(
    request: Request,
    run_id: UUID,
    body: LinuxFollowUpBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> StreamingResponse:
    _principal, record = _load_result(request, run_id)
    verify_browser_csrf(request, csrf_token)
    controls = (record.result_json or {}).get("controls")
    if not isinstance(controls, list):
        raise HTTPException(status.HTTP_409_CONFLICT, "Linux audit result is invalid.")

    def stream() -> Iterator[str]:
        try:
            service = DeviceAITokenStreamService(InternalModelGatewayClient.from_environment())
            for delta in service.stream_follow_up(controls, body.question):
                yield _event("DELTA", {"delta": delta})
            yield _event("COMPLETED")
        except (DeviceAIContractError, ProviderRequestError) as exc:
            code = exc.category if isinstance(exc, ProviderRequestError) else str(exc)
            yield _event("FAILED", {"code": code})

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
