"""PRODUCT-AI-08 owner-scoped PDF report and model disclosure API."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Query, Request, status
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from apps.api.auth_support import auth_enabled, current_principal
from apps.api.browser_csrf import verify_browser_csrf
from security_audit.application.result_ai_explanation import (
    ResultAIExplanationError,
    merge_administrator_explanation_inputs,
)
from security_audit.application.result_report import (
    ReportContractError,
    ReportKind,
    build_model_manifest,
    build_report_document,
    pdf_sha256,
    render_pdf,
    validate_report_snapshot,
)
from security_audit.common.canonical_json import JsonValue
from security_audit.common.service_settings import ServiceSettings
from security_audit.llm import InternalModelGatewayClient, ProviderRequestError
from security_audit.llm.local_vllm_preparation import LocalVLLMPreparation
from security_audit.persistence.database.result_report_repository import (
    allocate_report_version,
    append_access_event,
    append_report,
    get_or_create_snapshot,
    get_report,
    list_reports,
)
from security_audit.security.rbac import (
    AuthorizationOutcome,
    Permission,
    authorize,
)

router = APIRouter()


class ResultReportBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result_id: str = Field(pattern=r"^[a-f0-9]{16}$")
    result_version: int = Field(ge=1, le=1_000_000)
    observed_at_utc: str = Field(min_length=1, max_length=64)
    explanation_inputs: list[dict[str, Any]] = Field(
        min_length=18, max_length=18
    )
    administrator_results: list[dict[str, Any]] = Field(
        default_factory=list,
        max_length=5,
    )
    ai_explanation: dict[str, Any] | None = None
    report_kind: Literal["USER", "TECHNICAL"]
    test_environment_result: Literal[True]


@lru_cache(maxsize=1)
def _engine() -> Engine:
    return create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )


def _require_report_feature() -> None:
    if os.getenv("SECAI_DEV_DEMO_ENABLED", "false").casefold() != "true":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")
    if not auth_enabled():
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            {
                "code": "RESULT_REPORT_AUTHENTICATION_REQUIRED",
                "message": "보고서는 로그인한 사용자만 생성할 수 있습니다.",
            },
        )


def _assigned_asset(request: Request) -> UUID:
    principal = current_principal(request)
    if len(principal.asset_ids) != 1:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {
                "code": "RESULT_REPORT_ASSET_SELECTION_REQUIRED",
                "message": "보고서를 만들 PC를 하나 선택해야 합니다.",
            },
        )
    asset_id = next(iter(principal.asset_ids))
    decision = authorize(
        principal,
        Permission.ASSET_READ,
        principal.organization_id,
        asset_id,
    )
    if not decision.allowed:
        raise HTTPException(
            (
                status.HTTP_404_NOT_FOUND
                if decision.outcome is AuthorizationOutcome.NOT_FOUND
                else status.HTTP_403_FORBIDDEN
            ),
            {"code": decision.reason_code, "message": "보고서 대상 PC를 찾을 수 없습니다."},
        )
    return asset_id


def _technical_allowed(request: Request) -> bool:
    principal = current_principal(request)
    return authorize(
        principal,
        Permission.EVIDENCE_DOWNLOAD,
        principal.organization_id,
    ).allowed


def _safe_capability() -> dict[str, object]:
    try:
        capability = InternalModelGatewayClient.from_environment().capabilities()
    except (ProviderRequestError, OSError, ValueError):
        capability = {
            "runtime_profile": "UNAVAILABLE",
            "provider_kind": "UNKNOWN",
            "deployment_mode": "UNKNOWN",
            "model_id": "설정 확인 필요",
            "model_license": "REVIEW_REQUIRED",
            "external_data_transfer": True,
            "local_model_loaded": False,
        }
    capability["local_vllm_preparation"] = (
        LocalVLLMPreparation.from_environment().to_public()
    )
    return capability


def _record_metadata(record: object) -> dict[str, object]:
    report = cast(Any, record)
    return {
        "report_id": str(report.id),
        "report_kind": report.report_kind,
        "report_version": report.report_version,
        "content_sha256": report.content_sha256,
        "pdf_sha256": report.pdf_sha256,
        "created_at": report.created_at.isoformat(),
        "download_url": f"/api/v1/result-reports/{report.id}/download",
    }


def _audit_denied(
    request: Request,
    *,
    event_type: str,
    reason_code: str,
    requested_report_id: UUID | None = None,
) -> None:
    principal = current_principal(request)
    try:
        with Session(_engine()) as session, session.begin():
            append_access_event(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                event_type=event_type,
                outcome="DENY",
                reason_code=reason_code,
                requested_report_id=requested_report_id,
            )
    except SQLAlchemyError:
        return


@router.get("/api/v1/result-reports/capabilities")
def result_report_capabilities(request: Request) -> dict[str, object]:
    _require_report_feature()
    _assigned_asset(request)
    return {
        "schema_version": "1.0.0",
        "user_report_allowed": True,
        "technical_report_allowed": _technical_allowed(request),
        "reports_are_append_only": True,
        "technical_permission": Permission.EVIDENCE_DOWNLOAD.value,
    }


@router.post("/api/v1/result-reports", status_code=status.HTTP_201_CREATED)
def generate_result_report(
    request: Request,
    body: ResultReportBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    _require_report_feature()
    verify_browser_csrf(request, csrf_token)
    principal = current_principal(request)
    asset_id = _assigned_asset(request)
    report_kind = ReportKind(body.report_kind)
    if report_kind is ReportKind.TECHNICAL and not _technical_allowed(request):
        _audit_denied(
            request,
            event_type="GENERATE_DENIED",
            reason_code="TECHNICAL_REPORT_PERMISSION_REQUIRED",
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            {
                "code": "TECHNICAL_REPORT_PERMISSION_REQUIRED",
                "message": "기술 검증용 보고서는 승인된 보안 검증 담당자만 만들 수 있습니다.",
            },
        )
    try:
        merged_inputs = merge_administrator_explanation_inputs(
            body.explanation_inputs,
            body.administrator_results,
        )
        snapshot = validate_report_snapshot(
            {
                "result_id": body.result_id,
                "result_version": body.result_version,
                "observed_at_utc": body.observed_at_utc,
                "explanation_inputs": cast(list[JsonValue], merged_inputs),
                "ai_explanation": cast(JsonValue, body.ai_explanation),
                "test_environment_result": body.test_environment_result,
            }
        )
        manifest = build_model_manifest(_safe_capability(), snapshot.ai_explanation)
        now = datetime.now(UTC)
        with Session(_engine()) as session, session.begin():
            snapshot_record = get_or_create_snapshot(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                asset_id=asset_id,
                snapshot=snapshot,
            )
            version = allocate_report_version(
                session,
                snapshot=snapshot_record,
                report_kind=report_kind,
            )
            document = build_report_document(
                snapshot,
                report_kind,
                report_version=version,
                generated_at=now,
                model_manifest=manifest,
            )
            pdf = render_pdf(document)
            record = append_report(
                session,
                snapshot=snapshot_record,
                report_kind=report_kind,
                report_version=version,
                content_sha256=document.content_sha256,
                pdf_sha256=pdf_sha256(pdf),
                pdf_bytes=pdf,
                model_manifest=cast(dict[str, object], manifest),
                generated_by=principal.user_id,
            )
            append_access_event(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                event_type="GENERATED",
                outcome="ALLOW",
                reason_code="REPORT_GENERATED",
                report_id=record.id,
                event_metadata={
                    "report_kind": report_kind.value,
                    "report_version": version,
                    "snapshot_sha256": snapshot.snapshot_sha256,
                },
            )
            session.refresh(record)
            metadata = _record_metadata(record)
        return metadata
    except (ReportContractError, ResultAIExplanationError) as exc:
        _audit_denied(
            request,
            event_type="GENERATE_DENIED",
            reason_code=str(exc),
        )
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {
                "code": str(exc),
                "message": "점검 결과의 무결성을 확인할 수 없어 보고서를 만들지 않았습니다.",
            },
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            {
                "code": "RESULT_REPORT_STORAGE_UNAVAILABLE",
                "message": "보고서 저장소를 사용할 수 없습니다. 잠시 후 다시 시도하세요.",
            },
        ) from exc


@router.get("/api/v1/result-reports")
def get_result_reports(
    request: Request,
    result_id: str = Query(pattern=r"^[a-f0-9]{16}$"),
    result_version: int = Query(ge=1, le=1_000_000),
) -> dict[str, object]:
    _require_report_feature()
    _assigned_asset(request)
    principal = current_principal(request)
    try:
        with Session(_engine()) as session, session.begin():
            reports = list_reports(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                result_id=result_id,
                result_version=result_version,
                include_technical=_technical_allowed(request),
            )
            return {"reports": [_record_metadata(item) for item in reports]}
    except SQLAlchemyError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Report storage is unavailable.",
        ) from exc


def _load_report_or_404(request: Request, report_id: UUID) -> Any:
    principal = current_principal(request)
    denial: tuple[int, str] | None = None
    with Session(_engine()) as session, session.begin():
        record = get_report(
            session,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
            report_id=report_id,
        )
        if record is None:
            append_access_event(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                event_type="DOWNLOAD_DENIED",
                outcome="DENY",
                reason_code="REPORT_NOT_FOUND",
                requested_report_id=report_id,
            )
            denial = (status.HTTP_404_NOT_FOUND, "Report not found.")
        elif record.report_kind == "TECHNICAL" and not _technical_allowed(request):
            append_access_event(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                event_type="DOWNLOAD_DENIED",
                outcome="DENY",
                reason_code="TECHNICAL_REPORT_PERMISSION_REQUIRED",
                requested_report_id=report_id,
                report_id=record.id,
            )
            denial = (
                status.HTTP_403_FORBIDDEN,
                "Technical report permission is required.",
            )
        else:
            session.expunge(record)
    if denial is not None:
        raise HTTPException(denial[0], denial[1])
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found.")
    return record


@router.get("/api/v1/result-reports/{report_id}/download")
def download_result_report(request: Request, report_id: UUID) -> Response:
    _require_report_feature()
    record = _load_report_or_404(request, report_id)
    principal = current_principal(request)
    with Session(_engine()) as session, session.begin():
        append_access_event(
            session,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
            event_type="DOWNLOADED",
            outcome="ALLOW",
            reason_code="REPORT_DOWNLOADED",
            requested_report_id=report_id,
            report_id=record.id,
        )
    filename = (
        "secai-result-technical.pdf"
        if record.report_kind == "TECHNICAL"
        else "secai-result-user.pdf"
    )
    return Response(
        content=record.pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
