"""PRODUCT-AI-03 구조화 점검 결과 설명 JSON·SSE API."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from collections.abc import Iterator, Mapping, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from apps.api.auth_support import auth_enabled, current_principal
from apps.api.browser_csrf import verify_browser_csrf
from security_audit.application.result_ai_explanation import (
    ResultAIExecutionPolicy,
    ResultAIExplanationError,
    ResultAIExplanationService,
    merge_administrator_explanation_inputs,
)
from security_audit.application.result_ai_token_stream import (
    ResultAITokenStreamService,
)
from security_audit.application.result_follow_up import (
    ResultFollowUpError,
    ResultFollowUpService,
    build_result_follow_up_context,
)
from security_audit.application.result_guide_retrieval import (
    ResultGuideRetrievalError,
    ResultGuideRetrievalService,
)
from security_audit.application.result_recheck_comparison import (
    ResultRecheckComparisonAIService,
    ResultRecheckComparisonError,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256,
    canonical_sha256_without_fields,
)
from security_audit.common.service_settings import ServiceSettings
from security_audit.llm import (
    InternalModelGatewayClient,
    ProviderRequestError,
)
from security_audit.persistence.database.windows_ai_repository import (
    WindowsAIOutputError,
    append_windows_ai_output,
    get_windows_ai_outputs,
)

router = APIRouter()
_LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEV_ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
_CONTROL_ID_PATTERN = re.compile(r"^PC-(0[1-9]|1[0-8])$")


def encode_stored_control_card(
    *,
    source: str,
    knowledge_sources: list[dict[str, Any]],
) -> str:
    """항목 카드를 그대로 복원할 수 있게 본문과 출처를 함께 보관합니다."""

    return json.dumps(
        {"source": source, "knowledge_sources": knowledge_sources},
        ensure_ascii=False,
    )


def decode_stored_control_card(value: str) -> dict[str, Any] | None:
    try:
        loaded = json.loads(value)
    except json.JSONDecodeError:
        return None
    if not isinstance(loaded, dict):
        return None
    source = loaded.get("source")
    sources = loaded.get("knowledge_sources")
    if not isinstance(source, str) or not isinstance(sources, list):
        return None
    return {"source": source, "knowledge_sources": sources}


class ResultExplanationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    explanation_inputs: list[dict[str, Any]] = Field(min_length=1, max_length=18)
    guide_evidence: list[dict[str, Any]] = Field(min_length=1, max_length=18)
    profile: Literal["FAST", "PRECISE"] = "FAST"
    test_data_only: bool


class ScanResultExplanationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    explanation_inputs: list[dict[str, Any]] = Field(min_length=1, max_length=18)
    profile: Literal["FAST", "PRECISE"] = "FAST"
    test_environment_result: Literal[True]
    administrator_results: list[dict[str, Any]] = Field(
        default_factory=list,
        max_length=5,
    )
    # 저장된 결과에 연결되면 완성된 설명을 보관해 재방문 시 재생성하지 않습니다.
    snapshot_id: UUID | None = None
    # 이미 복원한 항목은 다시 만들지 않습니다. 관리자 점검으로 늘어난 항목만 생성합니다.
    restored_control_ids: list[str] = Field(
        default_factory=list,
        max_length=18,
    )
    restored_summary: bool = False

    @field_validator("restored_control_ids")
    @classmethod
    def _known_control_ids(cls, value: list[str]) -> list[str]:
        if any(_CONTROL_ID_PATTERN.fullmatch(item) is None for item in value):
            raise ValueError("복원 항목 식별자가 올바르지 않습니다.")
        return value


class ResultFollowUpBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result_id: str = Field(pattern=r"^[a-f0-9]{16}$")
    result_version: int = Field(ge=1, le=1_000_000)
    selected_control_id: str = Field(pattern=r"^PC-(0[1-9]|1[0-8])$")
    question: str = Field(min_length=1, max_length=500)
    explanation_input: dict[str, Any]
    profile: Literal["FAST", "PRECISE"] = "FAST"
    test_environment_result: Literal[True]


class ResultRecheckComparisonBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comparison: dict[str, Any]
    current_explanation_inputs: list[dict[str, Any]] = Field(
        min_length=1,
        max_length=18,
    )
    profile: Literal["FAST", "PRECISE"] = "FAST"
    test_environment_result: Literal[True]


def _require_product_demo() -> None:
    if os.getenv("SECAI_DEV_DEMO_ENABLED", "false").casefold() != "true":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")


@lru_cache(maxsize=1)
def _engine() -> Engine:
    return create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )


def _organization_id(request: Request) -> UUID:
    if auth_enabled():
        return current_principal(request).organization_id
    return _DEV_ORGANIZATION_ID


def _owner_user_id(request: Request) -> UUID | None:
    return current_principal(request).user_id if auth_enabled() else None


def _store_windows_ai_output_best_effort(
    *,
    organization_id: UUID,
    owner_user_id: UUID | None,
    snapshot_id: UUID | None,
    output_key: str,
    content: str,
) -> None:
    """생성 결과를 먼저 전달하고 캐시 저장 장애는 안전하게 분리합니다."""

    if snapshot_id is None or owner_user_id is None or not content.strip():
        return
    try:
        with Session(_engine()) as session, session.begin():
            append_windows_ai_output(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                snapshot_id=snapshot_id,
                output_key=output_key,
                content=content,
                content_sha256=hashlib.sha256(content.encode()).hexdigest(),
            )
    except (SQLAlchemyError, WindowsAIOutputError) as exc:
        _LOGGER.warning(
            "Windows AI cache write skipped: snapshot_id=%s output_key=%s error_type=%s",
            snapshot_id,
            output_key,
            type(exc).__name__,
        )


@router.get("/api/v1/result-explanations/snapshot/{snapshot_id}")
def windows_ai_snapshot(
    request: Request,
    snapshot_id: UUID,
    response: Response,
) -> dict[str, object]:
    """모델 호출 없이 저장된 Windows AI 설명만 복원합니다."""

    _require_product_demo()
    response.headers["Cache-Control"] = "no-store"
    owner_user_id = _owner_user_id(request)
    if owner_user_id is None:
        return {"available": False, "reason": "AUTH_REQUIRED"}
    try:
        with Session(_engine()) as session, session.begin():
            outputs = get_windows_ai_outputs(
                session,
                organization_id=_organization_id(request),
                owner_user_id=owner_user_id,
                snapshot_id=snapshot_id,
            )
    except SQLAlchemyError:
        return {"available": False, "cache_read_error": True}
    if not outputs:
        return {"available": False}
    controls: dict[str, object] = {}
    for key, value in outputs.items():
        if key == "SUMMARY":
            continue
        card = decode_stored_control_card(value)
        if card is not None:
            controls[key] = card
    return {
        "available": True,
        "snapshot_id": str(snapshot_id),
        "summary": outputs.get("SUMMARY", ""),
        "controls": controls,
    }


def _retrieve_guide_evidence(
    explanation_inputs: list[dict[str, Any]],
    *,
    organization_id: UUID,
) -> list[dict[str, JsonValue]]:
    retrieval = ResultGuideRetrievalService(PROJECT_ROOT)
    with Session(_engine()) as session, session.begin():
        return [
            retrieval.retrieve(
                session,
                cast(dict[str, JsonValue], explanation_input),
                organization_id=organization_id,
            ).to_json()
            for explanation_input in explanation_inputs
        ]


_merge_administrator_explanation_inputs = merge_administrator_explanation_inputs


def _execution_policy(
    client: InternalModelGatewayClient,
    *,
    test_data_only: bool,
) -> ResultAIExecutionPolicy:
    capability = client.capabilities()
    provider_kind = capability.get("provider_kind")
    external_data_transfer = capability.get("external_data_transfer")
    if not isinstance(external_data_transfer, bool):
        raise ProviderRequestError("INVALID_GATEWAY_RESPONSE", retryable=False)
    if provider_kind == "OPENROUTER":
        runtime_profile = "VLLM_COMPATIBILITY_TEST_DOUBLE"
        approved = (
            os.getenv(
                "SECAI_RESULT_AI_REMOTE_TEST_APPROVED",
                "false",
            ).casefold()
            == "true"
        )
    elif provider_kind == "VLLM" and external_data_transfer is False:
        runtime_profile = "LOCAL_VLLM_FULL_CONTEXT"
        approved = False
    else:
        raise ProviderRequestError(
            "RESULT_AI_RUNTIME_NOT_APPROVED",
            retryable=False,
        )
    return ResultAIExecutionPolicy(
        runtime_profile=cast(Any, runtime_profile),
        external_data_transfer=external_data_transfer,
        approved_deidentified_test_transfer=approved,
        test_data_only=test_data_only,
    )


def _service_and_policy(
    test_data_only: bool,
) -> tuple[ResultAIExplanationService, ResultAIExecutionPolicy]:
    client = InternalModelGatewayClient.from_environment()
    return (
        ResultAIExplanationService(client),
        _execution_policy(client, test_data_only=test_data_only),
    )


def _generate(body: ResultExplanationBody) -> dict[str, JsonValue]:
    try:
        service, policy = _service_and_policy(body.test_data_only)
        result = service.generate(
            cast(list[dict[str, JsonValue]], body.explanation_inputs),
            cast(list[dict[str, JsonValue]], body.guide_evidence),
            policy=policy,
            profile=body.profile,
        )
        return result.to_json()
    except ResultAIExplanationError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            {
                "code": exc.code,
                "message": "점검 결과 설명 입력 또는 실행 정책을 확인할 수 없습니다.",
                "retryable": False,
            },
        ) from exc
    except ProviderRequestError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            {
                "code": exc.category,
                "message": "AI 연결 상태를 확인할 수 없습니다. 공식 점검 결과는 그대로입니다.",
                "retryable": exc.retryable,
            },
        ) from exc


def _result_ai_batch_size() -> int:
    try:
        configured = int(os.getenv("SECAI_RESULT_AI_BATCH_SIZE", "6"))
    except ValueError:
        return 6
    return max(1, min(configured, 6))


def _stable_unique(values: Sequence[str], *, limit: int) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))[:limit]


def _merge_generated_batches(
    batches: Sequence[Mapping[str, JsonValue]],
) -> dict[str, JsonValue]:
    """검증이 끝난 묶음만 하나의 Schema-compatible 결과로 병합한다."""

    if not batches or any(batch.get("status") != "GENERATED" for batch in batches):
        raise ValueError("RESULT_AI_BATCH_NOT_GENERATED")
    first = batches[0]
    invariant_fields = (
        "schema_version",
        "runtime_profile",
        "external_data_transfer",
        "model_id",
        "prompt",
        "safety",
    )
    if any(
        batch.get(field) != first.get(field)
        for batch in batches[1:]
        for field in invariant_fields
    ):
        raise ValueError("RESULT_AI_BATCH_LINEAGE_MISMATCH")

    summaries: list[Mapping[str, JsonValue]] = []
    for batch in batches:
        summary = batch.get("summary")
        if not isinstance(summary, Mapping):
            raise ValueError("RESULT_AI_BATCH_SUMMARY_INVALID")
        summaries.append(summary)

    def summary_strings(field: str) -> list[str]:
        values: list[str] = []
        for summary in summaries:
            raw = summary.get(field)
            if not isinstance(raw, list) or not all(
                isinstance(item, str) for item in raw
            ):
                raise ValueError("RESULT_AI_BATCH_SUMMARY_INVALID")
            values.extend(cast(list[str], raw))
        return _stable_unique(values, limit=8)

    raw_overall_states = [
        cast(str, summary["overall_state"])
        for summary in summaries
        if isinstance(summary.get("overall_state"), str)
    ]
    if len(raw_overall_states) != len(summaries):
        raise ValueError("RESULT_AI_BATCH_SUMMARY_INVALID")
    overall_states = _stable_unique(
        raw_overall_states,
        limit=len(summaries),
    )

    explanation_hashes: list[str] = []
    evidence_hashes: list[str] = []
    official_results: list[dict[str, JsonValue]] = []
    items: list[dict[str, JsonValue]] = []
    citations: list[dict[str, JsonValue]] = []
    input_hashes: list[str] = []
    model_output_hashes: list[str] = []

    def batch_strings(
        batch: Mapping[str, JsonValue],
        field: str,
    ) -> list[str]:
        source = batch.get(field)
        if not isinstance(source, list) or not all(
            isinstance(value, str) for value in source
        ):
            raise ValueError("RESULT_AI_BATCH_HASH_INVALID")
        return cast(list[str], source)

    def batch_objects(
        batch: Mapping[str, JsonValue],
        field: str,
    ) -> list[dict[str, JsonValue]]:
        values = batch.get(field)
        if not isinstance(values, list) or not all(
            isinstance(value, dict) for value in values
        ):
            raise ValueError("RESULT_AI_BATCH_PAYLOAD_INVALID")
        return cast(list[dict[str, JsonValue]], values)

    def batch_hash(batch: Mapping[str, JsonValue], field: str) -> str:
        value = batch.get(field)
        if not isinstance(value, str):
            raise ValueError("RESULT_AI_BATCH_HASH_INVALID")
        return value

    for batch in batches:
        explanation_hashes.extend(
            batch_strings(batch, "explanation_input_sha256s")
        )
        evidence_hashes.extend(
            batch_strings(batch, "guide_evidence_sha256s")
        )
        official_results.extend(batch_objects(batch, "official_results"))
        items.extend(batch_objects(batch, "items"))
        citations.extend(batch_objects(batch, "citations"))
        input_hashes.append(batch_hash(batch, "input_sha256"))
        model_output_hashes.append(batch_hash(batch, "model_output_sha256"))

    def by_control(value: Mapping[str, JsonValue]) -> str:
        control_id = value.get("control_id")
        if not isinstance(control_id, str):
            raise ValueError("RESULT_AI_BATCH_CONTROL_INVALID")
        return control_id

    official_results.sort(key=by_control)
    items.sort(key=by_control)
    citations.sort(key=by_control)
    control_ids = [by_control(item) for item in items]
    if len(control_ids) != len(set(control_ids)):
        raise ValueError("RESULT_AI_BATCH_CONTROL_DUPLICATE")

    merged_summary: dict[str, JsonValue] = {
        "overall_state": " ".join(overall_states)[:2_000],
        "related_risks": cast(
            JsonValue,
            summary_strings("related_risks"),
        ),
        "user_actions": cast(
            JsonValue,
            summary_strings("user_actions"),
        ),
        "administrator_actions": cast(
            JsonValue,
            summary_strings("administrator_actions"),
        ),
        "limitations": cast(
            JsonValue,
            summary_strings("limitations"),
        ),
    }
    merged: dict[str, JsonValue] = {
        "schema_version": first["schema_version"],
        "status": "GENERATED",
        "reason_code": None,
        "runtime_profile": first["runtime_profile"],
        "external_data_transfer": first["external_data_transfer"],
        "model_id": first["model_id"],
        "prompt": first["prompt"],
        "explanation_input_sha256s": cast(
            JsonValue,
            _stable_unique(explanation_hashes, limit=18),
        ),
        "guide_evidence_sha256s": cast(
            JsonValue,
            _stable_unique(evidence_hashes, limit=18),
        ),
        "input_sha256": canonical_sha256(cast(JsonValue, input_hashes)),
        "model_output_sha256": canonical_sha256(
            cast(JsonValue, model_output_hashes)
        ),
        "official_results": cast(JsonValue, official_results),
        "summary": merged_summary,
        "items": cast(JsonValue, items),
        "citations": cast(JsonValue, citations),
        "retryable": False,
        "safety": first["safety"],
    }
    merged["output_sha256"] = canonical_sha256_without_fields(
        merged,
        {"output_sha256"},
    )
    return merged


def _result_ai_failure_detail(
    result: Mapping[str, JsonValue],
) -> dict[str, object]:
    reason_code = result.get("reason_code")
    code = reason_code if isinstance(reason_code, str) else "GENERATION_FAILED"
    messages = {
        "OUTPUT_TOKEN_LIMIT_REACHED": (
            "AI 답변이 길어 생성이 중단되었습니다. "
            "공식 판정 결과는 그대로이며 다시 시도할 수 있습니다."
        ),
        "MODEL_UNAVAILABLE": (
            "AI 연결을 일시적으로 사용할 수 없습니다. "
            "공식 판정 결과는 그대로입니다."
        ),
        "NO_EVIDENCE": (
            "설명에 필요한 KISA 근거가 부족해 AI 설명을 만들지 않았습니다."
        ),
        "DOCUMENT_CONFLICT": (
            "KISA 근거가 서로 달라 AI 설명 생성을 안전하게 중단했습니다."
        ),
    }
    status_value = result.get("status")
    lookup = code if code in messages else status_value
    return {
        "code": code,
        "message": messages.get(
            cast(str, lookup),
            (
                "AI 설명을 안전하게 완성하지 못했습니다. "
                "공식 판정 결과는 그대로입니다."
            ),
        ),
        "retryable": result.get("retryable") is True,
    }


def _generate_follow_up(
    body: ResultFollowUpBody,
    guide_evidence: dict[str, object],
) -> dict[str, JsonValue]:
    try:
        context = build_result_follow_up_context(
            result_id=body.result_id,
            result_version=body.result_version,
            selected_control_id=body.selected_control_id,
            question=body.question,
            explanation_input=body.explanation_input,
        )
        client = InternalModelGatewayClient.from_environment()
        result = ResultFollowUpService(client).generate(
            context,
            cast(dict[str, JsonValue], body.explanation_input),
            cast(dict[str, JsonValue], guide_evidence),
            policy=_execution_policy(client, test_data_only=True),
            profile=body.profile,
        )
        return result.to_json()
    except ResultFollowUpError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            {
                "code": exc.code,
                "message": "선택한 점검 결과와 질문 문맥을 확인할 수 없습니다.",
                "retryable": False,
            },
        ) from exc
    except ProviderRequestError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            {
                "code": exc.category,
                "message": "AI 연결 상태를 확인할 수 없습니다. 공식 점검 결과는 그대로입니다.",
                "retryable": exc.retryable,
            },
        ) from exc


def _generate_recheck_comparison(
    body: ResultRecheckComparisonBody,
    guide_evidence: list[dict[str, object]],
) -> dict[str, JsonValue]:
    try:
        client = InternalModelGatewayClient.from_environment()
        result = ResultRecheckComparisonAIService(client).generate(
            body.comparison,
            cast(
                list[dict[str, JsonValue]],
                body.current_explanation_inputs,
            ),
            cast(list[dict[str, JsonValue]], guide_evidence),
            policy=_execution_policy(client, test_data_only=True),
            profile=body.profile,
        )
        return result.to_json()
    except ResultRecheckComparisonError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            {
                "code": exc.code,
                "message": "이전 점검과 현재 점검의 비교 문맥을 확인할 수 없습니다.",
                "retryable": False,
            },
        ) from exc
    except ProviderRequestError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            {
                "code": exc.category,
                "message": (
                    "AI 연결 상태를 확인할 수 없습니다. "
                    "규칙 엔진의 변화 비교는 그대로입니다."
                ),
                "retryable": exc.retryable,
            },
        ) from exc


@router.post("/api/v1/result-explanations")
def generate_result_explanation(
    request: Request,
    body: ResultExplanationBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, JsonValue]:
    _require_product_demo()
    verify_browser_csrf(request, csrf_token)
    return _generate(body)


def _event(stage: str, payload: dict[str, object] | None = None) -> str:
    body: dict[str, object] = {"stage": stage}
    if payload:
        body.update(payload)
    return (
        "event: result-explanation-stage\n"
        f"data: {json.dumps(body, ensure_ascii=False)}\n\n"
    )


@router.post("/api/v1/result-explanations/stream")
def stream_result_explanation(
    request: Request,
    body: ResultExplanationBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> StreamingResponse:
    _require_product_demo()
    verify_browser_csrf(request, csrf_token)

    def event_stream() -> Iterator[str]:
        yield _event("VALIDATING_LINEAGE")
        yield _event("COMPARING_RULE_RESULTS")
        yield _event("GENERATING_EXPLANATION")
        try:
            result = _generate(body)
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {"code": "FAILED"}
            yield _event(
                "FAILED",
                {
                    "status_code": exc.status_code,
                    "detail": cast(dict[str, object], detail),
                },
            )
            return
        yield _event("COMPLETED", {"result": cast(dict[str, object], result)})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.post("/api/v1/result-explanations/from-scan/stream")
def stream_scan_result_explanation(
    request: Request,
    body: ScanResultExplanationBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> StreamingResponse:
    """시험 환경의 실제 점검 DTO를 KISA 근거와 연결해 AI로 설명한다."""

    _require_product_demo()
    verify_browser_csrf(request, csrf_token)
    organization_id = _organization_id(request)

    def event_stream() -> Iterator[str]:
        yield _event(
            "VALIDATING_SCAN_RESULT",
            {
                "test_environment_result": True,
                "official_rule_status_immutable": True,
            },
        )
        yield _event("SEARCHING_KISA_EVIDENCE")
        try:
            evidence = _retrieve_guide_evidence(
                body.explanation_inputs,
                organization_id=organization_id,
            )
        except (ResultGuideRetrievalError, SQLAlchemyError):
            yield _event(
                "FAILED",
                {
                    "status_code": status.HTTP_503_SERVICE_UNAVAILABLE,
                    "detail": {
                        "code": "RESULT_GUIDE_EVIDENCE_UNAVAILABLE",
                        "message": (
                            "KISA 근거를 확인하지 못했습니다. "
                            "규칙 엔진의 공식 판정은 그대로입니다."
                        ),
                        "retryable": True,
                    },
                },
            )
            return
        batch_size = _result_ai_batch_size()
        batches = [
            (
                body.explanation_inputs[start : start + batch_size],
                evidence[start : start + batch_size],
            )
            for start in range(0, len(body.explanation_inputs), batch_size)
        ]
        generated_batches: list[dict[str, JsonValue]] = []
        completed_controls = 0
        for batch_index, (explanation_batch, evidence_batch) in enumerate(
            batches,
            start=1,
        ):
            yield _event(
                "GENERATING_AI_EXPLANATION",
                {
                    "batch_index": batch_index,
                    "batch_count": len(batches),
                    "completed_controls": completed_controls,
                    "total_controls": len(body.explanation_inputs),
                },
            )
            try:
                batch_result = _generate(
                    ResultExplanationBody(
                        explanation_inputs=explanation_batch,
                        guide_evidence=cast(
                            list[dict[str, Any]],
                            evidence_batch,
                        ),
                        profile=body.profile,
                        test_data_only=True,
                    )
                )
            except HTTPException as exc:
                detail = (
                    exc.detail
                    if isinstance(exc.detail, dict)
                    else {"code": "FAILED"}
                )
                yield _event(
                    "FAILED",
                    {
                        "status_code": exc.status_code,
                        "detail": cast(dict[str, object], detail),
                    },
                )
                return
            if batch_result.get("status") != "GENERATED":
                yield _event(
                    "FAILED",
                    {
                        "status_code": status.HTTP_503_SERVICE_UNAVAILABLE,
                        "detail": _result_ai_failure_detail(batch_result),
                    },
                )
                return
            generated_batches.append(batch_result)
            completed_controls += len(explanation_batch)
            yield _event(
                "BATCH_COMPLETED",
                {
                    "batch_index": batch_index,
                    "batch_count": len(batches),
                    "completed_controls": completed_controls,
                    "total_controls": len(body.explanation_inputs),
                    "result": cast(dict[str, object], batch_result),
                },
            )
        try:
            result = _merge_generated_batches(generated_batches)
        except ValueError:
            yield _event(
                "FAILED",
                {
                    "status_code": status.HTTP_502_BAD_GATEWAY,
                    "detail": {
                        "code": "RESULT_AI_BATCH_MERGE_INVALID",
                        "message": (
                            "AI 설명 묶음의 연결 관계를 확인하지 못했습니다. "
                            "공식 판정 결과는 그대로입니다."
                        ),
                        "retryable": True,
                    },
                },
            )
            return
        yield _event(
            "COMPLETED",
            {
                "test_environment_result": True,
                "result": cast(dict[str, object], result),
            },
        )

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.post("/api/v1/result-explanations/from-scan/token-stream")
def stream_scan_result_tokens(
    request: Request,
    body: ScanResultExplanationBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> StreamingResponse:
    """전체 종합을 먼저 전송한 뒤 PC-01~18을 한 항목씩 설명한다."""

    _require_product_demo()
    verify_browser_csrf(request, csrf_token)
    organization_id = _organization_id(request)
    owner_user_id = _owner_user_id(request)

    def event_stream() -> Iterator[str]:
        yield _event(
            "ANALYSIS_STARTED",
            {
                "total_controls": 18,
                "official_rule_status_immutable": True,
                "test_environment_result": True,
            },
        )
        try:
            merged_inputs = _merge_administrator_explanation_inputs(
                body.explanation_inputs,
                body.administrator_results,
            )
            yield _event("SEARCHING_KISA_EVIDENCE")
            evidence = _retrieve_guide_evidence(
                merged_inputs,
                organization_id=organization_id,
            )
            client = InternalModelGatewayClient.from_environment()
            policy = _execution_policy(client, test_data_only=True)
            service = ResultAITokenStreamService(client)
            contexts = service.prepare(
                cast(list[dict[str, JsonValue]], merged_inputs),
                evidence,
                policy=policy,
            )
            yield _event(
                "SUMMARY_STARTED",
                {"status_counts": service.status_counts(contexts)},
            )
            if not body.restored_summary:
                summary_parts: list[str] = []
                for delta in service.stream_summary(
                    contexts,
                    profile=body.profile,
                ):
                    summary_parts.append(delta)
                    yield _event("SUMMARY_DELTA", {"delta": delta})
                _store_windows_ai_output_best_effort(
                    organization_id=organization_id,
                    owner_user_id=owner_user_id,
                    snapshot_id=body.snapshot_id,
                    output_key="SUMMARY",
                    content="".join(summary_parts),
                )
            yield _event("SUMMARY_COMPLETED")
            restored = set(body.restored_control_ids)
            for index, context in enumerate(contexts, start=1):
                if context.control_id in restored:
                    yield _event(
                        "CONTROL_RESTORED",
                        {
                            "control_id": context.control_id,
                            "completed_controls": index,
                            "total_controls": len(contexts),
                        },
                    )
                    continue
                control = service.public_control(context)
                yield _event(
                    "CONTROL_STARTED",
                    {
                        "control_index": index,
                        "total_controls": len(contexts),
                        "control": cast(dict[str, object], control),
                    },
                )
                generated_parts: list[str] = []
                for delta in service.stream_control(
                    context,
                    profile=body.profile,
                ):
                    generated_parts.append(delta)
                    yield _event(
                        "CONTROL_DELTA",
                        {
                            "control_id": context.control_id,
                            "delta": delta,
                        },
                    )
                _store_windows_ai_output_best_effort(
                    organization_id=organization_id,
                    owner_user_id=owner_user_id,
                    snapshot_id=body.snapshot_id,
                    output_key=context.control_id,
                    content=encode_stored_control_card(
                        source="".join(generated_parts),
                        knowledge_sources=cast(
                            list[dict[str, Any]],
                            control.get("knowledge_sources", []),
                        ),
                    ),
                )
                yield _event(
                    "CONTROL_COMPLETED",
                    {
                        "control_id": context.control_id,
                        "completed_controls": index,
                        "total_controls": len(contexts),
                        "knowledge_evaluation": cast(
                            dict[str, object],
                            service.evaluate_control(
                                context,
                                "".join(generated_parts),
                            ),
                        ),
                    },
                )
            yield _event(
                "ANALYSIS_COMPLETED",
                {
                    "completed_controls": len(contexts),
                    "official_rule_status_immutable": True,
                },
            )
        except (ResultGuideRetrievalError, SQLAlchemyError):
            yield _event(
                "FAILED",
                {
                    "detail": {
                        "code": "RESULT_GUIDE_EVIDENCE_UNAVAILABLE",
                        "message": "KISA 근거를 확인하지 못했습니다. 공식 판정은 그대로입니다.",
                        "retryable": True,
                    }
                },
            )
        except ResultAIExplanationError as exc:
            _LOGGER.warning("result_ai_token_stream_rejected code=%s", exc.code)
            token_limit_reached = exc.code == "OUTPUT_TOKEN_LIMIT_REACHED"
            yield _event(
                "FAILED",
                {
                    "detail": {
                        "code": exc.code,
                        "message": (
                            (
                                "AI 설명이 길어 출력 한도에서 중단되었습니다. "
                                "완료된 설명은 그대로 두고 다시 시도해 주세요."
                            )
                            if token_limit_reached
                            else (
                                "점검 결과 설명을 준비하지 못했습니다. "
                                "상세 점검 결과는 그대로 확인할 수 있습니다."
                            )
                        ),
                        "retryable": token_limit_reached,
                    }
                },
            )
        except ProviderRequestError as exc:
            yield _event(
                "FAILED",
                {
                    "detail": {
                        "code": exc.category,
                        "message": "AI 연결을 확인하지 못했습니다. 공식 판정은 그대로입니다.",
                        "retryable": exc.retryable,
                    }
                },
            )

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.post("/api/v1/result-explanations/follow-up/stream")
def stream_result_follow_up(
    request: Request,
    body: ResultFollowUpBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> StreamingResponse:
    """선택한 실제 시험 결과 한 건에 고정된 후속 질문을 생성한다."""

    _require_product_demo()
    verify_browser_csrf(request, csrf_token)
    organization_id = _organization_id(request)

    def event_stream() -> Iterator[str]:
        yield _event(
            "VALIDATING_RESULT_CONTEXT",
            {
                "result_id": body.result_id,
                "result_version": body.result_version,
                "selected_control_id": body.selected_control_id,
                "official_rule_status_immutable": True,
            },
        )
        yield _event("SEARCHING_SELECTED_KISA_EVIDENCE")
        try:
            evidence = _retrieve_guide_evidence(
                [body.explanation_input],
                organization_id=organization_id,
            )
            if len(evidence) != 1:
                raise ResultGuideRetrievalError("RESULT_GUIDE_EVIDENCE_UNAVAILABLE")
        except (ResultGuideRetrievalError, SQLAlchemyError):
            yield _event(
                "FAILED",
                {
                    "status_code": status.HTTP_503_SERVICE_UNAVAILABLE,
                    "detail": {
                        "code": "RESULT_GUIDE_EVIDENCE_UNAVAILABLE",
                        "message": (
                            "선택한 결과의 KISA 근거를 확인하지 못했습니다. "
                            "공식 판정은 그대로입니다."
                        ),
                        "retryable": True,
                    },
                },
            )
            return
        yield _event("GENERATING_FOLLOW_UP_ANSWER")
        try:
            result = _generate_follow_up(
                body,
                cast(dict[str, object], evidence[0]),
            )
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {"code": "FAILED"}
            yield _event(
                "FAILED",
                {
                    "status_code": exc.status_code,
                    "detail": cast(dict[str, object], detail),
                },
            )
            return
        yield _event(
            "COMPLETED",
            {
                "test_environment_result": True,
                "result": cast(dict[str, object], result),
            },
        )

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.post("/api/v1/result-explanations/comparison/stream")
def stream_result_recheck_comparison(
    request: Request,
    body: ResultRecheckComparisonBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> StreamingResponse:
    """이전/현재 DRAFT 규칙 상태 변화와 남은 위험을 설명한다."""

    _require_product_demo()
    verify_browser_csrf(request, csrf_token)
    organization_id = _organization_id(request)

    def event_stream() -> Iterator[str]:
        yield _event(
            "VALIDATING_RECHECK_LINEAGE",
            {"official_rule_status_immutable": True},
        )
        yield _event("SEARCHING_CHANGED_KISA_EVIDENCE")
        try:
            evidence = _retrieve_guide_evidence(
                body.current_explanation_inputs,
                organization_id=organization_id,
            )
            if len(evidence) != len(body.current_explanation_inputs):
                raise ResultGuideRetrievalError(
                    "RESULT_GUIDE_EVIDENCE_UNAVAILABLE"
                )
        except (ResultGuideRetrievalError, SQLAlchemyError):
            yield _event(
                "FAILED",
                {
                    "status_code": status.HTTP_503_SERVICE_UNAVAILABLE,
                    "detail": {
                        "code": "RECHECK_GUIDE_EVIDENCE_UNAVAILABLE",
                        "message": (
                            "변화 항목의 KISA 근거를 확인하지 못했습니다. "
                            "규칙 엔진의 비교 결과는 그대로입니다."
                        ),
                        "retryable": True,
                    },
                },
            )
            return
        yield _event("GENERATING_CHANGE_EXPLANATION")
        try:
            result = _generate_recheck_comparison(
                body,
                cast(list[dict[str, object]], evidence),
            )
        except HTTPException as exc:
            detail = (
                exc.detail
                if isinstance(exc.detail, dict)
                else {"code": "FAILED"}
            )
            yield _event(
                "FAILED",
                {
                    "status_code": exc.status_code,
                    "detail": cast(dict[str, object], detail),
                },
            )
            return
        yield _event(
            "COMPLETED",
            {
                "test_environment_result": True,
                "result": cast(dict[str, object], result),
            },
        )

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
