"""IMP-051 authenticated chat API contract; LIVE activation is deferred."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from dataclasses import replace
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from time import monotonic, sleep
from typing import Any, cast
from uuid import UUID

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Header,
    HTTPException,
    Query,
    Request,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import Engine, create_engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from apps.api.auth_support import auth_enabled, current_principal
from apps.api.browser_csrf import verify_browser_csrf
from security_audit.application.grounded_ai import (
    GroundedAIRequest,
    GroundedAIService,
    ModelExecutionPolicy,
)
from security_audit.application.integrated_guide_qa import (
    INTEGRATED_GUIDE_ID,
    INTEGRATED_GUIDE_VERSION,
    INTEGRATED_SCOPE_ID,
    IntegratedGuideTarget,
    generate_integrated_guide_answer,
)
from security_audit.application.local_grounded_summary import (
    LocalGroundedSummaryModel,
)
from security_audit.application.model_search import guide_search_top_k
from security_audit.chat import ChatContractError, ChatScope
from security_audit.chat.contracts import ChatCitation
from security_audit.common.canonical_json import JsonValue, canonical_sha256
from security_audit.common.service_settings import ServiceSettings
from security_audit.guides.contracts import load_json_strict
from security_audit.guides.grounding import ControlCitationSource
from security_audit.guides.retrieval import GuideSearchScope
from security_audit.llm import InternalModelGatewayClient, ProviderRequestError
from security_audit.persistence.database.chat_repository import (
    GenerationTrace,
    append_user_message,
    complete_chat_generation,
    create_chat_thread,
    edit_user_message,
    fail_chat_generation,
    list_chat_threads,
    load_chat_generation_context,
    load_chat_history,
    mark_chat_generation_streaming,
    move_chat_thread,
    rename_chat_thread,
    set_chat_scope,
    set_chat_thread_archived,
    set_chat_thread_pinned,
    start_chat_generation,
    stop_chat_generation,
    tombstone_chat_thread,
    undo_tombstone_chat_thread,
)
from security_audit.persistence.database.models import (
    ChatGenerationRunRecord,
    ChatMessageRecord,
    ChatThreadRecord,
)

router = APIRouter()
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONTROL_SOURCES_PATH = (
    PROJECT_ROOT
    / "guides"
    / "mappings"
    / "kisa_2026_all_control_sources.json"
)
GUIDE_CATALOG_PATH = PROJECT_ROOT / "guides" / "catalog.json"
PUBLIC_GUIDE_MANIFEST_PATH = PROJECT_ROOT / "guides" / "public_guides_manifest.json"
_KISA_GUIDE_ID = "kisa-major-infrastructure-detailed-guide"
_KISA_GUIDE_VERSION = "2026"
_KISA_SCOPE_ID = "kisa-2026-all"
_INTEGRATED_GUIDE_ID = INTEGRATED_GUIDE_ID
_INTEGRATED_GUIDE_VERSION = INTEGRATED_GUIDE_VERSION
_INTEGRATED_SCOPE_ID = INTEGRATED_SCOPE_ID
LOCAL_ANSWER_MODE = "LOCAL_GROUNDED_SUMMARY"
LOCAL_VLLM_ANSWER_MODE = "LOCAL_VLLM"
REMOTE_ANSWER_MODE = "REMOTE_OPENROUTER"
_STREAM_TTL_SECONDS = 600
_STREAM_MAX_CHARS = 100_000
_CANONICAL_CITATION_REFERENCE_PATTERN = re.compile(
    r"\[([1-9]\d?)\]|［([1-9]\d?)］|【([1-9]\d?)】"
)
_PARENTHESIZED_CITATION_REFERENCE_PATTERN = re.compile(
    r"\(([1-9]\d?)\)|（([1-9]\d?)）"
)
_CITATION_SENTENCE_ENDINGS = frozenset(".!?。！？;；:：")
_CITATION_CLOSING_MARKS = frozenset("\"'”’」』》〉")


def _citation_ordinal(match: re.Match[str]) -> int:
    return int(next(value for value in match.groups() if value is not None))


def _referenced_citation_ordinals(content: str) -> tuple[int, ...]:
    """본문에 표시된 근거 번호를 첫 등장 순서로 반환한다.

    대괄호형 표기는 근거 번호로 취급한다. 괄호형 표기는 문장부호 바로 뒤에
    놓인 경우에만 호환 표기로 인정해 ``(1) 점검`` 같은 순서 번호를 제외한다.
    """

    matches = [
        (matched.start(), matched.end(), _citation_ordinal(matched), True)
        for matched in _CANONICAL_CITATION_REFERENCE_PATTERN.finditer(content)
    ]
    matches.extend(
        (
            matched.start(),
            matched.end(),
            _citation_ordinal(matched),
            False,
        )
        for matched in _PARENTHESIZED_CITATION_REFERENCE_PATTERN.finditer(content)
    )
    matches.sort(key=lambda item: item[0])

    ordinals: list[int] = []
    seen: set[int] = set()
    previous_reference_end: int | None = None
    for start, end, ordinal, canonical in matches:
        accepted = canonical
        if not canonical:
            prefix_end = start
            while prefix_end > 0 and content[prefix_end - 1].isspace():
                prefix_end -= 1
            preceding_index = prefix_end - 1
            while (
                preceding_index >= 0
                and content[preceding_index] in _CITATION_CLOSING_MARKS
            ):
                preceding_index -= 1
            accepted = (
                preceding_index >= 0
                and content[preceding_index] in _CITATION_SENTENCE_ENDINGS
            ) or (
                previous_reference_end is not None
                and prefix_end == previous_reference_end
            )
        if not accepted:
            continue
        previous_reference_end = end
        if ordinal not in seen:
            seen.add(ordinal)
            ordinals.append(ordinal)
    return tuple(ordinals)


def _referenced_citation_payloads(
    content: str,
    citations: list[dict[str, object]],
) -> list[dict[str, object]]:
    """답변 본문에서 실제 참조한 번호의 출처만 사용자에게 노출한다."""

    referenced_ordinals = set(_referenced_citation_ordinals(content))
    return [
        citation
        for citation in citations
        if isinstance(citation.get("ordinal"), int)
        and not isinstance(citation.get("ordinal"), bool)
        and citation.get("ordinal") in referenced_ordinals
    ]


def _referenced_chat_citations(
    content: str,
    citations: tuple[ChatCitation, ...],
) -> tuple[ChatCitation, ...]:
    """저장할 근거를 본문의 인라인 번호와 동일한 ordinal로 제한한다."""

    referenced_ordinals = set(_referenced_citation_ordinals(content))
    selected: list[ChatCitation] = []
    for position, citation in enumerate(citations, start=1):
        ordinal = citation.ordinal or position
        if ordinal in referenced_ordinals:
            selected.append(replace(citation, ordinal=ordinal))
    return tuple(selected)


@lru_cache(maxsize=1)
def _stream_redis() -> Redis:
    return Redis.from_url(
        ServiceSettings.from_environment().redis_url(database=2),
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
    )


def _stream_keys(generation_id: UUID) -> tuple[str, str]:
    prefix = f"secai:guide-stream:{generation_id}"
    return f"{prefix}:content", f"{prefix}:epoch"


def _initialize_stream(generation_id: UUID) -> None:
    content_key, epoch_key = _stream_keys(generation_id)
    try:
        with _stream_redis().pipeline(transaction=True) as pipeline:
            pipeline.set(content_key, "", ex=_STREAM_TTL_SECONDS)
            pipeline.set(epoch_key, "0", ex=_STREAM_TTL_SECONDS)
            pipeline.execute()
    except RedisError:
        return


def _append_stream_token(generation_id: UUID, content: str) -> None:
    if not content:
        return
    content_key, epoch_key = _stream_keys(generation_id)
    try:
        current_length = int(cast(int, _stream_redis().strlen(content_key)))
        remaining = _STREAM_MAX_CHARS - current_length
        if remaining <= 0:
            return
        with _stream_redis().pipeline(transaction=False) as pipeline:
            pipeline.append(content_key, content[:remaining])
            pipeline.expire(content_key, _STREAM_TTL_SECONDS)
            pipeline.expire(epoch_key, _STREAM_TTL_SECONDS)
            pipeline.execute()
    except RedisError:
        return


def _reset_stream(generation_id: UUID) -> None:
    content_key, epoch_key = _stream_keys(generation_id)
    try:
        with _stream_redis().pipeline(transaction=True) as pipeline:
            pipeline.incr(epoch_key)
            pipeline.set(content_key, "", ex=_STREAM_TTL_SECONDS)
            pipeline.expire(epoch_key, _STREAM_TTL_SECONDS)
            pipeline.execute()
    except RedisError:
        return


def _read_stream(generation_id: UUID) -> tuple[str, int]:
    content_key, epoch_key = _stream_keys(generation_id)
    try:
        values = cast(
            list[str | None],
            _stream_redis().mget(content_key, epoch_key),
        )
    except RedisError:
        return "", 0
    content, epoch = values
    return str(content or ""), int(epoch or 0)


def _discard_stream(generation_id: UUID) -> None:
    try:
        _stream_redis().delete(*_stream_keys(generation_id))
    except RedisError:
        return


def _guide_model_runtime() -> tuple[
    InternalModelGatewayClient,
    ModelExecutionPolicy,
    str,
]:
    client = InternalModelGatewayClient.from_environment()
    capability = client.capabilities()
    provider_kind = capability.get("provider_kind")
    external_data_transfer = capability.get("external_data_transfer")
    if not isinstance(external_data_transfer, bool):
        raise ProviderRequestError("INVALID_GATEWAY_RESPONSE", retryable=False)
    if provider_kind == "OPENROUTER" and external_data_transfer:
        approved = (
            os.getenv(
                "SECAI_GUIDE_AI_REMOTE_TEST_APPROVED",
                os.getenv("SECAI_RESULT_AI_REMOTE_TEST_APPROVED", "false"),
            ).casefold()
            == "true"
        )
        return (
            client,
            ModelExecutionPolicy(
                deployment_mode="REMOTE_API",
                external_data_transfer=True,
                approved_external_content_transfer=approved,
            ),
            REMOTE_ANSWER_MODE,
        )
    if provider_kind == "VLLM" and not external_data_transfer:
        return (
            client,
            ModelExecutionPolicy(
                deployment_mode="LOCAL_VLLM",
                external_data_transfer=False,
                approved_external_content_transfer=False,
            ),
            LOCAL_VLLM_ANSWER_MODE,
        )
    raise ProviderRequestError("GUIDE_AI_RUNTIME_NOT_APPROVED", retryable=False)


class CreateThreadInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=160)
    guide_id: str = Field(min_length=3, max_length=128)
    guide_version: str = Field(min_length=1, max_length=64)
    scope_id: str = Field(min_length=3, max_length=128)
    profile: str = Field(pattern="^(FAST|PRECISE)$")


class UserMessageInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=24_000)
    idempotency_key: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$",
    )
    parent_message_id: UUID | None = None


class EditMessageInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=24_000)
    idempotency_key: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$",
    )


class RetryMessageInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$",
    )


class RenameThreadInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=160)


class PinThreadInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_pinned: bool


class MoveThreadInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    folder_name: str | None = Field(default=None, max_length=80)


class ArchiveThreadInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    archived: bool


def _require_chat_live() -> None:
    """PREVIEW direct URLs must not create stored conversations."""

    if os.getenv("SECAI_CHAT_LIVE_ENABLED", "false").casefold() != "true":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            {
                "code": "CHAT_PREVIEW_NOT_LIVE",
                "message": "대화 기능은 안전성 검증 중이며 아직 사용할 수 없습니다.",
                "retryable": False,
            },
        )
    if not auth_enabled():
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            {
                "code": "CHAT_AUTHENTICATION_REQUIRED",
                "message": "대화 저장 기능은 로그인 없이 사용할 수 없습니다.",
                "retryable": False,
            },
        )


@lru_cache(maxsize=1)
def _engine() -> Engine:
    return create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )


def _scope(request: Request) -> tuple[UUID, UUID]:
    principal = current_principal(request)
    return principal.organization_id, principal.user_id


@lru_cache(maxsize=1)
def _searchable_guide_options() -> tuple[dict[str, object], ...]:
    catalog = cast(
        dict[str, Any],
        json.loads(GUIDE_CATALOG_PATH.read_text(encoding="utf-8")),
    )
    guides = cast(list[dict[str, Any]], catalog["guides"])
    kisa = next(
        item
        for item in guides
        if item.get("guide_id") == _KISA_GUIDE_ID
        and item.get("version") == _KISA_GUIDE_VERSION
        and item.get("status") == "APPROVED"
    )
    options: list[dict[str, object]] = [
        {
            "guide_id": _KISA_GUIDE_ID,
            "version": _KISA_GUIDE_VERSION,
            "scope_id": _KISA_SCOPE_ID,
            "publisher": str(kisa["publisher"]),
            "title": str(kisa["title"]),
            "retrieval_role": "OFFICIAL_CHECK_REFERENCE",
            "decision_authority": False,
            "platforms": ["WINDOWS", "LINUX", "SWITCH"],
            "topics": ["TECHNICAL_VULNERABILITY_CHECK"],
        }
    ]
    manifest = load_json_strict(PUBLIC_GUIDE_MANIFEST_PATH)
    documents = manifest.get("documents")
    if not isinstance(documents, list):
        raise RuntimeError("PUBLIC_GUIDE_DOCUMENTS_INVALID")
    for document in documents:
        if (
            not isinstance(document, dict)
            or document.get("status") != "APPROVED"
            or document.get("retrieval_role") != "SUPPLEMENTAL_EXPLANATION"
            or document.get("decision_authority") is not False
        ):
            continue
        options.append(
            {
                "guide_id": str(document["guide_id"]),
                "version": str(document["version"]),
                "scope_id": str(document["scope_id"]),
                "publisher": str(document["publisher"]),
                "title": str(document["title"]),
                "retrieval_role": "SUPPLEMENTAL_EXPLANATION",
                "decision_authority": False,
                "platforms": list(cast(list[str], document["platforms"])),
                "topics": list(cast(list[str], document["topics"])),
            }
        )
    return tuple(options)


@lru_cache(maxsize=1)
def _approved_chat_guides() -> tuple[dict[str, object], ...]:
    return (
        {
            "guide_id": _INTEGRATED_GUIDE_ID,
            "version": _INTEGRATED_GUIDE_VERSION,
            "scope_id": _INTEGRATED_SCOPE_ID,
            "publisher": "Sec_AI",
            "title": "통합 보안 가이드 검색 (8종)",
            "retrieval_role": "INTEGRATED_READ_ONLY",
            "decision_authority": False,
            "platforms": ["WINDOWS", "LINUX", "SWITCH", "AI_SYSTEM", "PRODUCT"],
            "topics": ["INTEGRATED_SECURITY_GUIDANCE"],
        },
    )


def _guide_display_name(guide_id: str, guide_version: str) -> str:
    match = next(
        (
            item
            for item in _searchable_guide_options()
            if item["guide_id"] == guide_id and item["version"] == guide_version
        ),
        None,
    )
    if match is None:
        return guide_id
    return f"{match['publisher']} · {match['title']}"


def _require_approved_chat_scope(payload: CreateThreadInput) -> None:
    identity = (payload.guide_id, payload.guide_version, payload.scope_id)
    if not any(
        identity == (item["guide_id"], item["version"], item["scope_id"])
        for item in (*_approved_chat_guides(), *_searchable_guide_options())
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            {
                "code": "GUIDE_SCOPE_NOT_APPROVED",
                "message": "승인된 가이드와 검색 범위를 선택해 주세요.",
                "retryable": False,
            },
        )


@lru_cache(maxsize=16)
def _control_sources(
    guide_id: str,
    guide_version: str,
) -> dict[str, ControlCitationSource]:
    if (guide_id, guide_version) != (_KISA_GUIDE_ID, _KISA_GUIDE_VERSION):
        matches = [
            item
            for item in _searchable_guide_options()
            if item["guide_id"] == guide_id and item["version"] == guide_version
        ]
        if len(matches) != 1:
            return {}
        selected = matches[0]
        manifest = load_json_strict(PUBLIC_GUIDE_MANIFEST_PATH)
        documents = manifest.get("documents")
        if not isinstance(documents, list):
            return {}
        document = next(
            (
                item
                for item in documents
                if isinstance(item, dict)
                and item.get("guide_id") == guide_id
                and item.get("version") == guide_version
            ),
            None,
        )
        if document is None or not isinstance(document.get("page_count"), int):
            return {}
        return {
            "GUIDE-PAGE": ControlCitationSource(
                control_id="GUIDE-PAGE",
                document_code=f"{selected['publisher']} · {selected['title']}",
                page_start=1,
                page_end=int(document["page_count"]),
                section_label=str(selected["title"]),
            )
        }
    value = cast(
        dict[str, Any],
        json.loads(CONTROL_SOURCES_PATH.read_text(encoding="utf-8")),
    )
    mappings = cast(list[dict[str, Any]], value["mappings"])
    return {
        str(item["control_id"]): ControlCitationSource(
            control_id=str(item["control_id"]),
            document_code=str(item["source_document_code"]),
            page_start=int(item["page_start"]),
            page_end=int(item["page_end"]),
            section_label=str(item["section_label"]),
        )
        for item in mappings
    }


@lru_cache(maxsize=1)
def _integrated_guide_targets() -> tuple[IntegratedGuideTarget, ...]:
    return tuple(
        IntegratedGuideTarget(
            guide_id=str(item["guide_id"]),
            guide_version=str(item["version"]),
            scope_id=str(item["scope_id"]),
            citation_sources=_control_sources(
                str(item["guide_id"]),
                str(item["version"]),
            ),
        )
        for item in _searchable_guide_options()
    )


@router.get("/api/v1/chat/guides")
def chat_guides(request: Request) -> dict[str, object]:
    """로그인 사용자에게 실제 임베딩이 승인된 질문 대상을 반환합니다."""

    _require_chat_live()
    _scope(request)
    return {
        "guides": list(_approved_chat_guides()),
        "default_guide_id": _INTEGRATED_GUIDE_ID,
        "searched_document_count": len(_searchable_guide_options()),
        "official_decision_source": _KISA_GUIDE_ID,
        "supplemental_guides_change_findings": False,
    }


def _trace_payload(record: ChatGenerationRunRecord) -> dict[str, object] | None:
    if record.answer_mode is None:
        return None
    return {
        "answer_mode": record.answer_mode,
        "model_id": record.model_id,
        "prompt_sha256": record.prompt_sha256,
        "input_sha256": record.input_sha256,
        "output_sha256": record.output_sha256,
        "external_data_transfer": record.external_data_transfer,
    }


def _local_no_evidence_trace(question: str, answer: str) -> GenerationTrace:
    return GenerationTrace(
        answer_mode=LOCAL_ANSWER_MODE,
        model_id="secai-local-no-evidence-v1",
        prompt_sha256=canonical_sha256(
            cast(
                JsonValue,
                {
                    "template": "secai-local-no-evidence",
                    "version": "1.0.0",
                },
            )
        ),
        input_sha256=canonical_sha256(
            cast(JsonValue, {"question": question})
        ),
        output_sha256=canonical_sha256(
            cast(JsonValue, {"answer": answer})
        ),
    )


def _handle_contract_error(error: ChatContractError) -> HTTPException:
    if error.code == "CHAT_SCOPE_DENIED":
        return HTTPException(status.HTTP_404_NOT_FOUND, {"code": error.code})
    if error.code in {
        "CHAT_IDEMPOTENCY_CONFLICT",
        "GENERATION_ALREADY_TERMINAL",
        "CHAT_THREAD_NOT_ACTIVE",
        "CHAT_DELETE_UNDO_EXPIRED",
        "CHAT_DELETE_UNDO_NOT_AVAILABLE",
    }:
        return HTTPException(status.HTTP_409_CONFLICT, {"code": error.code})
    return HTTPException(
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        {"code": error.code},
    )


def _thread_view(record: ChatThreadRecord) -> dict[str, object]:
    return {
        "thread_id": str(record.id),
        "title": record.title,
        "guide": {
            "guide_id": record.guide_id,
            "version": record.guide_version,
            "scope_id": record.scope_id,
        },
        "profile": record.profile,
        "status": record.status,
        "retention_status": record.retention_status,
        "is_pinned": record.is_pinned,
        "folder_name": record.folder_name,
        "audit_trace_id": str(record.audit_trace_id),
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "undo_delete_until": (
            (record.tombstoned_at + timedelta(seconds=30)).isoformat()
            if record.tombstoned_at is not None
            else None
        ),
    }


def _message_view(record: ChatMessageRecord) -> dict[str, object]:
    return {
        "message_id": str(record.id),
        "thread_id": str(record.thread_id),
        "branch_id": str(record.branch_id),
        "role": record.role,
        "status": record.status,
        "revision": record.revision,
        "parent_message_id": (
            str(record.parent_message_id)
            if record.parent_message_id is not None
            else None
        ),
        "edit_of_message_id": (
            str(record.edit_of_message_id)
            if record.edit_of_message_id is not None
            else None
        ),
        "retry_of_message_id": (
            str(record.retry_of_message_id)
            if record.retry_of_message_id is not None
            else None
        ),
        "content": record.content,
        "content_sha256": record.content_sha256,
        "created_at": record.created_at.isoformat(),
    }


@router.post("/api/v1/chat/threads", status_code=status.HTTP_201_CREATED)
def create_thread(
    request: Request,
    payload: CreateThreadInput,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    _require_chat_live()
    verify_browser_csrf(request, csrf_token)
    _require_approved_chat_scope(payload)
    organization_id, owner_user_id = _scope(request)
    try:
        with Session(_engine()) as session, session.begin():
            record = create_chat_thread(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                title=payload.title,
                scope=ChatScope(
                    guide_id=payload.guide_id,
                    guide_version=payload.guide_version,
                    scope_id=payload.scope_id,
                    profile=payload.profile,
                ),
            )
            return _thread_view(record)
    except ChatContractError as exc:
        raise _handle_contract_error(exc) from exc


@router.get("/api/v1/chat/threads")
def thread_history(
    request: Request,
    query: str | None = Query(default=None, alias="q", max_length=100),
    folder_name: str | None = Query(default=None, max_length=80),
    view: str = Query(default="ACTIVE", pattern="^(ACTIVE|ARCHIVED|ALL)$"),
) -> dict[str, object]:
    _require_chat_live()
    organization_id, owner_user_id = _scope(request)
    with Session(_engine()) as session, session.begin():
        records = list_chat_threads(
            session,
            organization_id=organization_id,
            owner_user_id=owner_user_id,
            query=query,
            folder_name=folder_name,
            view=view,
        )
        return {"threads": [_thread_view(record) for record in records]}


def _manage_thread(
    request: Request,
    csrf_token: str | None,
    action: Any,
    **values: object,
) -> dict[str, object]:
    _require_chat_live()
    verify_browser_csrf(request, csrf_token)
    organization_id, owner_user_id = _scope(request)
    try:
        with Session(_engine()) as session, session.begin():
            record = action(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                **values,
            )
            return _thread_view(record)
    except ChatContractError as exc:
        raise _handle_contract_error(exc) from exc


@router.patch("/api/v1/chat/threads/{thread_id}/title")
def rename_thread(
    request: Request,
    thread_id: UUID,
    payload: RenameThreadInput,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    return _manage_thread(
        request,
        csrf_token,
        rename_chat_thread,
        thread_id=thread_id,
        title=payload.title,
    )


@router.patch("/api/v1/chat/threads/{thread_id}/pin")
def pin_thread(
    request: Request,
    thread_id: UUID,
    payload: PinThreadInput,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    return _manage_thread(
        request,
        csrf_token,
        set_chat_thread_pinned,
        thread_id=thread_id,
        is_pinned=payload.is_pinned,
    )


@router.patch("/api/v1/chat/threads/{thread_id}/folder")
def move_thread(
    request: Request,
    thread_id: UUID,
    payload: MoveThreadInput,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    return _manage_thread(
        request,
        csrf_token,
        move_chat_thread,
        thread_id=thread_id,
        folder_name=payload.folder_name,
    )


@router.patch("/api/v1/chat/threads/{thread_id}/archive")
def archive_thread(
    request: Request,
    thread_id: UUID,
    payload: ArchiveThreadInput,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    return _manage_thread(
        request,
        csrf_token,
        set_chat_thread_archived,
        thread_id=thread_id,
        archived=payload.archived,
    )


@router.post("/api/v1/chat/threads/{thread_id}/tombstone")
def tombstone_thread(
    request: Request,
    thread_id: UUID,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    return _manage_thread(
        request,
        csrf_token,
        tombstone_chat_thread,
        thread_id=thread_id,
    )


@router.post("/api/v1/chat/threads/{thread_id}/undo-delete")
def undo_delete_thread(
    request: Request,
    thread_id: UUID,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    return _manage_thread(
        request,
        csrf_token,
        undo_tombstone_chat_thread,
        thread_id=thread_id,
    )


@router.get("/api/v1/chat/threads/{thread_id}/messages")
def message_history(request: Request, thread_id: UUID) -> dict[str, object]:
    _require_chat_live()
    organization_id, owner_user_id = _scope(request)
    try:
        with Session(_engine()) as session, session.begin():
            history = load_chat_history(
                session,
                thread_id=thread_id,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
            )
            citations_by_message: dict[UUID, list[dict[str, object]]] = {}
            for citation in history.citations:
                citations_by_message.setdefault(citation.message_id, []).append(
                    {
                        "citation_id": str(citation.id),
                        "ordinal": citation.ordinal,
                        "guide_id": citation.guide_id,
                        "guide_version": citation.guide_version,
                        "scope_id": citation.scope_id,
                        "document_code": _guide_display_name(
                            citation.guide_id,
                            citation.guide_version,
                        ),
                        "chunk_id": str(citation.chunk_id),
                        "pdf_page_number": citation.pdf_page_number,
                        "section_label": citation.section_label,
                        "paragraph_ordinal": citation.paragraph_ordinal,
                    }
                )
            generation_by_message = {
                generation.response_message_id: _trace_payload(generation)
                for generation in session.scalars(
                    select(ChatGenerationRunRecord).where(
                        ChatGenerationRunRecord.thread_id == thread_id,
                        ChatGenerationRunRecord.response_message_id.is_not(None),
                    )
                )
                if generation.response_message_id is not None
            }
            return {
                "thread": _thread_view(history.thread),
                "messages": [
                    {
                        **_message_view(message),
                        "citations": _referenced_citation_payloads(
                            message.content,
                            citations_by_message.get(message.id, []),
                        ),
                        "generation_trace": generation_by_message.get(message.id),
                    }
                    for message in history.messages
                ],
            }
    except ChatContractError as exc:
        raise _handle_contract_error(exc) from exc


@router.post(
    "/api/v1/chat/threads/{thread_id}/messages",
    status_code=status.HTTP_202_ACCEPTED,
)
def send_message(
    request: Request,
    thread_id: UUID,
    payload: UserMessageInput,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    _require_chat_live()
    verify_browser_csrf(request, csrf_token)
    organization_id, owner_user_id = _scope(request)
    try:
        with Session(_engine()) as session, session.begin():
            message = append_user_message(
                session,
                thread_id=thread_id,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                content=payload.content,
                idempotency_key=f"message:{payload.idempotency_key}",
                parent_message_id=payload.parent_message_id,
            )
            generation = start_chat_generation(
                session,
                thread_id=thread_id,
                user_message_id=message.id,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                idempotency_key=f"generate:{payload.idempotency_key}",
            )
            return {
                "message": _message_view(message),
                "generation_id": str(generation.id),
                "generation_status": generation.status,
            }
    except ChatContractError as exc:
        raise _handle_contract_error(exc) from exc


@router.post(
    "/api/v1/chat/threads/{thread_id}/messages/{message_id}/edit",
    status_code=status.HTTP_202_ACCEPTED,
)
def edit_message(
    request: Request,
    thread_id: UUID,
    message_id: UUID,
    payload: EditMessageInput,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    _require_chat_live()
    verify_browser_csrf(request, csrf_token)
    organization_id, owner_user_id = _scope(request)
    try:
        with Session(_engine()) as session, session.begin():
            edited = edit_user_message(
                session,
                thread_id=thread_id,
                message_id=message_id,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                content=payload.content,
                idempotency_key=f"edit:{payload.idempotency_key}",
            )
            generation = start_chat_generation(
                session,
                thread_id=thread_id,
                user_message_id=edited.id,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                idempotency_key=f"generate-edit:{payload.idempotency_key}",
            )
            return {
                "message": _message_view(edited),
                "generation_id": str(generation.id),
                "generation_status": generation.status,
            }
    except ChatContractError as exc:
        raise _handle_contract_error(exc) from exc


@router.post(
    "/api/v1/chat/threads/{thread_id}/messages/{message_id}/retry",
    status_code=status.HTTP_202_ACCEPTED,
)
def retry_message(
    request: Request,
    thread_id: UUID,
    message_id: UUID,
    payload: RetryMessageInput,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    _require_chat_live()
    verify_browser_csrf(request, csrf_token)
    organization_id, owner_user_id = _scope(request)
    try:
        with Session(_engine()) as session, session.begin():
            history = load_chat_history(
                session,
                thread_id=thread_id,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
            )
            answer = next(
                (item for item in history.messages if item.id == message_id),
                None,
            )
            if (
                answer is None
                or answer.role != "ASSISTANT"
                or answer.parent_message_id is None
            ):
                raise ChatContractError("CHAT_RETRY_NOT_ALLOWED")
            generation = start_chat_generation(
                session,
                thread_id=thread_id,
                user_message_id=answer.parent_message_id,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                idempotency_key=f"retry:{payload.idempotency_key}",
                retry_of_message_id=answer.id,
            )
            return {
                "generation_id": str(generation.id),
                "generation_status": generation.status,
                "retry_of_message_id": str(answer.id),
            }
    except ChatContractError as exc:
        raise _handle_contract_error(exc) from exc


@router.post(
    "/api/v1/chat/threads/{thread_id}/messages/{message_id}/branch",
    status_code=status.HTTP_201_CREATED,
)
def branch_thread(
    request: Request,
    thread_id: UUID,
    message_id: UUID,
    payload: CreateThreadInput,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    _require_chat_live()
    verify_browser_csrf(request, csrf_token)
    _require_approved_chat_scope(payload)
    organization_id, owner_user_id = _scope(request)
    try:
        with Session(_engine()) as session, session.begin():
            record = create_chat_thread(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                title=payload.title,
                scope=ChatScope(
                    guide_id=payload.guide_id,
                    guide_version=payload.guide_version,
                    scope_id=payload.scope_id,
                    profile=payload.profile,
                ),
                branch_from_thread_id=thread_id,
                branch_from_message_id=message_id,
            )
            return _thread_view(record)
    except ChatContractError as exc:
        raise _handle_contract_error(exc) from exc


def _run_generation_task(
    generation_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
) -> dict[str, object] | None:
    """응답 연결과 분리된 작업에서 pgvector 근거 기반 답변을 완료한다."""

    try:
        with Session(_engine()) as session, session.begin():
            context = load_chat_generation_context(
                session,
                generation_id=generation_id,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
            )
            if context.generation.status != "STREAMING":
                return None
            question = context.question.content
            if len(question) > 500:
                raise ChatContractError("GUIDE_QUERY_LENGTH_INVALID")
            guide_id = context.thread.guide_id
            guide_version = context.thread.guide_version
            scope_id = context.thread.scope_id
            profile = context.thread.profile

        integrated_scope = (guide_id, guide_version, scope_id) == (
            _INTEGRATED_GUIDE_ID,
            _INTEGRATED_GUIDE_VERSION,
            _INTEGRATED_SCOPE_ID,
        )
        if integrated_scope:
            integrated_model: InternalModelGatewayClient | None
            integrated_policy: ModelExecutionPolicy | None
            try:
                integrated_model, integrated_policy, answer_mode = (
                    _guide_model_runtime()
                )
            except ProviderRequestError:
                integrated_model = None
                integrated_policy = None
                answer_mode = LOCAL_ANSWER_MODE
            with Session(_engine()) as search_session, search_session.begin():
                result = generate_integrated_guide_answer(
                    search_session,
                    organization_id=organization_id,
                    question=question,
                    profile=cast(Any, profile),
                    targets=_integrated_guide_targets(),
                    model=integrated_model,
                    policy=integrated_policy,
                    on_token=(
                        (
                            lambda content: _append_stream_token(
                                generation_id,
                                content,
                            )
                        )
                        if integrated_model is not None
                        else None
                    ),
                )
            if integrated_model is None and result.answer is not None:
                _append_stream_token(generation_id, result.answer)
            if result.status in {"MODEL_UNAVAILABLE", "GENERATION_FAILED"}:
                _reset_stream(generation_id)
                answer_mode = LOCAL_ANSWER_MODE
                with Session(_engine()) as search_session, search_session.begin():
                    result = generate_integrated_guide_answer(
                        search_session,
                        organization_id=organization_id,
                        question=question,
                        profile=cast(Any, profile),
                        targets=_integrated_guide_targets(),
                    )
                if result.answer is not None:
                    _append_stream_token(generation_id, result.answer)
        else:
            grounded_request = GroundedAIRequest(
                mode="GUIDE_QA",
                scope=GuideSearchScope(
                    organization_id=organization_id,
                    guide_id=guide_id,
                    guide_version=guide_version,
                    scope_id=scope_id,
                    query=question,
                    top_k=guide_search_top_k(profile),
                ),
                profile=cast(Any, profile),
            )
            model: InternalModelGatewayClient | LocalGroundedSummaryModel
            if (guide_id, guide_version) != (_KISA_GUIDE_ID, _KISA_GUIDE_VERSION):
                model = LocalGroundedSummaryModel()
                model_policy = ModelExecutionPolicy(
                    deployment_mode="LOCAL_EXTRACTIVE",
                    external_data_transfer=False,
                    approved_external_content_transfer=False,
                )
                answer_mode = LOCAL_ANSWER_MODE
            else:
                try:
                    model, model_policy, answer_mode = _guide_model_runtime()
                except ProviderRequestError:
                    model = LocalGroundedSummaryModel()
                    model_policy = ModelExecutionPolicy(
                        deployment_mode="LOCAL_EXTRACTIVE",
                        external_data_transfer=False,
                        approved_external_content_transfer=False,
                    )
                    answer_mode = LOCAL_ANSWER_MODE

            with Session(_engine()) as search_session, search_session.begin():
                result = GroundedAIService(model).generate_from_postgres(
                    search_session,
                    grounded_request,
                    citation_sources=_control_sources(guide_id, guide_version),
                    policy=model_policy,
                    on_token=lambda content: _append_stream_token(
                        generation_id,
                        content,
                    ),
                )

            if result.status in {"MODEL_UNAVAILABLE", "GENERATION_FAILED"}:
                _reset_stream(generation_id)
                answer_mode = LOCAL_ANSWER_MODE
                with Session(_engine()) as search_session, search_session.begin():
                    result = GroundedAIService(
                        LocalGroundedSummaryModel()
                    ).generate_from_postgres(
                        search_session,
                        grounded_request,
                        citation_sources=_control_sources(guide_id, guide_version),
                        policy=ModelExecutionPolicy(
                            deployment_mode="LOCAL_EXTRACTIVE",
                            external_data_transfer=False,
                            approved_external_content_transfer=False,
                        ),
                        on_token=lambda content: _append_stream_token(
                            generation_id,
                            content,
                        ),
                    )

        if result.status == "GENERATED" and result.answer is not None:
            if (
                result.model_id is None
                or result.prompt_sha256 is None
                or result.input_sha256 is None
                or result.output_sha256 is None
            ):
                raise ChatContractError("CHAT_GENERATION_TRACE_MISSING")
            candidate_citations = tuple(
                ChatCitation(
                    guide_id=citation.guide_id,
                    guide_version=citation.guide_version,
                    scope_id=citation.scope_id,
                    chunk_id=citation.chunk_id,
                    pdf_page_number=citation.pdf_page_number,
                    section_label=citation.section_label,
                    paragraph_ordinal=citation.paragraph_ordinal,
                    paragraph_sha256=citation.paragraph_sha256,
                    text_start=0,
                    text_end=len(result.answer),
                )
                for citation in result.citations
            )
            citations = _referenced_chat_citations(
                result.answer,
                candidate_citations,
            )
            trace = GenerationTrace(
                answer_mode=answer_mode,
                model_id=result.model_id,
                prompt_sha256=result.prompt_sha256,
                input_sha256=result.input_sha256,
                output_sha256=result.output_sha256,
            )
            with Session(_engine()) as session, session.begin():
                answer = complete_chat_generation(
                    session,
                    generation_id=generation_id,
                    organization_id=organization_id,
                    owner_user_id=owner_user_id,
                    content=result.answer,
                    citations=citations,
                    trace=trace,
                )
            return {
                "generation_id": str(generation_id),
                "status": "COMPLETED",
                "response_message_id": str(answer.id),
                "generation_trace": {
                    "answer_mode": trace.answer_mode,
                    "model_id": trace.model_id,
                    "prompt_sha256": trace.prompt_sha256,
                    "input_sha256": trace.input_sha256,
                    "output_sha256": trace.output_sha256,
                    "external_data_transfer": trace.external_data_transfer,
                },
            }

        if result.status == "NO_EVIDENCE":
            answer_text = (
                "승인된 통합 보안 가이드 8종에서 질문에 답할 근거를 찾지 못했습니다. "
                "확인하려는 장비·운영체제·보안 주제와 설정을 함께 적어 다시 질문해 주세요."
                if integrated_scope
                else (
                    "승인된 KISA 상세가이드 전체 범위에서 질문에 답할 근거를 "
                    "찾지 못했습니다. Unix U-01, Windows W-01, PC-07, 네트워크 "
                    "N-01, 클라우드 CA-01처럼 분류나 점검 항목과 확인하려는 "
                    "설정을 함께 적어 다시 질문해 주세요."
                )
            )
            _reset_stream(generation_id)
            _append_stream_token(generation_id, answer_text)
            trace = _local_no_evidence_trace(question, answer_text)
            with Session(_engine()) as session, session.begin():
                answer = complete_chat_generation(
                    session,
                    generation_id=generation_id,
                    organization_id=organization_id,
                    owner_user_id=owner_user_id,
                    content=answer_text,
                    citations=(),
                    trace=trace,
                )
            return {
                "generation_id": str(generation_id),
                "status": "COMPLETED",
                "response_message_id": str(answer.id),
                "grounding_status": "NO_EVIDENCE",
                "generation_trace": {
                    "answer_mode": trace.answer_mode,
                    "model_id": trace.model_id,
                    "prompt_sha256": trace.prompt_sha256,
                    "input_sha256": trace.input_sha256,
                    "output_sha256": trace.output_sha256,
                    "external_data_transfer": False,
                },
            }

        safe_code = result.reason_code or result.status
        _reset_stream(generation_id)
        with Session(_engine()) as session, session.begin():
            failed = fail_chat_generation(
                session,
                generation_id=generation_id,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                error_code=safe_code,
            )
        return {
            "generation_id": str(generation_id),
            "status": failed.status,
            "code": safe_code,
            "message": "안전하게 답변할 수 없어 생성을 중단했습니다.",
            "retryable": result.retryable,
        }
    except ChatContractError as exc:
        _reset_stream(generation_id)
        try:
            with Session(_engine()) as session, session.begin():
                fail_chat_generation(
                    session,
                    generation_id=generation_id,
                    organization_id=organization_id,
                    owner_user_id=owner_user_id,
                    error_code=exc.code,
                )
        except ChatContractError:
            pass
        return None
    except (OSError, SQLAlchemyError, ValueError):
        _reset_stream(generation_id)
        try:
            with Session(_engine()) as session, session.begin():
                fail_chat_generation(
                    session,
                    generation_id=generation_id,
                    organization_id=organization_id,
                    owner_user_id=owner_user_id,
                    error_code="GENERATION_FAILED",
                )
        except (ChatContractError, SQLAlchemyError):
            pass
        return None


@router.post("/api/v1/chat/generations/{generation_id}/run")
def run_generation(
    request: Request,
    generation_id: UUID,
    background_tasks: BackgroundTasks,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    """긴 LLM 호출은 백그라운드에서 실행하고 상태는 SSE로 전달한다."""

    _require_chat_live()
    verify_browser_csrf(request, csrf_token)
    organization_id, owner_user_id = _scope(request)
    try:
        with Session(_engine()) as session, session.begin():
            context = load_chat_generation_context(
                session,
                generation_id=generation_id,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
            )
            current_status = context.generation.status
            if current_status == "QUEUED":
                generation = mark_chat_generation_streaming(
                    session,
                    generation_id=generation_id,
                    organization_id=organization_id,
                    owner_user_id=owner_user_id,
                )
                _initialize_stream(generation_id)
                background_tasks.add_task(
                    _run_generation_task,
                    generation_id,
                    organization_id,
                    owner_user_id,
                )
                return {
                    "generation_id": str(generation.id),
                    "status": generation.status,
                }
            if current_status == "COMPLETED":
                return {
                    "generation_id": str(context.generation.id),
                    "status": current_status,
                    "response_message_id": str(
                        context.generation.response_message_id
                    ),
                    "generation_trace": _trace_payload(context.generation),
                }
            return {
                "generation_id": str(context.generation.id),
                "status": current_status,
                "code": context.generation.error_code,
            }
    except ChatContractError as exc:
        raise _handle_contract_error(exc) from exc


@router.post("/api/v1/chat/generations/{generation_id}/stop")
def stop_generation(
    request: Request,
    generation_id: UUID,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    _require_chat_live()
    verify_browser_csrf(request, csrf_token)
    organization_id, owner_user_id = _scope(request)
    try:
        with Session(_engine()) as session, session.begin():
            generation = stop_chat_generation(
                session,
                generation_id=generation_id,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
            )
            return {
                "generation_id": str(generation.id),
                "status": generation.status,
            }
    except ChatContractError as exc:
        raise _handle_contract_error(exc) from exc


@router.get("/api/v1/chat/generations/{generation_id}/events")
def generation_events(request: Request, generation_id: UUID) -> StreamingResponse:
    _require_chat_live()
    organization_id, owner_user_id = _scope(request)

    def event_stream() -> Iterator[str]:
        deadline = monotonic() + 300
        previous_status: str | None = None
        last_heartbeat = monotonic()
        stream_offset = 0
        stream_epoch = 0
        while monotonic() < deadline:
            with Session(_engine()) as session, session.begin():
                set_chat_scope(session, organization_id, owner_user_id)
                generation = session.scalar(
                    select(ChatGenerationRunRecord).where(
                        ChatGenerationRunRecord.id == generation_id
                    )
                )
                if generation is None:
                    error_payload = {"code": "CHAT_GENERATION_NOT_FOUND"}
                    yield (
                        "event: chat-error\n"
                        f"data: {json.dumps(error_payload)}\n\n"
                    )
                    return
                generation_status = generation.status
                stream_content, current_epoch = _read_stream(generation_id)
                if current_epoch != stream_epoch:
                    reset_payload = {"generation_id": str(generation_id)}
                    yield (
                        "event: answer-reset\n"
                        f"data: {json.dumps(reset_payload)}\n\n"
                    )
                    stream_epoch = current_epoch
                    stream_offset = 0
                if len(stream_content) < stream_offset:
                    stream_offset = 0
                if len(stream_content) > stream_offset:
                    delta = stream_content[stream_offset:]
                    stream_offset = len(stream_content)
                    token_payload = {
                        "generation_id": str(generation_id),
                        "content_delta": delta,
                        "offset": stream_offset,
                    }
                    yield (
                        "event: answer-token\n"
                        f"data: {json.dumps(token_payload, ensure_ascii=False)}\n\n"
                    )
                    last_heartbeat = monotonic()
                if generation_status != previous_status:
                    payload: dict[str, object] = {
                        "generation_id": str(generation.id),
                        "status": generation_status,
                        "error_code": generation.error_code,
                        "response_message_id": (
                            str(generation.response_message_id)
                            if generation.response_message_id is not None
                            else None
                        ),
                        "generation_trace": _trace_payload(generation),
                    }
                    yield (
                        "event: generation-status\n"
                        f"data: {json.dumps(payload)}\n\n"
                    )
                    previous_status = generation_status
                    last_heartbeat = monotonic()
                if generation_status in {"COMPLETED", "STOPPED", "FAILED"}:
                    _discard_stream(generation_id)
                    return
            if monotonic() - last_heartbeat >= 5:
                yield ": keep-alive\n\n"
                last_heartbeat = monotonic()
            sleep(0.25)
        timeout_payload = {"code": "CHAT_EVENT_WAIT_TIMEOUT"}
        _discard_stream(generation_id)
        yield f"event: chat-error\ndata: {json.dumps(timeout_payload)}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
