"""PostgreSQL adapter for owner-scoped append-only chat history."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from re import fullmatch
from uuid import UUID, uuid4

from sqlalchemy import select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from security_audit.chat import (
    ChatCitation,
    ChatContractError,
    ChatScope,
    GenerationStatus,
    MessageStatus,
    ThreadStatus,
)
from security_audit.common.canonical_json import canonical_sha256

from .models import (
    ChatCitationRecord,
    ChatGenerationRunRecord,
    ChatMessageRecord,
    ChatThreadManagementEventRecord,
    ChatThreadRecord,
)

CHAT_DELETE_UNDO_WINDOW = timedelta(seconds=30)
_INTEGRATED_CHAT_SCOPE = (
    "secai-integrated-security-guides",
    "2026-08-06",
    "integrated-all",
)


def _integrated_citation_allowed(
    session: Session,
    organization_id: UUID,
    citation: ChatCitation,
) -> bool:
    value = session.scalar(
        text(
            """
            SELECT EXISTS (
                SELECT 1
                FROM guide_content.guide_chunks AS chunk
                JOIN guide_content.guide_documents AS document
                  ON document.id = chunk.document_id
                WHERE chunk.chunk_id = CAST(:chunk_id AS uuid)
                  AND chunk.organization_id = CAST(:organization_id AS uuid)
                  AND chunk.guide_id = :guide_id
                  AND chunk.guide_version = :guide_version
                  AND chunk.scope_id = :scope_id
                  AND chunk.pdf_page_number = :pdf_page_number
                  AND chunk.status = 'READY'
                  AND document.status = 'APPROVED'
                  AND document.decision_authority = false
                  AND document.retrieval_role IN (
                      'OFFICIAL_CHECK_REFERENCE',
                      'SUPPLEMENTAL_EXPLANATION'
                  )
            )
            """
        ),
        {
            "chunk_id": str(citation.chunk_id),
            "organization_id": str(organization_id),
            "guide_id": citation.guide_id,
            "guide_version": citation.guide_version,
            "scope_id": citation.scope_id,
            "pdf_page_number": citation.pdf_page_number,
        },
    )
    return value is True


def _normalize_management_text(
    value: str,
    *,
    maximum: int,
    length_error: str,
) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise ChatContractError(length_error)
    if any(character in normalized for character in ("\r", "\n", "\x00")):
        raise ChatContractError("CHAT_MANAGEMENT_TEXT_INVALID")
    return normalized


def normalize_chat_title(value: str) -> str:
    return _normalize_management_text(
        value,
        maximum=160,
        length_error="CHAT_TITLE_LENGTH_INVALID",
    )


def normalize_chat_folder(value: str | None) -> str | None:
    if value is None:
        return None
    return _normalize_management_text(
        value,
        maximum=80,
        length_error="CHAT_FOLDER_LENGTH_INVALID",
    )


def normalize_chat_search(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    return _normalize_management_text(
        value,
        maximum=100,
        length_error="CHAT_SEARCH_LENGTH_INVALID",
    )


@dataclass(frozen=True, slots=True)
class ChatHistory:
    thread: ChatThreadRecord
    messages: tuple[ChatMessageRecord, ...]
    citations: tuple[ChatCitationRecord, ...]


@dataclass(frozen=True, slots=True)
class GenerationTrace:
    """완료 답변의 실행 방식과 입력·출력 확인값."""

    answer_mode: str
    model_id: str
    prompt_sha256: str
    input_sha256: str
    output_sha256: str

    def __post_init__(self) -> None:
        if self.answer_mode not in {
            "LOCAL_GROUNDED_SUMMARY",
            "LOCAL_VLLM",
            "REMOTE_OPENROUTER",
        }:
            raise ValueError("CHAT_GENERATION_TRACE_INVALID")
        if not self.model_id.strip() or len(self.model_id) > 200:
            raise ValueError("CHAT_GENERATION_TRACE_INVALID")
        for value in (
            self.prompt_sha256,
            self.input_sha256,
            self.output_sha256,
        ):
            if fullmatch(r"[a-f0-9]{64}", value) is None:
                raise ValueError("CHAT_GENERATION_TRACE_INVALID")

    @property
    def external_data_transfer(self) -> bool:
        return self.answer_mode == "REMOTE_OPENROUTER"


@dataclass(frozen=True, slots=True)
class ChatGenerationContext:
    generation: ChatGenerationRunRecord
    thread: ChatThreadRecord
    question: ChatMessageRecord


def _indexed_citations(
    citations: tuple[ChatCitation, ...],
) -> tuple[tuple[int, ChatCitation], ...]:
    """명시된 인라인 번호를 보존하고 중복 번호는 저장 전에 거부한다."""

    indexed: list[tuple[int, ChatCitation]] = []
    persisted_ordinals: set[int] = set()
    for position, citation in enumerate(citations, start=1):
        ordinal = citation.ordinal or position
        if ordinal in persisted_ordinals:
            raise ChatContractError("CITATION_ORDINAL_DUPLICATE")
        persisted_ordinals.add(ordinal)
        indexed.append((ordinal, citation))
    return tuple(indexed)


def set_chat_scope(session: Session, organization_id: UUID, owner_user_id: UUID) -> None:
    """Set the transaction-local values consumed by PostgreSQL FORCE RLS."""

    session.execute(
        text("SELECT set_config('secai.organization_id', :value, true)"),
        {"value": str(organization_id)},
    )
    session.execute(
        text("SELECT set_config('secai.user_id', :value, true)"),
        {"value": str(owner_user_id)},
    )


def _message_hash(
    role: str,
    content: str,
    revision: int,
    parent_message_id: UUID | None,
) -> str:
    return canonical_sha256(
        {
            "role": role,
            "content": content,
            "revision": revision,
            "parent_message_id": (
                str(parent_message_id) if parent_message_id is not None else None
            ),
        }
    )


def _thread(
    session: Session,
    thread_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    *,
    for_update: bool = False,
) -> ChatThreadRecord:
    statement = select(ChatThreadRecord).where(
        ChatThreadRecord.id == thread_id,
        ChatThreadRecord.organization_id == organization_id,
        ChatThreadRecord.owner_user_id == owner_user_id,
        ChatThreadRecord.status != ThreadStatus.TOMBSTONED.value,
    )
    if for_update:
        statement = statement.with_for_update()
    record = session.scalar(statement)
    if record is None:
        raise ChatContractError("CHAT_SCOPE_DENIED")
    return record


def _thread_including_tombstone(
    session: Session,
    thread_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    *,
    for_update: bool = False,
) -> ChatThreadRecord:
    statement = select(ChatThreadRecord).where(
        ChatThreadRecord.id == thread_id,
        ChatThreadRecord.organization_id == organization_id,
        ChatThreadRecord.owner_user_id == owner_user_id,
    )
    if for_update:
        statement = statement.with_for_update()
    record = session.scalar(statement)
    if record is None:
        raise ChatContractError("CHAT_SCOPE_DENIED")
    return record


def _management_snapshot(record: ChatThreadRecord) -> dict[str, object]:
    return {
        "title": record.title,
        "status": record.status,
        "is_pinned": record.is_pinned,
        "folder_name": record.folder_name,
        "status_before_tombstone": record.status_before_tombstone,
        "tombstoned_at": (
            record.tombstoned_at.isoformat()
            if record.tombstoned_at is not None
            else None
        ),
    }


def _record_management_event(
    session: Session,
    *,
    record: ChatThreadRecord,
    action: str,
    before_state: dict[str, object],
) -> None:
    session.add(
        ChatThreadManagementEventRecord(
            id=uuid4(),
            thread_id=record.id,
            organization_id=record.organization_id,
            owner_user_id=record.owner_user_id,
            action=action,
            before_state=before_state,
            after_state=_management_snapshot(record),
        )
    )


def _managed_thread(
    session: Session,
    *,
    thread_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
) -> ChatThreadRecord:
    set_chat_scope(session, organization_id, owner_user_id)
    return _thread(
        session,
        thread_id,
        organization_id,
        owner_user_id,
        for_update=True,
    )


def _message(
    session: Session,
    thread_id: UUID,
    message_id: UUID,
    *,
    for_update: bool = False,
) -> ChatMessageRecord:
    statement = select(ChatMessageRecord).where(
        ChatMessageRecord.id == message_id,
        ChatMessageRecord.thread_id == thread_id,
    )
    if for_update:
        statement = statement.with_for_update()
    record = session.scalar(statement)
    if record is None:
        raise ChatContractError("CHAT_MESSAGE_NOT_FOUND")
    return record


def create_chat_thread(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    title: str,
    scope: ChatScope,
    branch_from_thread_id: UUID | None = None,
    branch_from_message_id: UUID | None = None,
) -> ChatThreadRecord:
    set_chat_scope(session, organization_id, owner_user_id)
    normalized_title = normalize_chat_title(title)
    if branch_from_thread_id is not None:
        parent = _thread(
            session,
            branch_from_thread_id,
            organization_id,
            owner_user_id,
        )
        if branch_from_message_id is None:
            raise ChatContractError("CHAT_BRANCH_MESSAGE_REQUIRED")
        _message(session, parent.id, branch_from_message_id)
    elif branch_from_message_id is not None:
        raise ChatContractError("CHAT_BRANCH_THREAD_REQUIRED")
    record = ChatThreadRecord(
        id=uuid4(),
        organization_id=organization_id,
        owner_user_id=owner_user_id,
        title=normalized_title,
        guide_id=scope.guide_id,
        guide_version=scope.guide_version,
        scope_id=scope.scope_id,
        profile=scope.profile,
        status=ThreadStatus.ACTIVE.value,
        retention_status="REVIEW_REQUIRED",
        is_pinned=False,
        folder_name=None,
        status_before_tombstone=None,
        branch_from_thread_id=branch_from_thread_id,
        branch_from_message_id=branch_from_message_id,
        audit_trace_id=uuid4(),
        tombstoned_at=None,
    )
    session.add(record)
    session.flush()
    return record


def list_chat_threads(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    limit: int = 50,
    query: str | None = None,
    folder_name: str | None = None,
    view: str = "ACTIVE",
) -> tuple[ChatThreadRecord, ...]:
    set_chat_scope(session, organization_id, owner_user_id)
    safe_limit = min(100, max(1, limit))
    normalized_query = normalize_chat_search(query)
    normalized_folder = normalize_chat_folder(folder_name)
    if view not in {"ACTIVE", "ARCHIVED", "ALL"}:
        raise ChatContractError("CHAT_VIEW_INVALID")
    statement = select(ChatThreadRecord).where(
        ChatThreadRecord.status != ThreadStatus.TOMBSTONED.value
    )
    if view != "ALL":
        statement = statement.where(ChatThreadRecord.status == view)
    if normalized_query is not None:
        statement = statement.where(
            ChatThreadRecord.title.contains(normalized_query, autoescape=True)
        )
    if normalized_folder is not None:
        statement = statement.where(
            ChatThreadRecord.folder_name == normalized_folder
        )
    return tuple(
        session.scalars(
            statement.order_by(
                ChatThreadRecord.is_pinned.desc(),
                ChatThreadRecord.updated_at.desc(),
                ChatThreadRecord.id,
            ).limit(safe_limit)
        )
    )


def rename_chat_thread(
    session: Session,
    *,
    thread_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    title: str,
) -> ChatThreadRecord:
    record = _managed_thread(
        session,
        thread_id=thread_id,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
    )
    before = _management_snapshot(record)
    record.title = normalize_chat_title(title)
    record.updated_at = datetime.now(UTC)
    _record_management_event(
        session,
        record=record,
        action="RENAME",
        before_state=before,
    )
    session.flush()
    return record


def set_chat_thread_pinned(
    session: Session,
    *,
    thread_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    is_pinned: bool,
) -> ChatThreadRecord:
    record = _managed_thread(
        session,
        thread_id=thread_id,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
    )
    before = _management_snapshot(record)
    record.is_pinned = is_pinned
    record.updated_at = datetime.now(UTC)
    _record_management_event(
        session,
        record=record,
        action="PIN" if is_pinned else "UNPIN",
        before_state=before,
    )
    session.flush()
    return record


def move_chat_thread(
    session: Session,
    *,
    thread_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    folder_name: str | None,
) -> ChatThreadRecord:
    record = _managed_thread(
        session,
        thread_id=thread_id,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
    )
    before = _management_snapshot(record)
    record.folder_name = normalize_chat_folder(folder_name)
    record.updated_at = datetime.now(UTC)
    _record_management_event(
        session,
        record=record,
        action="MOVE",
        before_state=before,
    )
    session.flush()
    return record


def set_chat_thread_archived(
    session: Session,
    *,
    thread_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    archived: bool,
) -> ChatThreadRecord:
    record = _managed_thread(
        session,
        thread_id=thread_id,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
    )
    before = _management_snapshot(record)
    record.status = (
        ThreadStatus.ARCHIVED.value if archived else ThreadStatus.ACTIVE.value
    )
    record.updated_at = datetime.now(UTC)
    _record_management_event(
        session,
        record=record,
        action="ARCHIVE" if archived else "RESTORE_ARCHIVE",
        before_state=before,
    )
    session.flush()
    return record


def tombstone_chat_thread(
    session: Session,
    *,
    thread_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
) -> ChatThreadRecord:
    record = _managed_thread(
        session,
        thread_id=thread_id,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
    )
    before = _management_snapshot(record)
    record.status_before_tombstone = record.status
    record.status = ThreadStatus.TOMBSTONED.value
    record.tombstoned_at = datetime.now(UTC)
    record.updated_at = record.tombstoned_at
    _record_management_event(
        session,
        record=record,
        action="TOMBSTONE",
        before_state=before,
    )
    session.flush()
    return record


def undo_tombstone_chat_thread(
    session: Session,
    *,
    thread_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
) -> ChatThreadRecord:
    set_chat_scope(session, organization_id, owner_user_id)
    record = _thread_including_tombstone(
        session,
        thread_id,
        organization_id,
        owner_user_id,
        for_update=True,
    )
    if (
        record.status != ThreadStatus.TOMBSTONED.value
        or record.tombstoned_at is None
        or record.status_before_tombstone not in {
            ThreadStatus.ACTIVE.value,
            ThreadStatus.ARCHIVED.value,
        }
    ):
        raise ChatContractError("CHAT_DELETE_UNDO_NOT_AVAILABLE")
    if datetime.now(UTC) - record.tombstoned_at > CHAT_DELETE_UNDO_WINDOW:
        raise ChatContractError("CHAT_DELETE_UNDO_EXPIRED")
    before = _management_snapshot(record)
    record.status = record.status_before_tombstone
    record.status_before_tombstone = None
    record.tombstoned_at = None
    record.updated_at = datetime.now(UTC)
    _record_management_event(
        session,
        record=record,
        action="UNDO_TOMBSTONE",
        before_state=before,
    )
    session.flush()
    return record


def load_chat_history(
    session: Session,
    *,
    thread_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
) -> ChatHistory:
    set_chat_scope(session, organization_id, owner_user_id)
    thread_record = _thread(session, thread_id, organization_id, owner_user_id)
    messages = tuple(
        session.scalars(
            select(ChatMessageRecord)
            .where(ChatMessageRecord.thread_id == thread_id)
            .order_by(ChatMessageRecord.created_at, ChatMessageRecord.id)
        )
    )
    citations = tuple(
        session.scalars(
            select(ChatCitationRecord)
            .where(ChatCitationRecord.thread_id == thread_id)
            .order_by(ChatCitationRecord.message_id, ChatCitationRecord.ordinal)
        )
    )
    return ChatHistory(thread_record, messages, citations)


def append_user_message(
    session: Session,
    *,
    thread_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    content: str,
    idempotency_key: str,
    parent_message_id: UUID | None = None,
    branch_id: UUID | None = None,
) -> ChatMessageRecord:
    set_chat_scope(session, organization_id, owner_user_id)
    thread_record = _thread(
        session,
        thread_id,
        organization_id,
        owner_user_id,
        for_update=True,
    )
    if thread_record.status != ThreadStatus.ACTIVE.value:
        raise ChatContractError("CHAT_THREAD_NOT_ACTIVE")
    normalized = content.strip()
    if not normalized or len(normalized) > 24_000:
        raise ChatContractError("CHAT_CONTENT_LENGTH_INVALID")
    existing = session.scalar(
        select(ChatMessageRecord).where(
            ChatMessageRecord.thread_id == thread_id,
            ChatMessageRecord.request_idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        expected = _message_hash(
            "USER",
            normalized,
            existing.revision,
            parent_message_id,
        )
        if existing.content_sha256 != expected:
            raise ChatContractError("CHAT_IDEMPOTENCY_CONFLICT")
        return existing
    parent = (
        _message(session, thread_id, parent_message_id)
        if parent_message_id is not None
        else None
    )
    resolved_branch = branch_id or (
        parent.branch_id if parent is not None else uuid4()
    )
    record = ChatMessageRecord(
        id=uuid4(),
        thread_id=thread_id,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
        branch_id=resolved_branch,
        role="USER",
        status=MessageStatus.COMPLETED.value,
        revision=1,
        parent_message_id=parent_message_id,
        edit_of_message_id=None,
        retry_of_message_id=None,
        request_idempotency_key=idempotency_key,
        content=normalized,
        content_sha256=_message_hash("USER", normalized, 1, parent_message_id),
    )
    session.add(record)
    thread_record.updated_at = datetime.now(UTC)
    session.flush()
    return record


def edit_user_message(
    session: Session,
    *,
    thread_id: UUID,
    message_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    content: str,
    idempotency_key: str,
) -> ChatMessageRecord:
    set_chat_scope(session, organization_id, owner_user_id)
    _thread(session, thread_id, organization_id, owner_user_id, for_update=True)
    existing = session.scalar(
        select(ChatMessageRecord).where(
            ChatMessageRecord.thread_id == thread_id,
            ChatMessageRecord.request_idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        return existing
    original = _message(session, thread_id, message_id, for_update=True)
    if original.role != "USER" or original.status != MessageStatus.COMPLETED.value:
        raise ChatContractError("CHAT_EDIT_NOT_ALLOWED")
    normalized = content.strip()
    if not normalized or len(normalized) > 24_000:
        raise ChatContractError("CHAT_CONTENT_LENGTH_INVALID")
    original.status = MessageStatus.SUPERSEDED.value
    revision = original.revision + 1
    record = ChatMessageRecord(
        id=uuid4(),
        thread_id=thread_id,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
        branch_id=uuid4(),
        role="USER",
        status=MessageStatus.COMPLETED.value,
        revision=revision,
        parent_message_id=original.parent_message_id,
        edit_of_message_id=original.id,
        retry_of_message_id=None,
        request_idempotency_key=idempotency_key,
        content=normalized,
        content_sha256=_message_hash(
            "USER",
            normalized,
            revision,
            original.parent_message_id,
        ),
    )
    session.add(record)
    session.flush()
    return record


def start_chat_generation(
    session: Session,
    *,
    thread_id: UUID,
    user_message_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    idempotency_key: str,
    retry_of_message_id: UUID | None = None,
) -> ChatGenerationRunRecord:
    set_chat_scope(session, organization_id, owner_user_id)
    thread_record = _thread(session, thread_id, organization_id, owner_user_id)
    question = _message(session, thread_id, user_message_id)
    allowed = {MessageStatus.COMPLETED.value}
    if retry_of_message_id is not None:
        allowed.add(MessageStatus.SUPERSEDED.value)
        retry = _message(session, thread_id, retry_of_message_id)
        if retry.role != "ASSISTANT" or retry.parent_message_id != user_message_id:
            raise ChatContractError("CHAT_RETRY_NOT_ALLOWED")
    if question.role != "USER" or question.status not in allowed:
        raise ChatContractError("CHAT_GENERATION_INPUT_INVALID")
    generation_id = uuid4()
    session.execute(
        insert(ChatGenerationRunRecord)
        .values(
            id=generation_id,
            thread_id=thread_id,
            organization_id=organization_id,
            owner_user_id=owner_user_id,
            user_message_id=user_message_id,
            response_message_id=None,
            retry_of_message_id=retry_of_message_id,
            idempotency_key=idempotency_key,
            status=GenerationStatus.QUEUED.value,
            error_code=None,
            model_profile=thread_record.profile,
            started_at=None,
            stop_requested_at=None,
            completed_at=None,
        )
        .on_conflict_do_nothing(constraint="uq_chat_generation_request")
    )
    generation = session.scalar(
        select(ChatGenerationRunRecord).where(
            ChatGenerationRunRecord.thread_id == thread_id,
            ChatGenerationRunRecord.idempotency_key == idempotency_key,
        )
    )
    if generation is None:
        raise ChatContractError("CHAT_GENERATION_CREATE_FAILED")
    if (
        generation.user_message_id != user_message_id
        or generation.retry_of_message_id != retry_of_message_id
    ):
        raise ChatContractError("CHAT_IDEMPOTENCY_CONFLICT")
    return generation


def stop_chat_generation(
    session: Session,
    *,
    generation_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
) -> ChatGenerationRunRecord:
    set_chat_scope(session, organization_id, owner_user_id)
    now = datetime.now(UTC)
    stopped = session.scalar(
        update(ChatGenerationRunRecord)
        .where(
            ChatGenerationRunRecord.id == generation_id,
            ChatGenerationRunRecord.status.in_(
                (GenerationStatus.QUEUED.value, GenerationStatus.STREAMING.value)
            ),
        )
        .values(
            status=GenerationStatus.STOPPED.value,
            stop_requested_at=now,
            completed_at=now,
        )
        .returning(ChatGenerationRunRecord)
    )
    if stopped is not None:
        return stopped
    existing = session.scalar(
        select(ChatGenerationRunRecord).where(
            ChatGenerationRunRecord.id == generation_id
        )
    )
    if existing is None:
        raise ChatContractError("CHAT_GENERATION_NOT_FOUND")
    if existing.status == GenerationStatus.STOPPED.value:
        return existing
    raise ChatContractError("GENERATION_ALREADY_TERMINAL")


def load_chat_generation_context(
    session: Session,
    *,
    generation_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
) -> ChatGenerationContext:
    set_chat_scope(session, organization_id, owner_user_id)
    generation = session.scalar(
        select(ChatGenerationRunRecord).where(
            ChatGenerationRunRecord.id == generation_id
        )
    )
    if generation is None:
        raise ChatContractError("CHAT_GENERATION_NOT_FOUND")
    thread_record = _thread(
        session,
        generation.thread_id,
        organization_id,
        owner_user_id,
    )
    question = _message(
        session,
        generation.thread_id,
        generation.user_message_id,
    )
    return ChatGenerationContext(generation, thread_record, question)


def mark_chat_generation_streaming(
    session: Session,
    *,
    generation_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
) -> ChatGenerationRunRecord:
    set_chat_scope(session, organization_id, owner_user_id)
    generation = session.scalar(
        select(ChatGenerationRunRecord)
        .where(ChatGenerationRunRecord.id == generation_id)
        .with_for_update()
    )
    if generation is None:
        raise ChatContractError("CHAT_GENERATION_NOT_FOUND")
    if generation.status == GenerationStatus.QUEUED.value:
        generation.status = GenerationStatus.STREAMING.value
        generation.started_at = datetime.now(UTC)
        session.flush()
        return generation
    if generation.status in {
        GenerationStatus.STREAMING.value,
        GenerationStatus.COMPLETED.value,
    }:
        return generation
    raise ChatContractError("GENERATION_ALREADY_TERMINAL")


def fail_chat_generation(
    session: Session,
    *,
    generation_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    error_code: str,
) -> ChatGenerationRunRecord:
    if fullmatch(r"[A-Z][A-Z0-9_]{2,63}", error_code) is None:
        raise ChatContractError("CHAT_GENERATION_ERROR_CODE_INVALID")
    set_chat_scope(session, organization_id, owner_user_id)
    generation = session.scalar(
        select(ChatGenerationRunRecord)
        .where(ChatGenerationRunRecord.id == generation_id)
        .with_for_update()
    )
    if generation is None:
        raise ChatContractError("CHAT_GENERATION_NOT_FOUND")
    if generation.status == GenerationStatus.FAILED.value:
        return generation
    if generation.status not in {
        GenerationStatus.QUEUED.value,
        GenerationStatus.STREAMING.value,
    }:
        raise ChatContractError("GENERATION_ALREADY_TERMINAL")
    generation.status = GenerationStatus.FAILED.value
    generation.error_code = error_code
    generation.completed_at = datetime.now(UTC)
    session.flush()
    return generation


def complete_chat_generation(
    session: Session,
    *,
    generation_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    content: str,
    citations: tuple[ChatCitation, ...],
    trace: GenerationTrace,
) -> ChatMessageRecord:
    """Atomically append one response and exact citations, or return it once."""

    set_chat_scope(session, organization_id, owner_user_id)
    generation = session.scalar(
        select(ChatGenerationRunRecord)
        .where(ChatGenerationRunRecord.id == generation_id)
        .with_for_update()
    )
    if generation is None:
        raise ChatContractError("CHAT_GENERATION_NOT_FOUND")
    if generation.status == GenerationStatus.COMPLETED.value:
        if generation.response_message_id is None:
            raise ChatContractError("CHAT_GENERATION_INCONSISTENT")
        return _message(session, generation.thread_id, generation.response_message_id)
    if generation.status in {
        GenerationStatus.STOPPED.value,
        GenerationStatus.FAILED.value,
    }:
        raise ChatContractError("GENERATION_ALREADY_TERMINAL")
    thread_record = _thread(
        session,
        generation.thread_id,
        organization_id,
        owner_user_id,
    )
    normalized = content.strip()
    if not normalized or len(normalized) > 24_000:
        raise ChatContractError("CHAT_CONTENT_LENGTH_INVALID")
    thread_scope = (
        thread_record.guide_id,
        thread_record.guide_version,
        thread_record.scope_id,
    )
    for citation in citations:
        if thread_scope == _INTEGRATED_CHAT_SCOPE:
            if not _integrated_citation_allowed(session, organization_id, citation):
                raise ChatContractError("CITATION_SCOPE_MISMATCH")
        elif (
            citation.guide_id != thread_record.guide_id
            or citation.guide_version != thread_record.guide_version
            or citation.scope_id != thread_record.scope_id
        ):
            raise ChatContractError("CITATION_SCOPE_MISMATCH")
    indexed_citations = _indexed_citations(citations)
    question = _message(session, generation.thread_id, generation.user_message_id)
    response = ChatMessageRecord(
        id=uuid4(),
        thread_id=generation.thread_id,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
        branch_id=question.branch_id,
        role="ASSISTANT",
        status=MessageStatus.COMPLETED.value,
        revision=1,
        parent_message_id=question.id,
        edit_of_message_id=None,
        retry_of_message_id=generation.retry_of_message_id,
        request_idempotency_key=None,
        content=normalized,
        content_sha256=_message_hash("ASSISTANT", normalized, 1, question.id),
    )
    session.add(response)
    session.flush()
    for ordinal, citation in indexed_citations:
        session.add(
            ChatCitationRecord(
                id=uuid4(),
                message_id=response.id,
                thread_id=generation.thread_id,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                ordinal=ordinal,
                guide_id=citation.guide_id,
                guide_version=citation.guide_version,
                scope_id=citation.scope_id,
                chunk_id=citation.chunk_id,
                pdf_page_number=citation.pdf_page_number,
                section_label=citation.section_label,
                paragraph_ordinal=citation.paragraph_ordinal,
                paragraph_sha256=citation.paragraph_sha256,
                text_start=citation.text_start,
                text_end=citation.text_end,
            )
        )
    generation.response_message_id = response.id
    generation.answer_mode = trace.answer_mode
    generation.model_id = trace.model_id
    generation.prompt_sha256 = trace.prompt_sha256
    generation.input_sha256 = trace.input_sha256
    generation.output_sha256 = trace.output_sha256
    generation.external_data_transfer = trace.external_data_transfer
    generation.status = GenerationStatus.COMPLETED.value
    generation.completed_at = datetime.now(UTC)
    session.flush()
    return response
