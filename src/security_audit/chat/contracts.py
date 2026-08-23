"""Fail-closed, append-only conversation lifecycle contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID, uuid4

from security_audit.common.canonical_json import canonical_sha256

_HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_GUIDE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_SCOPE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_MAX_TITLE_CHARS = 160
_MAX_MESSAGE_CHARS = 24_000


class ChatContractError(ValueError):
    """Stable lifecycle error safe to map to a public API category."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ThreadStatus(StrEnum):
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"
    TOMBSTONED = "TOMBSTONED"


class MessageStatus(StrEnum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"
    SUPERSEDED = "SUPERSEDED"


class GenerationStatus(StrEnum):
    QUEUED = "QUEUED"
    STREAMING = "STREAMING"
    COMPLETED = "COMPLETED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class ChatScope:
    guide_id: str
    guide_version: str
    scope_id: str
    profile: str

    def __post_init__(self) -> None:
        if not _GUIDE_ID_PATTERN.fullmatch(self.guide_id):
            raise ChatContractError("CHAT_GUIDE_ID_INVALID")
        if not self.guide_version.strip() or len(self.guide_version) > 64:
            raise ChatContractError("CHAT_GUIDE_VERSION_INVALID")
        if not _SCOPE_ID_PATTERN.fullmatch(self.scope_id):
            raise ChatContractError("CHAT_GUIDE_SCOPE_INVALID")
        if self.profile not in {"FAST", "PRECISE"}:
            raise ChatContractError("CHAT_PROFILE_INVALID")


@dataclass(frozen=True, slots=True)
class ChatCitation:
    guide_id: str
    guide_version: str
    scope_id: str
    chunk_id: UUID
    pdf_page_number: int
    section_label: str
    paragraph_ordinal: int
    paragraph_sha256: str
    text_start: int
    text_end: int
    ordinal: int | None = None

    def __post_init__(self) -> None:
        if not _GUIDE_ID_PATTERN.fullmatch(self.guide_id):
            raise ChatContractError("CITATION_GUIDE_ID_INVALID")
        if not self.guide_version or len(self.guide_version) > 64:
            raise ChatContractError("CITATION_GUIDE_VERSION_INVALID")
        if not _SCOPE_ID_PATTERN.fullmatch(self.scope_id):
            raise ChatContractError("CITATION_SCOPE_INVALID")
        if self.pdf_page_number <= 0 or self.paragraph_ordinal <= 0:
            raise ChatContractError("CITATION_LOCATION_INVALID")
        if not self.section_label.strip() or len(self.section_label) > 256:
            raise ChatContractError("CITATION_SECTION_INVALID")
        if _HASH_PATTERN.fullmatch(self.paragraph_sha256) is None:
            raise ChatContractError("CITATION_HASH_INVALID")
        if self.text_start < 0 or self.text_end <= self.text_start:
            raise ChatContractError("CITATION_SPAN_INVALID")
        if self.ordinal is not None and not 1 <= self.ordinal <= 99:
            raise ChatContractError("CITATION_ORDINAL_INVALID")


@dataclass(slots=True)
class ChatMessageRecord:
    id: UUID
    branch_id: UUID
    role: str
    content: str
    status: MessageStatus
    revision: int
    parent_message_id: UUID | None
    edit_of_message_id: UUID | None = None
    retry_of_message_id: UUID | None = None
    citations: tuple[ChatCitation, ...] = ()
    content_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if self.role not in {"USER", "ASSISTANT"}:
            raise ChatContractError("CHAT_ROLE_INVALID")
        if self.revision <= 0:
            raise ChatContractError("CHAT_REVISION_INVALID")
        if self.status is not MessageStatus.PENDING:
            self.content = _validated_content(self.content)
        elif self.content:
            self.content = _validated_content(self.content)
        self.content_sha256 = canonical_sha256(
            {
                "role": self.role,
                "content": self.content,
                "revision": self.revision,
                "parent_message_id": (
                    str(self.parent_message_id)
                    if self.parent_message_id is not None
                    else None
                ),
            }
        )


@dataclass(frozen=True, slots=True)
class ChatStreamEvent:
    generation_id: UUID
    sequence: int
    event_type: str
    content: str


@dataclass(slots=True)
class ChatGeneration:
    id: UUID
    user_message_id: UUID
    idempotency_key: str
    branch_id: UUID
    status: GenerationStatus = GenerationStatus.QUEUED
    response_message_id: UUID | None = None
    retry_of_message_id: UUID | None = None


@dataclass(slots=True)
class ChatThread:
    id: UUID
    organization_id: UUID
    owner_user_id: UUID
    title: str
    scope: ChatScope
    audit_trace_id: UUID
    status: ThreadStatus = ThreadStatus.ACTIVE
    branch_from_thread_id: UUID | None = None
    branch_from_message_id: UUID | None = None
    retention_status: str = "REVIEW_REQUIRED"


def _validated_content(content: str) -> str:
    value = content.strip()
    if not value or len(value) > _MAX_MESSAGE_CHARS:
        raise ChatContractError("CHAT_CONTENT_LENGTH_INVALID")
    return value


def _validated_idempotency_key(value: str) -> str:
    key = value.strip()
    if _IDEMPOTENCY_PATTERN.fullmatch(key) is None:
        raise ChatContractError("CHAT_IDEMPOTENCY_KEY_INVALID")
    return key


class ChatConversation:
    """Deterministic aggregate used by API/application persistence adapters."""

    def __init__(self, thread: ChatThread) -> None:
        self.thread = thread
        self.messages: list[ChatMessageRecord] = []
        self._generations: dict[UUID, ChatGeneration] = {}
        self._generation_keys: dict[str, UUID] = {}
        self._stream_events: dict[UUID, list[ChatStreamEvent]] = {}

    @classmethod
    def create(
        cls,
        *,
        organization_id: UUID,
        owner_user_id: UUID,
        title: str,
        scope: ChatScope,
    ) -> ChatConversation:
        normalized_title = title.strip()
        if not normalized_title or len(normalized_title) > _MAX_TITLE_CHARS:
            raise ChatContractError("CHAT_TITLE_LENGTH_INVALID")
        return cls(
            ChatThread(
                id=uuid4(),
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                title=normalized_title,
                scope=scope,
                audit_trace_id=uuid4(),
            )
        )

    @property
    def scope(self) -> ChatScope:
        return self.thread.scope

    def require_access(self, organization_id: UUID, owner_user_id: UUID) -> None:
        if (
            organization_id != self.thread.organization_id
            or owner_user_id != self.thread.owner_user_id
            or self.thread.status is ThreadStatus.TOMBSTONED
        ):
            raise ChatContractError("CHAT_SCOPE_DENIED")

    def append_user_message(
        self,
        content: str,
        *,
        parent_message_id: UUID | None = None,
        branch_id: UUID | None = None,
    ) -> ChatMessageRecord:
        self._require_active()
        parent = self._message(parent_message_id) if parent_message_id is not None else None
        resolved_branch = branch_id or (parent.branch_id if parent is not None else uuid4())
        message = ChatMessageRecord(
            id=uuid4(),
            branch_id=resolved_branch,
            role="USER",
            content=_validated_content(content),
            status=MessageStatus.COMPLETED,
            revision=1,
            parent_message_id=parent_message_id,
        )
        self.messages.append(message)
        return message

    def edit_user_message(self, message_id: UUID, content: str) -> ChatMessageRecord:
        self._require_active()
        original = self._message(message_id)
        if original.role != "USER" or original.status is MessageStatus.SUPERSEDED:
            raise ChatContractError("CHAT_EDIT_NOT_ALLOWED")
        original.status = MessageStatus.SUPERSEDED
        edited = ChatMessageRecord(
            id=uuid4(),
            branch_id=uuid4(),
            role="USER",
            content=_validated_content(content),
            status=MessageStatus.COMPLETED,
            revision=original.revision + 1,
            parent_message_id=original.parent_message_id,
            edit_of_message_id=original.id,
        )
        self.messages.append(edited)
        return edited

    def start_generation(
        self,
        user_message_id: UUID,
        idempotency_key: str,
        *,
        retry_of_message_id: UUID | None = None,
    ) -> ChatGeneration:
        self._require_active()
        question = self._message(user_message_id)
        allowed_status = (
            {MessageStatus.COMPLETED, MessageStatus.SUPERSEDED}
            if retry_of_message_id is not None
            else {MessageStatus.COMPLETED}
        )
        if question.role != "USER" or question.status not in allowed_status:
            raise ChatContractError("CHAT_GENERATION_INPUT_INVALID")
        key = _validated_idempotency_key(idempotency_key)
        existing_id = self._generation_keys.get(key)
        if existing_id is not None:
            existing = self._generations[existing_id]
            if (
                existing.user_message_id != user_message_id
                or existing.retry_of_message_id != retry_of_message_id
            ):
                raise ChatContractError("CHAT_IDEMPOTENCY_CONFLICT")
            return existing
        generation = ChatGeneration(
            id=uuid4(),
            user_message_id=user_message_id,
            idempotency_key=key,
            branch_id=question.branch_id,
            retry_of_message_id=retry_of_message_id,
        )
        self._generations[generation.id] = generation
        self._generation_keys[key] = generation.id
        self._stream_events[generation.id] = []
        return generation

    def append_stream_chunk(
        self,
        generation_id: UUID,
        sequence: int,
        content: str,
    ) -> ChatStreamEvent:
        generation = self._generation(generation_id)
        self._require_generation_open(generation)
        if not content or len(content) > _MAX_MESSAGE_CHARS:
            raise ChatContractError("CHAT_STREAM_CHUNK_INVALID")
        events = self._stream_events[generation_id]
        if sequence != len(events) + 1:
            raise ChatContractError("CHAT_STREAM_SEQUENCE_INVALID")
        if sum(len(event.content) for event in events) + len(content) > _MAX_MESSAGE_CHARS:
            raise ChatContractError("CHAT_CONTENT_LENGTH_INVALID")
        event = ChatStreamEvent(generation_id, sequence, "CONTENT_DELTA", content)
        events.append(event)
        generation.status = GenerationStatus.STREAMING
        return event

    def complete_generation(
        self,
        generation_id: UUID,
        *,
        citations: tuple[ChatCitation, ...] = (),
    ) -> ChatMessageRecord:
        generation = self._generation(generation_id)
        self._require_generation_open(generation)
        content = "".join(
            event.content for event in self._stream_events[generation_id]
        )
        _validated_content(content)
        self._validate_citations(citations)
        message = ChatMessageRecord(
            id=uuid4(),
            branch_id=generation.branch_id,
            role="ASSISTANT",
            content=content,
            status=MessageStatus.COMPLETED,
            revision=1,
            parent_message_id=generation.user_message_id,
            retry_of_message_id=generation.retry_of_message_id,
            citations=citations,
        )
        self.messages.append(message)
        generation.status = GenerationStatus.COMPLETED
        generation.response_message_id = message.id
        return message

    def stop_generation(self, generation_id: UUID) -> ChatGeneration:
        generation = self._generation(generation_id)
        self._require_generation_open(generation)
        generation.status = GenerationStatus.STOPPED
        return generation

    def retry_answer(
        self,
        assistant_message_id: UUID,
        idempotency_key: str,
    ) -> ChatMessageRecord:
        answer = self._message(assistant_message_id)
        if answer.role != "ASSISTANT" or answer.parent_message_id is None:
            raise ChatContractError("CHAT_RETRY_NOT_ALLOWED")
        generation = self.start_generation(
            answer.parent_message_id,
            idempotency_key,
            retry_of_message_id=answer.id,
        )
        placeholder = ChatMessageRecord(
            id=uuid4(),
            branch_id=generation.branch_id,
            role="ASSISTANT",
            content="",
            status=MessageStatus.PENDING,
            revision=answer.revision + 1,
            parent_message_id=answer.parent_message_id,
            retry_of_message_id=answer.id,
        )
        self.messages.append(placeholder)
        generation.response_message_id = placeholder.id
        return placeholder

    def stream_events(self, generation_id: UUID) -> tuple[ChatStreamEvent, ...]:
        self._generation(generation_id)
        return tuple(self._stream_events[generation_id])

    def _require_active(self) -> None:
        if self.thread.status is not ThreadStatus.ACTIVE:
            raise ChatContractError("CHAT_THREAD_NOT_ACTIVE")

    def _message(self, message_id: UUID | None) -> ChatMessageRecord:
        if message_id is None:
            raise ChatContractError("CHAT_MESSAGE_NOT_FOUND")
        for message in self.messages:
            if message.id == message_id:
                return message
        raise ChatContractError("CHAT_MESSAGE_NOT_FOUND")

    def _generation(self, generation_id: UUID) -> ChatGeneration:
        generation = self._generations.get(generation_id)
        if generation is None:
            raise ChatContractError("CHAT_GENERATION_NOT_FOUND")
        return generation

    @staticmethod
    def _require_generation_open(generation: ChatGeneration) -> None:
        if generation.status in {
            GenerationStatus.COMPLETED,
            GenerationStatus.STOPPED,
            GenerationStatus.FAILED,
        }:
            raise ChatContractError("GENERATION_ALREADY_TERMINAL")

    def _validate_citations(self, citations: tuple[ChatCitation, ...]) -> None:
        ordinals: set[int] = set()
        for citation in citations:
            if (
                citation.guide_id != self.scope.guide_id
                or citation.guide_version != self.scope.guide_version
                or citation.scope_id != self.scope.scope_id
            ):
                raise ChatContractError("CITATION_SCOPE_MISMATCH")
            if citation.ordinal is not None:
                if citation.ordinal in ordinals:
                    raise ChatContractError("CITATION_ORDINAL_DUPLICATE")
                ordinals.add(citation.ordinal)
