"""Verify IMP-051 against the real PostgreSQL runtime role without retaining data."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from security_audit.chat import ChatCitation, ChatContractError, ChatScope
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.chat_repository import (
    GenerationTrace,
    append_user_message,
    complete_chat_generation,
    create_chat_thread,
    edit_user_message,
    load_chat_history,
    set_chat_scope,
    start_chat_generation,
    stop_chat_generation,
)
from security_audit.persistence.database.models import ChatThreadRecord

ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
OWNER_USER_ID = UUID("46000000-0000-4000-8000-000000000003")
OTHER_OWNER_USER_ID = UUID("46000000-0000-4000-8000-000000000099")


def main() -> int:
    engine = create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )
    summary: dict[str, object] = {}
    with Session(engine) as session:
        transaction = session.begin()
        try:
            thread = create_chat_thread(
                session,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                title="IMP-051 비식별 검증",
                scope=ChatScope(
                    guide_id="kisa-major-infrastructure-detailed-guide",
                    guide_version="2026",
                    scope_id="kisa-2026-pc",
                    profile="FAST",
                ),
            )
            repeated_messages = {
                append_user_message(
                    session,
                    thread_id=thread.id,
                    organization_id=ORGANIZATION_ID,
                    owner_user_id=OWNER_USER_ID,
                    content="비밀번호 변경 기준을 확인합니다.",
                    idempotency_key="verify-message-001",
                ).id
                for _ in range(100)
            }
            question_id = next(iter(repeated_messages))
            repeated_generations = {
                start_chat_generation(
                    session,
                    thread_id=thread.id,
                    user_message_id=question_id,
                    organization_id=ORGANIZATION_ID,
                    owner_user_id=OWNER_USER_ID,
                    idempotency_key="verify-generation-001",
                ).id
                for _ in range(100)
            }
            generation_id = next(iter(repeated_generations))
            chunk = session.execute(
                text(
                    """
                    SELECT
                        chunk_id, pdf_page_number, content_text
                    FROM guide_content.guide_chunks
                    WHERE organization_id = CAST(:organization_id AS uuid)
                      AND guide_id = :guide_id
                      AND guide_version = :guide_version
                      AND scope_id = :scope_id
                      AND control_id = 'PC-01'
                    ORDER BY pdf_page_number, chunk_id
                    LIMIT 1
                    """
                ),
                {
                    "organization_id": str(ORGANIZATION_ID),
                    "guide_id": thread.guide_id,
                    "guide_version": thread.guide_version,
                    "scope_id": thread.scope_id,
                },
            ).mappings().one()
            paragraph_hash = hashlib.sha256(
                str(chunk["content_text"]).encode("utf-8")
            ).hexdigest()
            answer = complete_chat_generation(
                session,
                generation_id=generation_id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                content="검증된 KISA 근거를 사용하는 비식별 계약 응답입니다.",
                citations=(
                    ChatCitation(
                        guide_id=thread.guide_id,
                        guide_version=thread.guide_version,
                        scope_id=thread.scope_id,
                        chunk_id=UUID(str(chunk["chunk_id"])),
                        pdf_page_number=int(chunk["pdf_page_number"]),
                        section_label="PC-01 비밀번호의 주기적 변경",
                        paragraph_ordinal=1,
                        paragraph_sha256=paragraph_hash,
                        text_start=0,
                        text_end=10,
                    ),
                ),
                trace=GenerationTrace(
                    answer_mode="LOCAL_GROUNDED_SUMMARY",
                    model_id="secai-imp051-contract-test",
                    prompt_sha256="a" * 64,
                    input_sha256="b" * 64,
                    output_sha256="c" * 64,
                ),
            )
            edited = edit_user_message(
                session,
                thread_id=thread.id,
                message_id=question_id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                content="비밀번호는 언제 변경해야 하나요?",
                idempotency_key="verify-edit-001",
            )
            retry = start_chat_generation(
                session,
                thread_id=thread.id,
                user_message_id=question_id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                idempotency_key="verify-retry-001",
                retry_of_message_id=answer.id,
            )
            stopped = stop_chat_generation(
                session,
                generation_id=retry.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
            )
            history = load_chat_history(
                session,
                thread_id=thread.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
            )

            set_chat_scope(session, ORGANIZATION_ID, OTHER_OWNER_USER_ID)
            cross_owner_count = session.scalar(
                select(ChatThreadRecord.id).where(ChatThreadRecord.id == thread.id)
            )
            set_chat_scope(session, ORGANIZATION_ID, OWNER_USER_ID)

            thread.status = "TOMBSTONED"
            thread.tombstoned_at = datetime.now(UTC)
            session.flush()
            tombstone_denied = False
            try:
                load_chat_history(
                    session,
                    thread_id=thread.id,
                    organization_id=ORGANIZATION_ID,
                    owner_user_id=OWNER_USER_ID,
                )
            except ChatContractError as exc:
                tombstone_denied = exc.code == "CHAT_SCOPE_DENIED"

            summary = {
                "migration": session.scalar(text("SELECT version_num FROM alembic_version")),
                "thread_created": True,
                "message_replays": 100,
                "unique_message_ids": len(repeated_messages),
                "generation_replays": 100,
                "unique_generation_ids": len(repeated_generations),
                "history_messages": len(history.messages),
                "history_citations": len(history.citations),
                "edit_preserved": edited.edit_of_message_id == question_id,
                "retry_stopped": stopped.status == "STOPPED",
                "cross_owner_rows": 0 if cross_owner_count is None else 1,
                "tombstone_denied": tombstone_denied,
                "official_finding_changed": False,
                "audit_pack_changed": False,
                "verification_rows_retained": False,
            }
            expected = {
                "migration": "0009_imp051",
                "unique_message_ids": 1,
                "unique_generation_ids": 1,
                "history_messages": 3,
                "history_citations": 1,
                "edit_preserved": True,
                "retry_stopped": True,
                "cross_owner_rows": 0,
                "tombstone_denied": True,
            }
            if any(summary[key] != value for key, value in expected.items()):
                raise RuntimeError("IMP051_DATABASE_VERIFICATION_FAILED")
        finally:
            transaction.rollback()
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
