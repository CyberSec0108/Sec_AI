"""실제 PostgreSQL에서 PRODUCT-AI-07 대화 관리 계약을 검증한다."""

from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

from security_audit.chat import ChatContractError, ChatScope
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.chat_repository import (
    append_user_message,
    create_chat_thread,
    list_chat_threads,
    move_chat_thread,
    rename_chat_thread,
    set_chat_scope,
    set_chat_thread_archived,
    set_chat_thread_pinned,
    tombstone_chat_thread,
    undo_tombstone_chat_thread,
)
from security_audit.persistence.database.models import (
    ChatMessageRecord,
    ChatThreadManagementEventRecord,
)

ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
OWNER_USER_ID = UUID("46000000-0000-4000-8000-000000000003")
OTHER_OWNER_USER_ID = UUID("46000000-0000-4000-8000-000000000090")


def main() -> None:
    engine = create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )
    thread_id: UUID
    summary: dict[str, object]
    with Session(engine) as session:
        transaction = session.begin()
        try:
            thread = create_chat_thread(
                session,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                title="PRODUCT-AI-07 임시 검증",
                scope=ChatScope(
                    guide_id="kisa-major-infrastructure-detailed-guide",
                    guide_version="2026",
                    scope_id="kisa-2026-pc",
                    profile="FAST",
                ),
            )
            thread_id = thread.id
            message = append_user_message(
                session,
                thread_id=thread.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                content="비밀번호 기준을 알려주세요.",
                idempotency_key="product-ai-07-message",
            )
            original_message_hash = message.content_sha256

            renamed = rename_chat_thread(
                session,
                thread_id=thread.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                title="PRODUCT-AI-07 전용 검증",
            )
            set_chat_thread_pinned(
                session,
                thread_id=thread.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                is_pinned=True,
            )
            moved = move_chat_thread(
                session,
                thread_id=thread.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                folder_name="재점검 결과",
            )
            set_chat_thread_archived(
                session,
                thread_id=thread.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                archived=True,
            )
            set_chat_thread_archived(
                session,
                thread_id=thread.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                archived=False,
            )
            tombstone_chat_thread(
                session,
                thread_id=thread.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
            )
            hidden_while_deleted = not list_chat_threads(
                session,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                query="PRODUCT-AI-07 전용",
                view="ALL",
            )
            restored = undo_tombstone_chat_thread(
                session,
                thread_id=thread.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
            )
            found = list_chat_threads(
                session,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                query="PRODUCT-AI-07 전용",
                folder_name="재점검 결과",
                view="ACTIVE",
            )

            other_owner_blocked = False
            try:
                rename_chat_thread(
                    session,
                    thread_id=thread.id,
                    organization_id=ORGANIZATION_ID,
                    owner_user_id=OTHER_OWNER_USER_ID,
                    title="권한 우회",
                )
            except ChatContractError as exc:
                other_owner_blocked = exc.code == "CHAT_SCOPE_DENIED"

            set_chat_scope(session, ORGANIZATION_ID, OWNER_USER_ID)
            audit_count = session.scalar(
                select(func.count())
                .select_from(ChatThreadManagementEventRecord)
                .where(ChatThreadManagementEventRecord.thread_id == thread.id)
            )
            stored_message = session.scalar(
                select(ChatMessageRecord).where(ChatMessageRecord.id == message.id)
            )
            checks = {
                "rename": renamed.title == "PRODUCT-AI-07 전용 검증",
                "pin": restored.is_pinned is True,
                "move": moved.folder_name == "재점검 결과",
                "archive_restore": restored.status == "ACTIVE",
                "tombstone_hidden": hidden_while_deleted,
                "undo_delete": restored.tombstoned_at is None,
                "search": len(found) == 1 and found[0].id == thread.id,
                "other_owner_blocked": other_owner_blocked,
                "management_audit_events": int(audit_count or 0),
                "message_append_only": (
                    stored_message is not None
                    and stored_message.content_sha256 == original_message_hash
                ),
            }
            summary = {"stage": "PRODUCT-AI-07", **checks}
            if (
                not all(
                    checks[name]
                    for name in (
                        "rename",
                        "pin",
                        "move",
                        "archive_restore",
                        "tombstone_hidden",
                        "undo_delete",
                        "search",
                        "other_owner_blocked",
                        "message_append_only",
                    )
                )
                or checks["management_audit_events"] != 7
            ):
                raise RuntimeError("PRODUCT-AI-07 PostgreSQL gate failed.")
        finally:
            transaction.rollback()

    with Session(engine) as session, session.begin():
        set_chat_scope(session, ORGANIZATION_ID, OWNER_USER_ID)
        retained = session.scalar(
            text(
                """
                SELECT count(*)
                FROM chat_threads
                WHERE id = CAST(:thread_id AS uuid)
                """
            ),
            {"thread_id": str(thread_id)},
        )
    summary["verification_rows_retained"] = int(retained or 0)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    engine.dispose()
    if retained:
        raise RuntimeError("PRODUCT-AI-07 verification data must be rolled back.")


if __name__ == "__main__":
    main()
