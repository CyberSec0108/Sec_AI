"""실제 PostgreSQL에서 IMP-053 질문→근거→답변→이력 연결을 검증한다."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from security_audit.application.grounded_ai import (
    GroundedAIRequest,
    GroundedAIService,
    ModelExecutionPolicy,
)
from security_audit.application.local_grounded_summary import (
    LocalGroundedSummaryModel,
)
from security_audit.chat import ChatCitation, ChatScope
from security_audit.common.canonical_json import JsonValue, canonical_sha256
from security_audit.common.service_settings import ServiceSettings
from security_audit.guides.grounding import ControlCitationSource
from security_audit.guides.retrieval import GuideSearchScope
from security_audit.persistence.database.chat_repository import (
    GenerationTrace,
    append_user_message,
    complete_chat_generation,
    create_chat_thread,
    load_chat_history,
    mark_chat_generation_streaming,
    set_chat_scope,
    start_chat_generation,
    stop_chat_generation,
)
from security_audit.persistence.database.models import ChatGenerationRunRecord

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MAPPING_PATH = (
    PROJECT_ROOT
    / "guides"
    / "mappings"
    / "kisa_2026_pc_control_sources.json"
)
ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
OWNER_USER_ID = UUID("46000000-0000-4000-8000-000000000003")


def _sources() -> dict[str, ControlCitationSource]:
    value = cast(
        dict[str, Any],
        json.loads(MAPPING_PATH.read_text(encoding="utf-8")),
    )
    return {
        str(item["control_id"]): ControlCitationSource(
            control_id=str(item["control_id"]),
            document_code=str(item["source_document_code"]),
            page_start=int(item["page_start"]),
            page_end=int(item["page_end"]),
            section_label=str(item["section_label"]),
        )
        for item in cast(list[dict[str, Any]], value["mappings"])
    }


def _official_inventory(session: Session) -> str:
    session.execute(
        text("SELECT set_config('secai.organization_id', :value, true)"),
        {"value": str(ORGANIZATION_ID)},
    )
    rows = session.execute(
        text(
            """
            SELECT id, output_sha256, audit_pack_sha256
            FROM finding_versions
            WHERE organization_id = CAST(:organization_id AS uuid)
            ORDER BY id
            """
        ),
        {"organization_id": str(ORGANIZATION_ID)},
    ).mappings()
    return canonical_sha256(
        cast(
            JsonValue,
            [
                {
                    "id": str(row["id"]),
                    "output_sha256": str(row["output_sha256"]),
                    "audit_pack_sha256": str(row["audit_pack_sha256"]),
                }
                for row in rows
            ],
        )
    )


def main() -> None:
    engine = create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )
    question = "PC-07 저장 장치의 파일 시스템은 무엇을 확인하나요?"
    thread_id: UUID
    summary: dict[str, object]
    with Session(engine) as session:
        transaction = session.begin()
        try:
            inventory_before = _official_inventory(session)
            thread = create_chat_thread(
                session,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                title="IMP-053 실제 연결 검증",
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
                content=question,
                idempotency_key="imp053-message-001",
            )
            generation = start_chat_generation(
                session,
                thread_id=thread.id,
                user_message_id=message.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                idempotency_key="imp053-generation-001",
            )
            mark_chat_generation_streaming(
                session,
                generation_id=generation.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
            )
            result = GroundedAIService(
                LocalGroundedSummaryModel()
            ).generate_from_postgres(
                session,
                GroundedAIRequest(
                    mode="GUIDE_QA",
                    scope=GuideSearchScope(
                        organization_id=ORGANIZATION_ID,
                        guide_id=thread.guide_id,
                        guide_version=thread.guide_version,
                        scope_id=thread.scope_id,
                        query=question,
                        top_k=5,
                    ),
                ),
                citation_sources=_sources(),
                policy=ModelExecutionPolicy(
                    deployment_mode="LOCAL_EXTRACTIVE",
                    external_data_transfer=False,
                    approved_external_content_transfer=False,
                ),
            )
            if (
                result.status != "GENERATED"
                or result.answer is None
                or result.model_id is None
                or result.prompt_sha256 is None
                or result.input_sha256 is None
                or result.output_sha256 is None
                or not result.citations
                or "[1]" not in result.answer
                or any(
                    f"[{ordinal}]" in result.answer
                    for ordinal in range(2, len(result.citations) + 1)
                )
            ):
                raise RuntimeError("IMP-053 grounded response was not generated.")
            citation = result.citations[0]
            trace = GenerationTrace(
                answer_mode="LOCAL_GROUNDED_SUMMARY",
                model_id=result.model_id,
                prompt_sha256=result.prompt_sha256,
                input_sha256=result.input_sha256,
                output_sha256=result.output_sha256,
            )
            answer = complete_chat_generation(
                session,
                generation_id=generation.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                content=result.answer,
                citations=(
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
                    ),
                ),
                trace=trace,
            )
            history = load_chat_history(
                session,
                thread_id=thread.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
            )
            stored_generation = session.scalar(
                select(ChatGenerationRunRecord).where(
                    ChatGenerationRunRecord.id == generation.id
                )
            )
            if stored_generation is None:
                raise RuntimeError("IMP-053 generation trace is missing.")

            stop_question = append_user_message(
                session,
                thread_id=thread.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                content="중단 동작 검증 질문",
                idempotency_key="imp053-message-stop",
                parent_message_id=answer.id,
            )
            stop_generation = start_chat_generation(
                session,
                thread_id=thread.id,
                user_message_id=stop_question.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                idempotency_key="imp053-generation-stop",
            )
            stopped = stop_chat_generation(
                session,
                generation_id=stop_generation.id,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
            )
            inventory_after = _official_inventory(session)
            checks = {
                "answer_completed": stored_generation.status == "COMPLETED",
                "citation_saved": len(history.citations) == 1,
                "history_saved": len(history.messages) == 2,
                "local_mode_saved": (
                    stored_generation.answer_mode == "LOCAL_GROUNDED_SUMMARY"
                ),
                "external_data_transfer": stored_generation.external_data_transfer,
                "trace_hashes_saved": all(
                    value is not None
                    for value in (
                        stored_generation.prompt_sha256,
                        stored_generation.input_sha256,
                        stored_generation.output_sha256,
                    )
                ),
                "stop_completed": stopped.status == "STOPPED",
                "official_finding_unchanged": inventory_before == inventory_after,
                "citation_page": citation.pdf_page_number,
            }
            summary = {"imp": "IMP-053", **checks}
            if (
                not checks["answer_completed"]
                or not checks["citation_saved"]
                or not checks["history_saved"]
                or not checks["local_mode_saved"]
                or checks["external_data_transfer"] is not False
                or not checks["trace_hashes_saved"]
                or not checks["stop_completed"]
                or not checks["official_finding_unchanged"]
            ):
                raise RuntimeError("IMP-053 actual PostgreSQL gate failed.")
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
        raise RuntimeError("IMP-053 verification data must be rolled back.")


if __name__ == "__main__":
    main()
