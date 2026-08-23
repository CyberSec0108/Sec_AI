from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest
from apps.api.main import app as audit_api_app
from fastapi.testclient import TestClient

from security_audit.chat import (
    ChatCitation,
    ChatContractError,
    ChatConversation,
    ChatScope,
    GenerationStatus,
    MessageStatus,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
OWNER_ID = UUID("46000000-0000-4000-8000-000000000010")
OTHER_OWNER_ID = UUID("46000000-0000-4000-8000-000000000090")


def _conversation() -> ChatConversation:
    return ChatConversation.create(
        organization_id=ORGANIZATION_ID,
        owner_user_id=OWNER_ID,
        title="비밀번호 기준 확인",
        scope=ChatScope(
            guide_id="kisa-major-infrastructure-detailed-guide",
            guide_version="2026",
            scope_id="kisa-2026-pc",
            profile="FAST",
        ),
    )


def test_edit_retry_branch_and_stream_stop_are_append_only() -> None:
    conversation = _conversation()
    first = conversation.append_user_message("비밀번호 변경 주기를 알려줘")
    generation = conversation.start_generation(first.id, "request-001")
    conversation.append_stream_chunk(generation.id, 1, "KISA 기준은 ")
    conversation.append_stream_chunk(generation.id, 2, "90일 이내입니다.")
    answer = conversation.complete_generation(
        generation.id,
        citations=(
            ChatCitation(
                guide_id=conversation.scope.guide_id,
                guide_version=conversation.scope.guide_version,
                scope_id=conversation.scope.scope_id,
                chunk_id=UUID("48000000-0000-4000-8000-000000000001"),
                pdf_page_number=555,
                section_label="PC-01 비밀번호의 주기적 변경",
                paragraph_ordinal=1,
                paragraph_sha256="a" * 64,
                text_start=0,
                text_end=12,
            ),
        ),
    )

    edited = conversation.edit_user_message(first.id, "비밀번호는 언제 변경해야 하나요?")
    retried = conversation.retry_answer(answer.id, "request-002")
    stopped_generation = conversation.start_generation(edited.id, "request-003")
    conversation.append_stream_chunk(stopped_generation.id, 1, "작성 중")
    stopped = conversation.stop_generation(stopped_generation.id)

    assert first.status is MessageStatus.SUPERSEDED
    assert edited.edit_of_message_id == first.id
    assert edited.branch_id != first.branch_id
    assert retried.retry_of_message_id == answer.id
    assert retried.status is MessageStatus.PENDING
    assert stopped.status is GenerationStatus.STOPPED
    assert len(conversation.messages) == 4
    assert conversation.messages[1].content == "KISA 기준은 90일 이내입니다."
    assert conversation.messages[1].citations[0].pdf_page_number == 555
    assert conversation.stream_events(stopped_generation.id)[0].content == "작성 중"


def test_generation_idempotency_and_terminal_state_prevent_duplicates() -> None:
    conversation = _conversation()
    question = conversation.append_user_message("PC-02 기준은 무엇인가요?")
    generation = conversation.start_generation(question.id, "same-request")

    repeated = {
        conversation.start_generation(question.id, "same-request").id
        for _ in range(100)
    }
    assert repeated == {generation.id}
    conversation.stop_generation(generation.id)

    with pytest.raises(ChatContractError, match="GENERATION_ALREADY_TERMINAL"):
        conversation.complete_generation(generation.id)
    with pytest.raises(ChatContractError, match="GENERATION_ALREADY_TERMINAL"):
        conversation.append_stream_chunk(generation.id, 1, "늦게 도착한 응답")


def test_owner_and_scope_are_fail_closed() -> None:
    conversation = _conversation()
    conversation.require_access(ORGANIZATION_ID, OWNER_ID)

    with pytest.raises(ChatContractError, match="CHAT_SCOPE_DENIED"):
        conversation.require_access(ORGANIZATION_ID, OTHER_OWNER_ID)
    with pytest.raises(ChatContractError, match="CHAT_SCOPE_DENIED"):
        conversation.require_access(
            UUID("46000000-0000-4000-8000-000000000099"),
            OWNER_ID,
        )


def test_citation_scope_and_stream_sequence_are_fail_closed() -> None:
    conversation = _conversation()
    question = conversation.append_user_message("변경 주기는?")
    generation = conversation.start_generation(question.id, "request-004")

    with pytest.raises(ChatContractError, match="CHAT_STREAM_SEQUENCE_INVALID"):
        conversation.append_stream_chunk(generation.id, 2, "순서가 잘못된 조각")

    conversation.append_stream_chunk(generation.id, 1, "답변")
    with pytest.raises(ChatContractError, match="CITATION_SCOPE_MISMATCH"):
        conversation.complete_generation(
            generation.id,
            citations=(
                ChatCitation(
                    guide_id=conversation.scope.guide_id,
                    guide_version=conversation.scope.guide_version,
                    scope_id="other-guide-scope",
                    chunk_id=UUID("48000000-0000-4000-8000-000000000001"),
                    pdf_page_number=555,
                    section_label="PC-01",
                    paragraph_ordinal=1,
                    paragraph_sha256="a" * 64,
                    text_start=0,
                    text_end=2,
                ),
            ),
        )


def test_imp051_schemas_and_database_migration_are_registered() -> None:
    catalog = json.loads(
        (PROJECT_ROOT / "database" / "schemas" / "schema-catalog.json").read_text(
            encoding="utf-8"
        )
    )
    examples = json.loads(
        (PROJECT_ROOT / "database" / "schemas" / "examples" / "index.json").read_text(
            encoding="utf-8"
        )
    )
    schema_files = {
        "chat_thread.schema.json",
        "chat_message.schema.json",
        "chat_citation.schema.json",
    }

    assert schema_files.issubset({entry["file"] for entry in catalog["schemas"]})
    assert schema_files.issubset({entry["schema"] for entry in examples["examples"]})

    migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0009_imp051_chat_conversation.py"
    ).read_text(encoding="utf-8")
    for table in (
        "chat_threads",
        "chat_messages",
        "chat_citations",
        "chat_generation_runs",
    ):
        assert table in migration
    assert "ON DELETE RESTRICT" in migration
    assert "secai_runtime" in migration


def test_chat_api_contract_is_registered_and_imp053_activates_product() -> None:
    main_source = (PROJECT_ROOT / "apps" / "api" / "main.py").read_text(
        encoding="utf-8"
    )
    chat_source = (PROJECT_ROOT / "apps" / "api" / "chat_conversation.py").read_text(
        encoding="utf-8"
    )
    features = (
        PROJECT_ROOT / "src" / "security_audit" / "application" / "product_features.py"
    ).read_text(encoding="utf-8")

    assert "chat_conversation_router" in main_source
    for path in (
        "/api/v1/chat/threads",
        "/messages",
        "/edit",
        "/retry",
        "/stop",
        "/events",
    ):
        assert path in chat_source
    assert 'feature_id="guide_chat"' in features
    assert "state=FeatureState.LIVE" in features


def test_preview_direct_api_cannot_create_or_change_chat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECAI_CHAT_LIVE_ENABLED", "false")
    with TestClient(audit_api_app) as client:
        create = client.post(
            "/api/v1/chat/threads",
            json={
                "title": "저장되면 안 되는 미리 보기",
                "guide_id": "kisa-major-infrastructure-detailed-guide",
                "guide_version": "2026",
                "scope_id": "kisa-2026-pc",
                "profile": "FAST",
            },
        )
        stop = client.post(
            "/api/v1/chat/generations/51000000-0000-4000-8000-000000000001/stop"
        )

    assert create.status_code == 409
    assert create.json()["detail"]["code"] == "CHAT_PREVIEW_NOT_LIVE"
    assert stop.status_code == 409
