from __future__ import annotations

from pathlib import Path

import pytest
from apps.api import product as product_api
from apps.api.chat_conversation import _referenced_citation_payloads
from apps.api.main import app
from fastapi.testclient import TestClient

from security_audit.application.local_grounded_summary import (
    LocalGroundedSummaryModel,
)
from security_audit.llm import ChatCompletionInput, ChatMessage
from security_audit.persistence.database.chat_repository import GenerationTrace

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_guide_chat_only_exposes_sources_referenced_by_the_answer() -> None:
    citations = [
        {"ordinal": ordinal, "section_label": f"검색 후보 {ordinal}"}
        for ordinal in range(1, 6)
    ]

    visible = _referenced_citation_payloads(
        "근거 문장입니다.[1] 같은 근거를 다시 설명합니다.[1]",
        citations,
    )

    assert [item["ordinal"] for item in visible] == [1]
    assert [
        item["ordinal"]
        for item in _referenced_citation_payloads(
            "렌더러가 정규화하는 괄호형 근거입니다.（3）",
            citations,
        )
    ] == [3]
    assert _referenced_citation_payloads("등록되지 않은 근거입니다.[9]", citations) == []


def _completion_input(
    *,
    mode: str = "GUIDE_QA",
    question: str = "저장 장치 형식은 무엇을 확인하나요?",
) -> ChatCompletionInput:
    payload = (
        '{"citation":{"control_id":"PC-07","guide_version":"2026",'
        '"pdf_page_number":571,"section_label":'
        '"PC-07 파일 시스템이 NTFS 포맷으로 설정"},'
        '"finding":null,"guide_excerpt":'
        '"PC-07 파일 시스템이 NTFS 포맷으로 설정. '
        '점검 대상 저장 장치의 파일 시스템이 모두 NTFS인지 확인합니다.",'
        f'"mode":"{mode}","question":"{question}"'
        "}"
    )
    return ChatCompletionInput(
        messages=(
            ChatMessage(role="system", content="읽기 전용 근거 요약"),
            ChatMessage(
                role="user",
                content=f"<untrusted_payload>{payload}</untrusted_payload>",
            ),
        ),
    )


def test_local_grounded_summary_answers_without_network_or_commands() -> None:
    model = LocalGroundedSummaryModel()

    result = model.complete(_completion_input())

    assert result.model_id == "secai-local-grounded-summary-v1"
    assert "PC-07" in result.content
    assert "NTFS" in result.content
    assert "571쪽" in result.content
    assert "[1]" in result.content
    assert [
        item["ordinal"]
        for item in _referenced_citation_payloads(
            result.content,
            [
                {"ordinal": 1, "section_label": "실제 사용 근거"},
                {"ordinal": 2, "section_label": "검색 후보만 된 근거"},
            ],
        )
    ] == [1]
    assert "PowerShell" not in result.content
    assert result.prompt_tokens is None
    assert result.completion_tokens is None


def test_local_grounded_summary_rejects_invalid_untrusted_envelope() -> None:
    model = LocalGroundedSummaryModel()
    request = ChatCompletionInput(
        messages=(
            ChatMessage(role="system", content="읽기 전용 근거 요약"),
            ChatMessage(role="user", content="경계 없는 입력"),
        )
    )

    with pytest.raises(ValueError, match="LOCAL_GROUNDED_PAYLOAD_INVALID"):
        model.complete(request)


def test_generation_trace_requires_exact_hashes_and_read_only_mode() -> None:
    trace = GenerationTrace(
        answer_mode="LOCAL_GROUNDED_SUMMARY",
        model_id="secai-local-grounded-summary-v1",
        prompt_sha256="a" * 64,
        input_sha256="b" * 64,
        output_sha256="c" * 64,
    )

    assert trace.external_data_transfer is False
    with pytest.raises(ValueError, match="CHAT_GENERATION_TRACE_INVALID"):
        GenerationTrace(
            answer_mode="REMOTE_OPENROUTER",
            model_id="unsafe",
            prompt_sha256="a" * 64,
            input_sha256="b" * 64,
            output_sha256="not-a-hash",
        )


def test_live_guide_chat_page_has_real_controls_and_no_preview_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_CHAT_LIVE_ENABLED", "true")
    monkeypatch.setattr(
        product_api,
        "browser_csrf_token",
        lambda _request: "csrf-test-token",
    )

    with TestClient(app) as client:
        response = client.get("/ui/guide-chat")

    assert response.status_code == 200
    for phrase in (
        "가이드 질의",
        "새 대화",
        "내 대화",
        "무엇이든 물어보세요",
        "질문 보내기",
        "중단",
        "출처",
        "빠른 답변",
    ):
        assert phrase in response.text
    assert 'class="container product-shell chat-page"' in response.text
    assert "chat-safety-notice" not in response.text
    assert "질문과 KISA 원문은 외부 AI 서비스로 보내지 않습니다" not in response.text
    assert "기술 정보 보기" not in response.text
    assert "예시 화면이며 실제 PC 자료를 사용하지 않음" not in response.text
    assert 'data-ui-standard="guide-chat-live-v1"' in response.text
    assert 'src="/static/app/restricted-markdown.js"' in response.text
    assert 'src="/static/app/guide-chat.js"' in response.text
    assert response.text.index("restricted-markdown.js") < response.text.index(
        "guide-chat.js"
    )
    assert 'id="history-panel-resizer"' in response.text
    assert 'name="csrf-token"' in response.text


def test_product_registry_and_header_integrate_history_in_live_chat() -> None:
    features = (
        PROJECT_ROOT
        / "src"
        / "security_audit"
        / "application"
        / "product_features.py"
    ).read_text(encoding="utf-8")
    header = (
        PROJECT_ROOT
        / "apps"
        / "web"
        / "templates"
        / "components"
        / "audit_ui.html"
    ).read_text(encoding="utf-8")

    guide_section = features.split('feature_id="guide_chat"', maxsplit=1)[1].split(
        "),", maxsplit=1
    )[0]
    assert "state=FeatureState.LIVE" in guide_section
    assert 'href="/ui/guide-chat"' in guide_section
    assert 'feature_id="history"' not in features
    assert 'href="/ui/guide-chat"' in header
    assert 'href="/ui/guide-chat#history"' not in header


def test_chat_run_api_and_generation_trace_migration_are_registered() -> None:
    api = (
        PROJECT_ROOT / "apps" / "api" / "chat_conversation.py"
    ).read_text(encoding="utf-8")
    migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0010_imp053_live_guide_chat.py"
    ).read_text(encoding="utf-8")

    assert "/api/v1/chat/generations/{generation_id}/run" in api
    assert "GroundedAIService" in api
    assert "InternalModelGatewayClient.from_environment()" in api
    assert "REMOTE_OPENROUTER" in api
    assert "SECAI_GUIDE_AI_REMOTE_TEST_APPROVED" in api
    for field in (
        "answer_mode",
        "model_id",
        "prompt_sha256",
        "input_sha256",
        "output_sha256",
    ):
        assert field in migration
    assert "secai_runtime" in migration
    assert "external_data_transfer" in migration


def test_guide_chat_javascript_uses_safe_dom_and_every_button_has_action() -> None:
    script = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "guide-chat.js"
    ).read_text(encoding="utf-8")

    assert "innerHTML" not in script
    assert "textContent" in script
    assert "SecAIRestrictedMarkdown.createStreamingRenderer" in script
    assert "normalizeInlineCitationPlacement" in script
    assert (
        "/source.pdf?requested_page=${pageNumber}"
        "#page=${pageNumber}&zoom=page-width"
    ) in script
    assert 'events.addEventListener("answer-token"' in script
    assert "messageListNearBottom" in script
    assert "followStreamingAnswer" in script
    assert 'messageList.addEventListener("scroll"' in script
    for path in (
        "/api/v1/chat/threads",
        "/messages",
        "/edit",
        "/retry",
        "/run",
        "/stop",
        "/events",
    ):
        assert path in script
    for button_id in (
        "new-chat",
        "send-question",
        "stop-answer",
        "cancel-edit",
    ):
        assert f'getElementById("{button_id}")' in script


def test_guide_chat_scroll_and_citation_rendering_are_resilient() -> None:
    script = (
        PROJECT_ROOT / "apps/web/static/app/guide-chat.js"
    ).read_text(encoding="utf-8")
    renderer = (
        PROJECT_ROOT / "apps/web/static/app/restricted-markdown.js"
    ).read_text(encoding="utf-8")
    styles = (
        PROJECT_ROOT / "apps/web/static/app/app.css"
    ).read_text(encoding="utf-8")

    assert "normalizeCitationSyntax" in renderer
    assert "asciiNumber || fullWidthNumber || bracketNumber" in renderer
    assert 'number.textContent = `[${citation.ordinal}]`' in script
    assert 'overflow-y: scroll' in styles
    assert 'overscroll-behavior-y: contain' in styles
    assert '.chat-source-card-heading' in styles


def test_live_generation_returns_before_slow_model_and_keeps_sse_alive() -> None:
    api = (
        PROJECT_ROOT / "apps" / "api" / "chat_conversation.py"
    ).read_text(encoding="utf-8")
    script = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "guide-chat.js"
    ).read_text(encoding="utf-8")

    assert "background_tasks.add_task(" in api
    assert '"generation_id": str(generation.id)' in api
    assert '"status": generation.status' in api
    assert 'yield ": keep-alive\\n\\n"' in api
    assert "event: answer-token" in api
    assert "_append_stream_token" in api
    assert "generationInProgress = true" in script
    assert 'result.status !== "STREAMING"' in script


def test_guide_chat_uses_accessible_icon_actions_and_feedback() -> None:
    template = (
        PROJECT_ROOT / "apps" / "web" / "templates" / "pages" / "guide_chat.html"
    ).read_text(encoding="utf-8")
    script = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "guide-chat.js"
    ).read_text(encoding="utf-8")

    assert 'class="panel-toggle-icon panel-toggle-icon-history"' in template
    assert 'class="panel-toggle-icon panel-toggle-icon-source"' in template
    assert "createIconButton" in script
    for icon_name in (
        '"pin"',
        '"edit"',
        '"archive"',
        '"trash"',
        '"copy"',
        '"thumb-up"',
        '"thumb-down"',
        '"retry"',
        '"branch"',
    ):
        assert icon_name in script
    assert '"folder"' not in script
    assert "폴더로 이동" not in script
    assert 'setAttribute("aria-pressed"' in script
    assert "manageButton.textContent = \"관리\"" not in script


def test_guide_chat_uses_compact_sidebar_drawer_and_composer() -> None:
    template = (
        PROJECT_ROOT / "apps/web/templates/pages/guide_chat.html"
    ).read_text(encoding="utf-8")
    script = (
        PROJECT_ROOT / "apps/web/static/app/guide-chat.js"
    ).read_text(encoding="utf-8")

    assert 'class="chat-sidebar-actions"' in template
    assert template.index('id="history-title"') < template.index('id="new-chat"')
    assert 'class="chat-composer-shell"' in template
    assert 'id="source-panel-close"' in template
    assert 'id="generation-trace"' not in template
    assert "기술 정보 보기" not in template
    assert 'restorePanelState("source", true)' in script
    assert "initializeHistoryPanelResizer" in script
