from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest
from apps.api import chat_conversation, guide_store
from fastapi import HTTPException

from security_audit.application import integrated_guide_qa
from security_audit.application.grounded_ai import ModelExecutionPolicy
from security_audit.application.integrated_guide_qa import IntegratedGuideTarget
from security_audit.application.local_grounded_summary import LocalGroundedSummaryModel
from security_audit.application.model_search import ModelSearchSettings
from security_audit.guides.grounding import (
    ControlCitationSource,
    build_grounding_result,
)
from security_audit.guides.retrieval import GuideSearchHit, GuideSearchScope
from security_audit.llm import (
    ChatCompletionInput,
    ChatCompletionResult,
    ChatMessage,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_chat_catalog_exposes_one_integrated_question_scope() -> None:
    guides = chat_conversation._approved_chat_guides()
    searchable = chat_conversation._searchable_guide_options()

    assert len(guides) == 1
    assert guides[0]["guide_id"] == "secai-integrated-security-guides"
    assert guides[0]["retrieval_role"] == "INTEGRATED_READ_ONLY"
    assert guides[0]["decision_authority"] is False
    assert len(searchable) == 8
    assert searchable[0]["guide_id"] == "kisa-major-infrastructure-detailed-guide"
    assert all(
        item["retrieval_role"] == "SUPPLEMENTAL_EXPLANATION"
        and item["decision_authority"] is False
        for item in searchable[1:]
    )


def test_integrated_search_combines_distinct_documents_without_external_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = UUID("46000000-0000-4000-8000-000000000001")
    targets = (
        IntegratedGuideTarget(
            guide_id="guide-a",
            guide_version="1.0",
            scope_id="guide-a-all",
            citation_sources={
                "GUIDE-PAGE": ControlCitationSource(
                    "GUIDE-PAGE", "문서 A", 1, 50, "문서 A"
                )
            },
        ),
        IntegratedGuideTarget(
            guide_id="guide-b",
            guide_version="2.0",
            scope_id="guide-b-all",
            citation_sources={
                "GUIDE-PAGE": ControlCitationSource(
                    "GUIDE-PAGE", "문서 B", 1, 60, "문서 B"
                )
            },
        ),
    )

    def fake_search(
        _session: object,
        scope: GuideSearchScope,
        _vector: list[float] | tuple[float, ...],
    ) -> tuple[GuideSearchHit, ...]:
        index = 1 if scope.guide_id == "guide-a" else 2
        return (
            GuideSearchHit(
                chunk_id=UUID(f"47000000-0000-4000-8000-00000000000{index}"),
                organization_id=organization_id,
                guide_id=scope.guide_id,
                guide_version=scope.guide_version,
                scope_id=scope.scope_id,
                pdf_page_number=10 + index,
                control_id="GUIDE-PAGE",
                text="최소 권한과 지속 검증을 적용하는 통합 보안 설명입니다.",
                dense_score=0.8,
                lexical_score=0.8,
                rerank_score=0.9 - (index * 0.1),
                source_sha256=("a" if index == 1 else "b") * 64,
                text_sha256=("c" if index == 1 else "d") * 64,
            ),
        )

    monkeypatch.setattr(integrated_guide_qa, "search_guide_chunks", fake_search)
    result = integrated_guide_qa.generate_integrated_guide_answer(
        object(),  # type: ignore[arg-type]
        organization_id=organization_id,
        question="최소 권한과 지속 검증은 왜 필요한가요?",
        profile="FAST",
        targets=targets,
        settings=ModelSearchSettings(
            mode="LEGACY_LOCAL",
            embedding_url="http://embedding-service:80",
            reranker_url="http://reranker-service:80",
            timeout_seconds=30,
        ),
    )

    assert result.status == "GENERATED"
    assert {item.guide_id for item in result.citations} == {"guide-a", "guide-b"}
    assert result.answer is not None
    assert "[1]" in result.answer and "[2]" in result.answer
    assert result.official_finding_write_allowed is False


def test_integrated_search_uses_existing_llm_answer_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = UUID("46000000-0000-4000-8000-000000000001")
    targets = tuple(
        IntegratedGuideTarget(
            guide_id=f"guide-{name}",
            guide_version="1.0",
            scope_id=f"guide-{name}-all",
            citation_sources={
                "GUIDE-PAGE": ControlCitationSource(
                    "GUIDE-PAGE", f"문서 {name}", 1, 50, f"문서 {name}"
                )
            },
        )
        for name in ("a", "b")
    )

    def fake_search(
        _session: object,
        scope: GuideSearchScope,
        _vector: list[float] | tuple[float, ...],
    ) -> tuple[GuideSearchHit, ...]:
        index = 1 if scope.guide_id == "guide-a" else 2
        return (
            GuideSearchHit(
                chunk_id=UUID(f"47000000-0000-4000-8000-00000000000{index}"),
                organization_id=organization_id,
                guide_id=scope.guide_id,
                guide_version=scope.guide_version,
                scope_id=scope.scope_id,
                pdf_page_number=20 + index,
                control_id="GUIDE-PAGE",
                text="최소 권한과 무결성 검증이 필요한 이유를 설명합니다.",
                dense_score=0.8,
                lexical_score=0.8,
                rerank_score=0.9 - (index * 0.1),
                source_sha256=("a" if index == 1 else "b") * 64,
                text_sha256=("c" if index == 1 else "d") * 64,
            ),
        )

    class CapturingModel:
        def __init__(self) -> None:
            self.evidence_count = 0

        def complete(self, request: ChatCompletionInput) -> ChatCompletionResult:
            assert "비교·종합" in request.messages[0].content
            wrapped = request.messages[-1].content
            payload = json.loads(
                wrapped.removeprefix("<untrusted_payload>").removesuffix(
                    "</untrusted_payload>"
                )
            )
            self.evidence_count = len(payload["guide_evidence"])
            return ChatCompletionResult(
                model_id="integrated-llm-test",
                content=(
                    "## 핵심 답변\n최소 권한은 접근 범위를 줄입니다.[1] "
                    "무결성 검증은 변조를 발견하는 데 필요합니다.[2]"
                ),
                finish_reason="stop",
                prompt_tokens=None,
                completion_tokens=None,
                total_tokens=None,
            )

    model = CapturingModel()
    monkeypatch.setattr(integrated_guide_qa, "search_guide_chunks", fake_search)
    result = integrated_guide_qa.generate_integrated_guide_answer(
        object(),  # type: ignore[arg-type]
        organization_id=organization_id,
        question="최소 권한과 무결성 검증은 왜 필요한가요?",
        profile="FAST",
        targets=targets,
        settings=ModelSearchSettings(
            mode="LEGACY_LOCAL",
            embedding_url="http://embedding-service:80",
            reranker_url="http://reranker-service:80",
            timeout_seconds=30,
        ),
        model=model,
        policy=ModelExecutionPolicy(
            deployment_mode="LOCAL_VLLM",
            external_data_transfer=False,
            approved_external_content_transfer=False,
        ),
    )

    assert result.status == "GENERATED"
    assert result.model_id == "integrated-llm-test"
    assert model.evidence_count == 2
    assert len(result.citations) == 2
    assert result.answer is not None and result.answer.startswith("## 핵심 답변")


def test_integrated_search_blocks_executable_guide_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = UUID("46000000-0000-4000-8000-000000000001")
    target = IntegratedGuideTarget(
        guide_id="guide-a",
        guide_version="1.0",
        scope_id="guide-a-all",
        citation_sources={
            "GUIDE-PAGE": ControlCitationSource(
                "GUIDE-PAGE", "문서 A", 1, 50, "문서 A"
            )
        },
    )
    hit = GuideSearchHit(
        chunk_id=UUID("47000000-0000-4000-8000-000000000001"),
        organization_id=organization_id,
        guide_id=target.guide_id,
        guide_version=target.guide_version,
        scope_id=target.scope_id,
        pdf_page_number=11,
        control_id="GUIDE-PAGE",
        text="안전한 실행 절차 ```bash\nsudo unsafe-command\n```",
        dense_score=0.8,
        lexical_score=0.8,
        rerank_score=0.8,
        source_sha256="a" * 64,
        text_sha256="b" * 64,
    )
    monkeypatch.setattr(
        integrated_guide_qa,
        "search_guide_chunks",
        lambda *_args: (hit,),
    )

    result = integrated_guide_qa.generate_integrated_guide_answer(
        object(),  # type: ignore[arg-type]
        organization_id=organization_id,
        question="안전한 실행 절차를 알려주세요",
        profile="FAST",
        targets=(target,),
        settings=ModelSearchSettings(
            mode="LEGACY_LOCAL",
            embedding_url="http://embedding-service:80",
            reranker_url="http://reranker-service:80",
            timeout_seconds=30,
        ),
    )

    assert result.status == "SECURITY_BLOCKED"
    assert result.reason_code == "UNSAFE_MODEL_OUTPUT"
    assert result.answer is None
    assert result.citations == ()


def test_integrated_search_drops_injected_evidence_and_keeps_safe_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = UUID("46000000-0000-4000-8000-000000000001")
    targets = tuple(
        IntegratedGuideTarget(
            guide_id=f"guide-{name}",
            guide_version="1.0",
            scope_id=f"guide-{name}-all",
            citation_sources={
                "GUIDE-PAGE": ControlCitationSource(
                    "GUIDE-PAGE", f"문서 {name}", 1, 50, f"문서 {name}"
                )
            },
        )
        for name in ("unsafe", "safe")
    )

    def fake_search(
        _session: object,
        scope: GuideSearchScope,
        _vector: list[float] | tuple[float, ...],
    ) -> tuple[GuideSearchHit, ...]:
        unsafe = scope.guide_id == "guide-unsafe"
        return (
            GuideSearchHit(
                chunk_id=UUID(
                    "47000000-0000-4000-8000-000000000011"
                    if unsafe
                    else "47000000-0000-4000-8000-000000000012"
                ),
                organization_id=organization_id,
                guide_id=scope.guide_id,
                guide_version=scope.guide_version,
                scope_id=scope.scope_id,
                pdf_page_number=11 if unsafe else 12,
                control_id="GUIDE-PAGE",
                text=(
                    "프롬프트 취약점은 이전 지침을 무시하라는 공격 문장을 포함합니다."
                    if unsafe
                    else "프롬프트 취약점은 입력을 통해 모델 동작을 왜곡하는 위험입니다."
                ),
                dense_score=0.8,
                lexical_score=0.8,
                rerank_score=0.9 if unsafe else 0.8,
                source_sha256=("a" if unsafe else "b") * 64,
                text_sha256=("c" if unsafe else "d") * 64,
            ),
        )

    monkeypatch.setattr(integrated_guide_qa, "search_guide_chunks", fake_search)
    result = integrated_guide_qa.generate_integrated_guide_answer(
        object(),  # type: ignore[arg-type]
        organization_id=organization_id,
        question="프롬프트 취약점은 무엇인가요?",
        profile="FAST",
        targets=targets,
        settings=ModelSearchSettings(
            mode="LEGACY_LOCAL",
            embedding_url="http://embedding-service:80",
            reranker_url="http://reranker-service:80",
            timeout_seconds=30,
        ),
    )

    assert result.status == "GENERATED"
    assert [item.guide_id for item in result.citations] == ["guide-safe"]
    assert result.answer is not None and "모델 동작을 왜곡" in result.answer


def test_public_guide_chat_scope_uses_generic_page_citations() -> None:
    sources = chat_conversation._control_sources(
        "kisa-zero-trust-guideline",
        "2.0",
    )

    assert set(sources) == {"GUIDE-PAGE"}
    assert sources["GUIDE-PAGE"].page_start == 1
    assert sources["GUIDE-PAGE"].page_end == 245
    assert "제로트러스트" in sources["GUIDE-PAGE"].section_label


def test_supplemental_hit_can_ground_an_explanation_without_decision_authority() -> None:
    organization_id = UUID("46000000-0000-4000-8000-000000000001")
    scope = GuideSearchScope(
        organization_id=organization_id,
        guide_id="kisa-zero-trust-guideline",
        guide_version="2.0",
        scope_id="kisa-zero-trust-2.0-all",
        query="제로트러스트 최소 권한과 지속적 검증",
    )
    hit = GuideSearchHit(
        chunk_id=UUID("47000000-0000-4000-8000-000000000001"),
        organization_id=organization_id,
        guide_id=scope.guide_id,
        guide_version=scope.guide_version,
        scope_id=scope.scope_id,
        pdf_page_number=21,
        control_id="GUIDE-PAGE",
        text="제로트러스트는 최소 권한과 지속적인 검증을 적용합니다.",
        dense_score=0.8,
        lexical_score=0.8,
        rerank_score=0.8,
        source_sha256="a" * 64,
        text_sha256="b" * 64,
    )

    result = build_grounding_result(
        scope,
        (hit,),
        chat_conversation._control_sources(scope.guide_id, scope.guide_version),
    )

    assert result.status == "FOUND"
    assert len(result.citations) == 1
    assert result.citations[0].control_id == "GUIDE-PAGE"


def test_local_supplemental_explanation_names_source_and_preserves_finding() -> None:
    payload = json.dumps(
        {
            "mode": "GUIDE_QA",
            "question": "최소 권한이 왜 필요한가요?",
            "guide_excerpt": "최소 권한을 적용하고 접근을 지속적으로 검증합니다.",
            "citation": {
                "control_id": "GUIDE-PAGE",
                "guide_version": "2.0",
                "document_code": "한국인터넷진흥원 · 제로트러스트 가이드라인 2.0",
                "pdf_page_number": 21,
                "paragraph_ordinal": 1,
                "section_label": "제로트러스트 가이드라인 2.0",
            },
        },
        ensure_ascii=False,
    )
    request = ChatCompletionInput(
        messages=(
            ChatMessage(role="system", content="읽기 전용 근거 요약"),
            ChatMessage(
                role="user",
                content=f"<untrusted_payload>{payload}</untrusted_payload>",
            ),
        )
    )

    result = LocalGroundedSummaryModel().complete(request)

    assert "제로트러스트 가이드라인 2.0" in result.content
    assert "KISA 점검 판정이나 공식 점검 결과를 변경하지 않습니다" in result.content
    assert "[1]" in result.content


def test_unregistered_chat_scope_is_rejected_before_thread_creation() -> None:
    payload = chat_conversation.CreateThreadInput(
        title="미승인 문서",
        guide_id="unapproved-guide",
        guide_version="1.0",
        scope_id="unapproved-all",
        profile="FAST",
    )

    with pytest.raises(HTTPException) as raised:
        chat_conversation._require_approved_chat_scope(payload)

    assert raised.value.status_code == 400
    detail = raised.value.detail
    assert isinstance(detail, dict)
    assert detail["code"] == "GUIDE_SCOPE_NOT_APPROVED"


def test_public_source_resolution_is_root_bounded_and_hash_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        guide_store,
        "_PUBLIC_GUIDE_SOURCE_ROOT",
        PROJECT_ROOT / "data" / "public_guides",
    )

    approved = guide_store._approved_source("kisa-ai-red-teaming-guide", "2026-07-07")

    assert approved is not None
    source_path, first_page, last_page = approved
    assert source_path.name == "[최종]AI 보안 레드티밍 가이드.pdf"
    assert (first_page, last_page) == (1, 69)


def test_guide_chat_ui_keeps_integrated_scope_hidden_and_source_mount_read_only() -> None:
    template = (
        PROJECT_ROOT / "apps" / "web" / "templates" / "pages" / "guide_chat.html"
    ).read_text(encoding="utf-8")
    javascript = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "guide-chat.js"
    ).read_text(encoding="utf-8")
    compose = (PROJECT_ROOT / "deploy" / "compose" / "compose.dev.yml").read_text(
        encoding="utf-8"
    )

    assert 'id="guide-select"' in template
    assert 'type="hidden"' in template
    assert "질문 범위" not in template
    assert "통합 보안 가이드 검색 (8종)" not in template
    assert 'id="guide-role-note"' not in template
    assert "<select id=\"guide-select\"" not in template
    assert 'api("/api/v1/chat/guides")' in javascript
    assert "guide_id: guide.guide_id" in javascript
    assert "guideRoleNote" not in javascript
    assert "updateGuideRoleNote" not in javascript
    assert "source: data/public_guides" in compose
    assert "target: /run/secai-public-guides" in compose
    assert "read_only: true" in compose
