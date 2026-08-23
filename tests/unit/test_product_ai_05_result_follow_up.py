from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import pytest
from apps.api import result_ai_explanation as result_ai_api
from apps.api.main import app
from fastapi.testclient import TestClient

from security_audit.application.result_ai_explanation import (
    ResultAIExecutionPolicy,
)
from security_audit.application.result_follow_up import (
    ResultFollowUpError,
    ResultFollowUpService,
    build_result_follow_up_context,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)
from security_audit.llm import (
    ChatCompletionInput,
    ChatCompletionResult,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _explanation_input(control_id: str = "PC-01") -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "control_id": control_id,
        "title": "비밀번호의 주기적 변경",
        "rule_status": "FAIL",
        "status_authority": "RULE_ENGINE",
        "observed_summary": "비밀번호 최대 사용 기간이 120일입니다",
        "expected_summary": "비밀번호 최대 사용 기간은 90일 이내",
        "judgement_explanation": "현재 확인값이 적용 기준을 초과했습니다.",
        "result_code": "PASSWORD_MAXIMUM_AGE_EXCEEDED",
        "result_code_visibility": "TECHNICAL_ONLY",
        "kisa_citations": [
            {
                "guide_id": "kisa-major-infrastructure-detailed-guide",
                "guide_version": "2026",
                "source_sha256": "a" * 64,
                "document_code": "KISA-2026-07-PC",
                "page_start": 555,
                "page_end": 556,
                "section_label": "PC-01 비밀번호의 주기적 변경",
                "mapping_status": "APPROVED",
            }
        ],
        "official_finding_write_allowed": False,
        "safety": {
            "raw_evidence_included": False,
            "sensitive_identifiers_included": False,
            "rule_status_unchanged": True,
            "internal_reason_code_user_visible": False,
        },
    }
    value["explanation_input_sha256"] = canonical_sha256_without_fields(
        value,
        {"explanation_input_sha256"},
    )
    return value


def _guide_evidence(
    explanation: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    paragraph = "PC-01은 비밀번호 최대 사용 기간을 90일 이내로 설정했는지 확인합니다."
    paragraph_sha256 = hashlib.sha256(paragraph.encode("utf-8")).hexdigest()
    chunk_id = str(uuid5(NAMESPACE_URL, "product-ai-05:PC-01"))
    citation: dict[str, JsonValue] = {
        "chunk_id": chunk_id,
        "guide_id": "kisa-major-infrastructure-detailed-guide",
        "guide_version": "2026",
        "document_code": "KISA-2026-07-PC",
        "source_sha256": "a" * 64,
        "scope_id": "kisa-2026-pc",
        "pdf_page_number": 555,
        "control_id": "PC-01",
        "section_label": "PC-01 비밀번호의 주기적 변경",
        "paragraph_ordinal": 1,
        "paragraph_sha256": paragraph_sha256,
        "text_sha256": paragraph_sha256,
    }
    value: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "status": "FOUND",
        "reason_code": None,
        "control_id": "PC-01",
        "rule_status": "FAIL",
        "status_authority": "RULE_ENGINE",
        "explanation_input_sha256": explanation["explanation_input_sha256"],
        "search_query_sha256": "b" * 64,
        "citations": [citation],
        "evidence_segments": [
            {
                "chunk_id": chunk_id,
                "paragraph_ordinal": 1,
                "paragraph_text": paragraph,
                "paragraph_sha256": paragraph_sha256,
            }
        ],
        "official_finding_write_allowed": False,
    }
    value["output_sha256"] = canonical_sha256_without_fields(
        value,
        {"output_sha256"},
    )
    return value


class StubFollowUpModel:
    def __init__(self) -> None:
        self.calls: list[ChatCompletionInput] = []

    def complete(self, request: ChatCompletionInput) -> ChatCompletionResult:
        self.calls.append(request)
        return ChatCompletionResult(
            model_id="openai/gpt-oss-120b",
            content=json.dumps(
                {
                    "answer": "비밀번호를 오래 사용하면 노출된 값이 악용될 수 있습니다.",
                    "risk_scenarios": ["유출된 비밀번호의 재사용 기간이 길어질 수 있습니다."],
                    "action_cautions": ["조직 정책을 확인한 뒤 변경하세요."],
                    "priority_reason": "계정 보호와 직접 관련된 항목입니다.",
                    "limitations": "현재 선택한 PC-01 결과만 사용했습니다.",
                    "suggested_questions": ["변경 전에 무엇을 확인해야 하나요?"],
                },
                ensure_ascii=False,
            ),
            finish_reason="stop",
            prompt_tokens=200,
            completion_tokens=100,
            total_tokens=300,
        )


def test_product_ai_05_binds_question_to_one_result_version_and_control() -> None:
    context = build_result_follow_up_context(
        result_id="a1b2c3d4e5f60718",
        result_version=2,
        selected_control_id="PC-01",
        question="이 상태가 실제로 어떤 위험을 만들 수 있나요?",
        explanation_input=_explanation_input(),
    )

    assert context.result_id == "a1b2c3d4e5f60718"
    assert context.result_version == 2
    assert context.control_id == "PC-01"
    assert context.rule_status == "FAIL"
    assert context.observed_summary == "비밀번호 최대 사용 기간이 120일입니다"
    assert context.explanation_input_sha256
    assert context.context_sha256
    assert context.test_data_only is True


def test_product_ai_05_rejects_cross_control_context() -> None:
    with pytest.raises(ResultFollowUpError) as raised:
        build_result_follow_up_context(
            result_id="a1b2c3d4e5f60718",
            result_version=2,
            selected_control_id="PC-02",
            question="왜 우선 확인해야 하나요?",
            explanation_input=_explanation_input("PC-01"),
        )

    assert raised.value.code == "RESULT_FOLLOW_UP_CONTROL_MISMATCH"


def test_product_ai_05_model_uses_only_selected_safe_context() -> None:
    explanation = _explanation_input()
    context = build_result_follow_up_context(
        result_id="a1b2c3d4e5f60718",
        result_version=2,
        selected_control_id="PC-01",
        question="왜 우선 확인해야 하나요?",
        explanation_input=explanation,
    )
    model = StubFollowUpModel()

    result = ResultFollowUpService(model).generate(
        context,
        explanation,
        _guide_evidence(explanation),
        policy=ResultAIExecutionPolicy(
            runtime_profile="VLLM_COMPATIBILITY_TEST_DOUBLE",
            external_data_transfer=True,
            approved_deidentified_test_transfer=True,
            test_data_only=True,
        ),
    )

    serialized_request = model.calls[0].messages[1].content
    assert result.status == "GENERATED"
    assert result.official_rule_status == "FAIL"
    assert result.result_id == "a1b2c3d4e5f60718"
    assert result.result_version == 2
    assert result.answer
    assert result.citations[0]["control_id"] == "PC-01"
    assert result.output_sha256 == canonical_sha256_without_fields(
        result.to_json(),
        {"output_sha256"},
    )
    assert "PASSWORD_MAXIMUM_AGE_EXCEEDED" not in serialized_request
    assert "a1b2c3d4e5f60718" not in serialized_request
    assert "비밀번호 최대 사용 기간이 120일입니다" in serialized_request


def test_product_ai_05_stream_uses_selected_context_and_kisa_evidence(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_DEMO_CSRF_TOKEN", "product-ai-05-test-csrf")
    captured: dict[str, object] = {}

    def retrieve(
        explanation_inputs: list[dict[str, Any]],
        *,
        organization_id: object,
    ) -> list[dict[str, object]]:
        captured["control_id"] = explanation_inputs[0]["control_id"]
        captured["organization_id"] = organization_id
        return [{"status": "FOUND", "control_id": "PC-01"}]

    def generate(
        body: Any,
        guide_evidence: dict[str, object],
    ) -> dict[str, object]:
        captured["result_id"] = body.result_id
        captured["result_version"] = body.result_version
        captured["question"] = body.question
        captured["guide_status"] = guide_evidence["status"]
        return {
            "status": "GENERATED",
            "answer": "현재 상태에서는 계정 탈취 위험이 커질 수 있습니다.",
            "runtime_profile": "VLLM_COMPATIBILITY_TEST_DOUBLE",
            "official_rule_status": "FAIL",
            "citations": [],
        }

    monkeypatch.setattr(result_ai_api, "_retrieve_guide_evidence", retrieve)
    monkeypatch.setattr(result_ai_api, "_generate_follow_up", generate)
    monkeypatch.setattr(
        result_ai_api,
        "_organization_id",
        lambda _request: "test-organization",
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/result-explanations/follow-up/stream",
            headers={"X-CSRF-Token": "product-ai-05-test-csrf"},
            json={
                "result_id": "a1b2c3d4e5f60718",
                "result_version": 2,
                "selected_control_id": "PC-01",
                "question": "왜 먼저 확인해야 하나요?",
                "explanation_input": _explanation_input(),
                "profile": "FAST",
                "test_environment_result": True,
            },
        )

    assert response.status_code == 200
    assert response.text.index("VALIDATING_RESULT_CONTEXT") < response.text.index(
        "SEARCHING_SELECTED_KISA_EVIDENCE"
    )
    assert response.text.index(
        "SEARCHING_SELECTED_KISA_EVIDENCE"
    ) < response.text.index("GENERATING_FOLLOW_UP_ANSWER")
    assert '"status": "GENERATED"' in response.text
    assert captured == {
        "control_id": "PC-01",
        "organization_id": "test-organization",
        "result_id": "a1b2c3d4e5f60718",
        "result_version": 2,
        "question": "왜 먼저 확인해야 하나요?",
        "guide_status": "FOUND",
    }


def test_product_ai_05_result_page_has_context_bound_follow_up_ui(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_DEMO_CSRF_TOKEN", "product-ai-05-test-csrf")

    with TestClient(app) as client:
        page = client.get("/ui/results")

    assert page.status_code == 200
    for phrase in (
        "이 결과를 AI에게 질문",
        "선택한 점검 결과에 이어서 질문합니다",
        "위험 시나리오",
        "조치할 때 주의할 점",
        "왜 이 순서로 확인해야 하나요?",
    ):
        assert phrase in page.text
    for element_id in (
        "result-follow-up-panel",
        "result-follow-up-context",
        "result-follow-up-question",
        "result-follow-up-answer",
        "result-follow-up-citations",
    ):
        assert f'id="{element_id}"' in page.text

    script = (
        PROJECT_ROOT / "apps/web/static/app/product-results.js"
    ).read_text(encoding="utf-8")
    assert '"/api/v1/result-explanations/follow-up/stream"' in script
    assert "openResultFollowUp" in script
    assert "submitResultFollowUp" in script
    assert "innerHTML" not in script
