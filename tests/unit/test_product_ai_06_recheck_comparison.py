from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from apps.api import result_ai_explanation as result_ai_api
from apps.api.main import app
from fastapi.testclient import TestClient

from security_audit.application.result_ai_explanation import (
    ResultAIExecutionPolicy,
)
from security_audit.application.result_recheck_comparison import (
    ResultRecheckComparisonAIService,
    build_recheck_comparison,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)
from security_audit.llm import ChatCompletionInput, ChatCompletionResult
from tests.unit.test_product_ai_05_result_follow_up import (
    _explanation_input,
    _guide_evidence,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _controls(*, pc01: str, pc02: str) -> list[dict[str, object]]:
    return [
        {
            "control_id": "PC-01",
            "title": "비밀번호의 주기적 변경",
            "assessment_status": pc01,
        },
        {
            "control_id": "PC-02",
            "title": "비밀번호 관리정책 설정",
            "assessment_status": pc02,
        },
    ]


def _comparison() -> dict[str, JsonValue]:
    return build_recheck_comparison(
        previous_result_id="1111111111111111",
        previous_result_version=1,
        previous_controls=_controls(pc01="PASS", pc02="ERROR"),
        current_result_id="2222222222222222",
        current_result_version=2,
        current_controls=_controls(pc01="FAIL", pc02="REVIEW"),
    )


class StubComparisonModel:
    def __init__(self) -> None:
        self.calls: list[ChatCompletionInput] = []

    def complete(self, request: ChatCompletionInput) -> ChatCompletionResult:
        self.calls.append(request)
        return ChatCompletionResult(
            model_id="openai/gpt-oss-120b",
            content=json.dumps(
                {
                    "overall_change": (
                        "PC-01은 악화되었고 PC-02는 자료를 확인해 불확실성이 줄었습니다."
                    ),
                    "improved_explanations": [
                        "PC-02는 수집 오류에서 조직 기준 확인 단계로 바뀌었습니다."
                    ],
                    "worsened_explanations": [
                        "PC-01은 양호에서 취약으로 바뀌어 우선 확인이 필요합니다."
                    ],
                    "unchanged_summary": "변경되지 않은 항목은 없습니다.",
                    "remaining_risk_explanation": (
                        "PC-01의 비밀번호 변경 주기 위험이 남아 있습니다."
                    ),
                    "recommended_next_actions": [
                        "조직 정책을 확인한 뒤 비밀번호 변경 주기를 조정하세요."
                    ],
                    "limitations": [
                        "두 점검 시점의 비식별 규칙 상태만 비교했습니다."
                    ],
                },
                ensure_ascii=False,
            ),
            finish_reason="stop",
            prompt_tokens=200,
            completion_tokens=100,
            total_tokens=300,
        )


def test_product_ai_06_builds_append_only_change_classes_and_hash() -> None:
    comparison = _comparison()

    assert comparison["summary"] == {
        "improved": 1,
        "worsened": 1,
        "unchanged": 0,
        "remaining_risk": 2,
    }
    changes = cast(list[dict[str, JsonValue]], comparison["changes"])
    assert [item["change"] for item in changes] == ["WORSENED", "IMPROVED"]
    assert comparison["comparison_sha256"] == canonical_sha256_without_fields(
        comparison,
        {"comparison_sha256"},
    )
    serialized = json.dumps(comparison, ensure_ascii=False)
    assert "actual" not in serialized
    assert "result_code" not in serialized


def test_product_ai_06_does_not_call_pass_na_transition_worsened() -> None:
    comparison = build_recheck_comparison(
        previous_result_id="3333333333333333",
        previous_result_version=3,
        previous_controls=_controls(pc01="PASS", pc02="N/A"),
        current_result_id="4444444444444444",
        current_result_version=4,
        current_controls=_controls(pc01="N/A", pc02="PASS"),
    )

    assert comparison["summary"] == {
        "improved": 0,
        "worsened": 0,
        "unchanged": 2,
        "remaining_risk": 0,
    }


def test_product_ai_06_ai_explains_change_without_changing_rule_status() -> None:
    comparison = _comparison()
    explanation = _explanation_input()
    evidence = _guide_evidence(explanation)
    model = StubComparisonModel()

    result = ResultRecheckComparisonAIService(model).generate(
        comparison,
        [explanation],
        [evidence],
        policy=ResultAIExecutionPolicy(
            runtime_profile="VLLM_COMPATIBILITY_TEST_DOUBLE",
            external_data_transfer=True,
            approved_deidentified_test_transfer=True,
            test_data_only=True,
        ),
    )

    assert result.status == "GENERATED"
    assert result.comparison_sha256 == comparison["comparison_sha256"]
    assert result.official_changes == (
        ("PC-01", "PASS", "FAIL", "WORSENED"),
        ("PC-02", "ERROR", "REVIEW", "IMPROVED"),
    )
    assert result.output_sha256 == canonical_sha256_without_fields(
        result.to_json(),
        {"output_sha256"},
    )
    serialized_request = model.calls[0].messages[1].content
    assert "1111111111111111" not in serialized_request
    assert "2222222222222222" not in serialized_request
    assert "PASSWORD_MAXIMUM_AGE_EXCEEDED" not in serialized_request


def test_product_ai_06_stream_uses_org_scoped_current_kisa_context(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_DEMO_CSRF_TOKEN", "product-ai-06-test-csrf")
    captured: dict[str, object] = {}

    def retrieve(
        explanation_inputs: list[dict[str, Any]],
        *,
        organization_id: object,
    ) -> list[dict[str, object]]:
        captured["control_ids"] = [
            item["control_id"] for item in explanation_inputs
        ]
        captured["organization_id"] = organization_id
        return [{"status": "FOUND", "control_id": "PC-01"}]

    def generate(
        body: Any,
        evidence: list[dict[str, object]],
    ) -> dict[str, object]:
        captured["comparison_sha256"] = body.comparison["comparison_sha256"]
        captured["evidence_count"] = len(evidence)
        return {
            "status": "GENERATED",
            "runtime_profile": "VLLM_COMPATIBILITY_TEST_DOUBLE",
            "official_changes": body.comparison["changes"],
            "citations": [],
        }

    monkeypatch.setattr(result_ai_api, "_retrieve_guide_evidence", retrieve)
    monkeypatch.setattr(
        result_ai_api,
        "_generate_recheck_comparison",
        generate,
    )
    monkeypatch.setattr(
        result_ai_api,
        "_organization_id",
        lambda _request: "test-organization",
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/result-explanations/comparison/stream",
            headers={"X-CSRF-Token": "product-ai-06-test-csrf"},
            json={
                "comparison": _comparison(),
                "current_explanation_inputs": [_explanation_input()],
                "profile": "FAST",
                "test_environment_result": True,
            },
        )

    assert response.status_code == 200
    assert response.text.index("VALIDATING_RECHECK_LINEAGE") < response.text.index(
        "SEARCHING_CHANGED_KISA_EVIDENCE"
    )
    assert response.text.index(
        "SEARCHING_CHANGED_KISA_EVIDENCE"
    ) < response.text.index("GENERATING_CHANGE_EXPLANATION")
    assert '"status": "GENERATED"' in response.text
    assert captured["control_ids"] == ["PC-01"]
    assert captured["organization_id"] == "test-organization"
    assert captured["evidence_count"] == 1


def test_product_ai_06_results_page_owns_scan_and_recheck_lifecycle() -> None:
    home_source = (PROJECT_ROOT / "apps/web/static/app/product.js").read_text(
        encoding="utf-8"
    )
    results_source = (
        PROJECT_ROOT / "apps/web/static/app/product-results.js"
    ).read_text(encoding="utf-8")

    assert 'location.assign("/ui/results?start_scan=1")' in home_source
    assert 'request("/v1/scan", "POST")' not in home_source
    assert 'current.status === "COMPLETED"' in results_source
    assert 'request("/v1/recheck", "POST")' in results_source


def test_product_ai_06_result_page_has_deterministic_and_ai_change_panels(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_DEMO_CSRF_TOKEN", "product-ai-06-test-csrf")

    with TestClient(app) as client:
        page = client.get("/ui/results")

    for phrase in (
        "이전 결과와 비교",
        "개선",
        "악화",
        "변경 없음",
        "남아 있는 위험",
        "AI가 변화의 의미를 설명합니다",
    ):
        assert phrase in page.text
    for element_id in (
        "recheck-comparison-panel",
        "comparison-improved",
        "comparison-worsened",
        "comparison-unchanged",
        "comparison-remaining-risk",
        "ai-comparison-status",
        "ai-comparison-content",
    ):
        assert f'id="{element_id}"' in page.text
