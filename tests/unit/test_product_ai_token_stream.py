from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from security_audit.application.result_ai_explanation import (
    ResultAIExplanationError,
    ValidatedResultContext,
)
from security_audit.application.result_ai_token_stream import (
    ResultAITokenStreamService,
)
from security_audit.common.canonical_json import JsonValue
from security_audit.llm import (
    ChatCompletionInput,
    ChatCompletionStreamChunk,
    ChatMessage,
    ModelGatewaySettings,
    OpenAICompatibleProvider,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _validated_context() -> ValidatedResultContext:
    explanation: dict[str, JsonValue] = {
        "title": "비밀번호의 주기적 변경",
        "what_was_checked": "비밀번호 최대 사용 기간",
        "observed_summary": "42일마다 변경",
        "expected_summary": "1~90일 이내 변경",
        "judgement_explanation": "현재 설정이 기준을 충족합니다.",
        "allowed_actions": ["현재 설정 유지"],
    }
    citation: dict[str, JsonValue] = {
        "guide_id": "internal-guide-id",
        "guide_version": "2026",
        "pdf_page_number": 555,
        "section_label": "PC-01 비밀번호의 주기적 변경",
        "paragraph_ordinal": 2,
    }
    return ValidatedResultContext(
        control_id="PC-01",
        rule_status="PASS",
        explanation_input_sha256="a" * 64,
        guide_evidence_sha256="b" * 64,
        explanation=explanation,
        evidence={"status": "FOUND"},
        citation=citation,
        paragraph="비밀번호를 1~90일 이내에 변경합니다.",
    )


class _CapturingStreamModel:
    def __init__(self, finish_reason: str) -> None:
        self.finish_reason = finish_reason
        self.requests: list[ChatCompletionInput] = []

    def stream(
        self,
        request: ChatCompletionInput,
    ) -> Iterator[ChatCompletionStreamChunk]:
        self.requests.append(request)
        yield ChatCompletionStreamChunk(
            model_id="test-model",
            content_delta="## 전체 상태\n\n설명",
        )
        yield ChatCompletionStreamChunk(
            model_id="test-model",
            content_delta="",
            finish_reason=self.finish_reason,
        )


class _WrongCountStreamModel(_CapturingStreamModel):
    def stream(
        self,
        request: ChatCompletionInput,
    ) -> Iterator[ChatCompletionStreamChunk]:
        self.requests.append(request)
        yield ChatCompletionStreamChunk(
            model_id="test-model",
            content_delta=(
                "## 전체 상태\n\n양호 9개, 취약 2개, 기준 확인 필요 7개입니다.\n\n"
                "## 먼저 확인할 항목\n\n- 취약 2개부터 확인합니다.\n- PC-09 확인"
            ),
        )
        yield ChatCompletionStreamChunk(
            model_id="test-model",
            content_delta="",
            finish_reason=self.finish_reason,
        )


class _MultiDeltaSummaryModel(_CapturingStreamModel):
    def __init__(self) -> None:
        super().__init__("stop")
        self.emitted_deltas = 0

    def stream(
        self,
        request: ChatCompletionInput,
    ) -> Iterator[ChatCompletionStreamChunk]:
        self.requests.append(request)
        for delta in (
            "## 먼저 확인할 항목\n\n",
            "- 첫 번째 설명\n",
            "- 두 번째 설명",
        ):
            self.emitted_deltas += 1
            yield ChatCompletionStreamChunk(
                model_id="test-model",
                content_delta=delta,
            )
        yield ChatCompletionStreamChunk(
            model_id="test-model",
            content_delta="",
            finish_reason=self.finish_reason,
        )


def _settings(tmp_path: Path) -> ModelGatewaySettings:
    api_key = tmp_path / "api-key"
    gateway_token = tmp_path / "gateway-token"
    api_key.write_text("test-upstream-key", encoding="utf-8")
    gateway_token.write_text("test-gateway-token", encoding="utf-8")
    return ModelGatewaySettings(
        api_base="https://openrouter.ai/api/v1",
        model_id="openai/gpt-oss-120b",
        api_key_file=str(api_key),
        gateway_token_file=str(gateway_token),
        request_timeout_seconds=240.0,
        reasoning_effort="low",
    )


def test_openai_compatible_provider_emits_true_sse_deltas(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        events = (
            {"model": "openai/gpt-oss-120b", "choices": [
                {"delta": {"content": "PC-01 "}, "finish_reason": None}
            ]},
            {"model": "openai/gpt-oss-120b", "choices": [
                {"delta": {"content": "설명"}, "finish_reason": "stop"}
            ]},
        )
        content = "".join(
            f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            for event in events
        ) + "data: [DONE]\n\n"
        return httpx.Response(200, text=content)

    provider = OpenAICompatibleProvider(
        _settings(tmp_path),
        transport=httpx.MockTransport(handler),
    )
    chunks = list(
        provider.stream(
            ChatCompletionInput(
                messages=(ChatMessage(role="user", content="설명"),),
                max_tokens=32,
            )
        )
    )

    request_body = captured["body"]
    assert isinstance(request_body, dict)
    assert request_body["stream"] is True
    assert [chunk.content_delta for chunk in chunks] == ["PC-01 ", "설명"]
    assert chunks[-1].finish_reason == "stop"


def test_ai_analysis_page_streams_summary_then_controls_without_inner_html() -> None:
    template = (
        PROJECT_ROOT / "apps/web/templates/pages/result_ai_analysis.html"
    ).read_text(encoding="utf-8")
    script = (
        PROJECT_ROOT / "apps/web/static/app/result-ai-analysis.js"
    ).read_text(encoding="utf-8")
    api = (
        PROJECT_ROOT / "apps/api/result_ai_explanation.py"
    ).read_text(encoding="utf-8")

    assert 'id="ai-control-stream"' in template
    assert 'id="ai-summary-panel"' in template
    assert template.index('id="ai-summary-panel"') < template.index(
        'id="ai-control-stream"'
    )
    assert 'id="ai-stream-stop"' in template
    assert '"CONTROL_STARTED"' in script
    assert '"CONTROL_DELTA"' in script
    assert '"SUMMARY_DELTA"' in script
    assert "innerHTML" not in script
    assert "for index, context in enumerate(contexts, start=1)" in api
    assert api.index('"SUMMARY_STARTED"') < api.index('"CONTROL_STARTED"')
    assert "/api/v1/result-explanations/from-scan/token-stream" in api
    assert "RESULT_AI_EVIDENCE_NOT_FOUND" not in (
        PROJECT_ROOT
        / "src/security_audit/application/result_ai_token_stream.py"
    ).read_text(encoding="utf-8")
    assert "AI 설명 입력 또는 출력 안전 계약" not in api
    assert "knowledge_sources" in (
        PROJECT_ROOT
        / "src/security_audit/application/result_ai_token_stream.py"
    ).read_text(encoding="utf-8")
    assert "knowledge_evaluation" in api
    assert "ai-source-list" in script
    assert "source.display_label" in script
    assert "onCitationActivate" in script
    assert "normalizeSectionHeadings" in script
    assert 'sentence.trimEnd() + citations' in script
    assert "AI 종합 설명의 근거와 한계" in template
    assert "전체 상태와 우선 조치를 먼저 종합" in template
    assert "AbortController" in script
    assert "activeController.abort()" in script
    assert 'heading.textContent = "상세 설명"' in script


def test_summary_prompt_uses_readable_sections_and_enough_output_tokens() -> None:
    model = _CapturingStreamModel("stop")
    service = ResultAITokenStreamService(model)

    assert "설명" in "".join(
        service.stream_summary([_validated_context()], profile="FAST")
    )

    request = model.requests[0]
    system_prompt = request.messages[0].content
    assert request.max_tokens >= 2_400
    assert "Markdown 표" in system_prompt
    assert "## 설명의 한계" in system_prompt
    assert "제목 다음에는 빈 줄" in system_prompt


def test_control_prompt_numbers_sections_and_separates_three_source_types() -> None:
    model = _CapturingStreamModel("stop")
    service = ResultAITokenStreamService(model)

    assert "설명" in "".join(
        service.stream_control(_validated_context(), profile="FAST")
    )

    request = model.requests[0]
    system_prompt = request.messages[0].content
    user_prompt = request.messages[1].content
    assert "## 1. 왜 중요한가요?" in system_prompt
    assert "## 2. 내 PC 결과의 의미" in system_prompt
    assert "## 3. 다음에 할 일" in system_prompt
    assert "정확한 항목이 1~5개이면 이름을 모두" in system_prompt
    assert "6개 이상이면 대표 항목은 최대 5개" in system_prompt
    assert "문장부호 뒤에 공백 없이" in system_prompt
    assert "출처 번호로 시작하지" in system_prompt
    assert '"citation_id": "[1]"' in user_prompt
    assert '"citation_id": "[2]"' in user_prompt
    assert '"citation_id": "[3]"' in user_prompt
    assert "judgement_explanation" not in user_prompt
    assert "RULE_ENGINE" not in user_prompt


def test_summary_compacts_all_18_controls_within_chat_message_limit() -> None:
    model = _CapturingStreamModel("stop")
    service = ResultAITokenStreamService(model)
    contexts: list[ValidatedResultContext] = []
    for number in range(1, 19):
        base = _validated_context()
        explanation = dict(base.explanation)
        explanation.update(
            {
                "title": "점검 항목 " + ("가" * 1_000),
                "what_was_checked": "확인 대상 " + ("나" * 3_000),
                "observed_summary": "실제 확인값 " + ("다" * 3_000),
                "expected_summary": "KISA 기준 " + ("라" * 3_000),
            }
        )
        contexts.append(
            replace(
                base,
                control_id=f"PC-{number:02d}",
                explanation=explanation,
            )
        )

    assert "설명" in "".join(service.stream_summary(contexts, profile="FAST"))

    summary_message = model.requests[0].messages[1].content
    assert len(summary_message) <= 24_000
    assert all(f'"control_id":"PC-{number:02d}"' in summary_message for number in range(1, 19))


def test_summary_uses_rule_engine_counts_instead_of_model_counts() -> None:
    model = _WrongCountStreamModel("stop")
    service = ResultAITokenStreamService(model)
    statuses = ["PASS"] * 8 + ["FAIL"] * 5 + ["REVIEW"] * 5
    contexts = [
        replace(
            _validated_context(),
            control_id=f"PC-{number:02d}",
            rule_status=status,
        )
        for number, status in enumerate(statuses, start=1)
    ]
    model_output = "".join(service.stream_summary(contexts, profile="FAST"))

    assert "총 18개 중 양호 8개, 취약 5개, 수집 오류 0개, 기준 확인 필요 5개" in model_output
    assert "양호 2개" not in model_output
    assert "취약 2개" not in model_output
    assert "PC-09 확인" in model_output
    assert service.status_counts(contexts) == {
        "total": 18,
        "pass": 8,
        "fail": 5,
        "error": 0,
        "review": 5,
        "not_applicable": 0,
    }


def test_summary_yields_before_model_stream_is_fully_consumed() -> None:
    model = _MultiDeltaSummaryModel()
    service = ResultAITokenStreamService(model)
    stream = service.stream_summary([_validated_context()], profile="FAST")

    first = next(stream)

    assert "총 1개 중 양호 1개" in first
    assert model.emitted_deltas == 0
    assert next(stream) == "## 먼저 확인할 항목\n"
    assert model.emitted_deltas == 1
    assert next(stream) == "\n"
    assert model.emitted_deltas == 1
    assert next(stream) == "- 첫 번째 설명\n"
    assert model.emitted_deltas == 2
    assert next(stream) == "- 두 번째 설명"
    assert model.emitted_deltas == 3


def test_token_limit_finish_reason_is_not_reported_as_completed() -> None:
    model = _CapturingStreamModel("length")
    service = ResultAITokenStreamService(model)

    with pytest.raises(ResultAIExplanationError) as exc_info:
        list(service.stream_summary([_validated_context()], profile="FAST"))

    assert exc_info.value.code == "OUTPUT_TOKEN_LIMIT_REACHED"


def test_scan_completion_merges_admin_result_into_integrated_ai_view() -> None:
    product = (
        PROJECT_ROOT / "apps/web/static/app/product.js"
    ).read_text(encoding="utf-8")
    results = (
        PROJECT_ROOT / "apps/web/static/app/product-results.js"
    ).read_text(encoding="utf-8")
    template = (
        PROJECT_ROOT / "apps/web/templates/pages/product_results.html"
    ).read_text(encoding="utf-8")
    integrated = (
        PROJECT_ROOT / "apps/web/static/app/product-results-integrated.js"
    ).read_text(encoding="utf-8")

    assert "window.localStorage.setItem(" in product
    assert "aiAnalysisPendingKey" in product
    assert "storeAIAnalysisPayload" in results
    assert "openPendingAIAnalysis(administratorResults || [])" in results
    assert "revealCompletedResults(result.results || [])" in results
    assert "updateControlFromAdministrator(item)" in results
    assert "dispatchIntegratedResults(administratorResults, true)" in results
    assert 'window.location.assign("/ui/ai-analysis")' not in results
    assert "loadAIExplanation(result.ai_explanation_inputs" not in results
    assert 'src="/static/app/product-results-integrated.js"' in template
    assert 'id="integrated-results-panel"' in template
    assert "/api/v1/result-explanations/from-scan/token-stream" in integrated
    assert "AbortController" in integrated
    assert "onCitationActivate" in integrated
    assert "innerHTML" not in integrated


def test_saved_criteria_are_used_and_review_remains_a_public_status() -> None:
    criteria = (
        PROJECT_ROOT / "apps/web/templates/pages/assessment_criteria.html"
    ).read_text(encoding="utf-8")
    product = (
        PROJECT_ROOT / "apps/web/static/app/product.js"
    ).read_text(encoding="utf-8")
    results = (
        PROJECT_ROOT / "apps/web/static/app/product-results.js"
    ).read_text(encoding="utf-8")

    assert "KISA 기준과 안전한 SecAI 보조 기본 범위가 자동 적용" in criteria
    assert "판정에 필요한 기본 범위가 비어 있지 않습니다" in criteria
    assert "자료를 읽지 못한 경우는 기준 부족과 섞지 않고 수집 오류" in criteria
    assert 'new Option("KISA·제품 기본 기준", "")' in product
    assert "selection_kind=KISA_DEFAULT" not in product
    assert 'return value === "REVIEW" ? "ERROR"' not in results
    assert 'REVIEW: "기준 확인 필요"' in results

    review_context = replace(_validated_context(), rule_status="REVIEW")
    assert (
        ResultAITokenStreamService.public_control(review_context)["rule_status"]
        == "REVIEW"
    )

    model = _CapturingStreamModel("stop")
    service = ResultAITokenStreamService(model)
    assert "설명" in "".join(service.stream_summary([review_context], profile="FAST"))
    summary_message = model.requests[0].messages[1].content
    assert '"rule_status":"REVIEW"' in summary_message
