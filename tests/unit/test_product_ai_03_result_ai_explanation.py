from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import cast
from uuid import NAMESPACE_URL, uuid5

import pytest
from apps.api import result_ai_explanation as result_ai_api
from apps.api.main import app
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from security_audit.application.result_ai_explanation import (
    ResultAIExecutionPolicy,
    ResultAIExplanationError,
    ResultAIExplanationService,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)
from security_audit.llm import (
    ChatCompletionInput,
    ChatCompletionResult,
    ProviderRequestError,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_SHA256 = "44fe393981b244147be6af7423d99dc15633c089fad0bcb296cbe2371dde812d"


def _source(control_id: str) -> dict[str, JsonValue]:
    number = int(control_id.split("-")[1])
    return {
        "guide_id": "kisa-major-infrastructure-detailed-guide",
        "guide_version": "2026",
        "source_sha256": SOURCE_SHA256,
        "document_code": "KISA-2026-07-PC",
        "page_start": 554 + number,
        "page_end": 554 + number,
        "section_label": f"{control_id} KISA 점검 항목",
        "mapping_status": "APPROVED",
    }


def _explanation(
    control_id: str,
    *,
    rule_status: str,
) -> dict[str, JsonValue]:
    source = _source(control_id)
    value: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "control_id": control_id,
        "title": f"{control_id} 점검 항목",
        "importance": "HIGH",
        "what_was_checked": f"{control_id}에서 적용 중인 설정을 확인했습니다.",
        "observed_summary": f"{control_id}의 비식별 실제 확인값",
        "normalized_facts": {"actual_summary": "비식별 실제 확인값"},
        "collection_methods": [
            {
                "probe_id": f"win.test.{control_id.casefold()}",
                "method_code": "WINDOWS_API",
                "method_summary": "승인된 Windows 읽기 전용 방법으로 확인",
                "collection_status": "COLLECTED",
            }
        ],
        "execution_tools": [
            {
                "probe_id": f"win.test.{control_id.casefold()}",
                "probe_version": "1.0.0",
                "tool_name": "SecAI Windows Collector",
                "collector_name": "SecAI Windows Collector",
                "collector_version": "0.1.0",
                "adapter_id": "secai.test",
                "adapter_version": "1.0.0",
            }
        ],
        "source_locations": [
            {
                "probe_id": f"win.test.{control_id.casefold()}",
                "user_label": "Windows 보안 설정",
                "technical_locator": "approved-read-only-source",
            }
        ],
        "rule_status": rule_status,
        "status_authority": "RULE_ENGINE",
        "result_code": f"{control_id.replace('-', '')}_INTERNAL_REASON",
        "result_code_visibility": "TECHNICAL_ONLY",
        "expected_summary": f"{control_id} KISA 안전 기준",
        "judgement_explanation": "실제값과 규칙 기준을 비교한 공식 판정 이유입니다.",
        "collection_limitations": [],
        "importance_source": "상",
        "kisa_citations": [source],
        "allowed_actions": ["조직 담당자에게 안전한 설정 방법을 문의하세요."],
        "assessment_kind": "DEVELOPMENT_DRAFT",
        "source_rule_result_sha256": "a" * 64,
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
    control_id: str,
    *,
    rule_status: str,
    status: str = "FOUND",
) -> dict[str, JsonValue]:
    source = _source(control_id)
    chunk_id = uuid5(NAMESPACE_URL, f"product-ai-03:{control_id}")
    paragraph = f"{control_id}은 KISA 안전 기준에 따라 해당 설정 상태를 확인합니다."
    paragraph_sha256 = hashlib.sha256(paragraph.encode("utf-8")).hexdigest()
    citation: dict[str, JsonValue] = {
        "chunk_id": str(chunk_id),
        "guide_id": source["guide_id"],
        "guide_version": source["guide_version"],
        "document_code": source["document_code"],
        "source_sha256": source["source_sha256"],
        "scope_id": "kisa-2026-pc",
        "pdf_page_number": source["page_start"],
        "control_id": control_id,
        "section_label": source["section_label"],
        "paragraph_ordinal": 1,
        "paragraph_sha256": paragraph_sha256,
        "text_sha256": hashlib.sha256(paragraph.encode("utf-8")).hexdigest(),
        "dense_score": 0.95,
        "lexical_score": 0.95,
        "rerank_score": 0.95,
    }
    value: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "status": status,
        "reason_code": None if status == "FOUND" else "NO_MATCH_FOR_RESULT_CONTROL",
        "control_id": control_id,
        "rule_status": rule_status,
        "status_authority": "RULE_ENGINE",
        "explanation_input_sha256": _explanation(
            control_id,
            rule_status=rule_status,
        )["explanation_input_sha256"],
        "search_query_sha256": "b" * 64,
        "citations": [citation] if status == "FOUND" else [],
        "evidence_segments": (
            [
                {
                    "chunk_id": str(chunk_id),
                    "paragraph_ordinal": 1,
                    "paragraph_text": paragraph,
                    "paragraph_sha256": paragraph_sha256,
                }
            ]
            if status == "FOUND"
            else []
        ),
        "official_finding_write_allowed": False,
    }
    value["output_sha256"] = canonical_sha256_without_fields(
        value,
        {"output_sha256"},
    )
    return value


def _model_payload() -> dict[str, object]:
    return {
        "summary": {
            "overall_state": "취약 항목을 우선 확인해야 합니다.",
            "related_risks": ["계정 보호 설정이 함께 약하면 침해 위험이 커질 수 있습니다."],
            "user_actions": ["안내된 설정을 확인하고 변경 전 현재 상태를 기록하세요."],
            "administrator_actions": ["조직 정책과 충돌하는지 관리자가 확인하세요."],
            "limitations": ["테스트 데이터로 생성한 설명입니다."],
        },
        "items": [
            {
                "control_id": "PC-01",
                "risk_explanation": (
                    "비밀번호를 오래 사용하면 노출된 비밀번호가 악용될 수 있습니다."
                ),
                "ai_priority": "HIGH",
                "priority_reason": "계정 탈취 위험과 직접 관련된 항목입니다.",
                "user_actions": ["비밀번호 변경 시기를 확인하세요."],
                "administrator_actions": ["조직의 암호 정책 적용 여부를 확인하세요."],
                "limitations": [],
                "related_controls": ["PC-02"],
            },
            {
                "control_id": "PC-02",
                "risk_explanation": "비밀번호 정책이 약하면 추측 공격에 취약할 수 있습니다.",
                "ai_priority": "HIGH",
                "priority_reason": "PC-01과 함께 계정 보호 수준에 영향을 줍니다.",
                "user_actions": ["현재 적용 기준을 담당자에게 문의하세요."],
                "administrator_actions": ["암호 복잡성 정책을 추가 확인하세요."],
                "limitations": ["관리자 추가 확인이 필요할 수 있습니다."],
                "related_controls": ["PC-01"],
            },
        ],
    }


class StubModel:
    def __init__(self, payload: dict[str, object] | None = None) -> None:
        self.payload = payload or _model_payload()
        self.calls: list[ChatCompletionInput] = []

    def complete(self, request: ChatCompletionInput) -> ChatCompletionResult:
        self.calls.append(request)
        return ChatCompletionResult(
            model_id="openai/gpt-oss-120b",
            content=json.dumps(self.payload, ensure_ascii=False),
            finish_reason="stop",
            prompt_tokens=200,
            completion_tokens=120,
            total_tokens=320,
        )


def _remote_test_policy() -> ResultAIExecutionPolicy:
    return ResultAIExecutionPolicy(
        runtime_profile="VLLM_COMPATIBILITY_TEST_DOUBLE",
        external_data_transfer=True,
        approved_deidentified_test_transfer=True,
        test_data_only=True,
    )


def _inputs() -> tuple[list[dict[str, JsonValue]], list[dict[str, JsonValue]]]:
    explanations = [
        _explanation("PC-01", rule_status="FAIL"),
        _explanation("PC-02", rule_status="REVIEW"),
    ]
    evidence = [
        _guide_evidence("PC-01", rule_status="FAIL"),
        _guide_evidence("PC-02", rule_status="REVIEW"),
    ]
    return explanations, evidence


def test_product_ai_03_generates_structured_result_without_changing_rule_status() -> None:
    model = StubModel()
    explanations, evidence = _inputs()
    explanations_before = deepcopy(explanations)
    evidence_before = deepcopy(evidence)

    result = ResultAIExplanationService(model).generate(
        explanations,
        evidence,
        policy=_remote_test_policy(),
        profile="FAST",
    )
    body = result.to_json()

    assert result.status == "GENERATED"
    assert result.runtime_profile == "VLLM_COMPATIBILITY_TEST_DOUBLE"
    assert [
        (item["control_id"], item["rule_status"], item["status_authority"])
        for item in cast(list[dict[str, JsonValue]], body["items"])
    ] == [
        ("PC-01", "FAIL", "RULE_ENGINE"),
        ("PC-02", "REVIEW", "RULE_ENGINE"),
    ]
    assert body["summary"]
    assert len(cast(list[JsonValue], body["citations"])) == 2
    assert body["safety"] == {
        "official_finding_write_allowed": False,
        "audit_pack_write_allowed": False,
        "rule_status_unchanged": True,
        "test_data_only": True,
    }
    prompt = cast(dict[str, JsonValue], body["prompt"])
    assert len(str(prompt["template_sha256"])) == 64
    for key in ("input_sha256", "model_output_sha256", "output_sha256"):
        assert len(str(body[key])) == 64
    assert explanations == explanations_before
    assert evidence == evidence_before

    serialized_request = json.dumps(
        [
            {"role": message.role, "content": message.content}
            for message in model.calls[0].messages
        ],
        ensure_ascii=False,
    )
    for prohibited in (
        "result_code",
        "PC01_INTERNAL_REASON",
        "probe_id",
        "adapter_id",
        "technical_locator",
    ):
        assert prohibited not in serialized_request


def test_product_ai_03_rejects_model_attempt_to_emit_official_status() -> None:
    payload = _model_payload()
    cast(list[dict[str, object]], payload["items"])[0]["rule_status"] = "PASS"
    explanations, evidence = _inputs()

    result = ResultAIExplanationService(StubModel(payload)).generate(
        explanations,
        evidence,
        policy=_remote_test_policy(),
    )

    assert result.status == "SECURITY_BLOCKED"
    assert result.reason_code == "MODEL_OUTPUT_CONTRACT_INVALID"
    assert result.items == ()
    assert result.official_results == (("PC-01", "FAIL"), ("PC-02", "REVIEW"))


def test_product_ai_03_missing_evidence_never_calls_model_and_preserves_results() -> None:
    model = StubModel()
    explanations, evidence = _inputs()
    evidence[1] = _guide_evidence(
        "PC-02",
        rule_status="REVIEW",
        status="INSUFFICIENT_EVIDENCE",
    )

    result = ResultAIExplanationService(model).generate(
        explanations,
        evidence,
        policy=_remote_test_policy(),
    )

    assert result.status == "NO_EVIDENCE"
    assert result.reason_code == "NO_MATCH_FOR_RESULT_CONTROL"
    assert result.official_results == (("PC-01", "FAIL"), ("PC-02", "REVIEW"))
    assert not model.calls


def test_product_ai_03_model_failure_keeps_official_results_available() -> None:
    class FailedModel:
        def complete(self, request: ChatCompletionInput) -> ChatCompletionResult:
            raise ProviderRequestError("MODEL_GATEWAY_UNAVAILABLE", retryable=True)

    explanations, evidence = _inputs()
    result = ResultAIExplanationService(FailedModel()).generate(
        explanations,
        evidence,
        policy=_remote_test_policy(),
    )

    assert result.status == "MODEL_UNAVAILABLE"
    assert result.reason_code == "MODEL_GATEWAY_UNAVAILABLE"
    assert result.retryable is True
    assert result.official_results == (("PC-01", "FAIL"), ("PC-02", "REVIEW"))
    assert result.summary is None
    assert result.items == ()


def test_product_ai_03_uses_large_output_budget_and_reports_truncation() -> None:
    class LengthLimitedModel:
        def __init__(self) -> None:
            self.calls: list[ChatCompletionInput] = []

        def complete(self, request: ChatCompletionInput) -> ChatCompletionResult:
            self.calls.append(request)
            return ChatCompletionResult(
                model_id="openai/gpt-oss-120b",
                content='{"summary":{"overall_state":"중간에서 잘린 답변"',
                finish_reason="length",
                prompt_tokens=5_699,
                completion_tokens=8_000,
                total_tokens=13_699,
            )

    model = LengthLimitedModel()
    explanations, evidence = _inputs()
    result = ResultAIExplanationService(model).generate(
        explanations,
        evidence,
        policy=_remote_test_policy(),
        profile="FAST",
    )

    assert model.calls[0].max_tokens == 8_000
    assert result.status == "GENERATION_FAILED"
    assert result.reason_code == "OUTPUT_TOKEN_LIMIT_REACHED"
    assert result.retryable is True
    assert result.official_results == (("PC-01", "FAIL"), ("PC-02", "REVIEW"))


def test_product_ai_03_remote_test_and_local_runtime_policies_fail_closed() -> None:
    with pytest.raises(ResultAIExplanationError, match="REMOTE_TEST_APPROVAL_REQUIRED"):
        ResultAIExecutionPolicy(
            runtime_profile="VLLM_COMPATIBILITY_TEST_DOUBLE",
            external_data_transfer=True,
            approved_deidentified_test_transfer=False,
            test_data_only=True,
        )
    with pytest.raises(ResultAIExplanationError, match="REMOTE_TEST_DATA_ONLY_REQUIRED"):
        ResultAIExecutionPolicy(
            runtime_profile="VLLM_COMPATIBILITY_TEST_DOUBLE",
            external_data_transfer=True,
            approved_deidentified_test_transfer=True,
            test_data_only=False,
        )
    with pytest.raises(ResultAIExplanationError, match="LOCAL_RUNTIME_EXTERNAL_TRANSFER"):
        ResultAIExecutionPolicy(
            runtime_profile="LOCAL_VLLM_FULL_CONTEXT",
            external_data_transfer=True,
            approved_deidentified_test_transfer=False,
            test_data_only=False,
        )


def test_product_ai_03_output_hash_is_deterministic_for_one_hundred_runs() -> None:
    explanations, evidence = _inputs()
    hashes = {
        ResultAIExplanationService(StubModel()).generate(
            explanations,
            evidence,
            policy=_remote_test_policy(),
        ).output_sha256
        for _ in range(100)
    }

    assert len(hashes) == 1


def test_product_ai_03_schema_and_examples_are_registered() -> None:
    catalog = json.loads(
        (PROJECT_ROOT / "database" / "schemas" / "schema-catalog.json").read_text(
            encoding="utf-8"
        )
    )
    examples = json.loads(
        (
            PROJECT_ROOT / "database" / "schemas" / "examples" / "index.json"
        ).read_text(encoding="utf-8")
    )
    schema = json.loads(
        (
            PROJECT_ROOT
            / "database"
            / "schemas"
            / "result_ai_explanation.schema.json"
        ).read_text(encoding="utf-8")
    )
    schema_id = "https://schemas.sec-ai.local/v1/result_ai_explanation.schema.json"

    assert any(entry["id"] == schema_id for entry in catalog["schemas"])
    assert sum(
        entry["schema"] == "result_ai_explanation.schema.json"
        for entry in examples["examples"]
    ) == 2
    valid = json.loads(
        (
            PROJECT_ROOT
            / "database"
            / "schemas"
            / "examples"
            / "valid"
            / "result_ai_explanation.json"
        ).read_text(encoding="utf-8")
    )
    assert list(Draft202012Validator(schema).iter_errors(valid)) == []


def test_product_ai_03_merged_validated_batches_keep_schema_and_lineage() -> None:
    explanations, evidence = _inputs()
    first_payload = deepcopy(_model_payload())
    second_payload = deepcopy(_model_payload())
    first_payload["items"] = cast(list[dict[str, object]], first_payload["items"])[:1]
    second_payload["items"] = cast(
        list[dict[str, object]],
        second_payload["items"],
    )[1:]
    cast(list[dict[str, object]], first_payload["items"])[0][
        "related_controls"
    ] = []
    cast(list[dict[str, object]], second_payload["items"])[0][
        "related_controls"
    ] = []
    first = ResultAIExplanationService(StubModel(first_payload)).generate(
        explanations[:1],
        evidence[:1],
        policy=_remote_test_policy(),
    )
    second = ResultAIExplanationService(StubModel(second_payload)).generate(
        explanations[1:],
        evidence[1:],
        policy=_remote_test_policy(),
    )

    merged = result_ai_api._merge_generated_batches(
        [first.to_json(), second.to_json()]
    )
    schema = json.loads(
        (
            PROJECT_ROOT
            / "database"
            / "schemas"
            / "result_ai_explanation.schema.json"
        ).read_text(encoding="utf-8")
    )

    assert list(Draft202012Validator(schema).iter_errors(merged)) == []
    assert [
        item["control_id"]
        for item in cast(list[dict[str, JsonValue]], merged["items"])
    ] == ["PC-01", "PC-02"]
    assert len(str(merged["output_sha256"])) == 64


def test_product_ai_03_json_and_sse_api_use_the_same_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    explanations, evidence = _inputs()
    service = ResultAIExplanationService(StubModel())
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_ENABLED", "false")
    monkeypatch.setenv("SECAI_DEMO_CSRF_TOKEN", "csrf-product-ai-03")
    monkeypatch.setattr(
        result_ai_api,
        "_service_and_policy",
        lambda _test_data_only: (service, _remote_test_policy()),
    )
    payload = {
        "explanation_inputs": explanations,
        "guide_evidence": evidence,
        "profile": "FAST",
        "test_data_only": True,
    }
    headers = {"X-CSRF-Token": "csrf-product-ai-03"}

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/result-explanations",
            json=payload,
            headers=headers,
        )
        stream = client.post(
            "/api/v1/result-explanations/stream",
            json=payload,
            headers=headers,
        )

    assert response.status_code == 200
    assert response.json()["status"] == "GENERATED"
    assert response.json()["output_sha256"]
    assert stream.status_code == 200
    assert stream.headers["content-type"].startswith("text/event-stream")
    for stage in (
        "VALIDATING_LINEAGE",
        "COMPARING_RULE_RESULTS",
        "GENERATING_EXPLANATION",
        "COMPLETED",
    ):
        assert stage in stream.text
    assert response.json()["output_sha256"] in stream.text
