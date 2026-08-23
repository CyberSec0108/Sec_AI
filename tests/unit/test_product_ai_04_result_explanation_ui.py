from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from apps.api import result_ai_explanation as result_ai_api
from apps.api.main import app
from fastapi.testclient import TestClient
from tools.build_imp034_collector import _embedded_resources

from security_audit.application.current_host_regression import (
    ProbeObservation,
    evaluate_live_draft_observations,
)
from security_audit.application.result_explanation_input import (
    build_scan_explanation_inputs,
)
from security_audit.application.result_explanation_presentation import (
    build_result_explanation_presentations,
)
from security_audit.application.scan_result_guidance import build_control_results
from security_audit.common.canonical_json import JsonValue

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_product_ai_04_windows_exe_embeds_result_explanation_resources() -> None:
    resources = {
        str(item["path"]) for item in _embedded_resources(PROJECT_ROOT)
    }

    assert (
        "collectors/one_shot/contracts/product_ai_01_explanation_sources.json"
        in resources
    )
    assert "guides/mappings/kisa_2026_pc_control_sources.json" in resources


def _controls() -> list[dict[str, object]]:
    statuses = ("PASS", "FAIL", "ERROR", "REVIEW", "N/A")
    return [
        {
            "control_id": f"PC-{index:02d}",
            "title": f"PC-{index:02d} 점검 항목",
            "importance": "상" if index % 3 else "중",
            "checked_summary": f"PC-{index:02d} 설정을 확인했습니다.",
            "evidence_summary": f"PC-{index:02d} 비식별 확인 자료",
            "action_guidance": "필요하면 조직 담당자에게 문의하세요.",
            "assessment_status": statuses[(index - 1) % len(statuses)],
            "assessment_label": "시험 판정",
            "actual": f"비식별 실제 확인값 {index}",
            "expected": f"KISA 안전 기준 {index}",
            "result_code": f"PC{index:02d}_INTERNAL_REASON",
            "assessment_kind": "DEVELOPMENT_DRAFT",
        }
        for index in range(1, 19)
    ]


def _standard_probe_results() -> list[dict[str, object]]:
    contract = json.loads(
        (
            PROJECT_ROOT
            / "collectors"
            / "one_shot"
            / "contracts"
            / "product_ai_01_explanation_sources.json"
        ).read_text(encoding="utf-8")
    )
    return [
        {
            "probe_id": source["probe_id"],
            "probe_version": source["probe_version"],
            "control_ids": [source["control_id"]],
            "collection_status": (
                "UNSUPPORTED"
                if source["control_id"] in {"PC-02", "PC-04", "PC-06", "PC-08", "PC-10"}
                else "COLLECTED"
            ),
        }
        for source in contract["sources"]
        if source["control_id"] not in {"PC-02", "PC-04", "PC-06", "PC-08", "PC-10"}
    ]


def test_product_ai_04_builds_ai_inputs_from_actual_partial_standard_scan() -> None:
    inputs = build_scan_explanation_inputs(
        PROJECT_ROOT,
        controls=_controls(),
        collected_probe_results=_standard_probe_results(),
    )

    assert len(inputs) == 18
    assert inputs[0]["observed_summary"] == "비식별 실제 확인값 1"
    collection_methods = cast(
        list[dict[str, JsonValue]],
        inputs[1]["collection_methods"],
    )
    assert collection_methods[0]["collection_status"] == "UNSUPPORTED"
    assert inputs[1]["collection_limitations"]
    assert all(
        cast(dict[str, JsonValue], item["safety"])["raw_evidence_included"]
        is False
        for item in inputs
    )


def test_product_ai_04_actual_standard_scan_completes_safe_ai_input_contract() -> None:
    observations = (
        ProbeObservation(
            probe_id="win.security.password-age",
            collection_status="COLLECTED",
            error_code="NONE",
            adapter_id="secai.windows-native",
            adapter_version="0.1.0",
            privilege="STANDARD_USER",
            collected_at="2026-07-26T01:02:03Z",
            records=({"maximum_password_age_days": 42},),
        ),
    )
    assessments = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=observations,
    )
    receipt = {
        "results": _standard_probe_results(),
        "_evaluation_observations": observations,
    }
    controls = build_control_results(receipt, assessments=assessments)

    inputs = build_scan_explanation_inputs(
        PROJECT_ROOT,
        controls=controls,
        collected_probe_results=_standard_probe_results(),
    )

    assert len(inputs) == 18
    assert all(item["rule_status"] in {"PASS", "FAIL", "ERROR", "REVIEW", "N/A"} for item in inputs)
    pc02 = next(item for item in inputs if item["control_id"] == "PC-02")
    assert pc02["rule_status"] == "ERROR"
    assert pc02["observed_summary"] == (
        "관리자 권한이 필요한 자료를 아직 확인하지 못했습니다"
    )
    assert pc02["collection_limitations"]


def test_product_ai_04_builds_user_presentations_without_internal_reason_codes() -> None:
    presentations = build_result_explanation_presentations(
        PROJECT_ROOT,
        controls=_controls(),
    )
    serialized = json.dumps(presentations, ensure_ascii=False)

    assert len(presentations) == 18
    assert presentations[0]["control_id"] == "PC-01"
    assert presentations[0]["official_status"] == "PASS"
    assert presentations[0]["status_authority"] == "RULE_ENGINE"
    assert presentations[0]["collection_methods"] == [
        "Windows가 실제로 적용하는 비밀번호 최대 사용 기간을 읽습니다."
    ]
    assert presentations[0]["execution_tools"] == [
        "SecAI Windows 읽기 전용 점검 도구"
    ]
    assert presentations[0]["source_locations"] == [
        "Windows 유효 비밀번호 정책"
    ]
    assert presentations[0]["observed_summary"] == "비식별 실제 확인값 1"
    assert presentations[0]["expected_summary"] == "KISA 안전 기준 1"
    assert presentations[0]["judgement_explanation"]
    kisa_source = cast(
        dict[str, JsonValue],
        presentations[0]["kisa_source"],
    )
    assert kisa_source["page_label"]
    assert "result_code" not in serialized
    assert "INTERNAL_REASON" not in serialized
    assert "technical_locator" not in serialized


def test_administrator_ai_merge_uses_stable_collection_status() -> None:
    original = [{
        "control_id": "PC-02",
        "rule_status": "ERROR",
        "observed_summary": "관리자 자료 미수집",
        "expected_summary": "관리자 자료 수집",
        "assessment_kind": "DEVELOPMENT_DRAFT",
        "result_code": "LIVE_DRAFT_EVIDENCE_NOT_COLLECTED",
        "judgement_explanation": "관리자 점검 전입니다.",
        "collection_methods": [{
            "probe_id": "win.security.password-policy",
            "collection_status": "UNSUPPORTED",
        }],
        "collection_limitations": ["관리자 자료 미수집"],
        "source_rule_result_sha256": "a" * 64,
        "explanation_input_sha256": "b" * 64,
    }]
    administrator = [{
        "control_id": "PC-02",
        "probe_id": "win.security.password-policy",
        "collection_status": "COLLECTED",
        "collection_status_label": "표시 문구가 바뀌어도 성공",
        "assessment_status": "REVIEW",
        "actual": "비밀번호 정책 자료를 수집했습니다.",
        "expected": "선택한 조직 기준과 비교",
        "assessment_kind": "DEVELOPMENT_DRAFT",
        "result_code": "ORGANIZATION_PASSWORD_STANDARD_REQUIRED",
        "judgement_explanation": "기준 확인이 필요합니다.",
    }]

    merged = result_ai_api._merge_administrator_explanation_inputs(
        original,
        administrator,
    )[0]
    methods = cast(list[dict[str, JsonValue]], merged["collection_methods"])

    assert merged["rule_status"] == "REVIEW"
    assert methods[0]["collection_status"] == "COLLECTED"
    assert merged["collection_limitations"] == []


def test_product_ai_04_scan_api_uses_test_environment_result_and_kisa_retrieval(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    source = (
        PROJECT_ROOT / "apps/api/result_ai_explanation.py"
    ).read_text(encoding="utf-8")

    assert "/api/v1/result-explanations/from-scan/stream" in source
    assert "ResultGuideRetrievalService" in source
    assert "test_environment_result" in source
    assert "VLLM_COMPATIBILITY_TEST_DOUBLE" in source
    assert "LOCAL_VLLM_FULL_CONTEXT" in source


def test_product_ai_04_gateway_keeps_result_explanation_sse_open() -> None:
    gateway = (
        PROJECT_ROOT / "deploy" / "gateway" / "nginx.conf"
    ).read_text(encoding="utf-8")
    stream_location = gateway.split(
        "location ^~ /api/v1/result-explanations/",
        maxsplit=1,
    )[1].split("\n        }", maxsplit=1)[0]

    assert "proxy_read_timeout 300s;" in stream_location
    assert "proxy_buffering off;" in stream_location
    assert "proxy_cache off;" in stream_location
    assert "proxy_read_timeout 15s;" in gateway


def test_product_ai_04_scan_stream_sends_actual_test_result_to_ai(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_DEMO_CSRF_TOKEN", "product-ai-04-test-csrf")
    inputs = build_scan_explanation_inputs(
        PROJECT_ROOT,
        controls=_controls(),
        collected_probe_results=_standard_probe_results(),
    )
    captured: dict[str, object] = {}

    def retrieve(
        explanation_inputs: list[dict[str, Any]],
        *,
        organization_id: object,
    ) -> list[dict[str, object]]:
        captured["observed_summary"] = explanation_inputs[0]["observed_summary"]
        captured["organization_id"] = organization_id
        return [{"control_id": item["control_id"]} for item in explanation_inputs]

    generated_batch_sizes: list[int] = []

    def generate(body: Any) -> dict[str, object]:
        captured["test_data_only"] = body.test_data_only
        generated_batch_sizes.append(len(body.explanation_inputs))
        batch_control_ids = [
            item["control_id"] for item in body.explanation_inputs
        ]
        return {
            "schema_version": "1.0.0",
            "status": "GENERATED",
            "reason_code": None,
            "runtime_profile": "VLLM_COMPATIBILITY_TEST_DOUBLE",
            "external_data_transfer": True,
            "model_id": "openai/gpt-oss-120b",
            "prompt": {
                "template_id": "secai-result-analysis",
                "template_version": "1.0.0",
                "template_sha256": "1" * 64,
            },
            "explanation_input_sha256s": [
                f"{index:064x}" for index in range(1, len(batch_control_ids) + 1)
            ],
            "guide_evidence_sha256s": [
                f"{index + 100:064x}"
                for index in range(1, len(batch_control_ids) + 1)
            ],
            "input_sha256": "2" * 64,
            "model_output_sha256": "3" * 64,
            "official_results": [
                {
                    "control_id": control_id,
                    "rule_status": "ERROR",
                    "status_authority": "RULE_ENGINE",
                }
                for control_id in batch_control_ids
            ],
            "summary": {
                "overall_state": "묶음 설명",
                "related_risks": [],
                "user_actions": [],
                "administrator_actions": [],
                "limitations": [],
            },
            "items": [
                {"control_id": control_id}
                for control_id in batch_control_ids
            ],
            "citations": [
                {"control_id": control_id}
                for control_id in batch_control_ids
            ],
            "retryable": False,
            "safety": {
                "official_finding_write_allowed": False,
                "audit_pack_write_allowed": False,
                "test_data_only": True,
                "rule_status_unchanged": True,
            },
            "output_sha256": "4" * 64,
        }

    monkeypatch.setattr(result_ai_api, "_retrieve_guide_evidence", retrieve)
    monkeypatch.setattr(result_ai_api, "_generate", generate)
    monkeypatch.setattr(
        result_ai_api,
        "_organization_id",
        lambda _request: "test-organization",
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/result-explanations/from-scan/stream",
            headers={"X-CSRF-Token": "product-ai-04-test-csrf"},
            json={
                "explanation_inputs": inputs,
                "profile": "FAST",
                "test_environment_result": True,
            },
        )

    assert response.status_code == 200
    assert response.text.index("VALIDATING_SCAN_RESULT") < response.text.index(
        "SEARCHING_KISA_EVIDENCE"
    )
    assert response.text.index("SEARCHING_KISA_EVIDENCE") < response.text.index(
        "GENERATING_AI_EXPLANATION"
    )
    assert '"status": "GENERATED"' in response.text
    assert response.text.count("BATCH_COMPLETED") == 3
    assert response.text.index("BATCH_COMPLETED") < response.text.index(
        '"stage": "COMPLETED"'
    )
    assert generated_batch_sizes == [6, 6, 6]
    assert '"completed_controls": 6' in response.text
    assert '"completed_controls": 18' in response.text
    assert captured["observed_summary"] == "비식별 실제 확인값 1"
    assert captured["test_data_only"] is True


def test_product_ai_04_result_page_uses_one_result_format_and_dedicated_ai_page(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_DEMO_CSRF_TOKEN", "product-ai-04-test-csrf")

    with TestClient(app) as client:
        page = client.get("/ui/results")

    assert page.status_code == 200
    for phrase in (
        "항목별 점검 결과",
        "일반 점검과 관리자 추가 확인 결과를 같은 형식으로 보여드립니다.",
        "AI 설명 보기",
    ):
        assert phrase in page.text
    assert "시험 환경" not in page.text
    assert "현재 OpenRouter" not in page.text
    assert 'id="open-ai-analysis"' in page.text
    assert 'id="administrator-options-panel"' in page.text
    assert 'id="restart-administrator-scan"' not in page.text
    assert 'id="ai-explanation-panel"' not in page.text
    assert 'id="administrator-result-panel"' not in page.text


def test_product_ai_04_script_renders_readable_sections_without_internal_code() -> None:
    script = (
        PROJECT_ROOT / "apps/web/static/app/product-results.js"
    ).read_text(encoding="utf-8")
    stylesheet = (
        PROJECT_ROOT / "apps/web/static/app/app.css"
    ).read_text(encoding="utf-8")

    for symbol in (
        "loadAIExplanation",
        "renderAIExplanation",
        "renderAIExplanationItem",
        "renderOfficialExplanation",
        'slice(0, 3)',
        '"/api/v1/result-explanations/from-scan/stream"',
        '"공식 판정 · "',
        '"AI 해석·권장"',
        '"무엇을 확인했나요"',
        '"확인 방법"',
        '"내 PC에서 확인한 내용"',
        '"왜 이런 결과가 나왔나요"',
        '"어떤 위험이 있나요"',
        '"다음 행동"',
        '"근거와 출처"',
        '"KISA 근거를 찾고 있습니다."',
        '"AI가 위험과 조치 방법을 정리하고 있습니다."',
        '"BATCH_COMPLETED"',
        '"개 중 "',
        '"개 설명을 화면에 표시했습니다."',
        '"AI 답변이 길어 생성이 중단되었습니다.',
    ):
        assert symbol in script
    assert '"판정 이유 코드"' not in script
    assert "innerHTML" not in script
    for selector in (
        ".ai-explanation-panel",
        ".ai-summary-grid",
        ".ai-priority-list",
        ".ai-preview-item",
        ".official-explanation",
    ):
        assert selector in stylesheet


def test_scan_progress_shows_pc01_to_pc18_with_real_status_fields() -> None:
    template = (
        PROJECT_ROOT / "apps/web/templates/pages/product_results.html"
    ).read_text(encoding="utf-8")
    script = (
        PROJECT_ROOT / "apps/web/static/app/product-results.js"
    ).read_text(encoding="utf-8")

    assert 'id="scan-control-progress"' in template
    assert 'id="scan-control-progress-list"' in template
    assert '"PC-01"' in script
    assert '"PC-18"' in script
    assert "completed_control_ids" in script
    assert "current_control_id" in script
    assert '"확인 중"' in script
    assert '"확인 완료"' in script
    assert '"관리자 확인"' in script
    assert '"일반 점검 후 실행 예정"' in script
    assert '"관리자 점검 예정 5개"' in script


def test_full_scan_consent_launches_administrator_checks_after_standard_scan() -> None:
    script = (
        PROJECT_ROOT / "apps/web/static/app/product-results.js"
    ).read_text(encoding="utf-8")

    assert "secai_pending_administrator_scan_consent" in script
    assert "readPendingAdministratorConsent" in script
    assert "consumePendingAdministratorConsent" in script
    assert "startConsentedAdministratorScan(report)" in script
    assert 'bridgeUrl + "/v1/administrator/launch"' in script
    assert "consent.consent_version" in script
    assert "consent.probe_ids" in script
    assert "Windows 권한 확인창에서 ‘예’를 선택해 주세요." in script


def test_full_scan_waits_for_administrator_result_before_revealing_results() -> None:
    script = (
        PROJECT_ROOT / "apps/web/static/app/product-results.js"
    ).read_text(encoding="utf-8")

    assert "showAdministratorWaiting" in script
    assert "revealCompletedResults" in script
    assert "standard_result_id: currentResultId" in script
    assert "administratorReport.standard_result_id !== result.result_id" in script
    assert "revealCompletedResults(result.results || [])" in script


def test_administrator_values_take_priority_in_integrated_result_cards() -> None:
    script = (
        PROJECT_ROOT / "apps/web/static/app/product-results-integrated.js"
    ).read_text(encoding="utf-8")
    stylesheet = (
        PROJECT_ROOT / "apps/web/static/app/app.css"
    ).read_text(encoding="utf-8")

    assert "item.administrator_verified" in script
    assert "item.checked_summary" in script
    assert "item.actual" in script
    assert ".integrated-control-card > .integrated-sources" in stylesheet
