from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from security_audit.application.result_ai_explanation import (
    ResultAIExplanationError,
    merge_administrator_explanation_inputs,
)
from security_audit.application.result_report import (
    ReportContractError,
    ReportKind,
    _draw_control,
    _PdfLayout,
    build_model_manifest,
    build_report_document,
    render_pdf,
    validate_report_snapshot,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _explanation(control_number: int) -> dict[str, object]:
    control_id = f"PC-{control_number:02d}"
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "control_id": control_id,
        "title": f"{control_id} 시험 항목",
        "importance": "HIGH",
        "what_was_checked": "Windows에 실제 적용된 보안 설정을 확인했습니다.",
        "observed_summary": "내 PC에서 확인한 실제값입니다.",
        "normalized_facts": {"actual_summary": "내 PC 실제값"},
        "collection_methods": [
            {
                "probe_id": f"win.test.{control_number}",
                "method_code": "WINDOWS_API",
                "method_summary": "Windows API로 읽기 전용 확인",
                "collection_status": "COLLECTED",
            }
        ],
        "execution_tools": [
            {
                "probe_id": f"win.test.{control_number}",
                "probe_version": "0.1.0",
                "tool_name": "SecAI Windows 읽기 전용 점검 도구",
                "collector_name": "sec-ai-one-shot-collector",
                "collector_version": "0.1.0",
                "adapter_id": "secai.windows-native",
                "adapter_version": "0.1.0",
            }
        ],
        "source_locations": [
            {
                "probe_id": f"win.test.{control_number}",
                "user_label": "Windows 보안 설정",
                "technical_locator": "PowerShell:Get-SecAITest",
            }
        ],
        "evidence_trace": [
            {
                "probe_id": f"win.test.{control_number}",
                "collection_status": "COLLECTED",
                "collected_at_utc": "2026-07-26T03:59:00Z",
                "normalized_records_sha256": "f" * 64,
                "source_labels": ["Windows 보안 설정"],
                "raw_evidence_available": False,
            }
        ],
        "rule_status": "FAIL" if control_number == 1 else "PASS",
        "status_authority": "RULE_ENGINE",
        "result_code": (
            "PASSWORD_COMPLEXITY_NOT_OBSERVED"
            if control_number == 1
            else f"PC_{control_number:02d}_PASS"
        ),
        "result_code_visibility": "TECHNICAL_ONLY",
        "expected_summary": "KISA 권고 기준을 충족",
        "judgement_explanation": "실제값을 규칙 기준과 비교한 결과입니다.",
        "collection_limitations": [],
        "importance_source": "상",
        "kisa_citations": [
            {
                "guide_id": "kisa-major-infrastructure-detailed-guide",
                "guide_version": "2026",
                "source_sha256": "a" * 64,
                "document_code": "KISA-2026-07-PC",
                "page_start": 555 + control_number,
                "page_end": 555 + control_number,
                "section_label": f"{control_id} 점검 항목",
                "mapping_status": "DRAFT",
            }
        ],
        "allowed_actions": ["조직의 보안 담당자와 설정 변경 여부를 확인하세요."],
        "assessment_kind": "DEVELOPMENT_DRAFT",
        "source_rule_result_sha256": f"{control_number:x}" * 64,
        "official_finding_write_allowed": False,
        "safety": {
            "raw_evidence_included": False,
            "sensitive_identifiers_included": False,
            "rule_status_unchanged": True,
            "internal_reason_code_user_visible": False,
        },
    }
    value["explanation_input_sha256"] = canonical_sha256_without_fields(
        cast(dict[str, JsonValue], value),
        {"explanation_input_sha256"},
    )
    return value


def _snapshot_payload() -> dict[str, object]:
    explanations = [_explanation(index) for index in range(1, 19)]
    ai: dict[str, object] = {
        "result_id": "0123456789abcdef",
        "result_version": 3,
        "observed_at_utc": "2026-07-26T04:00:00Z",
        "explanation_inputs": explanations,
        "ai_explanation": {
            "status": "GENERATED",
            "runtime_profile": "VLLM_COMPATIBILITY_TEST_DOUBLE",
            "external_data_transfer": True,
            "model_id": "openai/gpt-oss-120b",
            "prompt": {
                "template_id": "secai-result-analysis",
                "template_version": "1.0.0",
                "template_sha256": "b" * 64,
            },
            "explanation_input_sha256s": [
                str(item["explanation_input_sha256"]) for item in explanations
            ],
            "guide_evidence_sha256s": ["c" * 64],
            "input_sha256": "d" * 64,
            "model_output_sha256": "e" * 64,
            "official_results": [
                {
                    "control_id": str(item["control_id"]),
                    "rule_status": str(item["rule_status"]),
                    "status_authority": "RULE_ENGINE",
                }
                for item in explanations
            ],
            "summary": {
                "overall_state": "취약 항목 한 건을 먼저 확인하세요.",
                "related_risks": ["계정 탈취 위험이 커질 수 있습니다."],
                "user_actions": ["현재 설정을 확인하세요."],
                "administrator_actions": ["조직 정책을 확인하세요."],
                "limitations": ["승인 전 시험 판정입니다."],
            },
            "items": [],
            "citations": [],
            "safety": {
                "official_finding_write_allowed": False,
                "audit_pack_write_allowed": False,
                "rule_status_unchanged": True,
                "test_data_only": True,
            },
        },
        "test_environment_result": True,
    }
    explanation = cast(dict[str, object], ai["ai_explanation"])
    explanation["output_sha256"] = canonical_sha256_without_fields(
        cast(dict[str, JsonValue], explanation),
        {"output_sha256"},
    )
    return ai


def _model_capability() -> dict[str, object]:
    return {
        "runtime_profile": "VLLM_COMPATIBILITY_TEST_DOUBLE",
        "provider_kind": "OPENROUTER",
        "deployment_mode": "REMOTE_API",
        "model_id": "openai/gpt-oss-120b",
        "model_license": "Apache-2.0",
        "external_data_transfer": True,
        "local_model_loaded": False,
    }


def _administrator_result(control_number: int) -> dict[str, object]:
    control_id = f"PC-{control_number:02d}"
    return {
        "control_id": control_id,
        "probe_id": f"win.test.{control_number}",
        "collection_status": "COLLECTED",
        "assessment_status": "FAIL",
        "actual": f"{control_id} 관리자 권한 실측값",
        "expected": f"{control_id} 관리자 권한 기준",
        "assessment_kind": "DEVELOPMENT_DRAFT",
        "result_code": f"{control_id.replace('-', '_')}_ADMIN_FAIL",
        "judgement_explanation": "관리자 권한으로 수집한 값을 기준과 비교했습니다.",
    }


def test_snapshot_requires_exact_18_control_coverage_and_canonical_hashes() -> None:
    validated = validate_report_snapshot(_snapshot_payload())

    assert validated.result_id == "0123456789abcdef"
    assert len(validated.explanation_inputs) == 18
    assert validated.snapshot_sha256

    tampered = _snapshot_payload()
    cast(list[dict[str, object]], tampered["explanation_inputs"])[0][
        "observed_summary"
    ] = "변조됨"
    with pytest.raises(ReportContractError, match="EXPLANATION_INPUT_HASH_MISMATCH"):
        validate_report_snapshot(tampered)

    tampered_ai = _snapshot_payload()
    ai = cast(dict[str, object], tampered_ai["ai_explanation"])
    summary = cast(dict[str, object], ai["summary"])
    summary["overall_state"] = "변조된 AI 설명"
    with pytest.raises(ReportContractError, match="AI_OUTPUT_HASH_MISMATCH"):
        validate_report_snapshot(tampered_ai)


def test_user_report_excludes_internal_code_tool_and_technical_locator() -> None:
    snapshot = validate_report_snapshot(_snapshot_payload())
    manifest = build_model_manifest(_model_capability(), snapshot.ai_explanation)
    document = build_report_document(
        snapshot,
        ReportKind.USER,
        report_version=1,
        generated_at=datetime(2026, 7, 26, tzinfo=UTC),
        model_manifest=manifest,
    )
    text = "\n".join(document.lines)

    assert "AI 종합 설명" in text
    assert "KISA PC 보안 가이드 2026" in text
    assert "KISA-2026-07-PC" not in text
    assert "공식 판정 (규칙 엔진)" in text
    assert "[1] 내 PC 점검 결과" in text
    assert "[2] KISA PC 보안 가이드 2026" in text
    assert "[3] AI 일반 보안지식" in text
    assert "PC 보안 점검 판정 규칙" not in text
    assert "공식 판정 근거 아님·최신성 보장 안 됨" in text
    assert "PASSWORD_COMPLEXITY_NOT_OBSERVED" not in text
    assert "PowerShell:Get-SecAITest" not in text
    assert "sec-ai-one-shot-collector" not in text


def test_user_report_uses_collected_administrator_result_and_recomputed_hash() -> None:
    payload = _snapshot_payload()
    original_inputs = cast(list[dict[str, object]], payload["explanation_inputs"])
    original_pc02_hash = original_inputs[1]["explanation_input_sha256"]

    merged_inputs = merge_administrator_explanation_inputs(
        original_inputs,
        [_administrator_result(2)],
    )

    assert merged_inputs[1]["observed_summary"] == "PC-02 관리자 권한 실측값"
    assert merged_inputs[1]["rule_status"] == "FAIL"
    assert merged_inputs[1]["collection_limitations"] == []
    assert merged_inputs[1]["explanation_input_sha256"] != original_pc02_hash
    payload["explanation_inputs"] = merged_inputs
    payload["ai_explanation"] = None
    snapshot = validate_report_snapshot(payload)
    document = build_report_document(
        snapshot,
        ReportKind.USER,
        report_version=1,
        generated_at=datetime(2026, 8, 5, tzinfo=UTC),
        model_manifest=build_model_manifest(_model_capability(), None),
    )
    text = "\n".join(document.lines)
    pc02 = text.split("[PC-02]", 1)[1].split("[PC-03]", 1)[0]

    assert "PC-02 관리자 권한 실측값" in pc02
    assert "공식 판정 (규칙 엔진): FAIL" in pc02
    assert "관리자 권한이 필요한 자료를 아직 확인하지 못했습니다" not in pc02


def test_administrator_result_rejects_unknown_or_mismatched_probe() -> None:
    inputs = [_explanation(index) for index in range(1, 19)]
    unknown = _administrator_result(2)
    unknown["control_id"] = "PC-01"
    with pytest.raises(
        ResultAIExplanationError,
        match="ADMINISTRATOR_RESULT_COVERAGE_INVALID",
    ):
        merge_administrator_explanation_inputs(inputs, [unknown])

    mismatched = _administrator_result(2)
    mismatched["probe_id"] = "win.test.unrelated"
    with pytest.raises(
        ResultAIExplanationError,
        match="ADMINISTRATOR_RESULT_INPUT_INVALID",
    ):
        merge_administrator_explanation_inputs(inputs, [mismatched])


def test_user_report_has_structured_sections_without_obtrusive_warning() -> None:
    snapshot = validate_report_snapshot(_snapshot_payload())
    document = build_report_document(
        snapshot,
        ReportKind.USER,
        report_version=1,
        generated_at=datetime(2026, 8, 5, tzinfo=UTC),
        model_manifest=build_model_manifest(_model_capability(), snapshot.ai_explanation),
    )

    assert "현재 결과는 승인 전 시험 판정이며 공식 Finding이 아닙니다." not in document.lines
    assert any(line.startswith("판정 성격: ") for line in document.lines)

    layout = _PdfLayout(document)
    fill_count = sum(command.endswith(" re f") for command in layout.commands)
    section_start = layout.y
    layout.section("1. 점검 요약")
    assert sum(command.endswith(" re f") for command in layout.commands) > fill_count
    assert section_start - layout.y >= 50

    source_rectangles = sum(" re " in command for command in layout.commands)
    layout.source_heading()
    layout.source_line("[1]", "내 PC 점검 결과 · 실제 확인값")
    assert sum(" re " in command for command in layout.commands) == source_rectangles


def test_control_card_moves_before_core_rows_would_split_at_page_bottom() -> None:
    snapshot = validate_report_snapshot(_snapshot_payload())
    document = build_report_document(
        snapshot,
        ReportKind.USER,
        report_version=1,
        generated_at=datetime(2026, 8, 5, tzinfo=UTC),
        model_manifest=build_model_manifest(_model_capability(), snapshot.ai_explanation),
    )
    layout = _PdfLayout(document)
    layout.y = 150
    first_page_commands = len(layout.commands)

    _draw_control(
        layout,
        [
            "[PC-02] 비밀번호 관리정책 설정",
            "공식 판정 (규칙 엔진): ERROR",
            "무엇을 확인했나요: 비밀번호 길이·복잡성·재사용 정책",
            "내 PC에서 확인한 값: 관리자 권한이 필요한 자료를 확인하지 못했습니다.",
            "판정 기준: KISA 비밀번호 관리정책 기준 충족",
            "판정 이유: 필요한 자료가 없어 판정을 확정하지 않았습니다.",
        ],
    )

    assert len(layout.pages) == 2
    assert len(layout.pages[0]) == first_page_commands


def test_technical_report_contains_rule_lineage_hashes_and_model_disclosure() -> None:
    snapshot = validate_report_snapshot(_snapshot_payload())
    manifest = build_model_manifest(_model_capability(), snapshot.ai_explanation)
    document = build_report_document(
        snapshot,
        ReportKind.TECHNICAL,
        report_version=2,
        generated_at=datetime(2026, 7, 26, tzinfo=UTC),
        model_manifest=manifest,
    )
    text = "\n".join(document.lines)

    assert "PASSWORD_COMPLEXITY_NOT_OBSERVED" in text
    assert "PowerShell:Get-SecAITest" in text
    assert "sec-ai-one-shot-collector" in text
    assert "정규화 증적: actual_summary = 내 PC 실제값" in text
    assert "실제 증적 추적: win.test.1 · COLLECTED" in text
    assert "f" * 64 in text
    assert "원본 증적 포함: 아니요" in text
    assert snapshot.snapshot_sha256 in text
    assert "VLLM_COMPATIBILITY_TEST_DOUBLE" in text
    assert "Apache-2.0" in text
    assert "외부 전송: 예" in text
    assert "로컬 vLLM 공급망 검증: NOT_PREPARED" in text


def test_pdf_is_deterministic_korean_cid_pdf() -> None:
    snapshot = validate_report_snapshot(_snapshot_payload())
    manifest = build_model_manifest(_model_capability(), snapshot.ai_explanation)
    document = build_report_document(
        snapshot,
        ReportKind.USER,
        report_version=1,
        generated_at=datetime(2026, 7, 26, tzinfo=UTC),
        model_manifest=manifest,
    )

    first = render_pdf(document)
    second = render_pdf(document)

    assert first == second
    assert first.startswith(b"%PDF-1.4")
    assert b"/KSCms-UHC-H" in first
    assert b"/HYGoThic-Medium" in first
    assert b"/Type /FontDescriptor /FontName /HYGoThic-Medium" in first
    assert b"/HYSMyeongJo-Medium" not in first
    assert b" re f" in first
    assert b" re S" in first
    assert b"0.063 0.165 0.263 rg" in first
    assert first.rstrip().endswith(b"%%EOF")


def test_model_manifest_does_not_claim_remote_test_double_is_local_vllm() -> None:
    snapshot = validate_report_snapshot(_snapshot_payload())
    capability = _model_capability()
    capability["local_vllm_preparation"] = {
        "status": "PREPARED_NOT_ACTIVE",
        "image": "sec-ai-mvp/vllm-openai-gpu:0.23.0",
        "image_digest": (
            "sha256:"
            "48f9f370497eee3748a693c01030c82dbcee87a0db52f5e7901c9744787f4a00"
        ),
        "base_image_digest": (
            "sha256:"
            "3a1e7f5904e1a1192a02aa0086ceaffc33985d7044c7bb25b3a43d61bdbe3ac0"
        ),
    }
    manifest = build_model_manifest(capability, snapshot.ai_explanation)

    assert manifest["usage_type"] == "COMPATIBILITY_TEST"
    assert manifest["runtime_profile"] == "VLLM_COMPATIBILITY_TEST_DOUBLE"
    local_vllm = cast(dict[str, JsonValue], manifest["local_vllm"])
    assert local_vllm["image_digest"] == (
        "sha256:"
        "48f9f370497eee3748a693c01030c82dbcee87a0db52f5e7901c9744787f4a00"
    )
    assert (
        local_vllm["verification_status"]
        == "PREPARED_NOT_ACTIVE"
    )
    assert manifest["external_data_transfer"] is True

    capability_without_runtime = _model_capability()
    capability_without_runtime.pop("runtime_profile")
    inferred = build_model_manifest(capability_without_runtime, None)
    assert inferred["runtime_profile"] == "VLLM_COMPATIBILITY_TEST_DOUBLE"


def test_migration_and_ui_expose_append_only_owner_scoped_reports() -> None:
    migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0012_product_ai_08_result_reports.py"
    ).read_text(encoding="utf-8")
    api = (PROJECT_ROOT / "apps" / "api" / "result_reports.py").read_text(
        encoding="utf-8"
    )
    snapshot_variant_migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0022_result_report_snapshot_variants.py"
    ).read_text(encoding="utf-8")
    repository = (
        PROJECT_ROOT
        / "src"
        / "security_audit"
        / "persistence"
        / "database"
        / "result_report_repository.py"
    ).read_text(encoding="utf-8")
    template = (
        PROJECT_ROOT / "apps" / "web" / "templates" / "pages" / "product_results.html"
    ).read_text(encoding="utf-8")
    product_script = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "product-results.js"
    ).read_text(encoding="utf-8")

    assert "FORCE ROW LEVEL SECURITY" in migration
    assert "GRANT SELECT, INSERT" in migration
    assert "GRANT UPDATE" not in migration
    assert "GRANT DELETE" not in migration
    assert "snapshot_sha256" in snapshot_variant_migration
    assert "DROP CONSTRAINT uq_result_report_snapshot_identity" in snapshot_variant_migration
    assert "ResultReportSnapshotRecord.snapshot_sha256" in repository
    assert "snapshot: ResultReportSnapshotRecord" in repository
    assert "LargeBinary" in (
        PROJECT_ROOT / "src" / "security_audit" / "persistence" / "database" / "models.py"
    ).read_text(encoding="utf-8")
    assert "verify_browser_csrf" in api
    assert "Permission.EVIDENCE_DOWNLOAD" in api
    assert 'headers={"Content-Disposition":' in api
    assert 'id="download-user-report"' in template
    assert 'id="download-technical-report"' in template
    assert 'id="download-model-manifest"' not in template
    assert "AI 모델 활용 명세 받기" not in template
    assert "downloadModelManifest" not in product_script
    assert "download_model_manifest" not in api
    assert "model_manifest_url" not in api
    assert "administrator_results" in api
    assert "administrator_results:" in product_script


def test_dev_local_owner_receives_technical_report_role() -> None:
    bootstrap = (
        PROJECT_ROOT / "apps" / "api" / "auth_bootstrap.py"
    ).read_text(encoding="utf-8")

    assert '_SECURITY_OFFICER_ROLE_ID = UUID(' in bootstrap
    assert 'role_name="SECURITY_OFFICER"' in bootstrap
    assert 'role_name == "SECURITY_OFFICER"' in bootstrap
