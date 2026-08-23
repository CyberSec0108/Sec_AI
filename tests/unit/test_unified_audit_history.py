from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from security_audit.application.audit_history import (
    AuditHistoryContractError,
    AuditHistoryPolicy,
    attach_device_history_context,
    summarize_result_controls,
    validate_windows_audit_presentation,
    validate_windows_audit_snapshot,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _windows_result() -> dict[str, object]:
    statuses = ("PASS", "FAIL", "ERROR", "REVIEW", "N/A")
    controls: list[dict[str, object]] = []
    for index in range(1, 19):
        status = statuses[(index - 1) % len(statuses)]
        controls.append(
            {
                "control_id": f"PC-{index:02d}",
                "title": f"Windows 점검 항목 {index}",
                "importance": "상",
                "source": "KISA PC 보안 가이드 2026",
                "display_status": "EVIDENCE_COLLECTED",
                "status_label": "확인 완료",
                "checked_summary": "승인된 설정을 확인합니다.",
                "evidence_summary": "비식별 확인값입니다.",
                "action_guidance": "담당자 검토 후 조치합니다.",
                "administrator_required": False,
                "assessment_status": status,
                "assessment_label": status,
                "actual": "현재값",
                "expected": "기대값",
                "result_code": f"TEST_{status.replace('/', '_')}",
                "assessment_kind": "DRAFT",
            }
        )
    explanations = []
    ai_inputs = []
    for control in controls:
        control_id = str(control["control_id"])
        explanation: dict[str, JsonValue] = {
            "schema_version": "1.0.0",
            "control_id": control_id,
            "title": str(control["title"]),
            "official_status": str(control["assessment_status"]),
            "status_authority": "RULE_ENGINE",
            "observed_summary": "비식별 확인값",
            "expected_summary": "안전 기준",
            "judgement_explanation": "규칙 엔진 판정 설명",
        }
        explanation["presentation_sha256"] = canonical_sha256_without_fields(
            explanation,
            {"presentation_sha256"},
        )
        explanations.append(explanation)
        ai_input: dict[str, JsonValue] = {
            "schema_version": "1.0.0",
            "control_id": control_id,
            "title": str(control["title"]),
            "rule_status": str(control["assessment_status"]),
            "status_authority": "RULE_ENGINE",
            "observed_summary": "비식별 확인값",
            "expected_summary": "안전 기준",
            "judgement_explanation": "규칙 엔진 판정 설명",
            "safety": {
                "raw_evidence_included": False,
                "sensitive_identifiers_included": False,
                "rule_status_unchanged": True,
                "internal_reason_code_user_visible": False,
            },
        }
        ai_input["explanation_input_sha256"] = canonical_sha256_without_fields(
            ai_input,
            {"explanation_input_sha256"},
        )
        ai_inputs.append(ai_input)
    return {
        "result_id": "0123456789abcdef",
        "sequence": 3,
        "attempt": 3,
        "observed_at_utc": "2026-08-07T01:02:03Z",
        "controls": controls,
        "explanations": explanations,
        "ai_explanation_inputs": ai_inputs,
        "raw_values_persisted": False,
        "settings_modified": False,
        "official_finding_created": False,
        "result_kind": "LIVE_DRAFT_ASSESSMENT",
        "criteria_context": {"criteria_sha256": "a" * 64},
    }


def test_windows_history_snapshot_is_safe_deterministic_and_append_only_ready() -> None:
    first = validate_windows_audit_snapshot(_windows_result())
    second = validate_windows_audit_snapshot(_windows_result())

    assert first.result_id == "0123456789abcdef"
    assert first.result_version == 3
    assert first.observed_at == datetime(2026, 8, 7, 1, 2, 3, tzinfo=UTC)
    assert first.result_sha256 == second.result_sha256
    assert first.criteria_sha256 == "a" * 64
    assert len(cast(list[object], first.result_json["controls"])) == 18
    assert "vulnerability_inventory" not in first.result_json
    assert len(cast(list[object], first.result_json["official_explanations"])) == 18
    assert len(cast(list[object], first.result_json["ai_explanation_inputs"])) == 18
    assert first.counts == {
        "total": 18,
        "pass": 4,
        "fail": 4,
        "error": 4,
        "review": 3,
        "not_applicable": 3,
    }


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("raw_values_persisted", True, "RAW_VALUES_PERSISTED_FORBIDDEN"),
        ("settings_modified", True, "SETTINGS_MODIFIED_FORBIDDEN"),
        ("official_finding_created", True, "OFFICIAL_FINDING_WRITE_FORBIDDEN"),
        ("result_kind", "COLLECTION_GUIDANCE", "WINDOWS_RESULT_KIND_INVALID"),
    ),
)
def test_windows_history_snapshot_rejects_unsafe_or_non_assessed_results(
    field: str,
    value: object,
    code: str,
) -> None:
    result = _windows_result()
    result[field] = value

    with pytest.raises(AuditHistoryContractError, match=code):
        validate_windows_audit_snapshot(result)


def test_windows_history_snapshot_rejects_incomplete_or_duplicate_control_coverage() -> None:
    result = _windows_result()
    controls = list(cast(list[dict[str, object]], result["controls"]))
    controls[-1] = dict(controls[0])
    result["controls"] = controls

    with pytest.raises(AuditHistoryContractError, match="CONTROL_COVERAGE_INVALID"):
        validate_windows_audit_snapshot(result)


def test_result_summary_supports_existing_linux_and_switch_status_shape() -> None:
    counts = summarize_result_controls(
        {
            "controls": [
                {"control_id": "U-01", "status": "PASS"},
                {"control_id": "U-02", "status": "FAIL"},
                {"control_id": "U-03", "status": "N/A"},
            ]
        }
    )

    assert counts == {
        "total": 3,
        "pass": 1,
        "fail": 1,
        "error": 0,
        "review": 0,
        "not_applicable": 1,
    }


def test_history_policy_is_versioned_and_never_physically_deletes() -> None:
    policy = AuditHistoryPolicy(
        id=None,
        version=2,
        retention_days=730,
        backup_required=True,
        deletion_mode="TOMBSTONE_AFTER_BACKUP",
        created_at=None,
    )

    assert policy.public_view()["physical_delete_allowed"] is False
    assert policy.public_view()["retention_days"] == 730


def test_windows_completed_ai_and_administrator_screen_are_safe_append_payloads() -> None:
    administrator_report = {
        "status": "COMPLETED",
        "observed_at_utc": "2026-08-07T01:03:00Z",
        "selected_probe_count": 1,
        "collected_probe_count": 1,
        "review_required_count": 0,
        "collection_error_count": 0,
        "assessment_review_count": 0,
        "results": [
            {
                "control_id": "PC-02",
                "probe_id": "win.security.password-policy",
                "title": "비밀번호 관리정책 설정",
                "collection_status": "COLLECTED",
                "assessment_status": "PASS",
                "actual": "비식별 현재값",
                "expected": "안전 기준",
                "assessment_kind": "DRAFT",
                "result_code": "PASSWORD_POLICY_PASS",
                "judgement_explanation": "관리자 자료를 규칙으로 판정했습니다.",
            }
        ],
        "settings_modified": False,
        "raw_values_persisted": False,
        "official_finding_created": False,
    }
    ai_screen = {
        "version": 1,
        "generation_key": "0123456789abcdef:3:PC-02:COLLECTED:PASS",
        "summary_source": "## 전체 설명\n\n저장된 종합 설명입니다.[1]",
        "controls": [
            {
                "control_id": f"PC-{index:02d}",
                "source": f"## 항목 설명\n\nPC-{index:02d} 저장 설명입니다.[1]",
                "knowledge_sources": [],
            }
            for index in range(1, 19)
        ],
    }

    admin = validate_windows_audit_presentation(
        {
            "result_id": "0123456789abcdef",
            "result_version": 3,
            "presentation_kind": "ADMINISTRATOR",
            "administrator_report": administrator_report,
            "test_environment_result": True,
        }
    )
    completed = validate_windows_audit_presentation(
        {
            "result_id": "0123456789abcdef",
            "result_version": 3,
            "presentation_kind": "AI_COMPLETED",
            "administrator_report": administrator_report,
            "ai_screen": ai_screen,
            "test_environment_result": True,
        }
    )

    assert admin.presentation_kind == "ADMINISTRATOR"
    assert completed.presentation_kind == "AI_COMPLETED"
    assert completed.payload["ai_screen"] == ai_screen
    assert admin.payload_sha256 != completed.payload_sha256


def test_linux_and_switch_result_context_includes_official_and_ai_inputs() -> None:
    result: dict[str, object] = {
        "schema_version": "1.0.0",
        "controls": [{"control_id": "U-01", "status": "PASS"}],
        "result_sha256": "a" * 64,
    }
    official: list[dict[str, object]] = [
        {"control_id": "U-01", "status_authority": "RULE_ENGINE"}
    ]
    ai_inputs: list[dict[str, object]] = [
        {"control_id": "U-01", "observed_summary": "비식별 값"}
    ]

    enriched = attach_device_history_context(
        result,
        official_explanations=official,
        ai_explanation_inputs=ai_inputs,
    )

    assert enriched["official_explanations"] == official
    assert enriched["ai_explanation_inputs"] == ai_inputs
    assert enriched["result_sha256"] != "a" * 64


def test_migration_and_web_contract_expose_owner_scoped_unified_history() -> None:
    migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0031_unified_audit_history.py"
    ).read_text(encoding="utf-8")
    result_center = (
        PROJECT_ROOT / "apps" / "web" / "templates" / "pages" / "result_center.html"
    ).read_text(encoding="utf-8")
    script = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "audit-history.js"
    ).read_text(encoding="utf-8")
    windows_script = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "product-results.js"
    ).read_text(encoding="utf-8")
    presentation_migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0033_windows_audit_presentations.py"
    ).read_text(encoding="utf-8")
    integrated_script = (
        PROJECT_ROOT
        / "apps"
        / "web"
        / "static"
        / "app"
        / "product-results-integrated.js"
    ).read_text(encoding="utf-8")
    detail_template = (
        PROJECT_ROOT
        / "apps"
        / "web"
        / "templates"
        / "pages"
        / "audit_history_detail.html"
    ).read_text(encoding="utf-8")
    detail_script = (
        PROJECT_ROOT
        / "apps"
        / "web"
        / "static"
        / "app"
        / "audit-history-detail.js"
    ).read_text(encoding="utf-8")

    assert "CREATE TABLE windows_audit_snapshots" in migration
    assert "CREATE TABLE audit_history_policies" in migration
    assert "ENABLE ROW LEVEL SECURITY" in migration
    assert "owner_user_id = NULLIF(current_setting('secai.user_id'" in migration
    assert "BEFORE UPDATE OR DELETE" in migration
    assert 'id="audit-history-list"' in result_center
    assert '"/api/v1/audit-history"' in script
    assert '"/api/v1/audit-history/windows"' in windows_script
    assert "CREATE TABLE windows_audit_presentations" in presentation_migration
    assert "ENABLE ROW LEVEL SECURITY" in presentation_migration
    assert "BEFORE UPDATE OR DELETE" in presentation_migration
    assert '"/api/v1/audit-history/windows/presentation"' in windows_script
    assert "loadServerCompletedSnapshot" in integrated_script
    assert "secai:windows-ai-snapshot-completed" in integrated_script
    assert "AI 입력 snapshot 확인" in detail_template
    assert "저장된 관리자 권한 점검 화면" in detail_template
    assert "SecAIRestrictedMarkdown" in detail_script
    assert '"/api/v1/audit-history/"' in detail_script
