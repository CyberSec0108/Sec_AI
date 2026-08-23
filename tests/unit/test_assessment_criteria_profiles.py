from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from security_audit.application.assessment_criteria import (
    DEFAULT_UNNECESSARY_SERVICE_IDS,
    CriteriaContractError,
    build_effective_criteria,
    canonical_criteria_sha256,
    decode_criteria_execution_context,
    encode_criteria_execution_context,
    validate_criteria_values,
)
from security_audit.application.current_host_regression import (
    ProbeObservation,
    evaluate_live_draft_observations,
)
from security_audit.collector.criteria_contract import (
    decode_criteria_execution_context as decode_collector_criteria_context,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _execution_context(
    *,
    personal_values: dict[str, object] | None = None,
) -> dict[str, object]:
    effective = build_effective_criteria(personal_values=personal_values)
    values = {key: item["value"] for key, item in effective.items()}
    return {
        "values": values,
        "sources": {key: item["source"] for key, item in effective.items()},
        "criteria_sha256": canonical_criteria_sha256(values),
        "organization_profile": None,
        "personal_profile": None,
    }


def test_effective_criteria_uses_organization_then_personal_precedence() -> None:
    effective = build_effective_criteria(
        organization_values={"password_minimum_length": 12},
        personal_values={"password_minimum_length": 14},
    )

    item = effective["password_minimum_length"]
    assert item["value"] == 14
    assert item["source"] == "PERSONAL"
    assert item["official_value"] == 10
    assert item["strength"] == "STRONGER"


def test_personal_setting_never_replaces_official_reference() -> None:
    effective = build_effective_criteria(
        organization_values={"password_maximum_age_days": 60},
        personal_values={"password_maximum_age_days": 120},
    )

    item = effective["password_maximum_age_days"]
    assert item["value"] == 120
    assert item["official_value"] == 90
    assert item["strength"] == "WEAKER"
    assert item["official_reference"] == "KISA PC 보안 가이드 2026"


def test_pc05_has_a_nonempty_product_default_without_claiming_a_kisa_catalog() -> None:
    effective = build_effective_criteria(
        organization_values={"password_minimum_length": 12},
        personal_values={"password_maximum_age_days": 60},
    )

    item = effective["unnecessary_service_ids"]
    assert item["value"] == list(DEFAULT_UNNECESSARY_SERVICE_IDS)
    assert "RemoteRegistry" in item["value"]
    assert len(item["value"]) >= 5
    assert item["source"] == "KISA_DEFAULT"
    assert item["official_reference"] == (
        "SecAI Windows 10·11 최소 기본 점검 범위 (KISA PC-05 보조)"
    )


def test_pc05_default_is_sent_by_both_contracts_and_rendered_in_the_form() -> None:
    context = _execution_context()
    encoded = encode_criteria_execution_context(context)

    assert decode_criteria_execution_context(encoded) == context
    assert decode_collector_criteria_context(encoded) == context
    template = (
        PROJECT_ROOT / "apps/web/templates/components/criteria_form.html"
    ).read_text(encoding="utf-8")
    api = (PROJECT_ROOT / "apps/api/assessment_criteria.py").read_text(
        encoding="utf-8"
    )
    collector_contract = (
        PROJECT_ROOT / "src/security_audit/collector/criteria_contract.py"
    ).read_text(encoding="utf-8")

    assert 'name="unnecessary_service_ids"' in template
    assert "KISA가 특정 서비스 이름을 직접 열거한 목록이 아닙니다" in template
    assert '"unnecessary_service_ids"' in api
    assert '"unnecessary_service_ids"' in collector_contract


def test_product_defaults_cover_scope_dependent_windows_controls() -> None:
    effective = build_effective_criteria()

    assert effective["wininet_current_user_scope_accepted"]["value"] is True
    assert effective["screensaver_current_user_scope_accepted"]["value"] is True
    assert effective["autoplay_disabled_required"]["value"] is True
    assert effective["remote_assistance_disabled_required"]["value"] is True
    assert effective["antivirus_signature_maximum_age_hours"]["value"] == 24
    assert all(
        effective[key]["official_reference"].startswith("SecAI Windows 10·11")
        for key in (
            "wininet_current_user_scope_accepted",
            "screensaver_current_user_scope_accepted",
            "autoplay_disabled_required",
            "remote_assistance_disabled_required",
            "antivirus_signature_maximum_age_hours",
        )
    )


def test_product_defaults_make_collected_scope_controls_deterministic() -> None:
    def observation(
        probe_id: str,
        record: dict[str, object],
        *,
        user_sid: str | None = None,
    ) -> ProbeObservation:
        return ProbeObservation(
            probe_id=probe_id,
            collection_status="COLLECTED",
            error_code="NONE",
            adapter_id="secai.windows-registry",
            adapter_version="0.1.0",
            privilege="STANDARD_USER",
            collected_at="2026-08-05T01:02:03Z",
            records=(record,),
            user_sid=user_sid,
        )

    assessments = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=(
            observation(
                "win.browser.wininet-cache-policy",
                {
                    "applicability": "APPLICABLE",
                    "empty_cache_on_exit": True,
                    "evaluated_user_count": 1,
                    "user_coverage_complete": False,
                    "policy_source": "CURRENT_USER",
                },
            ),
            observation(
                "win.antivirus.update-status",
                {
                    "product_id": "MICROSOFT_DEFENDER_ANTIVIRUS",
                    "product_name": "Microsoft Defender Antivirus",
                    "product_present": True,
                    "product_state": "ACTIVE",
                    "service_enabled": True,
                    "operating_mode": "Normal",
                    "engine_version": "1.1.1",
                    "signature_version": "1.2.3",
                    "signature_updated_at": "2026-08-05T00:02:03Z",
                    "automatic_updates_enabled": None,
                    "real_time_protection_enabled": True,
                    "health_state": "HEALTHY",
                },
            ),
            observation(
                "win.user.screensaver-policy",
                {
                    "subject_id": "CURRENT_USER",
                    "screen_save_active": "1",
                    "screen_save_timeout_seconds": 300,
                    "screen_saver_is_secure": "1",
                    "screen_saver_executable_present": True,
                    "effective_policy_source": "CURRENT_USER",
                    "user_coverage_complete": False,
                },
                user_sid="S-1-5-21-1000",
            ),
            observation(
                "win.media.autoplay-policy",
                {
                    "turn_off_autoplay_enabled": True,
                    "autoplay_scope": "ALL_DRIVES",
                    "autorun_default_behavior": "DO_NOT_EXECUTE",
                    "non_volume_autoplay_disallowed": True,
                    "effective_policy_source": "WINDOWS_EFFECTIVE",
                },
            ),
            observation(
                "win.remote-assistance.policy",
                {
                    "f_allow_to_get_help": "MISSING",
                    "f_allow_unsolicited": "MISSING",
                    "effective_policy_source": "WINDOWS_EFFECTIVE",
                },
            ),
        ),
        criteria_context=_execution_context(),
    )

    assert assessments["PC-09"]["status"] == "PASS"
    assert assessments["PC-13"]["status"] == "PASS"
    assert assessments["PC-16"]["status"] == "PASS"
    assert assessments["PC-17"]["status"] == "PASS"
    assert assessments["PC-18"]["status"] == "FAIL"


def test_unknown_or_wrong_typed_criterion_is_rejected() -> None:
    with pytest.raises(CriteriaContractError, match="허용되지 않은"):
        validate_criteria_values({"powershell_command": "Get-Item HKLM:"})

    with pytest.raises(CriteriaContractError, match="정수"):
        validate_criteria_values({"password_minimum_length": True})

    with pytest.raises(CriteriaContractError, match="한 개 이상"):
        validate_criteria_values({"unnecessary_service_ids": []})


def test_criteria_hash_is_independent_from_input_order() -> None:
    left = {
        "password_minimum_length": 12,
        "password_complexity_required": True,
    }
    right = {
        "password_complexity_required": True,
        "password_minimum_length": 12,
    }

    assert canonical_criteria_sha256(left) == canonical_criteria_sha256(right)


def test_execution_context_round_trip_rejects_a_changed_value() -> None:
    context = _execution_context(personal_values={"password_minimum_length": 14})

    assert decode_criteria_execution_context(
        encode_criteria_execution_context(context)
    ) == context

    context_values = cast(dict[str, object], context["values"])
    context_values["password_minimum_length"] = 8
    with pytest.raises(CriteriaContractError, match="확인값"):
        encode_criteria_execution_context(context)


def test_personal_criterion_is_separate_from_official_kisa_decision() -> None:
    assessments = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=(
            ProbeObservation(
                probe_id="win.security.password-age",
                collection_status="COLLECTED",
                error_code="NONE",
                adapter_id="secai.windows-native",
                adapter_version="0.1.0",
                privilege="STANDARD_USER",
                collected_at="2026-08-02T01:02:03Z",
                records=(
                    {
                        "maximum_password_age_days": 42,
                        "policy_defined": True,
                        "policy_source": "WINDOWS_EFFECTIVE",
                    },
                ),
            ),
        ),
        criteria_context=_execution_context(
            personal_values={"password_maximum_age_days": 30}
        ),
    )

    pc01 = assessments["PC-01"]
    additional = cast(dict[str, object], pc01["additional_criteria"])
    assert pc01["status"] == "PASS"
    assert additional["status"] == "FAIL"


def test_criteria_access_is_in_account_page_not_top_navigation() -> None:
    header = (PROJECT_ROOT / "apps/web/templates/components/audit_ui.html").read_text(
        encoding="utf-8"
    )
    session = (PROJECT_ROOT / "apps/web/templates/pages/session.html").read_text(
        encoding="utf-8"
    )

    assert '>점검 기준</a>' not in header
    assert 'href="/ui/criteria">내 점검 기준 선택·관리</a>' in session


def test_personal_and_organization_forms_can_restore_kisa_values() -> None:
    personal = (
        PROJECT_ROOT / "apps/web/templates/pages/assessment_criteria.html"
    ).read_text(encoding="utf-8")
    organization = (
        PROJECT_ROOT / "apps/web/templates/pages/admin_assessment_criteria.html"
    ).read_text(encoding="utf-8")
    reset_script = (
        PROJECT_ROOT / "apps/web/static/app/criteria-reset.js"
    ).read_text(encoding="utf-8")

    assert 'formaction="/ui/criteria/personal/reset"' in personal
    assert 'formaction="/admin/criteria/reset"' in organization
    assert "기본 점검값 선택" in personal
    assert "기본 점검값으로 되돌리기" in organization
    for page in (personal, organization):
        assert "/static/app/criteria-reset.js" in page
    assert "KISA 기준과 SecAI 보조 기본 범위를 적용" in reset_script
    assert "secai_selected_criteria_profile" in reset_script
