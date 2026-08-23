from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast

from apps.api.result_ai_explanation import _merge_administrator_explanation_inputs

from security_audit.application.administrator_scan import build_administrator_results
from security_audit.application.assessment_criteria import (
    build_effective_criteria,
    canonical_criteria_sha256,
)
from security_audit.application.current_host_regression import (
    ProbeObservation,
    evaluate_live_draft_observations,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ADMINISTRATOR_SCRIPT = (
    PROJECT_ROOT
    / "collectors"
    / "one_shot"
    / "probes"
    / "windows"
    / "powershell"
    / "imp031_administrator_controls.ps1"
)


def _criteria_context(
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


def _observation(
    probe_id: str,
    records: tuple[dict[str, JsonValue], ...],
    *,
    collected_at: str = "2026-08-05T10:00:00Z",
    privilege: str = "ADMINISTRATOR",
) -> ProbeObservation:
    adapters = {
        "win.security.password-policy": "secai.windows-account-policy",
        "win.network.smb-shares": "secai.windows-smb-native",
        "win.services.inventory": "secai.windows-service-control-manager",
        "win.software.messengers": "secai.windows-installed-software-inventory",
        "win.boot.entries": "secai.windows-bcdedit-native",
        "win.update.compliance": "secai.windows-update-history-build",
    }
    return ProbeObservation(
        probe_id=probe_id,
        collection_status="COLLECTED",
        error_code="NONE",
        adapter_id=adapters[probe_id],
        adapter_version="0.1.0",
        privilege=privilege,
        collected_at=collected_at,
        records=records,
    )


def _administrator_observations() -> tuple[ProbeObservation, ...]:
    return (
        _observation(
            "win.security.password-policy",
            (
                {
                    "minimum_password_length": 12,
                    "maximum_password_age_days": 60,
                    "complexity_enabled": True,
                    "password_required": True,
                    "policy_source": "WINDOWS_EFFECTIVE",
                },
            ),
        ),
        _observation(
            "win.network.smb-shares",
            (
                {
                    "record_type": "SUMMARY",
                    "share_count": 0,
                    "regular_share_count": 0,
                    "default_admin_share_count": 0,
                    "unrestricted_everyone_share_count": 0,
                    "broad_write_share_count": 0,
                    "auto_share_wks_disabled": True,
                },
            ),
        ),
        _observation(
            "win.software.messengers",
            (
                {
                    "record_type": "SUMMARY",
                    "installed_product_count": 120,
                    "messenger_catalog_count": 10,
                    "detected_messenger_product_count": 0,
                    "running_messenger_product_count": 0,
                    "low_confidence_match_count": 0,
                },
            ),
        ),
        _observation(
            "win.boot.entries",
            (
                {
                    "record_type": "SUMMARY",
                    "bootable_os_count": 1,
                    "parser_profile": "BCDEDIT_OSLOADER_WINLOAD_BLOCK_COUNT_WITH_NAMES",
                },
                {
                    "record_type": "BOOT_ENTRY",
                    "display_name": "Windows 11",
                    "entry_identifier": "{current}",
                },
            ),
        ),
        _observation(
            "win.update.compliance",
            (
                {
                    "product_name": "Windows 11 Pro",
                    "display_version": "24H2",
                    "edition_group": "Professional",
                    "os_build": "26100",
                    "ubr": 1,
                    "update_inventory_source": "WINDOWS_UPDATE_HISTORY_AND_BUILD",
                    "history_record_count": 20,
                    "latest_history_at": "2026-08-01T10:00:00Z",
                    "automatic_updates_enabled": True,
                    "restart_pending": False,
                },
            ),
        ),
    )


def test_product_default_scope_is_non_empty_for_pc05() -> None:
    default_ids = cast(
        list[str],
        build_effective_criteria()["unnecessary_service_ids"]["value"],
    )

    assert len(default_ids) >= 5
    assert "RemoteRegistry" in default_ids


def test_administrator_five_are_collected_and_decided_with_default_scope() -> None:
    observations = _administrator_observations()
    assessments = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=observations,
        criteria_context=_criteria_context(),
    )

    control_ids = ("PC-02", "PC-04", "PC-06", "PC-08", "PC-10")
    assert {assessments[item]["status"] for item in control_ids} == {"PASS"}
    assert all(
        assessments[item]["result_code"]
        not in {
            "ORGANIZATION_PASSWORD_STANDARD_REQUIRED",
            "ORGANIZATION_SHARE_STANDARD_REQUIRED",
            "ORGANIZATION_MESSENGER_STANDARD_REQUIRED",
            "PATCH_BASELINE_REVIEW_REQUIRED",
        }
        for item in control_ids
    )

    receipt = {
        "observed_at_utc": "2026-08-05T10:00:00Z",
        "explicit_consent": True,
        "selected_probe_ids": [item.probe_id for item in observations],
        "settings_diff_count": 0,
        "results": [
            {
                "probe_id": item.probe_id,
                "control_ids": [control_id],
                "privilege": "ADMINISTRATOR",
                "collection_status": "COLLECTED",
                "error_code": "NONE",
                "record_count": len(item.records),
            }
            for item, control_id in zip(observations, control_ids, strict=True)
        ],
    }
    result = build_administrator_results(receipt, assessments=assessments)
    rows = cast(list[dict[str, object]], result["results"])

    assert result["collected_probe_count"] == 5
    assert result["collection_error_count"] == 0
    assert result["assessment_review_count"] == 0
    assert [row["collection_status"] for row in rows] == ["COLLECTED"] * 5
    assert [row["assessment_status"] for row in rows] == ["PASS"] * 5


def test_pc05_uses_collected_services_instead_of_hardcoded_zero() -> None:
    stopped = _observation(
        "win.services.inventory",
        (
            {
                "service_key": "RemoteRegistry",
                "state": "STOPPED",
                "start_mode": "DISABLED",
            },
            {
                "service_key": "EventLog",
                "state": "RUNNING",
                "start_mode": "AUTO",
            },
        ),
        privilege="STANDARD_USER",
    )
    running = _observation(
        "win.services.inventory",
        (
            {
                "service_key": "RemoteRegistry",
                "state": "RUNNING",
                "start_mode": "AUTO",
            },
        ),
        privilege="STANDARD_USER",
    )

    stopped_result = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=(stopped,),
        criteria_context=_criteria_context(),
    )["PC-05"]
    running_result = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=(running,),
        criteria_context=_criteria_context(),
    )["PC-05"]

    assert stopped_result["status"] == "PASS"
    assert running_result["status"] == "FAIL"
    assert "실행 1개" in cast(str, running_result["actual"])


def test_pc04_and_pc06_compare_private_identifiers_with_selected_criteria() -> None:
    share_name = "WorkDocs"
    share_hash = hashlib.sha256(share_name.lower().encode("utf-8")).hexdigest()
    share_observation = _observation(
        "win.network.smb-shares",
        (
            {
                "record_type": "SUMMARY",
                "share_count": 1,
                "regular_share_count": 1,
                "default_admin_share_count": 0,
                "unrestricted_everyone_share_count": 0,
                "broad_write_share_count": 0,
                "auto_share_wks_disabled": True,
            },
            {
                "record_type": "REGULAR_SHARE",
                "share_name_sha256": share_hash,
                "everyone_full_access": False,
                "broad_write_access": False,
            },
        ),
    )
    messenger_observation = _observation(
        "win.software.messengers",
        (
            {
                "record_type": "SUMMARY",
                "installed_product_count": 120,
                "messenger_catalog_count": 10,
                "detected_messenger_product_count": 1,
                "running_messenger_product_count": 1,
                "low_confidence_match_count": 0,
            },
            {
                "record_type": "MESSENGER_MATCH",
                "catalog_id": "MICROSOFT_TEAMS",
                "display_name": "Microsoft Teams",
                "installed": True,
                "running": True,
                "match_confidence": "HIGH",
            },
        ),
    )

    default_result = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=(share_observation, messenger_observation),
        criteria_context=_criteria_context(),
    )
    approved_result = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=(share_observation, messenger_observation),
        criteria_context=_criteria_context(
            personal_values={
                "approved_share_ids": [share_name],
                "approved_messenger_products": ["Microsoft Teams"],
            }
        ),
    )

    assert default_result["PC-04"]["status"] == "FAIL"
    assert default_result["PC-06"]["status"] == "FAIL"
    assert approved_result["PC-04"]["status"] == "PASS"
    assert approved_result["PC-06"]["status"] == "PASS"


def test_pc06_actual_value_lists_small_messenger_sets_and_limits_large_sets() -> None:
    names = (
        "KakaoTalk",
        "Telegram Desktop",
        "LINE",
        "WhatsApp",
        "Discord",
        "Slack",
    )

    def observation(selected: tuple[str, ...]) -> ProbeObservation:
        matches: tuple[dict[str, JsonValue], ...] = tuple(
            {
                "record_type": "MESSENGER_MATCH",
                "catalog_id": name.upper().replace(" ", "_"),
                "display_name": name,
                "installed": True,
                "running": index == 0,
                "match_confidence": "HIGH",
            }
            for index, name in enumerate(selected)
        )
        return _observation(
            "win.software.messengers",
            (
                {
                    "record_type": "SUMMARY",
                    "installed_product_count": 650,
                    "messenger_catalog_count": 10,
                    "detected_messenger_product_count": len(selected),
                    "running_messenger_product_count": 1,
                    "low_confidence_match_count": 0,
                },
                *matches,
            ),
        )

    small = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=(observation(names[:2]),),
        criteria_context=_criteria_context(),
    )["PC-06"]
    large = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=(observation(names),),
        criteria_context=_criteria_context(),
    )["PC-06"]

    assert "메신저 2개(KakaoTalk, Telegram Desktop)" in cast(str, small["actual"])
    assert "실행 1개(KakaoTalk)" in cast(str, small["actual"])
    assert "미승인 2개(KakaoTalk, Telegram Desktop)" in cast(str, small["actual"])
    assert "메신저 6개(KakaoTalk, Telegram Desktop, LINE, WhatsApp, Discord 외 1개)" in cast(
        str, large["actual"]
    )
    assert "Slack" not in cast(str, large["actual"])


def test_pc08_actual_value_lists_collected_boot_entry_names() -> None:
    observation = _observation(
        "win.boot.entries",
        (
            {
                "record_type": "SUMMARY",
                "bootable_os_count": 3,
                "parser_profile": "BCDEDIT_OSLOADER_WINLOAD_BLOCKS_WITH_NAMES",
            },
            {
                "record_type": "BOOT_ENTRY",
                "display_name": "Windows 11",
                "entry_identifier": "{current}",
            },
            {
                "record_type": "BOOT_ENTRY",
                "display_name": "Windows 11 테스트",
                "entry_identifier": "{11111111-1111-1111-1111-111111111111}",
            },
            {
                "record_type": "BOOT_ENTRY",
                "display_name": "Windows 10",
                "entry_identifier": "{22222222-2222-2222-2222-222222222222}",
            },
        ),
    )

    result = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=(observation,),
        criteria_context=_criteria_context(),
    )["PC-08"]

    assert result["status"] == "FAIL"
    assert (
        "부팅 가능한 운영체제 항목 3개(Windows 11({current}), "
        "Windows 11 테스트({11111111-1111-1111-1111-111111111111}), "
        "Windows 10({22222222-2222-2222-2222-222222222222}))"
        == result["actual"]
    )


def test_pc08_collector_preserves_boot_entry_name_and_identifier() -> None:
    source = ADMINISTRATOR_SCRIPT.read_text(encoding="ascii")

    assert 'record_type = "BOOT_ENTRY"' in source
    assert "display_name" in source
    assert "entry_identifier" in source


def test_pc10_no_successful_update_history_is_a_fail_not_a_collection_error() -> None:
    observation = _observation(
        "win.update.compliance",
        (
            {
                "product_name": "Windows 11 Pro",
                "display_version": "24H2",
                "edition_group": "Professional",
                "os_build": "26100",
                "ubr": 1,
                "update_inventory_source": "WINDOWS_UPDATE_HISTORY_AND_BUILD",
                "history_record_count": 0,
                "successful_install_history_count": 0,
                "latest_history_at": None,
                "automatic_updates_enabled": True,
                "restart_pending": False,
            },
        ),
    )

    result = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=(observation,),
        criteria_context=_criteria_context(),
    )["PC-10"]

    assert result["status"] == "FAIL"
    assert result["result_code"] == "NO_SUCCESSFUL_UPDATE_HISTORY"


def test_administrator_rows_replace_ai_rule_inputs_and_rehash_all_five() -> None:
    observations = _administrator_observations()
    assessments = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=observations,
        criteria_context=_criteria_context(),
    )
    controls = ("PC-02", "PC-04", "PC-06", "PC-08", "PC-10")
    receipt = {
        "observed_at_utc": "2026-08-05T10:00:00Z",
        "explicit_consent": True,
        "selected_probe_ids": [item.probe_id for item in observations],
        "settings_diff_count": 0,
        "results": [
            {
                "probe_id": item.probe_id,
                "control_ids": [control_id],
                "privilege": "ADMINISTRATOR",
                "collection_status": "COLLECTED",
                "error_code": "NONE",
                "record_count": len(item.records),
            }
            for item, control_id in zip(observations, controls, strict=True)
        ],
    }
    rows = cast(
        list[dict[str, object]],
        build_administrator_results(receipt, assessments=assessments)["results"],
    )
    original = [
        {
            "control_id": control_id,
            "rule_status": "ERROR",
            "observed_summary": "관리자 자료 미수집",
            "expected_summary": "관리자 자료 수집",
            "assessment_kind": "DEVELOPMENT_DRAFT",
            "result_code": "LIVE_DRAFT_EVIDENCE_NOT_COLLECTED",
            "judgement_explanation": "관리자 점검 전입니다.",
            "collection_methods": [
                {
                    "probe_id": observation.probe_id,
                    "collection_status": "UNSUPPORTED",
                }
            ],
            "collection_limitations": ["관리자 자료 미수집"],
            "source_rule_result_sha256": "a" * 64,
            "explanation_input_sha256": "b" * 64,
        }
        for control_id, observation in zip(controls, observations, strict=True)
    ]

    merged = _merge_administrator_explanation_inputs(original, rows)

    assert [item["rule_status"] for item in merged] == ["PASS"] * 5
    assert all(item["collection_limitations"] == [] for item in merged)
    assert "Windows 11({current})" in cast(str, merged[3]["observed_summary"])
    assert all(
        item["explanation_input_sha256"]
        == canonical_sha256_without_fields(
            cast(dict[str, JsonValue], item),
            {"explanation_input_sha256"},
        )
        for item in merged
    )


def test_administrator_script_avoids_the_reproduced_strict_mode_failures() -> None:
    source = ADMINISTRATOR_SCRIPT.read_text(encoding="ascii")

    assert ".MinPasswordLength.Value" not in source
    assert ".MaxPasswordAge.Value" not in source
    assert "$_.DisplayName" not in source
    assert "$autoShare.AutoShareWks" not in source
    assert "$auPolicy.NoAutoUpdate" not in source
    assert "BCDEDIT_OSLOADER_WINLOAD_BLOCK_COUNT" in source
    assert "\\winload" in source.casefold()
    assert "if ($currentBlock.Count -gt 0)" in source
    assert "Get-SecAiBootEntryRecord -Lines @($currentBlock)" in source
    for field in (
        "share_name_sha256",
        "broad_write_share_count",
        "everyone_full_access",
        "broad_write_access",
        "messenger_catalog_count",
        "detected_messenger_product_count",
        "running_messenger_product_count",
        "low_confidence_match_count",
        "match_confidence",
    ):
        assert field in source
    assert "PasswordComplexity" in source
    assert "/mergedpolicy" not in source
    assert "Operation" in source
    assert "ResultCode" in source


def test_product_uses_saved_organization_default_and_preserves_review_status() -> None:
    product = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "product.js"
    ).read_text(encoding="utf-8")
    results = (
        PROJECT_ROOT
        / "apps"
        / "web"
        / "static"
        / "app"
        / "product-results.js"
    ).read_text(encoding="utf-8")

    assert "selection_kind=KISA_DEFAULT" not in product
    assert 'return value === "REVIEW" ? "ERROR"' not in results
    assert 'REVIEW: "기준 확인 필요"' in results
    assert "KISA·제품 기본값" in results
    assert 'data.selected_kind === "ORGANIZATION"' in results
