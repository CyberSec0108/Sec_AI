from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from security_audit.application.current_host_regression import (
    ProbeObservation,
    evaluate_current_host_observations,
)
from security_audit.common.canonical_json import JsonValue

PROJECT_ROOT = Path(__file__).resolve().parents[2]
COLLECTED_AT = "2026-07-23T12:00:00Z"


def _observation(
    probe_id: str,
    record: dict[str, object] | None,
    *,
    adapter_id: str = "secai.windows-registry",
    privilege: str = "STANDARD_USER",
) -> ProbeObservation:
    return ProbeObservation(
        probe_id=probe_id,
        collection_status="COLLECTED" if record is not None else "ERROR",
        error_code="NONE" if record is not None else "QUERY_FAILED",
        adapter_id=adapter_id,
        adapter_version="0.1.0",
        privilege=privilege,
        collected_at=COLLECTED_AT,
        records=(
            ()
            if record is None
            else (cast(Mapping[str, JsonValue], record),)
        ),
        user_sid="S-1-5-21-1000" if probe_id == "win.user.screensaver-policy" else None,
    )


def _observations() -> list[ProbeObservation]:
    observations = [
        _observation(
            "win.security.password-age",
            {
                "maximum_password_age_days": 90,
                "policy_defined": True,
                "policy_source": "WINDOWS_EFFECTIVE",
            },
            adapter_id="secai.windows-native",
        ),
        _observation(
            "win.security.password-policy",
            None,
            adapter_id="secai.windows-account-policy",
            privilege="ADMINISTRATOR",
        ),
        _observation(
            "win.security.recovery-console",
            {
                "automatic_admin_logon": "NOT_DEFINED",
                "policy_defined": False,
                "policy_source": "WINDOWS_EFFECTIVE",
                "os_edition": "Professional",
                "os_build": "26200",
            },
        ),
        _observation(
            "win.network.smb-shares",
            None,
            adapter_id="secai.windows-smb-native",
            privilege="ADMINISTRATOR",
        ),
        _observation(
            "win.services.inventory",
            {"service_key": "EventLog", "state": "RUNNING", "start_mode": "AUTO"},
            adapter_id="secai.windows-service-control-manager",
        ),
        _observation(
            "win.software.messengers",
            None,
            adapter_id="secai.windows-installed-software-inventory",
            privilege="ADMINISTRATOR",
        ),
        _observation(
            "win.boot.entries",
            None,
            adapter_id="secai.windows-bcdedit-native",
            privilege="ADMINISTRATOR",
        ),
        _observation(
            "win.browser.wininet-cache-policy",
            {
                "applicability": "UNKNOWN",
                "empty_cache_on_exit": None,
                "evaluated_user_count": 1,
                "user_coverage_complete": False,
                "policy_source": "CURRENT_USER",
            },
        ),
        _observation(
            "win.update.compliance",
            None,
            adapter_id="secai.windows-update-history-build",
            privilege="ADMINISTRATOR",
        ),
        _observation(
            "win.os.lifecycle",
            {
                "product_name": "Windows 11 Pro",
                "edition_group": "Professional",
                "display_version": "25H2",
                "os_build": "26200",
                "ubr": 1000,
                "architecture": "x86_64",
            },
            adapter_id="secai.windows-native",
        ),
        _observation(
            "win.autologon.config",
            {
                "auto_admin_logon_value": "MISSING",
                "default_password_present": False,
                "related_autologon_configuration_present": False,
            },
            adapter_id="secai.winlogon-native",
        ),
        _observation(
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
                "signature_updated_at": "2026-07-23T10:00:00Z",
                "automatic_updates_enabled": None,
                "real_time_protection_enabled": True,
                "health_state": "HEALTHY",
            },
            adapter_id="secai.microsoft-defender-antivirus",
        ),
        _observation(
            "win.antivirus.realtime-status",
            {
                "product_id": "MICROSOFT_DEFENDER_ANTIVIRUS",
                "product_name": "Microsoft Defender Antivirus",
                "product_present": True,
                "product_state": "ACTIVE",
                "service_enabled": True,
                "operating_mode": "Normal",
                "real_time_protection_enabled": True,
                "behavior_monitor_enabled": True,
                "ioav_protection_enabled": True,
            },
            adapter_id="secai.microsoft-defender-antivirus",
        ),
        _observation(
            "win.firewall.effective-profiles",
            {"profile": "DOMAIN", "enabled": True},
            adapter_id="secai.windows-firewall",
        ),
        _observation(
            "win.user.screensaver-policy",
            {
                "subject_id": "CURRENT_USER",
                "screen_save_active": "MISSING",
                "screen_save_timeout_seconds": None,
                "screen_saver_is_secure": "MISSING",
                "screen_saver_executable_present": False,
                "effective_policy_source": "CURRENT_USER",
                "user_coverage_complete": False,
            },
        ),
        _observation(
            "win.media.autoplay-policy",
            {
                "turn_off_autoplay_enabled": False,
                "autoplay_scope": "PARTIAL_OR_UNDEFINED",
                "autorun_default_behavior": "UNDEFINED_OR_EXECUTE",
                "non_volume_autoplay_disallowed": False,
                "effective_policy_source": "WINDOWS_EFFECTIVE",
            },
        ),
        _observation(
            "win.remote-assistance.policy",
            {
                "f_allow_to_get_help": "MISSING",
                "f_allow_unsolicited": "MISSING",
                "effective_policy_source": "WINDOWS_EFFECTIVE",
            },
        ),
    ]
    storage: dict[str, dict[str, object]] = {
        "win.storage.disks": {
            "volume_id": "vol-001",
            "disk_id": "disk-0",
            "volume_class": "WINDOWS_OS_VOLUME",
            "bus_type": "NVME",
            "is_virtual": False,
            "is_removable": False,
            "is_online": True,
            "storage_kind": "BASIC_DISK",
            "disk_image_state": "NOT_APPLICABLE",
        },
        "win.storage.partitions": {
            "volume_id": "vol-001",
            "partition_role": "DATA",
            "gpt_type": "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
            "trusted_role_identity": True,
            "is_system": True,
            "is_boot": True,
            "is_hidden": False,
        },
        "win.storage.volumes": {
            "volume_id": "vol-001",
            "filesystem": "NTFS",
            "volume_class": "WINDOWS_OS_VOLUME",
            "drive_type": "FIXED",
            "drive_letter": "C",
            "mount_kind": "DRIVE_LETTER",
            "health_status": "HEALTHY",
            "operational_status": "OK",
            "bitlocker_state": "UNLOCKED_PROTECTED",
        },
    }
    observations.extend(
        _observation(
            probe_id,
            record,
            adapter_id="secai.windows-storage-native",
        )
        for probe_id, record in storage.items()
    )
    return observations


def test_imp038_actual_package_to_finding_replay_contract() -> None:
    report = evaluate_current_host_observations(
        PROJECT_ROOT,
        observations=_observations(),
        host={
            "os_family": "WINDOWS",
            "product_name": "Windows 11 Pro",
            "edition": "Professional",
            "display_version": "25H2",
            "build": 26200,
            "ubr": 1000,
            "architecture": "x86_64",
            "timezone": "Asia/Seoul",
            "clock_status": "UNKNOWN",
        },
    )

    pipeline = cast(dict[str, JsonValue], report["pipeline"])
    summary = cast(dict[str, JsonValue], report["summary"])
    replay = cast(dict[str, JsonValue], report["replay"])
    assert pipeline["package_validated"] is True
    assert pipeline["rule_decision_count"] == 18
    assert pipeline["draft_finding_count"] == 18
    assert summary["false_pass_count"] == 0
    assert replay["create_count"] == 18
    assert replay["return_existing_count"] == 1782
    assert replay["duplicate_finding_count"] == 0
    assert report["official_finding_created"] is False
    assert report["development_draft_only"] is True
    serialized = json.dumps(report, ensure_ascii=False).casefold()
    assert "s-1-5-21-" not in serialized
    assert "vol-001" not in serialized
