from __future__ import annotations

import json

import pytest

from security_audit.application.windows_baseline_acceptance import (
    BaselineReceiptError,
    build_windows_baseline_receipt,
)


def _receipt() -> dict[str, object]:
    return build_windows_baseline_receipt(
        observed_at_utc="2026-07-23T12:00:00Z",
        operating_system={
            "edition": "Microsoft Windows 11 Enterprise",
            "display_version": "25H2",
            "build": "26200.5710",
            "architecture": "x86_64",
        },
        token={
            "level": "STANDARD_USER",
            "integrity_level": "MEDIUM",
        },
        security_products=[
            {
                "name": "Microsoft Defender Antivirus",
                "state": "ACTIVE",
                "detail": "실시간 보호 사용",
            },
            {
                "name": "Windows Defender Firewall",
                "state": "ACTIVE",
                "detail": "확인한 프로필 3개 중 3개 사용",
            },
        ],
        collector={
            "artifact": "SecAI-Collector-Windows-x64.exe",
            "self_check": "PASS",
            "release_channel": "DEV-SIGNED-UNTRUSTED-OUTSIDE-TEST",
        },
        docker_services=[
            {"service": name, "running": True, "healthy": True}
            for name in (
                "postgres",
                "redis",
                "aistor",
                "clamav",
                "api",
                "worker",
                "scheduler",
                "gateway",
            )
        ],
        snapshot_surfaces=[
            "POWERSHELL_EXECUTION_POLICY",
            "DISK_FLAGS",
            "PARTITION_LAYOUT",
            "VOLUME_FILESYSTEM",
            "BITLOCKER_STATE",
        ],
        settings_before_after_equal=True,
        settings_diff_count=0,
    )


def test_imp036_receipt_is_deidentified_and_marks_current_pc_as_not_clean_vm() -> None:
    receipt = _receipt()
    serialized = json.dumps(receipt, ensure_ascii=False).casefold()

    assert receipt["acceptance_status"] == "PASS"
    assert receipt["environment"]["clean_vm_verified"] is False  # type: ignore[index]
    assert receipt["settings_safety"]["settings_diff_count"] == 0  # type: ignore[index]
    assert receipt["docker_core"]["healthy_services"] == 8  # type: ignore[index]
    assert receipt["privacy"]["sid_disclosed"] is False  # type: ignore[index]
    assert receipt["privacy"]["volume_identifiers_disclosed"] is False  # type: ignore[index]
    assert receipt["official_finding_created"] is False
    assert receipt["portable_bundle_created"] is False
    for forbidden in ("s-1-5-21-", "hostname", "volume_guid", "sha256", "secret"):
        assert forbidden not in serialized


def test_imp036_receipt_fails_closed_when_settings_change() -> None:
    with pytest.raises(BaselineReceiptError, match="settings"):
        build_windows_baseline_receipt(
            observed_at_utc="2026-07-23T12:00:00Z",
            operating_system={
                "edition": "Microsoft Windows 11 Enterprise",
                "display_version": "25H2",
                "build": "26200.5710",
                "architecture": "x86_64",
            },
            token={"level": "STANDARD_USER", "integrity_level": "MEDIUM"},
            security_products=[],
            collector={
                "artifact": "SecAI-Collector-Windows-x64.exe",
                "self_check": "PASS",
                "release_channel": "DEV-SIGNED-UNTRUSTED-OUTSIDE-TEST",
            },
            docker_services=[],
            snapshot_surfaces=[],
            settings_before_after_equal=False,
            settings_diff_count=1,
        )


def test_imp036_receipt_requires_exact_healthy_core_service_set() -> None:
    with pytest.raises(BaselineReceiptError, match="Docker Core"):
        build_windows_baseline_receipt(
            observed_at_utc="2026-07-23T12:00:00Z",
            operating_system={
                "edition": "Microsoft Windows 11 Enterprise",
                "display_version": "25H2",
                "build": "26200.5710",
                "architecture": "x86_64",
            },
            token={"level": "STANDARD_USER", "integrity_level": "MEDIUM"},
            security_products=[],
            collector={
                "artifact": "SecAI-Collector-Windows-x64.exe",
                "self_check": "PASS",
                "release_channel": "DEV-SIGNED-UNTRUSTED-OUTSIDE-TEST",
            },
            docker_services=[
                {"service": "api", "running": True, "healthy": True}
            ],
            snapshot_surfaces=[],
            settings_before_after_equal=True,
            settings_diff_count=0,
        )
