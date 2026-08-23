from __future__ import annotations

import json

import pytest

from security_audit.application.windows_host_collection_acceptance import (
    HostCollectionReceiptError,
    build_host_collection_receipt,
)
from security_audit.collector.expanded import (
    ADMINISTRATOR_PROBES,
    STANDARD_NON_STORAGE_PROBES,
)

STORAGE_PROBES = (
    "win.storage.disks",
    "win.storage.partitions",
    "win.storage.volumes",
)


def _result(
    probe_id: str,
    *,
    privilege: str,
    status: str = "COLLECTED",
    error_code: str = "NONE",
) -> dict[str, object]:
    return {
        "probe_id": probe_id,
        "control_ids": ["PC-07"],
        "privilege": privilege,
        "collection_status": status,
        "error_code": error_code,
        "record_count": 1 if status == "COLLECTED" else 0,
    }


def _receipt() -> dict[str, object]:
    standard = [
        _result(
            probe_id,
            privilege="STANDARD_USER",
            status="ERROR" if probe_id == "win.storage.disks" else "COLLECTED",
            error_code=(
                "PERMISSION_DENIED"
                if probe_id == "win.storage.disks"
                else "NONE"
            ),
        )
        for probe_id in (*STANDARD_NON_STORAGE_PROBES, *STORAGE_PROBES)
    ]
    administrator = [
        _result(probe_id, privilege="ADMINISTRATOR")
        for probe_id in ADMINISTRATOR_PROBES
    ]
    return build_host_collection_receipt(
        observed_at_utc="2026-07-23T12:00:00Z",
        standard_results=standard,
        administrator_results=administrator,
        administrator_consent=True,
        automatic_uac=False,
        standard_settings_diff_count=0,
        administrator_settings_diff_count=0,
    )


def test_imp037_preserves_each_probe_collection_state_without_finding() -> None:
    receipt = _receipt()
    rows = receipt["results"]
    serialized = json.dumps(receipt, ensure_ascii=False).casefold()

    assert receipt["acceptance_status"] == "PASS"
    assert receipt["summary"]["total"] == 20  # type: ignore[index]
    assert receipt["summary"]["collected"] == 19  # type: ignore[index]
    assert receipt["summary"]["permission_denied"] == 1  # type: ignore[index]
    assert len(rows) == 20  # type: ignore[arg-type]
    assert receipt["administrator"]["explicit_consent"] is True  # type: ignore[index]
    assert receipt["safety"]["automatic_uac"] is False  # type: ignore[index]
    assert receipt["safety"]["settings_diff_count"] == 0  # type: ignore[index]
    assert receipt["official_finding_created"] is False
    assert "s-1-5-21-" not in serialized
    assert "volume_guid" not in serialized
    assert "sha256" not in serialized


def test_imp037_rejects_missing_administrator_consent() -> None:
    with pytest.raises(HostCollectionReceiptError, match="consent"):
        build_host_collection_receipt(
            observed_at_utc="2026-07-23T12:00:00Z",
            standard_results=[],
            administrator_results=[],
            administrator_consent=False,
            automatic_uac=False,
            standard_settings_diff_count=0,
            administrator_settings_diff_count=0,
        )


def test_imp037_rejects_status_coercion_and_settings_change() -> None:
    standard = [
        _result(probe_id, privilege="STANDARD_USER")
        for probe_id in (*STANDARD_NON_STORAGE_PROBES, *STORAGE_PROBES)
    ]
    standard[0]["collection_status"] = "PASS"
    with pytest.raises(HostCollectionReceiptError):
        build_host_collection_receipt(
            observed_at_utc="2026-07-23T12:00:00Z",
            standard_results=standard,
            administrator_results=[
                _result(probe_id, privilege="ADMINISTRATOR")
                for probe_id in ADMINISTRATOR_PROBES
            ],
            administrator_consent=True,
            automatic_uac=False,
            standard_settings_diff_count=0,
            administrator_settings_diff_count=1,
        )


def test_imp037_accepts_current_deidentified_probe_metadata_and_strips_it() -> None:
    standard = [
        {
            **_result(probe_id, privilege="STANDARD_USER"),
            "collected_at_utc": "2026-08-05T10:00:00Z",
            "normalized_records_sha256": "a" * 64,
            "raw_evidence_available": False,
        }
        for probe_id in (*STANDARD_NON_STORAGE_PROBES, *STORAGE_PROBES)
    ]
    administrator = [
        {
            **_result(probe_id, privilege="ADMINISTRATOR"),
            "collected_at_utc": "2026-08-05T10:00:01Z",
            "normalized_records_sha256": "b" * 64,
            "raw_evidence_available": False,
        }
        for probe_id in ADMINISTRATOR_PROBES
    ]

    receipt = build_host_collection_receipt(
        observed_at_utc="2026-08-05T10:00:02Z",
        standard_results=standard,
        administrator_results=administrator,
        administrator_consent=True,
        automatic_uac=False,
        standard_settings_diff_count=0,
        administrator_settings_diff_count=0,
    )

    serialized = json.dumps(receipt, ensure_ascii=False)
    assert receipt["acceptance_status"] == "PASS"
    assert "normalized_records_sha256" not in serialized
    assert "raw_evidence_available" not in serialized
