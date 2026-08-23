from __future__ import annotations

import copy
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from security_audit.analysis.normalization import (
    EvidenceNormalizer,
    NormalizationCode,
    NormalizationError,
)
from security_audit.analysis.package_validation import PackageInspection, ValidatedPackage
from security_audit.common.canonical_json import canonical_sha256

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
NORMALIZED_AT = datetime(2026, 7, 22, 8, 1, tzinfo=UTC)

PACKAGE_ID = "be95ac96-21ca-5ecd-8e79-972c5b398a6a"
MANIFEST_ID = "51000000-0000-4000-8000-000000000001"
JOB_ID = "dfc13b7c-7aac-500b-bc5f-9f7a2ebcdf1c"
ASSET_ID = "069fa286-2475-5b74-8655-da1922f20337"
ARCHIVE_SHA256 = "a" * 64
CONTENT_SET_SHA256 = "b" * 64
GPT_DATA = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"


def _record(
    probe_id: str,
    evidence_id: str,
    raw_value: dict[str, object] | None,
    *,
    status: str = "COLLECTED",
    error_code: str = "NONE",
    redacted: bool = False,
    probe_version: str = "0.1.0",
) -> dict[str, object]:
    provider = {
        "win.storage.disks": "MSFT_Disk",
        "win.storage.partitions": "MSFT_Partition",
        "win.storage.volumes": "MSFT_Volume",
    }.get(probe_id, "UnknownProvider")
    record: dict[str, object] = {
        "evidence_id": evidence_id,
        "control_id": "PC-07",
        "guide_version": "2026",
        "probe_id": probe_id,
        "probe_version": probe_version,
        "collected_at": "2026-07-22T08:00:00Z",
        "source_locator": {
            "type": "CIM",
            "provider": provider,
            "locator": f"synthetic:{probe_id}",
        },
        "collection_status": status,
        "error_code": error_code,
        "redacted": redacted,
        "evidence_sha256": "c" * 64,
    }
    if raw_value is not None:
        record["raw_value"] = raw_value
    elif status != "COLLECTED":
        record["normalized_candidate"] = {"volume_id": "vol-os"}
    return record


def _disk_raw(volume_id: str = "vol-os") -> dict[str, object]:
    return {
        "volume_id": volume_id,
        "disk_id": "disk-0",
        "volume_class": "windows_os_volume",
        "bus_type": "nvme",
        "is_virtual": False,
        "is_removable": False,
        "is_online": True,
        "storage_kind": "basic_disk",
        "disk_image_state": "not_applicable",
    }


def _partition_raw(volume_id: str = "vol-os") -> dict[str, object]:
    return {
        "volume_id": volume_id,
        "partition_role": "data",
        "gpt_type": GPT_DATA.lower(),
        "trusted_role_identity": True,
        "is_system": True,
        "is_boot": True,
        "is_hidden": False,
    }


def _volume_raw(
    volume_id: str = "vol-os",
    *,
    filesystem: object = " ntfs ",
) -> dict[str, object]:
    return {
        "volume_id": volume_id,
        "filesystem": filesystem,
        "volume_class": "windows_os_volume",
        "drive_type": "fixed",
        "drive_letter": "c:",
        "mount_kind": "drive_letter",
        "health_status": "healthy",
        "operational_status": "ok",
        "bitlocker_state": "none",
    }


def _descriptor(records: list[dict[str, object]]) -> dict[str, object]:
    return {
        "id": PACKAGE_ID,
        "job_id": JOB_ID,
        "asset_id": ASSET_ID,
        "manifest_id": MANIFEST_ID,
        "correlation_id": "d906b1b4-000e-5ee1-a3d4-63d4f4b4decc",
        "collector": {"version": "0.1.0"},
        "archive": {
            "archive_sha256": ARCHIVE_SHA256,
            "content_set_sha256": CONTENT_SET_SHA256,
            "file_count": 4,
        },
        "evidence_records": records,
    }


def _descriptor_bytes(descriptor: dict[str, object]) -> bytes:
    return json.dumps(descriptor, separators=(",", ":")).encode("utf-8")


def _validated(descriptor: dict[str, object]) -> ValidatedPackage:
    return ValidatedPackage(
        package_id=PACKAGE_ID,
        manifest_id=MANIFEST_ID,
        job_id=JOB_ID,
        asset_id=ASSET_ID,
        descriptor_sha256=canonical_sha256(cast(dict[str, Any], descriptor)),
        manifest_content_sha256="d" * 64,
        authentication_profile="ONLINE-AUTHENTICATED",
        inspection=PackageInspection(
            archive_sha256=ARCHIVE_SHA256,
            content_set_sha256=CONTENT_SET_SHA256,
            compressed_bytes=1024,
            uncompressed_bytes=2048,
            file_count=4,
            files=(),
        ),
    )


@pytest.fixture
def normalizer() -> EvidenceNormalizer:
    return EvidenceNormalizer(SCHEMA_ROOT)


def _normalize(
    normalizer: EvidenceNormalizer,
    descriptor: dict[str, object],
    *,
    validated: ValidatedPackage | None = None,
    normalized_at: datetime = NORMALIZED_AT,
) -> tuple[dict[str, object], ...]:
    result = normalizer.normalize(
        validated or _validated(descriptor),
        _descriptor_bytes(descriptor),
        normalized_at=normalized_at,
    )
    return cast(tuple[dict[str, object], ...], result)


def _expect_code(
    normalizer: EvidenceNormalizer,
    descriptor: dict[str, object],
    expected: NormalizationCode,
    *,
    validated: ValidatedPackage | None = None,
    normalized_at: datetime = NORMALIZED_AT,
) -> None:
    with pytest.raises(NormalizationError) as captured:
        _normalize(
            normalizer,
            descriptor,
            validated=validated,
            normalized_at=normalized_at,
        )
    assert captured.value.code is expected


def test_three_allowlisted_pc07_probes_are_normalized_and_schema_valid(
    normalizer: EvidenceNormalizer,
) -> None:
    descriptor = _descriptor(
        [
            _record("win.storage.volumes", "9237db20-b70b-5ffc-86f3-af6827ef81ff", _volume_raw()),
            _record("win.storage.disks", "9c60bb21-869d-5a33-8c56-2001666f4741", _disk_raw()),
            _record(
                "win.storage.partitions",
                "adfd6291-6884-5e4d-a028-293d7ae2bb5f",
                _partition_raw(),
            ),
        ]
    )

    result = _normalize(normalizer, descriptor)

    assert [item["probe_id"] for item in result] == [
        "win.storage.disks",
        "win.storage.partitions",
        "win.storage.volumes",
    ]
    volume = result[2]
    assert volume["normalized_value"] == {
        **_volume_raw(),
        "filesystem": "NTFS",
        "volume_class": "WINDOWS_OS_VOLUME",
        "drive_type": "FIXED",
        "drive_letter": "C",
        "mount_kind": "DRIVE_LETTER",
        "health_status": "HEALTHY",
        "operational_status": "OK",
        "bitlocker_state": "NONE",
    }
    assert volume["collection_status"] == "COLLECTED"
    assert "finding" not in volume


@pytest.mark.parametrize(
    ("status", "error_code"),
    [("ERROR", "PROBE_TIMEOUT"), ("SKIPPED", "PERMISSION_DENIED")],
)
def test_non_collected_state_is_preserved_and_never_becomes_fail(
    normalizer: EvidenceNormalizer,
    status: str,
    error_code: str,
) -> None:
    descriptor = _descriptor(
        [
            _record(
                "win.storage.volumes",
                "9237db20-b70b-5ffc-86f3-af6827ef81ff",
                None,
                status=status,
                error_code=error_code,
            )
        ]
    )

    output = _normalize(normalizer, descriptor)[0]

    assert output["collection_status"] == status
    assert output["error_code"] == error_code
    assert output["subject"] == {"scope": "VOLUME", "subject_key": "vol-os"}
    assert "normalized_value" not in output
    assert "finding_status" not in output


def test_unknown_filesystem_is_preserved_as_unknown_not_false_failure(
    normalizer: EvidenceNormalizer,
) -> None:
    descriptor = _descriptor(
        [
            _record(
                "win.storage.volumes",
                "9237db20-b70b-5ffc-86f3-af6827ef81ff",
                _volume_raw(filesystem="FutureFS"),
            )
        ]
    )

    output = _normalize(normalizer, descriptor)[0]

    normalized = cast(dict[str, object], output["normalized_value"])
    assert normalized["filesystem"] is None


def test_output_is_deterministic_for_same_bound_input(normalizer: EvidenceNormalizer) -> None:
    records = [
        _record("win.storage.volumes", "9237db20-b70b-5ffc-86f3-af6827ef81ff", _volume_raw()),
        _record("win.storage.disks", "9c60bb21-869d-5a33-8c56-2001666f4741", _disk_raw()),
    ]
    first_descriptor = _descriptor(records)
    second_descriptor = _descriptor(list(reversed(copy.deepcopy(records))))

    first = _normalize(normalizer, first_descriptor)
    second = _normalize(normalizer, second_descriptor)

    assert first == second


def test_unpromotable_package_is_rejected(normalizer: EvidenceNormalizer) -> None:
    descriptor = _descriptor([])
    validated = replace(_validated(descriptor), eligible_for_original_promotion=False)
    _expect_code(
        normalizer,
        descriptor,
        NormalizationCode.UNVALIDATED_PACKAGE,
        validated=validated,
    )


def test_descriptor_changed_after_validation_is_rejected(normalizer: EvidenceNormalizer) -> None:
    descriptor = _descriptor([])
    validated = _validated(descriptor)
    descriptor["correlation_id"] = "10000000-0000-4000-8000-000000000002"
    _expect_code(
        normalizer,
        descriptor,
        NormalizationCode.DESCRIPTOR_BINDING_MISMATCH,
        validated=validated,
    )


def test_validated_scope_mismatch_is_rejected(normalizer: EvidenceNormalizer) -> None:
    descriptor = _descriptor([])
    validated = replace(_validated(descriptor), asset_id="10000000-0000-4000-8000-000000000004")
    _expect_code(
        normalizer,
        descriptor,
        NormalizationCode.DESCRIPTOR_BINDING_MISMATCH,
        validated=validated,
    )


@pytest.mark.parametrize(
    ("probe_id", "probe_version"),
    [("win.storage.unknown", "0.1.0"), ("win.storage.volumes", "0.2.0")],
)
def test_unknown_probe_or_version_is_rejected(
    normalizer: EvidenceNormalizer,
    probe_id: str,
    probe_version: str,
) -> None:
    descriptor = _descriptor(
        [
            _record(
                probe_id,
                "9237db20-b70b-5ffc-86f3-af6827ef81ff",
                _volume_raw(),
                probe_version=probe_version,
            )
        ]
    )
    _expect_code(normalizer, descriptor, NormalizationCode.NORMALIZER_NOT_ALLOWED)


def test_extra_raw_field_is_rejected_fail_closed(normalizer: EvidenceNormalizer) -> None:
    raw = _volume_raw()
    raw["unexpected"] = True
    descriptor = _descriptor(
        [_record("win.storage.volumes", "9237db20-b70b-5ffc-86f3-af6827ef81ff", raw)]
    )
    _expect_code(normalizer, descriptor, NormalizationCode.NORMALIZATION_INPUT_INVALID)


@pytest.mark.parametrize(
    ("status", "error_code"),
    [("COLLECTED", "PROBE_TIMEOUT"), ("ERROR", "NONE")],
)
def test_inconsistent_collection_state_is_rejected(
    normalizer: EvidenceNormalizer,
    status: str,
    error_code: str,
) -> None:
    descriptor = _descriptor(
        [
            _record(
                "win.storage.volumes",
                "9237db20-b70b-5ffc-86f3-af6827ef81ff",
                _volume_raw() if status == "COLLECTED" else None,
                status=status,
                error_code=error_code,
            )
        ]
    )
    _expect_code(normalizer, descriptor, NormalizationCode.NORMALIZATION_INPUT_INVALID)


def test_naive_normalization_time_is_rejected(normalizer: EvidenceNormalizer) -> None:
    descriptor = _descriptor([])
    _expect_code(
        normalizer,
        descriptor,
        NormalizationCode.NORMALIZATION_INPUT_INVALID,
        normalized_at=datetime(2026, 7, 22, 8, 1),
    )


def test_normalization_before_collection_is_rejected(normalizer: EvidenceNormalizer) -> None:
    descriptor = _descriptor(
        [_record("win.storage.volumes", "9237db20-b70b-5ffc-86f3-af6827ef81ff", _volume_raw())]
    )
    _expect_code(
        normalizer,
        descriptor,
        NormalizationCode.NORMALIZATION_INPUT_INVALID,
        normalized_at=datetime(2026, 7, 22, 7, 59, tzinfo=UTC),
    )


def test_redacted_raw_value_is_omitted_from_output(normalizer: EvidenceNormalizer) -> None:
    descriptor = _descriptor(
        [
            _record(
                "win.storage.volumes",
                "9237db20-b70b-5ffc-86f3-af6827ef81ff",
                _volume_raw(),
                redacted=True,
            )
        ]
    )

    output = _normalize(normalizer, descriptor)[0]

    assert "raw_value" not in output
    assert output["redaction"] == {"applied": True, "method": "OMITTED"}
