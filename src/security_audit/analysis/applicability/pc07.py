"""Approved PC-07 volume applicability and exclusion evaluation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from .contracts import (
    ApplicabilityDecision,
    ApplicabilityStatus,
    ExcludedSubject,
    NormalizedEvidenceRecord,
)

_INCLUDED_CLASSES = (
    "WINDOWS_OS_VOLUME",
    "LOCAL_FIXED_DATA_VOLUME",
    "MOUNTED_FOLDER_VOLUME",
    "ATTACHED_VHD_VOLUME",
    "STORAGE_SPACES_LOGICAL_VOLUME",
    "BITLOCKER_VOLUME",
)
_EXCLUDED_CLASSES = (
    "EFI_SYSTEM_PARTITION",
    "MICROSOFT_RESERVED_PARTITION",
    "WINDOWS_RECOVERY_PARTITION",
    "APPROVED_OEM_UTILITY_PARTITION",
    "OPTICAL_VOLUME",
    "REMOVABLE_VOLUME",
    "NETWORK_VOLUME",
    "DETACHED_DISK_IMAGE",
    "VOLATILE_RAM_DISK",
)
_APPROVED_PARAMETERS: dict[str, object] = {
    "include_volume_classes": _INCLUDED_CLASSES,
    "exclude_volume_classes": _EXCLUDED_CLASSES,
    "require_trusted_exclusion_identity": True,
    "drive_letter_absence_is_exclusion": False,
    "usb_bus_alone_is_exclusion": False,
    "empty_evaluated_set_status": "ERROR",
    "classification_unknown_status": "ERROR",
}
_PARTITION_EXCLUSIONS = {
    "EFI_SYSTEM_PARTITION": ("EFI_SYSTEM", "EXCLUDED_EFI_SYSTEM_PARTITION"),
    "MICROSOFT_RESERVED_PARTITION": (
        "MICROSOFT_RESERVED",
        "EXCLUDED_MICROSOFT_RESERVED",
    ),
    "WINDOWS_RECOVERY_PARTITION": (
        "WINDOWS_RECOVERY",
        "EXCLUDED_WINDOWS_RECOVERY",
    ),
    "APPROVED_OEM_UTILITY_PARTITION": ("OEM_UTILITY", "EXCLUDED_OEM_UTILITY"),
}
_OTHER_EXCLUSIONS = {
    "OPTICAL_VOLUME": "EXCLUDED_OPTICAL",
    "REMOVABLE_VOLUME": "EXCLUDED_REMOVABLE",
    "NETWORK_VOLUME": "EXCLUDED_NETWORK",
    "DETACHED_DISK_IMAGE": "EXCLUDED_DETACHED_DISK_IMAGE",
    "VOLATILE_RAM_DISK": "EXCLUDED_VOLATILE_RAM_DISK",
}


def _string_sequence(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return tuple(value)


def pc07_applicability_parameters_are_approved(parameters: Mapping[str, object]) -> bool:
    """Return whether parameters exactly match the approved PC-07 rule version."""

    if set(parameters) != set(_APPROVED_PARAMETERS):
        return False
    for key, approved in _APPROVED_PARAMETERS.items():
        actual = parameters[key]
        if isinstance(approved, tuple):
            if _string_sequence(actual) != approved:
                return False
        elif actual != approved or type(actual) is not type(approved):
            return False
    return True


def _records_by_subject(
    records: Sequence[NormalizedEvidenceRecord],
) -> dict[str, dict[str, NormalizedEvidenceRecord]]:
    grouped: dict[str, dict[str, NormalizedEvidenceRecord]] = {}
    for record in records:
        grouped.setdefault(record.subject_key, {})[record.probe_id] = record
    return grouped


def _value(record: NormalizedEvidenceRecord | None) -> Mapping[str, object] | None:
    if record is None or record.collection_status != "COLLECTED":
        return None
    return record.normalized_value


def _trusted_exclusion_reason(
    volume_class: str,
    subject_records: Mapping[str, NormalizedEvidenceRecord],
) -> str | None:
    disk = _value(subject_records.get("win.storage.disks"))
    partition = _value(subject_records.get("win.storage.partitions"))
    volume = _value(subject_records.get("win.storage.volumes"))

    if volume_class in _PARTITION_EXCLUSIONS:
        expected_role, reason = _PARTITION_EXCLUSIONS[volume_class]
        if (
            partition is not None
            and partition.get("partition_role") == expected_role
            and partition.get("trusted_role_identity") is True
        ):
            return reason
        return None

    if volume_class == "DETACHED_DISK_IMAGE":
        if (
            disk is not None
            and disk.get("disk_image_state") == "DETACHED"
            and disk.get("is_online") is False
        ):
            return _OTHER_EXCLUSIONS[volume_class]
        return None
    if volume_class == "OPTICAL_VOLUME":
        is_optical = volume is not None and volume.get("drive_type") == "CDROM"
        return _OTHER_EXCLUSIONS[volume_class] if is_optical else None
    if volume_class == "REMOVABLE_VOLUME":
        removable = (volume and volume.get("drive_type") == "REMOVABLE") or (
            disk and disk.get("is_removable") is True
        )
        return _OTHER_EXCLUSIONS[volume_class] if removable else None
    if volume_class == "NETWORK_VOLUME":
        is_network = volume is not None and volume.get("drive_type") == "NETWORK"
        return _OTHER_EXCLUSIONS[volume_class] if is_network else None
    if volume_class == "VOLATILE_RAM_DISK":
        is_ram_disk = volume is not None and volume.get("drive_type") == "RAMDISK"
        return _OTHER_EXCLUSIONS[volume_class] if is_ram_disk else None
    return None


def evaluate_pc07_applicability(
    records: Sequence[NormalizedEvidenceRecord],
) -> ApplicabilityDecision:
    """Select PC-07 candidate volumes without silently excluding uncertain subjects."""

    grouped = _records_by_subject(records)
    candidates: list[str] = []
    excluded: list[ExcludedSubject] = []
    classification_incomplete = False

    for subject_id in sorted(grouped):
        subject_records = grouped[subject_id]
        disk = _value(subject_records.get("win.storage.disks"))
        if disk is None or not isinstance(disk.get("volume_class"), str):
            classification_incomplete = True
            continue
        volume_class = disk["volume_class"]
        if volume_class in _INCLUDED_CLASSES:
            if disk.get("is_online") is not True:
                classification_incomplete = True
                continue
            candidates.append(subject_id)
            continue
        if volume_class in _EXCLUDED_CLASSES:
            reason = _trusted_exclusion_reason(volume_class, subject_records)
            if reason is None:
                classification_incomplete = True
            else:
                excluded.append(ExcludedSubject(subject_id, reason))
            continue
        classification_incomplete = True

    if classification_incomplete:
        classification_errors = sorted(
            {
                record.error_code
                for record in records
                if record.collection_status != "COLLECTED" and record.error_code != "NONE"
            }
        )
        return ApplicabilityDecision(
            status=ApplicabilityStatus.UNDETERMINED,
            reason_code="VOLUME_CLASSIFICATION_INCOMPLETE",
            candidate_volume_ids=tuple(candidates),
            excluded_volumes=tuple(excluded),
            error_codes=tuple(classification_errors) or ("EVIDENCE_INCOMPLETE",),
        )

    candidate_errors = {
        record.error_code
        for record in records
        if record.subject_key in candidates
        and record.collection_status != "COLLECTED"
        and record.error_code != "NONE"
    }
    required_probes = {
        "win.storage.disks",
        "win.storage.partitions",
        "win.storage.volumes",
    }
    if any(set(grouped[subject_id]) != required_probes for subject_id in candidates):
        candidate_errors.add("EVIDENCE_INCOMPLETE")
    if candidate_errors:
        return ApplicabilityDecision(
            status=ApplicabilityStatus.UNDETERMINED,
            reason_code="VOLUME_EVIDENCE_INCOMPLETE",
            candidate_volume_ids=tuple(candidates),
            excluded_volumes=tuple(excluded),
            error_codes=tuple(sorted(candidate_errors)),
        )
    if not candidates:
        return ApplicabilityDecision(
            status=ApplicabilityStatus.UNDETERMINED,
            reason_code="NO_EVALUATED_VOLUME",
            candidate_volume_ids=(),
            excluded_volumes=tuple(excluded),
            error_codes=("EVIDENCE_INCOMPLETE",),
        )
    return ApplicabilityDecision(
        status=ApplicabilityStatus.APPLICABLE,
        reason_code="WINDOWS_FIXED_VOLUME_SET",
        candidate_volume_ids=tuple(candidates),
        excluded_volumes=tuple(excluded),
    )
