"""Allowlisted PC-01~18 raw evidence normalization without DB, network, or rules."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Never, cast
from uuid import UUID, uuid5

from security_audit.analysis.package_validation import (
    PackageSchemaCatalog,
    PackageValidationCode,
    PackageValidationError,
    ValidatedPackage,
    load_strict_json,
)
from security_audit.common.canonical_json import JsonValue, canonical_sha256

from .contracts import NormalizationCode, NormalizationError

_NORMALIZER_NAME = "sec-ai-normalizer"
_NORMALIZER_VERSION = "0.1.0"
_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_GUID_PATTERN = re.compile(
    r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
)

_VOLUME_CLASSES = frozenset(
    {
        "WINDOWS_OS_VOLUME",
        "LOCAL_FIXED_DATA_VOLUME",
        "MOUNTED_FOLDER_VOLUME",
        "ATTACHED_VHD_VOLUME",
        "STORAGE_SPACES_LOGICAL_VOLUME",
        "BITLOCKER_VOLUME",
        "EFI_SYSTEM_PARTITION",
        "MICROSOFT_RESERVED_PARTITION",
        "WINDOWS_RECOVERY_PARTITION",
        "APPROVED_OEM_UTILITY_PARTITION",
        "OPTICAL_VOLUME",
        "REMOVABLE_VOLUME",
        "NETWORK_VOLUME",
        "DETACHED_DISK_IMAGE",
        "VOLATILE_RAM_DISK",
    }
)

type RawMapper = Callable[[Mapping[str, object]], dict[str, JsonValue]]


def _reject(code: NormalizationCode, message: str) -> Never:
    raise NormalizationError(code, message)


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(NormalizationCode.NORMALIZATION_INPUT_INVALID, "Expected an object value.")
    return cast(Mapping[str, object], value)


def _sequence(value: object) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _reject(NormalizationCode.NORMALIZATION_INPUT_INVALID, "Expected an array value.")
    return cast(Sequence[object], value)


def _string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str):
        _reject(NormalizationCode.NORMALIZATION_INPUT_INVALID, "Expected a string field.")
    return value


def _boolean(mapping: Mapping[str, object], key: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool):
        _reject(NormalizationCode.NORMALIZATION_INPUT_INVALID, "Expected a boolean field.")
    return value


def _exact_keys(raw: Mapping[str, object], required: frozenset[str]) -> None:
    if frozenset(raw) != required:
        _reject(
            NormalizationCode.NORMALIZATION_INPUT_INVALID,
            "Raw evidence fields differ from the allowlisted Probe contract.",
        )


def _identifier(mapping: Mapping[str, object], key: str) -> str:
    value = _string(mapping, key).strip()
    if _ID_PATTERN.fullmatch(value) is None:
        _reject(NormalizationCode.NORMALIZATION_INPUT_INVALID, "Identifier is invalid.")
    return value


def _enum(mapping: Mapping[str, object], key: str, allowed: frozenset[str]) -> str:
    value = _string(mapping, key).strip().upper()
    if value not in allowed:
        _reject(NormalizationCode.NORMALIZATION_INPUT_INVALID, "Enum value is not allowed.")
    return value


def _normalize_disk(raw: Mapping[str, object]) -> dict[str, JsonValue]:
    _exact_keys(
        raw,
        frozenset(
            {
                "volume_id",
                "disk_id",
                "volume_class",
                "bus_type",
                "is_virtual",
                "is_removable",
                "is_online",
                "storage_kind",
                "disk_image_state",
            }
        ),
    )
    return {
        "volume_id": _identifier(raw, "volume_id"),
        "disk_id": _identifier(raw, "disk_id"),
        "volume_class": _enum(raw, "volume_class", _VOLUME_CLASSES),
        "bus_type": _enum(
            raw,
            "bus_type",
            frozenset(
                {
                    "NVME",
                    "SATA",
                    "SAS",
                    "USB",
                    "FILE_BACKED_VIRTUAL",
                    "STORAGE_SPACES",
                    "UNKNOWN",
                }
            ),
        ),
        "is_virtual": _boolean(raw, "is_virtual"),
        "is_removable": _boolean(raw, "is_removable"),
        "is_online": _boolean(raw, "is_online"),
        "storage_kind": _enum(
            raw,
            "storage_kind",
            frozenset({"BASIC_DISK", "VHD", "VHDX", "STORAGE_SPACES_LOGICAL", "UNKNOWN"}),
        ),
        "disk_image_state": _enum(
            raw,
            "disk_image_state",
            frozenset({"ATTACHED", "DETACHED", "NOT_APPLICABLE", "UNKNOWN"}),
        ),
    }


def _normalize_partition(raw: Mapping[str, object]) -> dict[str, JsonValue]:
    _exact_keys(
        raw,
        frozenset(
            {
                "volume_id",
                "partition_role",
                "gpt_type",
                "trusted_role_identity",
                "is_system",
                "is_boot",
                "is_hidden",
            }
        ),
    )
    gpt_type = _string(raw, "gpt_type").strip().upper()
    if _GUID_PATTERN.fullmatch(gpt_type) is None:
        _reject(NormalizationCode.NORMALIZATION_INPUT_INVALID, "GPT type is invalid.")
    return {
        "volume_id": _identifier(raw, "volume_id"),
        "partition_role": _enum(
            raw,
            "partition_role",
            frozenset(
                {
                    "DATA",
                    "EFI_SYSTEM",
                    "MICROSOFT_RESERVED",
                    "WINDOWS_RECOVERY",
                    "OEM_UTILITY",
                    "UNKNOWN",
                }
            ),
        ),
        "gpt_type": gpt_type,
        "trusted_role_identity": _boolean(raw, "trusted_role_identity"),
        "is_system": _boolean(raw, "is_system"),
        "is_boot": _boolean(raw, "is_boot"),
        "is_hidden": _boolean(raw, "is_hidden"),
    }


def _filesystem(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 32:
        _reject(NormalizationCode.NORMALIZATION_INPUT_INVALID, "Filesystem value is invalid.")
    known = {
        "ntfs": "NTFS",
        "fat32": "FAT32",
        "exfat": "exFAT",
        "refs": "ReFS",
        "raw": "RAW",
    }
    return known.get(value.strip().casefold())


def _drive_letter(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        _reject(NormalizationCode.NORMALIZATION_INPUT_INVALID, "Drive letter is invalid.")
    normalized = value.strip().removesuffix(":").upper()
    if len(normalized) != 1 or not "A" <= normalized <= "Z":
        _reject(NormalizationCode.NORMALIZATION_INPUT_INVALID, "Drive letter is invalid.")
    return normalized


def _normalize_volume(raw: Mapping[str, object]) -> dict[str, JsonValue]:
    _exact_keys(
        raw,
        frozenset(
            {
                "volume_id",
                "filesystem",
                "volume_class",
                "drive_type",
                "drive_letter",
                "mount_kind",
                "health_status",
                "operational_status",
                "bitlocker_state",
            }
        ),
    )
    return {
        "volume_id": _identifier(raw, "volume_id"),
        "filesystem": _filesystem(raw.get("filesystem")),
        "volume_class": _enum(raw, "volume_class", _VOLUME_CLASSES),
        "drive_type": _enum(
            raw,
            "drive_type",
            frozenset({"FIXED", "REMOVABLE", "NETWORK", "CDROM", "RAMDISK", "UNKNOWN"}),
        ),
        "drive_letter": _drive_letter(raw.get("drive_letter")),
        "mount_kind": _enum(
            raw,
            "mount_kind",
            frozenset({"DRIVE_LETTER", "FOLDER_MOUNT", "NO_MOUNT", "UNKNOWN"}),
        ),
        "health_status": _enum(
            raw,
            "health_status",
            frozenset({"HEALTHY", "WARNING", "UNHEALTHY", "UNKNOWN"}),
        ),
        "operational_status": _enum(
            raw,
            "operational_status",
            frozenset({"OK", "DEGRADED", "ERROR", "OFFLINE", "UNKNOWN"}),
        ),
        "bitlocker_state": _enum(
            raw,
            "bitlocker_state",
            frozenset({"NONE", "UNLOCKED_PROTECTED", "UNLOCKED_UNPROTECTED", "LOCKED", "UNKNOWN"}),
        ),
    }


_PROBE_FIELDS: Mapping[str, frozenset[str]] = {
    "win.security.password-age": frozenset(
        {"maximum_password_age_days", "policy_defined", "policy_source"}
    ),
    "win.security.password-policy": frozenset(
        {
            "minimum_password_length",
            "maximum_password_age_days",
            "complexity_enabled",
            "password_required",
            "policy_source",
        }
    ),
    "win.security.recovery-console": frozenset(
        {
            "automatic_admin_logon",
            "policy_defined",
            "policy_source",
            "os_edition",
            "os_build",
        }
    ),
    "win.network.smb-shares": frozenset(
        {
            "default_admin_share_count",
            "unrestricted_everyone_share_count",
            "least_privilege_violation_count",
            "authentication_gap_count",
            "auto_share_wks_disabled",
        }
    ),
    "win.services.inventory": frozenset(
        {
            "evaluated_unnecessary_service_count",
            "running_unnecessary_service_count",
            "automatic_unnecessary_service_count",
        }
    ),
    "win.software.messengers": frozenset(
        {
            "evaluated_denied_product_count",
            "installed_denied_product_count",
            "running_denied_product_count",
            "low_confidence_match_count",
        }
    ),
    "win.boot.entries": frozenset(
        {
            "bootable_os_count",
            "excluded_recovery_entry_count",
            "excluded_diagnostic_entry_count",
            "excluded_virtualization_entry_count",
        }
    ),
    "win.browser.wininet-cache-policy": frozenset(
        {
            "applicability",
            "empty_cache_on_exit",
            "ie_desktop_used",
            "ie_mode_used",
            "wininet_used",
            "organization_scope_confirmed",
            "evaluated_user_count",
        }
    ),
    "win.update.compliance": frozenset(
        {
            "display_version",
            "os_build",
            "ubr",
            "installed_cumulative_kb",
            "missing_required_update_count",
            "automatic_updates_enabled",
            "update_inventory_source",
            "restart_pending",
            "last_successful_scan_at",
        }
    ),
    "win.os.lifecycle": frozenset(
        {
            "product_name",
            "edition_group",
            "display_version",
            "os_build",
            "ubr",
            "architecture",
        }
    ),
    "win.autologon.config": frozenset(
        {
            "auto_admin_logon_value",
            "default_password_present",
            "related_autologon_configuration_present",
        }
    ),
    "win.antivirus.update-status": frozenset(
        {
            "product_id",
            "product_name",
            "product_present",
            "product_state",
            "service_enabled",
            "operating_mode",
            "engine_version",
            "signature_version",
            "signature_updated_at",
            "automatic_updates_enabled",
            "real_time_protection_enabled",
            "health_state",
            "adapter_id",
            "adapter_version",
        }
    ),
    "win.antivirus.realtime-status": frozenset(
        {
            "product_id",
            "product_name",
            "product_present",
            "product_state",
            "service_enabled",
            "operating_mode",
            "real_time_protection_enabled",
            "behavior_monitor_enabled",
            "ioav_protection_enabled",
            "adapter_id",
            "adapter_version",
        }
    ),
    "win.firewall.effective-profiles": frozenset(
        {
            "adapter_id",
            "adapter_version",
            "policy_store",
            "domain_applicable",
            "domain_enabled",
            "private_applicable",
            "private_enabled",
            "public_applicable",
            "public_enabled",
            "third_party_present",
        }
    ),
    "win.user.screensaver-policy": frozenset(
        {
            "subject_id",
            "screen_save_active",
            "screen_save_timeout_seconds",
            "screen_saver_is_secure",
            "screen_saver_executable_present",
            "effective_policy_source",
            "user_coverage_complete",
        }
    ),
    "win.media.autoplay-policy": frozenset(
        {
            "turn_off_autoplay_enabled",
            "autoplay_scope",
            "autorun_default_behavior",
            "non_volume_autoplay_disallowed",
            "effective_policy_source",
        }
    ),
    "win.remote-assistance.policy": frozenset(
        {
            "f_allow_to_get_help",
            "f_allow_unsolicited",
            "effective_policy_source",
        }
    ),
}

_PROBE_SCOPES: Mapping[str, str] = {
    "win.security.password-age": "POLICY",
    "win.security.password-policy": "POLICY",
    "win.security.recovery-console": "POLICY",
    "win.network.smb-shares": "ASSET",
    "win.services.inventory": "ASSET",
    "win.software.messengers": "ASSET",
    "win.boot.entries": "ASSET",
    "win.browser.wininet-cache-policy": "POLICY",
    "win.update.compliance": "ASSET",
    "win.os.lifecycle": "ASSET",
    "win.autologon.config": "ASSET",
    "win.antivirus.update-status": "ASSET",
    "win.antivirus.realtime-status": "ASSET",
    "win.firewall.effective-profiles": "ASSET",
    "win.user.screensaver-policy": "USER",
    "win.media.autoplay-policy": "POLICY",
    "win.remote-assistance.policy": "POLICY",
}


def _normalize_probe_object(
    probe_id: str,
    raw: Mapping[str, object],
) -> dict[str, JsonValue]:
    expected = _PROBE_FIELDS[probe_id]
    _exact_keys(raw, expected)
    if any(
        not isinstance(value, (str, int, float, bool, type(None)))
        for value in raw.values()
    ):
        _reject(
            NormalizationCode.NORMALIZATION_INPUT_INVALID,
            "Probe evidence contains a non-scalar value.",
        )
    return cast(dict[str, JsonValue], dict(raw))


def _probe_mapper(probe_id: str) -> RawMapper:
    return lambda raw: _normalize_probe_object(probe_id, raw)


_REGISTRY: Mapping[tuple[str, str], RawMapper] = {
    ("win.storage.disks", "0.1.0"): _normalize_disk,
    ("win.storage.partitions", "0.1.0"): _normalize_partition,
    ("win.storage.volumes", "0.1.0"): _normalize_volume,
    **{
        (probe_id, "0.1.0"): _probe_mapper(probe_id)
        for probe_id in _PROBE_FIELDS
    },
}


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        _reject(
            NormalizationCode.NORMALIZATION_INPUT_INVALID,
            "normalized_at must be timezone-aware.",
        )
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_utc_timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        _reject(NormalizationCode.NORMALIZATION_INPUT_INVALID, "Timestamp must use UTC Z form.")
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as exc:
        raise NormalizationError(
            NormalizationCode.NORMALIZATION_INPUT_INVALID,
            "Timestamp is invalid.",
        ) from exc
    return parsed


class EvidenceNormalizer:
    """Normalize only records from a cryptographically bound ValidatedPackage."""

    def __init__(self, schema_root: Path) -> None:
        self._schemas = PackageSchemaCatalog(schema_root)

    def normalize(
        self,
        validated_package: ValidatedPackage,
        descriptor_bytes: bytes,
        *,
        normalized_at: datetime,
    ) -> tuple[dict[str, JsonValue], ...]:
        if not validated_package.eligible_for_original_promotion:
            _reject(NormalizationCode.UNVALIDATED_PACKAGE, "Package did not pass validation.")
        try:
            descriptor = cast(dict[str, JsonValue], load_strict_json(descriptor_bytes))
        except PackageValidationError as exc:
            raise NormalizationError(
                NormalizationCode.DESCRIPTOR_BINDING_MISMATCH,
                "Descriptor is not the validated strict JSON document.",
            ) from exc
        if canonical_sha256(descriptor) != validated_package.descriptor_sha256:
            _reject(
                NormalizationCode.DESCRIPTOR_BINDING_MISMATCH,
                "Descriptor digest differs from the validated package.",
            )
        descriptor_mapping = cast(Mapping[str, object], descriptor)
        self._validate_package_binding(validated_package, descriptor_mapping)
        timestamp = _utc_timestamp(normalized_at)
        normalized_instant = _parse_utc_timestamp(timestamp)
        records = tuple(
            self._normalize_record(
                validated_package,
                descriptor_mapping,
                raw,
                timestamp,
                normalized_instant,
            )
            for raw in _sequence(descriptor_mapping.get("evidence_records"))
        )
        return tuple(sorted(records, key=self._sort_key))

    def _validate_package_binding(
        self,
        validated: ValidatedPackage,
        descriptor: Mapping[str, object],
    ) -> None:
        if (
            _string(descriptor, "id") != validated.package_id
            or _string(descriptor, "job_id") != validated.job_id
            or _string(descriptor, "asset_id") != validated.asset_id
            or _string(descriptor, "manifest_id") != validated.manifest_id
        ):
            _reject(
                NormalizationCode.DESCRIPTOR_BINDING_MISMATCH,
                "Descriptor scope differs from the validated package.",
            )
        archive = _mapping(descriptor.get("archive"))
        inspection = validated.inspection
        if (
            _string(archive, "archive_sha256") != inspection.archive_sha256
            or _string(archive, "content_set_sha256") != inspection.content_set_sha256
            or archive.get("file_count") != inspection.file_count
        ):
            _reject(
                NormalizationCode.DESCRIPTOR_BINDING_MISMATCH,
                "Descriptor archive facts differ from the validated package.",
            )

    def _normalize_record(
        self,
        validated: ValidatedPackage,
        descriptor: Mapping[str, object],
        raw_record: object,
        timestamp: str,
        normalized_instant: datetime,
    ) -> dict[str, JsonValue]:
        record = _mapping(raw_record)
        probe_id = _string(record, "probe_id")
        probe_version = _string(record, "probe_version")
        mapper = _REGISTRY.get((probe_id, probe_version))
        if mapper is None:
            _reject(
                NormalizationCode.NORMALIZER_NOT_ALLOWED,
                "Probe normalizer ID and version are not allowlisted.",
            )
        source_id = _string(record, "evidence_id")
        status = _string(record, "collection_status")
        error_code = _string(record, "error_code")
        if status not in {"COLLECTED", "ERROR", "SKIPPED"}:
            _reject(NormalizationCode.NORMALIZATION_INPUT_INVALID, "Collection status is invalid.")
        if (status == "COLLECTED") != (error_code == "NONE"):
            _reject(
                NormalizationCode.NORMALIZATION_INPUT_INVALID,
                "Collection status and error code are inconsistent.",
            )
        raw_value = record.get("raw_value")
        normalized_value: dict[str, JsonValue] | None = None
        scope = _PROBE_SCOPES.get(probe_id, "VOLUME")
        subject: dict[str, JsonValue] = {"scope": scope}
        if status == "COLLECTED":
            normalized_value = mapper(_mapping(raw_value))
            if scope == "VOLUME":
                subject["subject_key"] = cast(str, normalized_value["volume_id"])
            elif scope == "USER":
                execution_identity = _mapping(record.get("execution_identity"))
                subject["user_sid"] = _string(execution_identity, "user_sid")
        else:
            candidate = _mapping(record.get("normalized_candidate"))
            if scope == "VOLUME":
                subject["subject_key"] = _identifier(candidate, "volume_id")
            elif scope == "USER":
                subject["user_sid"] = _string(candidate, "user_sid")
        collected_at = _string(record, "collected_at")
        if _parse_utc_timestamp(collected_at) > normalized_instant:
            _reject(
                NormalizationCode.NORMALIZATION_INPUT_INVALID,
                "Normalization time is earlier than collection time.",
            )
        redacted = record.get("redacted")
        if not isinstance(redacted, bool):
            _reject(NormalizationCode.NORMALIZATION_INPUT_INVALID, "Redaction flag is invalid.")
        output: dict[str, JsonValue] = {
            "schema_version": "1.0.0",
            "id": str(
                uuid5(
                    UUID(validated.package_id),
                    f"{_NORMALIZER_NAME}:{_NORMALIZER_VERSION}:{source_id}",
                )
            ),
            "created_at": timestamp,
            "source": "normalizer",
            "producer_name": _NORMALIZER_NAME,
            "producer_version": _NORMALIZER_VERSION,
            "correlation_id": _string(descriptor, "correlation_id"),
            "job_id": validated.job_id,
            "asset_id": validated.asset_id,
            "package_id": validated.package_id,
            "source_evidence_id": source_id,
            "control_id": _string(record, "control_id"),
            "guide_version": _string(record, "guide_version"),
            "collector_version": _string(_mapping(descriptor.get("collector")), "version"),
            "probe_id": probe_id,
            "probe_version": probe_version,
            "subject": subject,
            "collected_at": collected_at,
            "normalized_at": timestamp,
            "source_locator": cast(
                dict[str, JsonValue],
                dict(_mapping(record.get("source_locator"))),
            ),
            "collection_status": status,
            "error_code": error_code,
            "redaction": {
                "applied": redacted,
                "method": "OMITTED" if redacted else "NONE",
            },
            "evidence_sha256": _string(record, "evidence_sha256"),
        }
        if raw_value is not None and not redacted:
            output["raw_value"] = cast(JsonValue, raw_value)
        if normalized_value is not None:
            output["normalized_value"] = normalized_value
        for optional in ("unit", "policy_scope", "policy_source"):
            value = record.get(optional)
            if value is not None:
                output[optional] = cast(JsonValue, value)
        try:
            self._schemas.validate(
                output,
                "normalized_evidence.schema.json",
                PackageValidationCode.DESCRIPTOR_SCHEMA_INVALID,
            )
        except PackageValidationError as exc:
            raise NormalizationError(
                NormalizationCode.NORMALIZED_EVIDENCE_SCHEMA_INVALID,
                "Normalizer output failed the normalized evidence Schema.",
            ) from exc
        return output

    @staticmethod
    def _sort_key(record: Mapping[str, JsonValue]) -> tuple[str, str, str]:
        subject = cast(Mapping[str, JsonValue], record["subject"])
        return (
            cast(str, subject.get("subject_key", "")),
            cast(str, record["probe_id"]),
            cast(str, record["id"]),
        )
