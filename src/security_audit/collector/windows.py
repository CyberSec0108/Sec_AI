"""IMP-029 Windows read-only context and PC-07 storage collection."""

from __future__ import annotations

import os
import re
from base64 import b64encode
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Never, cast

from security_audit.analysis.package_validation import PackageValidationError, load_strict_json
from security_audit.common.canonical_json import JsonValue
from security_audit.platforms.discovery import (
    AdapterSelection,
    PlatformFingerprint,
    current_platform_support_catalog,
    discover_windows_platform,
)

from .contracts import VerifiedExecutionPlan
from .process import (
    BoundedCommandResult,
    BoundedExecutionCode,
    BoundedExecutionError,
    BoundedProcessExecutor,
)

CommandResult = BoundedCommandResult

WINDOWS_PROBE_SCRIPT_SHA256 = (
    "0dc549f5fbc6d4841e572102b740ac0f9d895c033b72b71c3cb3be441f063bee"
)
_EXPECTED_PROBES = (
    "win.storage.disks",
    "win.storage.partitions",
    "win.storage.volumes",
)
_SID_PATTERN = re.compile(r"^S-1-(?:\d+-){1,14}\d+$")
_OPAQUE_VOLUME_PATTERN = re.compile(r"^vol-\d{3}$")
_OPAQUE_DISK_PATTERN = re.compile(r"^disk-\d+$")
_GUID_PATTERN = re.compile(
    r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
)


class WindowsCollectionCode(StrEnum):
    """Stable collector-boundary outcomes; these are not Finding states."""

    UNSUPPORTED_OS = "UNSUPPORTED_OS"
    PLAN_INVALID = "PLAN_INVALID"
    SCRIPT_INTEGRITY_MISMATCH = "SCRIPT_INTEGRITY_MISMATCH"
    POWERSHELL_UNAVAILABLE = "POWERSHELL_UNAVAILABLE"
    PROBE_TIMEOUT = "PROBE_TIMEOUT"
    OUTPUT_TOO_LARGE = "OUTPUT_TOO_LARGE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    PROBE_EXECUTION_FAILED = "PROBE_EXECUTION_FAILED"
    PROBE_OUTPUT_INVALID = "PROBE_OUTPUT_INVALID"
    TARGET_CONTEXT_MISMATCH = "TARGET_CONTEXT_MISMATCH"
    UNEXPECTED_ELEVATION = "UNEXPECTED_ELEVATION"


class WindowsCollectionError(RuntimeError):
    """Fail-closed read-only collection error without host identifiers."""

    def __init__(self, code: WindowsCollectionCode, message: str) -> None:
        super().__init__(message)
        self.code = code


type CommandExecutor = Callable[[tuple[str, ...], int, bytes, int], CommandResult]


@dataclass(frozen=True, slots=True)
class WindowsExecutionContext:
    os_family: str
    os_version: str
    product_name: str
    display_version: str
    build_number: str
    ubr: int
    architecture: str
    process_sid: str
    is_administrator: bool
    integrity_level: str
    collected_at_utc: str

    def platform_fingerprint(self) -> PlatformFingerprint:
        """현재 Windows PC 계약을 자동 식별 계약으로 변환합니다."""

        return discover_windows_platform(
            product_kind="CLIENT",
            product_version=self.os_version,
            build=self.build_number,
            machine=self.architecture,
        )

    def adapter_selection(self) -> AdapterSelection:
        return current_platform_support_catalog().resolve(
            self.platform_fingerprint()
        )

    def redacted(self) -> dict[str, JsonValue]:
        """Return display-safe context without the persistent user SID."""

        return {
            "os_family": self.os_family,
            "os_version": self.os_version,
            "product_name": self.product_name,
            "display_version": self.display_version,
            "build_number": self.build_number,
            "ubr": self.ubr,
            "architecture": self.architecture,
            "process_sid": "S-1-5-21-[REDACTED]",
            "sid_format_valid": _SID_PATTERN.fullmatch(self.process_sid) is not None,
            "is_administrator": self.is_administrator,
            "integrity_level": self.integrity_level,
            "collected_at_utc": self.collected_at_utc,
        }


@dataclass(frozen=True, slots=True)
class WindowsProbeResult:
    probe_id: str
    probe_version: str
    control_ids: tuple[str, ...]
    collection_status: str
    synthetic: bool
    payload: JsonValue


@dataclass(frozen=True, slots=True)
class WindowsCollectionRun:
    manifest_id: str
    manifest_sha256: str
    job_id: str
    asset_id: str
    execution_mode: str
    real_os_access: bool
    elevation_requested: bool
    settings_modified: bool
    context: WindowsExecutionContext
    results: tuple[WindowsProbeResult, ...]


def _reject(code: WindowsCollectionCode, message: str) -> Never:
    raise WindowsCollectionError(code, message)


def _string(mapping: Mapping[str, object], key: str, *, allow_empty: bool = False) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or (not allow_empty and not value):
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Probe returned an invalid string.")
    return value


def _boolean(mapping: Mapping[str, object], key: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool):
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Probe returned an invalid boolean.")
    return value


def _integer(mapping: Mapping[str, object], key: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Probe returned an invalid integer.")
    return value


def _object(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Probe returned an invalid object.")
    return cast(Mapping[str, object], value)


def _array(value: object) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Probe returned an invalid array.")
    return cast(Sequence[object], value)


def _exact_keys(mapping: Mapping[str, object], expected: frozenset[str]) -> None:
    if frozenset(mapping) != expected:
        _reject(
            WindowsCollectionCode.PROBE_OUTPUT_INVALID,
            "Probe fields differ from the fixed read-only contract.",
        )


def _enum(mapping: Mapping[str, object], key: str, values: frozenset[str]) -> str:
    value = _string(mapping, key)
    if value not in values:
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Probe returned an invalid enum.")
    return value


def _validate_context(raw: Mapping[str, object]) -> WindowsExecutionContext:
    _exact_keys(
        raw,
        frozenset(
            {
                "os_family",
                "os_version",
                "product_name",
                "display_version",
                "build_number",
                "ubr",
                "architecture",
                "process_sid",
                "is_administrator",
                "integrity_level",
                "collected_at_utc",
            }
        ),
    )
    sid = _string(raw, "process_sid")
    if _SID_PATTERN.fullmatch(sid) is None:
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Process SID format is invalid.")
    build_number = _string(raw, "build_number")
    if not build_number.isascii() or not build_number.isdecimal():
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Windows build number is invalid.")
    timestamp = _string(raw, "collected_at_utc")
    if not timestamp.endswith("Z") or len(timestamp) > 32:
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Collection timestamp is invalid.")
    return WindowsExecutionContext(
        os_family=_enum(raw, "os_family", frozenset({"WINDOWS"})),
        os_version=_enum(raw, "os_version", frozenset({"10", "11", "UNSUPPORTED"})),
        product_name=_string(raw, "product_name"),
        display_version=_string(raw, "display_version", allow_empty=True),
        build_number=build_number,
        ubr=_integer(raw, "ubr"),
        architecture=_enum(raw, "architecture", frozenset({"x86_64", "x86"})),
        process_sid=sid,
        is_administrator=_boolean(raw, "is_administrator"),
        integrity_level=_enum(
            raw,
            "integrity_level",
            frozenset({"LOW", "MEDIUM", "MEDIUM_PLUS", "HIGH", "SYSTEM", "UNKNOWN"}),
        ),
        collected_at_utc=timestamp,
    )


def _validate_disk(raw: Mapping[str, object]) -> dict[str, JsonValue]:
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
    volume_id = _string(raw, "volume_id")
    disk_id = _string(raw, "disk_id")
    if (
        _OPAQUE_VOLUME_PATTERN.fullmatch(volume_id) is None
        or _OPAQUE_DISK_PATTERN.fullmatch(disk_id) is None
    ):
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Opaque storage ID is invalid.")
    return {
        "volume_id": volume_id,
        "disk_id": disk_id,
        "volume_class": _enum(
            raw,
            "volume_class",
            frozenset(
                {
                    "WINDOWS_OS_VOLUME",
                    "LOCAL_FIXED_DATA_VOLUME",
                    "MOUNTED_FOLDER_VOLUME",
                    "ATTACHED_VHD_VOLUME",
                    "STORAGE_SPACES_LOGICAL_VOLUME",
                    "EFI_SYSTEM_PARTITION",
                    "MICROSOFT_RESERVED_PARTITION",
                    "WINDOWS_RECOVERY_PARTITION",
                    "OPTICAL_VOLUME",
                    "REMOVABLE_VOLUME",
                    "VOLATILE_RAM_DISK",
                }
            ),
        ),
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


def _validate_partition(raw: Mapping[str, object]) -> dict[str, JsonValue]:
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
    volume_id = _string(raw, "volume_id")
    gpt_type = _string(raw, "gpt_type")
    if (
        _OPAQUE_VOLUME_PATTERN.fullmatch(volume_id) is None
        or _GUID_PATTERN.fullmatch(gpt_type) is None
    ):
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Partition identity is invalid.")
    return {
        "volume_id": volume_id,
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


def _validate_volume(raw: Mapping[str, object]) -> dict[str, JsonValue]:
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
    volume_id = _string(raw, "volume_id")
    if _OPAQUE_VOLUME_PATTERN.fullmatch(volume_id) is None:
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Opaque volume ID is invalid.")
    filesystem = raw.get("filesystem")
    if filesystem is not None and (not isinstance(filesystem, str) or len(filesystem) > 32):
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Filesystem value is invalid.")
    drive_letter = raw.get("drive_letter")
    if drive_letter is not None and (
        not isinstance(drive_letter, str)
        or len(drive_letter) != 1
        or drive_letter not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ):
        _reject(WindowsCollectionCode.PROBE_OUTPUT_INVALID, "Drive letter is invalid.")
    return {
        "volume_id": volume_id,
        "filesystem": filesystem,
        "volume_class": _string(raw, "volume_class"),
        "drive_type": _enum(
            raw,
            "drive_type",
            frozenset({"FIXED", "REMOVABLE", "NETWORK", "CDROM", "RAMDISK", "UNKNOWN"}),
        ),
        "drive_letter": drive_letter,
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
            frozenset(
                {"NONE", "UNLOCKED_PROTECTED", "UNLOCKED_UNPROTECTED", "LOCKED", "UNKNOWN"}
            ),
        ),
    }


class WindowsReadOnlyCollector:
    """Execute one fixed PowerShell script after receiving a verified plan."""

    def __init__(
        self,
        script_path: Path,
        *,
        executor: CommandExecutor | None = None,
        platform_name: str | None = None,
        powershell_path: Path | None = None,
    ) -> None:
        self._script_path = script_path.resolve()
        self._platform_name = platform_name or os.name
        self._executor = executor or BoundedProcessExecutor(platform_name=self._platform_name)
        self._powershell_path = powershell_path

    def execute(self, plan: VerifiedExecutionPlan) -> WindowsCollectionRun:
        self._validate_plan(plan)
        if self._platform_name != "nt":
            _reject(
                WindowsCollectionCode.UNSUPPORTED_OS,
                "The Windows read-only Collector can run only on Windows.",
            )
        self._verify_script()
        powershell = self._resolve_powershell()
        try:
            fixed_script = self._script_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise WindowsCollectionError(
                WindowsCollectionCode.SCRIPT_INTEGRITY_MISMATCH,
                "The fixed read-only Probe script is unavailable.",
            ) from exc
        timeout_seconds = min(probe.timeout_seconds for probe in plan.probes)
        max_output_bytes = min(probe.max_output_bytes for probe in plan.probes)
        command = (
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            b64encode(fixed_script.encode("utf-16le")).decode("ascii"),
        )
        try:
            completed = self._executor(command, timeout_seconds, b"", max_output_bytes)
        except BoundedExecutionError as exc:
            code = {
                BoundedExecutionCode.START_FAILED: WindowsCollectionCode.POWERSHELL_UNAVAILABLE,
                BoundedExecutionCode.STDIN_FAILED: WindowsCollectionCode.PROBE_EXECUTION_FAILED,
                BoundedExecutionCode.TIMEOUT: WindowsCollectionCode.PROBE_TIMEOUT,
                BoundedExecutionCode.OUTPUT_TOO_LARGE: WindowsCollectionCode.OUTPUT_TOO_LARGE,
            }[exc.code]
            raise WindowsCollectionError(code, str(exc)) from exc
        if len(completed.stdout) > max_output_bytes or len(completed.stderr) > max_output_bytes:
            _reject(
                WindowsCollectionCode.OUTPUT_TOO_LARGE,
                "The read-only Probe exceeded its output limit.",
            )
        if completed.returncode != 0:
            if b"0x80041003" in completed.stderr.lower():
                _reject(
                    WindowsCollectionCode.PERMISSION_DENIED,
                    "The read-only Windows Probe lacked permission to read storage.",
                )
            _reject(
                WindowsCollectionCode.PROBE_EXECUTION_FAILED,
                "The read-only Windows Probe could not complete.",
            )
        try:
            parsed = load_strict_json(completed.stdout)
        except PackageValidationError as exc:
            raise WindowsCollectionError(
                WindowsCollectionCode.PROBE_OUTPUT_INVALID,
                "The read-only Windows Probe returned invalid strict JSON.",
            ) from exc
        root = _object(parsed)
        _exact_keys(root, frozenset({"schema_version", "context", "subjects"}))
        if root.get("schema_version") != "1.0.0":
            _reject(
                WindowsCollectionCode.PROBE_OUTPUT_INVALID,
                "The read-only Probe output version is unsupported.",
            )
        context = _validate_context(_object(root.get("context")))
        context.adapter_selection()
        if (
            context.os_family != "WINDOWS"
            or context.os_version not in {"10", "11"}
            or context.architecture != "x86_64"
        ):
            _reject(
                WindowsCollectionCode.TARGET_CONTEXT_MISMATCH,
                "The current Windows 10/11 x64 context does not match the Collector target.",
            )
        if context.is_administrator:
            _reject(
                WindowsCollectionCode.UNEXPECTED_ELEVATION,
                "Standard-user PC-07 Probes must not run in an elevated process.",
            )
        disks: list[JsonValue] = []
        partitions: list[JsonValue] = []
        volumes: list[JsonValue] = []
        seen_volume_ids: set[str] = set()
        for raw_subject in _array(root.get("subjects")):
            subject = _object(raw_subject)
            _exact_keys(subject, frozenset({"disk", "partition", "volume"}))
            disk = _validate_disk(_object(subject.get("disk")))
            partition = _validate_partition(_object(subject.get("partition")))
            volume = _validate_volume(_object(subject.get("volume")))
            volume_ids = {
                cast(str, disk["volume_id"]),
                cast(str, partition["volume_id"]),
                cast(str, volume["volume_id"]),
            }
            if len(volume_ids) != 1:
                _reject(
                    WindowsCollectionCode.PROBE_OUTPUT_INVALID,
                    "Storage records are not joined to one opaque volume ID.",
                )
            volume_id = volume_ids.pop()
            if volume_id in seen_volume_ids:
                _reject(
                    WindowsCollectionCode.PROBE_OUTPUT_INVALID,
                    "Probe returned a duplicate opaque volume ID.",
                )
            seen_volume_ids.add(volume_id)
            if disk["volume_class"] != volume["volume_class"]:
                _reject(
                    WindowsCollectionCode.PROBE_OUTPUT_INVALID,
                    "Storage classification differs between Probe records.",
                )
            disks.append(disk)
            partitions.append(partition)
            volumes.append(volume)
        if not seen_volume_ids:
            _reject(
                WindowsCollectionCode.PROBE_OUTPUT_INVALID,
                "Probe did not return any partition-backed storage subjects.",
            )
        payloads: dict[str, JsonValue] = {
            "win.storage.disks": disks,
            "win.storage.partitions": partitions,
            "win.storage.volumes": volumes,
        }
        results = tuple(
            WindowsProbeResult(
                probe_id=probe.probe_id,
                probe_version=probe.probe_version,
                control_ids=probe.control_ids,
                collection_status="COLLECTED",
                synthetic=False,
                payload=payloads[probe.probe_id],
            )
            for probe in plan.probes
        )
        return WindowsCollectionRun(
            manifest_id=plan.manifest_id,
            manifest_sha256=plan.manifest_sha256,
            job_id=plan.job_id,
            asset_id=plan.asset_id,
            execution_mode="WINDOWS_READ_ONLY",
            real_os_access=True,
            elevation_requested=False,
            settings_modified=False,
            context=context,
            results=results,
        )

    def _validate_plan(self, plan: VerifiedExecutionPlan) -> None:
        actual = tuple(probe.probe_id for probe in plan.probes)
        if actual != _EXPECTED_PROBES:
            _reject(
                WindowsCollectionCode.PLAN_INVALID,
                "The execution plan is not the exact IMP-029 PC-07 Probe set.",
            )
        if any(
            probe.required_privilege != "STANDARD_USER"
            or probe.probe_version != "0.1.0"
            or probe.control_ids != ("PC-07",)
            for probe in plan.probes
        ):
            _reject(
                WindowsCollectionCode.PLAN_INVALID,
                "The execution plan exceeds the read-only PC-07 contract.",
            )

    def _verify_script(self) -> None:
        import hashlib

        try:
            digest = hashlib.sha256(self._script_path.read_bytes()).hexdigest()
        except OSError as exc:
            raise WindowsCollectionError(
                WindowsCollectionCode.SCRIPT_INTEGRITY_MISMATCH,
                "The fixed read-only Probe script is unavailable.",
            ) from exc
        if digest != WINDOWS_PROBE_SCRIPT_SHA256:
            _reject(
                WindowsCollectionCode.SCRIPT_INTEGRITY_MISMATCH,
                "The fixed read-only Probe script digest is not allowlisted.",
            )

    def _resolve_powershell(self) -> Path:
        if self._powershell_path is not None:
            candidate = self._powershell_path.resolve()
        else:
            system_root = os.environ.get("SystemRoot")
            if not system_root:
                _reject(
                    WindowsCollectionCode.POWERSHELL_UNAVAILABLE,
                    "The trusted Windows system directory is unavailable.",
                )
            candidate = (
                Path(system_root)
                / "System32"
                / "WindowsPowerShell"
                / "v1.0"
                / "powershell.exe"
            ).resolve()
        if not candidate.is_file() or candidate.name.casefold() != "powershell.exe":
            _reject(
                WindowsCollectionCode.POWERSHELL_UNAVAILABLE,
                "The trusted Windows PowerShell executable is unavailable.",
            )
        return candidate
