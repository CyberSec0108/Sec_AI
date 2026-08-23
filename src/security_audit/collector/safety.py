"""IMP-030 privilege separation and before/after safety verification."""

from __future__ import annotations

import hashlib
import os
import re
from base64 import b64encode
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Never, cast

from security_audit.analysis.package_validation import PackageValidationError, load_strict_json

from .contracts import VerifiedExecutionPlan, VerifiedProbeRequest
from .process import (
    BoundedCommandResult,
    BoundedExecutionCode,
    BoundedExecutionError,
    BoundedProcessExecutor,
)
from .windows import WindowsCollectionRun, WindowsReadOnlyCollector

SAFETY_SNAPSHOT_SCRIPT_SHA256 = (
    "5c507ed7a884206a32fd30bcab67c97e7649b2253e307a60aa6c0ea75dd028c1"
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

type SafetyCommandExecutor = Callable[
    [tuple[str, ...], int, bytes, int],
    BoundedCommandResult,
]


class PrivilegeLevel(StrEnum):
    STANDARD_USER = "STANDARD_USER"
    ADMINISTRATOR = "ADMINISTRATOR"


class CollectorSafetyCode(StrEnum):
    POLICY_INVALID = "POLICY_INVALID"
    PRIVILEGE_NOT_ALLOWED = "PRIVILEGE_NOT_ALLOWED"
    STANDARD_PLAN_EMPTY = "STANDARD_PLAN_EMPTY"
    ELEVATED_PLAN_REQUIRES_SEPARATE_PROCESS = "ELEVATED_PLAN_REQUIRES_SEPARATE_PROCESS"
    EXPLICIT_CONSENT_REQUIRED = "EXPLICIT_CONSENT_REQUIRED"
    SNAPSHOT_SCRIPT_INTEGRITY_MISMATCH = "SNAPSHOT_SCRIPT_INTEGRITY_MISMATCH"
    SNAPSHOT_UNAVAILABLE = "SNAPSHOT_UNAVAILABLE"
    SNAPSHOT_TIMEOUT = "SNAPSHOT_TIMEOUT"
    SNAPSHOT_OUTPUT_TOO_LARGE = "SNAPSHOT_OUTPUT_TOO_LARGE"
    SNAPSHOT_OUTPUT_INVALID = "SNAPSHOT_OUTPUT_INVALID"
    SETTINGS_CHANGED = "SETTINGS_CHANGED"


class CollectorSafetyError(RuntimeError):
    def __init__(self, code: CollectorSafetyCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ProcessLimits:
    max_timeout_seconds: int
    max_output_bytes: int
    terminate_process_tree: bool


@dataclass(frozen=True, slots=True)
class SnapshotPolicy:
    required_before_and_after: bool
    max_timeout_seconds: int
    max_output_bytes: int
    surfaces: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CollectorSafetyPolicy:
    policy_id: str
    auto_elevation: bool
    separate_process_required: bool
    explicit_user_consent_required: bool
    standard_process_rejects_elevated_token: bool
    allowed_privileges: frozenset[PrivilegeLevel]
    process_limits: ProcessLimits
    settings_snapshot: SnapshotPolicy

    @classmethod
    def from_file(cls, path: Path) -> CollectorSafetyPolicy:
        try:
            raw = load_strict_json(path.read_bytes())
        except (OSError, PackageValidationError) as exc:
            raise CollectorSafetyError(
                CollectorSafetyCode.POLICY_INVALID,
                "The Collector safety policy is unavailable or invalid.",
            ) from exc
        root = _object(raw)
        _exact_keys(
            root,
            frozenset(
                {
                    "schema_version",
                    "policy_id",
                    "auto_elevation",
                    "separate_process_required",
                    "explicit_user_consent_required",
                    "standard_process_rejects_elevated_token",
                    "allowed_privileges",
                    "process_limits",
                    "settings_snapshot",
                }
            ),
        )
        if root.get("schema_version") != "1.0.0":
            _reject(CollectorSafetyCode.POLICY_INVALID, "Safety policy version is unsupported.")
        privileges = frozenset(
            _privilege(item) for item in _sequence(root.get("allowed_privileges"))
        )
        if privileges != frozenset({PrivilegeLevel.STANDARD_USER, PrivilegeLevel.ADMINISTRATOR}):
            _reject(
                CollectorSafetyCode.POLICY_INVALID,
                "Safety policy privilege levels differ from the fixed contract.",
            )
        process = _object(root.get("process_limits"))
        _exact_keys(
            process,
            frozenset(
                {
                    "max_timeout_seconds",
                    "max_output_bytes",
                    "terminate_process_tree",
                }
            ),
        )
        snapshot = _object(root.get("settings_snapshot"))
        _exact_keys(
            snapshot,
            frozenset(
                {
                    "required_before_and_after",
                    "max_timeout_seconds",
                    "max_output_bytes",
                    "surfaces",
                }
            ),
        )
        surfaces = tuple(_string(item) for item in _sequence(snapshot.get("surfaces")))
        expected_surfaces = (
            "POWERSHELL_EXECUTION_POLICY",
            "DISK_FLAGS",
            "PARTITION_LAYOUT",
            "VOLUME_FILESYSTEM",
            "BITLOCKER_STATE",
        )
        policy = cls(
            policy_id=_string(root.get("policy_id")),
            auto_elevation=_boolean(root.get("auto_elevation")),
            separate_process_required=_boolean(root.get("separate_process_required")),
            explicit_user_consent_required=_boolean(
                root.get("explicit_user_consent_required")
            ),
            standard_process_rejects_elevated_token=_boolean(
                root.get("standard_process_rejects_elevated_token")
            ),
            allowed_privileges=privileges,
            process_limits=ProcessLimits(
                max_timeout_seconds=_positive_integer(process.get("max_timeout_seconds")),
                max_output_bytes=_positive_integer(process.get("max_output_bytes")),
                terminate_process_tree=_boolean(process.get("terminate_process_tree")),
            ),
            settings_snapshot=SnapshotPolicy(
                required_before_and_after=_boolean(
                    snapshot.get("required_before_and_after")
                ),
                max_timeout_seconds=_positive_integer(
                    snapshot.get("max_timeout_seconds")
                ),
                max_output_bytes=_positive_integer(snapshot.get("max_output_bytes")),
                surfaces=surfaces,
            ),
        )
        if (
            policy.auto_elevation
            or not policy.separate_process_required
            or not policy.explicit_user_consent_required
            or not policy.standard_process_rejects_elevated_token
            or not policy.process_limits.terminate_process_tree
            or not policy.settings_snapshot.required_before_and_after
            or policy.settings_snapshot.surfaces != expected_surfaces
        ):
            _reject(
                CollectorSafetyCode.POLICY_INVALID,
                "Safety policy weakens a mandatory IMP-030 boundary.",
            )
        return policy


@dataclass(frozen=True, slots=True)
class ElevationNotice:
    required: bool
    probe_ids: tuple[str, ...]
    explicit_user_consent_required: bool
    auto_start: bool
    message: str


@dataclass(frozen=True, slots=True)
class PrivilegeSeparatedPlans:
    standard: VerifiedExecutionPlan | None
    elevated: VerifiedExecutionPlan | None
    elevation_notice: ElevationNotice


@dataclass(frozen=True, slots=True)
class SafetySnapshot:
    snapshot_sha256: str
    collected_at_utc: str


@dataclass(frozen=True, slots=True)
class SafetyVerifiedCollection:
    collection: WindowsCollectionRun
    privilege: PrivilegeLevel
    settings_before_after_equal: bool
    settings_diff_count: int
    auto_elevation: bool
    elevated_probe_count: int


def _reject(code: CollectorSafetyCode, message: str) -> Never:
    raise CollectorSafetyError(code, message)


def _object(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(CollectorSafetyCode.POLICY_INVALID, "Expected an object.")
    return cast(Mapping[str, object], value)


def _sequence(value: object) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _reject(CollectorSafetyCode.POLICY_INVALID, "Expected an array.")
    return cast(Sequence[object], value)


def _exact_keys(value: Mapping[str, object], expected: frozenset[str]) -> None:
    if frozenset(value) != expected:
        _reject(CollectorSafetyCode.POLICY_INVALID, "Safety policy fields are invalid.")


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        _reject(CollectorSafetyCode.POLICY_INVALID, "Expected a non-empty string.")
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        _reject(CollectorSafetyCode.POLICY_INVALID, "Expected a boolean.")
    return value


def _positive_integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        _reject(CollectorSafetyCode.POLICY_INVALID, "Expected a positive integer.")
    return value


def _privilege(value: object) -> PrivilegeLevel:
    try:
        return PrivilegeLevel(_string(value))
    except ValueError as exc:
        raise CollectorSafetyError(
            CollectorSafetyCode.PRIVILEGE_NOT_ALLOWED,
            "A Probe requested an unsupported privilege level.",
        ) from exc


def _subplan(
    source: VerifiedExecutionPlan,
    probes: tuple[VerifiedProbeRequest, ...],
) -> VerifiedExecutionPlan | None:
    if not probes:
        return None
    return VerifiedExecutionPlan(
        manifest_id=source.manifest_id,
        manifest_sha256=source.manifest_sha256,
        job_id=source.job_id,
        asset_id=source.asset_id,
        nonce=source.nonce,
        verified_at=source.verified_at,
        probes=probes,
    )


def split_execution_plan(
    plan: VerifiedExecutionPlan,
    policy: CollectorSafetyPolicy,
) -> PrivilegeSeparatedPlans:
    standard: list[VerifiedProbeRequest] = []
    elevated: list[VerifiedProbeRequest] = []
    for probe in plan.probes:
        privilege = _privilege(probe.required_privilege)
        if privilege not in policy.allowed_privileges:
            _reject(
                CollectorSafetyCode.PRIVILEGE_NOT_ALLOWED,
                "A Probe privilege is outside the safety policy.",
            )
        if privilege is PrivilegeLevel.STANDARD_USER:
            standard.append(probe)
        else:
            elevated.append(probe)
    elevated_ids = tuple(probe.probe_id for probe in elevated)
    notice = ElevationNotice(
        required=bool(elevated_ids),
        probe_ids=elevated_ids,
        explicit_user_consent_required=policy.explicit_user_consent_required,
        auto_start=False,
        message=(
            "관리자 권한이 필요한 점검은 별도 실행 전에 사용자에게 항목과 이유를 알립니다."
            if elevated_ids
            else "현재 작업에는 관리자 권한이 필요한 Probe가 없습니다."
        ),
    )
    return PrivilegeSeparatedPlans(
        standard=_subplan(plan, tuple(standard)),
        elevated=_subplan(plan, tuple(elevated)),
        elevation_notice=notice,
    )


def authorize_elevated_plan(
    plans: PrivilegeSeparatedPlans,
    *,
    explicit_user_consent: bool,
) -> VerifiedExecutionPlan | None:
    if plans.elevated is None:
        return None
    if not explicit_user_consent:
        _reject(
            CollectorSafetyCode.EXPLICIT_CONSENT_REQUIRED,
            "The separate elevated Probe plan requires explicit user consent.",
        )
    return plans.elevated


class WindowsSafetySnapshotter:
    """Capture only a digest of stable mutable Windows settings."""

    def __init__(
        self,
        script_path: Path,
        policy: CollectorSafetyPolicy,
        *,
        executor: SafetyCommandExecutor | None = None,
        platform_name: str | None = None,
        powershell_path: Path | None = None,
    ) -> None:
        self._script_path = script_path.resolve()
        self._policy = policy
        self._platform_name = platform_name or os.name
        self._executor = executor or BoundedProcessExecutor(
            platform_name=self._platform_name
        )
        self._powershell_path = powershell_path

    def capture(self) -> SafetySnapshot:
        if self._platform_name != "nt":
            _reject(
                CollectorSafetyCode.SNAPSHOT_UNAVAILABLE,
                "Windows safety snapshots can run only on Windows.",
            )
        self._verify_script()
        powershell = self._resolve_powershell()
        try:
            source = self._script_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CollectorSafetyError(
                CollectorSafetyCode.SNAPSHOT_SCRIPT_INTEGRITY_MISMATCH,
                "The fixed safety snapshot script is unavailable.",
            ) from exc
        command = (
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            b64encode(source.encode("utf-16le")).decode("ascii"),
        )
        snapshot_policy = self._policy.settings_snapshot
        try:
            completed = self._executor(
                command,
                snapshot_policy.max_timeout_seconds,
                b"",
                snapshot_policy.max_output_bytes,
            )
        except BoundedExecutionError as exc:
            code = {
                BoundedExecutionCode.START_FAILED: CollectorSafetyCode.SNAPSHOT_UNAVAILABLE,
                BoundedExecutionCode.STDIN_FAILED: CollectorSafetyCode.SNAPSHOT_UNAVAILABLE,
                BoundedExecutionCode.TIMEOUT: CollectorSafetyCode.SNAPSHOT_TIMEOUT,
                BoundedExecutionCode.OUTPUT_TOO_LARGE: (
                    CollectorSafetyCode.SNAPSHOT_OUTPUT_TOO_LARGE
                ),
            }[exc.code]
            raise CollectorSafetyError(code, str(exc)) from exc
        if completed.returncode != 0:
            _reject(
                CollectorSafetyCode.SNAPSHOT_UNAVAILABLE,
                "The fixed safety snapshot Probe could not complete.",
            )
        try:
            parsed = load_strict_json(completed.stdout)
        except PackageValidationError as exc:
            raise CollectorSafetyError(
                CollectorSafetyCode.SNAPSHOT_OUTPUT_INVALID,
                "The fixed safety snapshot returned invalid strict JSON.",
            ) from exc
        root = _object(parsed)
        _exact_keys(
            root,
            frozenset({"schema_version", "snapshot_sha256", "collected_at_utc"}),
        )
        digest = _string(root.get("snapshot_sha256"))
        timestamp = _string(root.get("collected_at_utc"))
        if (
            root.get("schema_version") != "1.0.0"
            or _SHA256_PATTERN.fullmatch(digest) is None
            or not timestamp.endswith("Z")
            or len(timestamp) > 32
        ):
            _reject(
                CollectorSafetyCode.SNAPSHOT_OUTPUT_INVALID,
                "The fixed safety snapshot fields are invalid.",
            )
        return SafetySnapshot(digest, timestamp)

    def _verify_script(self) -> None:
        try:
            digest = hashlib.sha256(self._script_path.read_bytes()).hexdigest()
        except OSError as exc:
            raise CollectorSafetyError(
                CollectorSafetyCode.SNAPSHOT_SCRIPT_INTEGRITY_MISMATCH,
                "The fixed safety snapshot script is unavailable.",
            ) from exc
        if digest != SAFETY_SNAPSHOT_SCRIPT_SHA256:
            _reject(
                CollectorSafetyCode.SNAPSHOT_SCRIPT_INTEGRITY_MISMATCH,
                "The fixed safety snapshot script digest is not allowlisted.",
            )

    def _resolve_powershell(self) -> Path:
        if self._powershell_path is not None:
            candidate = self._powershell_path.resolve()
        else:
            system_root = os.environ.get("SystemRoot")
            if not system_root:
                _reject(
                    CollectorSafetyCode.SNAPSHOT_UNAVAILABLE,
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
                CollectorSafetyCode.SNAPSHOT_UNAVAILABLE,
                "The trusted Windows PowerShell executable is unavailable.",
            )
        return candidate


class SafeWindowsCollectionCoordinator:
    """Run the standard plan between immutable before/after snapshots."""

    def __init__(
        self,
        policy: CollectorSafetyPolicy,
        collector: WindowsReadOnlyCollector,
        snapshotter: WindowsSafetySnapshotter,
    ) -> None:
        self._policy = policy
        self._collector = collector
        self._snapshotter = snapshotter

    def collect_standard(
        self,
        plan: VerifiedExecutionPlan,
    ) -> SafetyVerifiedCollection:
        plans = split_execution_plan(plan, self._policy)
        if plans.standard is None:
            _reject(
                CollectorSafetyCode.STANDARD_PLAN_EMPTY,
                "The standard-user Probe plan is empty.",
            )
        if plans.elevated is not None:
            _reject(
                CollectorSafetyCode.ELEVATED_PLAN_REQUIRES_SEPARATE_PROCESS,
                "Elevated Probes must be executed later in a separate process.",
            )
        before = self._snapshotter.capture()
        try:
            collection = self._collector.execute(plans.standard)
        except Exception as original:
            after_error = self._snapshotter.capture()
            if before.snapshot_sha256 != after_error.snapshot_sha256:
                raise CollectorSafetyError(
                    CollectorSafetyCode.SETTINGS_CHANGED,
                    "Windows settings changed while a Probe failed.",
                ) from original
            raise
        after = self._snapshotter.capture()
        if before.snapshot_sha256 != after.snapshot_sha256:
            _reject(
                CollectorSafetyCode.SETTINGS_CHANGED,
                "Windows settings changed during read-only collection.",
            )
        return SafetyVerifiedCollection(
            collection=collection,
            privilege=PrivilegeLevel.STANDARD_USER,
            settings_before_after_equal=True,
            settings_diff_count=0,
            auto_elevation=self._policy.auto_elevation,
            elevated_probe_count=0,
        )
