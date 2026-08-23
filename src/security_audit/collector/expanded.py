"""IMP-031 fixed PC-01~18 Windows Probe groups."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Never, cast

from security_audit.analysis.package_validation import PackageValidationError, load_strict_json
from security_audit.common.canonical_json import JsonScalar

from .contracts import VerifiedExecutionPlan, VerifiedProbeRequest
from .process import (
    BoundedCommandResult,
    BoundedExecutionCode,
    BoundedExecutionError,
    BoundedProcessExecutor,
)
from .windows import WindowsExecutionContext

STANDARD_SCRIPT_SHA256 = (
    "7c362ae57f719d02d878d9b5f1ca8014f270d2b848fcb22d9142758477ad7699"
)
ADMINISTRATOR_SCRIPT_SHA256 = (
    "c1acc75fab089c8553c95d4f736ccbb00daeded9170afb6338c8ecc10707df93"
)

STANDARD_NON_STORAGE_PROBES = (
    "win.security.password-age",
    "win.security.recovery-console",
    "win.services.inventory",
    "win.browser.wininet-cache-policy",
    "win.os.lifecycle",
    "win.autologon.config",
    "win.antivirus.update-status",
    "win.antivirus.realtime-status",
    "win.firewall.effective-profiles",
    "win.user.screensaver-policy",
    "win.media.autoplay-policy",
    "win.remote-assistance.policy",
)
ADMINISTRATOR_PROBES = (
    "win.security.password-policy",
    "win.network.smb-shares",
    "win.software.messengers",
    "win.boot.entries",
    "win.update.compliance",
)

_EXPECTED_ADAPTERS = {
    "win.security.password-age": ("secai.windows-native", "0.1.0"),
    "win.security.password-policy": ("secai.windows-account-policy", "0.1.0"),
    "win.security.recovery-console": ("secai.windows-registry", "0.1.0"),
    "win.network.smb-shares": ("secai.windows-smb-native", "0.1.0"),
    "win.services.inventory": (
        "secai.windows-service-control-manager",
        "0.1.0",
    ),
    "win.software.messengers": (
        "secai.windows-installed-software-inventory",
        "0.1.0",
    ),
    "win.boot.entries": ("secai.windows-bcdedit-native", "0.1.0"),
    "win.browser.wininet-cache-policy": ("secai.windows-registry", "0.1.0"),
    "win.update.compliance": (
        "secai.windows-update-history-build",
        "0.1.0",
    ),
    "win.os.lifecycle": ("secai.windows-native", "0.1.0"),
    "win.autologon.config": ("secai.winlogon-native", "0.1.0"),
    "win.antivirus.update-status": (
        "secai.microsoft-defender-antivirus",
        "0.1.0",
    ),
    "win.antivirus.realtime-status": (
        "secai.microsoft-defender-antivirus",
        "0.1.0",
    ),
    "win.firewall.effective-profiles": ("secai.windows-firewall", "0.1.0"),
    "win.user.screensaver-policy": ("secai.windows-registry", "0.1.0"),
    "win.media.autoplay-policy": ("secai.windows-registry", "0.1.0"),
    "win.remote-assistance.policy": ("secai.windows-registry", "0.1.0"),
}
_SID_PATTERN = re.compile(r"^S-1-(?:\d+-){1,14}\d+$")
_SAFE_RESULT_KEYS = frozenset(
    {
        "probe_id",
        "probe_version",
        "control_ids",
        "collection_status",
        "error_code",
        "adapter_id",
        "adapter_version",
        "coverage",
        "records",
    }
)
_FORBIDDEN_RECORD_KEYS = frozenset(
    {
        "password",
        "password_content",
        "default_password",
        "secret",
        "token",
        "private_key",
        "username",
        "user_name",
        "hostname",
        "host_name",
        "process_sid",
        "volume_label",
        "serial_number",
        "product_key",
    }
)
_COLLECTION_STATUSES = frozenset({"COLLECTED", "ERROR", "UNSUPPORTED"})
_ERROR_CODES = frozenset(
    {
        "NONE",
        "PERMISSION_DENIED",
        "SOURCE_UNAVAILABLE",
        "ADAPTER_UNSUPPORTED",
        "QUERY_FAILED",
    }
)


class ExpandedCollectionCode(str):
    PLAN_INVALID = "PLAN_INVALID"
    SCRIPT_INTEGRITY_MISMATCH = "SCRIPT_INTEGRITY_MISMATCH"
    POWERSHELL_UNAVAILABLE = "POWERSHELL_UNAVAILABLE"
    PROBE_TIMEOUT = "PROBE_TIMEOUT"
    OUTPUT_TOO_LARGE = "OUTPUT_TOO_LARGE"
    PROBE_EXECUTION_FAILED = "PROBE_EXECUTION_FAILED"
    PROBE_OUTPUT_INVALID = "PROBE_OUTPUT_INVALID"
    TARGET_CONTEXT_MISMATCH = "TARGET_CONTEXT_MISMATCH"
    PRIVILEGE_CONTEXT_MISMATCH = "PRIVILEGE_CONTEXT_MISMATCH"


class ExpandedCollectionError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


type ExpandedCommandExecutor = Callable[
    [tuple[str, ...], int, bytes, int],
    BoundedCommandResult,
]


@dataclass(frozen=True, slots=True)
class ExpandedProbeResult:
    probe_id: str
    probe_version: str
    control_ids: tuple[str, ...]
    collection_status: str
    error_code: str
    adapter_id: str
    adapter_version: str
    coverage: str
    records: tuple[Mapping[str, JsonScalar], ...]


@dataclass(frozen=True, slots=True)
class ExpandedWindowsCollection:
    context: WindowsExecutionContext
    privilege: str
    real_os_access: bool
    settings_modified: bool
    official_finding_created: bool
    results: tuple[ExpandedProbeResult, ...]


def _reject(code: str, message: str) -> Never:
    raise ExpandedCollectionError(code, message)


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(ExpandedCollectionCode.PROBE_OUTPUT_INVALID, "Probe object is invalid.")
    return cast(Mapping[str, object], value)


def _sequence(value: object) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _reject(ExpandedCollectionCode.PROBE_OUTPUT_INVALID, "Probe array is invalid.")
    return cast(Sequence[object], value)


def _string(value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value) or len(value) > 256:
        _reject(ExpandedCollectionCode.PROBE_OUTPUT_INVALID, "Probe string is invalid.")
    return value


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _reject(ExpandedCollectionCode.PROBE_OUTPUT_INVALID, "Probe integer is invalid.")
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        _reject(ExpandedCollectionCode.PROBE_OUTPUT_INVALID, "Probe boolean is invalid.")
    return value


def _context(value: object) -> WindowsExecutionContext:
    raw = _mapping(value)
    expected = frozenset(
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
    )
    if frozenset(raw) != expected:
        _reject(ExpandedCollectionCode.PROBE_OUTPUT_INVALID, "Context fields are invalid.")
    sid = _string(raw.get("process_sid"))
    build = _string(raw.get("build_number"))
    timestamp = _string(raw.get("collected_at_utc"))
    if (
        _SID_PATTERN.fullmatch(sid) is None
        or not build.isascii()
        or not build.isdecimal()
        or not timestamp.endswith("Z")
        or len(timestamp) > 32
    ):
        _reject(ExpandedCollectionCode.PROBE_OUTPUT_INVALID, "Context identity is invalid.")
    integrity = _string(raw.get("integrity_level"))
    if integrity not in {"LOW", "MEDIUM", "MEDIUM_PLUS", "HIGH", "SYSTEM", "UNKNOWN"}:
        _reject(ExpandedCollectionCode.PROBE_OUTPUT_INVALID, "Integrity level is invalid.")
    return WindowsExecutionContext(
        os_family=_string(raw.get("os_family")),
        os_version=_string(raw.get("os_version")),
        product_name=_string(raw.get("product_name")),
        display_version=_string(raw.get("display_version"), allow_empty=True),
        build_number=build,
        ubr=_integer(raw.get("ubr")),
        architecture=_string(raw.get("architecture")),
        process_sid=sid,
        is_administrator=_boolean(raw.get("is_administrator")),
        integrity_level=integrity,
        collected_at_utc=timestamp,
    )


def _record(value: object) -> Mapping[str, JsonScalar]:
    raw = _mapping(value)
    if not raw or len(raw) > 32:
        _reject(ExpandedCollectionCode.PROBE_OUTPUT_INVALID, "Probe record size is invalid.")
    result: dict[str, JsonScalar] = {}
    for key, item in raw.items():
        if (
            not isinstance(key, str)
            or not key
            or len(key) > 64
            or key.casefold() in _FORBIDDEN_RECORD_KEYS
        ):
            _reject(ExpandedCollectionCode.PROBE_OUTPUT_INVALID, "Probe record key is forbidden.")
        if not isinstance(item, (str, int, float, bool, type(None))):
            _reject(ExpandedCollectionCode.PROBE_OUTPUT_INVALID, "Probe record value is invalid.")
        if isinstance(item, str) and len(item) > 256:
            _reject(ExpandedCollectionCode.PROBE_OUTPUT_INVALID, "Probe record text is too long.")
        result[key] = item
    return result


class ExpandedWindowsCollector:
    """Execute one exact privilege group using a fixed stdin PowerShell source."""

    def __init__(
        self,
        script_path: Path,
        *,
        privilege: str,
        executor: ExpandedCommandExecutor | None = None,
        platform_name: str | None = None,
        powershell_path: Path | None = None,
    ) -> None:
        if privilege not in {"STANDARD_USER", "ADMINISTRATOR"}:
            raise ValueError("Unsupported Collector privilege group.")
        self._script_path = script_path.resolve()
        self._privilege = privilege
        self._platform_name = platform_name or os.name
        self._executor = executor or BoundedProcessExecutor(
            platform_name=self._platform_name
        )
        self._powershell_path = powershell_path

    def execute(self, plan: VerifiedExecutionPlan) -> ExpandedWindowsCollection:
        actual_ids = tuple(probe.probe_id for probe in plan.probes)
        expected_ids: tuple[str, ...] = STANDARD_NON_STORAGE_PROBES
        if self._privilege == "ADMINISTRATOR":
            expected_ids = tuple(
                probe_id
                for probe_id in ADMINISTRATOR_PROBES
                if probe_id in actual_ids
            )
        if (
            not actual_ids
            or actual_ids != expected_ids
            or any(
                probe.probe_version != "0.1.0"
                or probe.required_privilege != self._privilege
                or probe.timeout_seconds > 30
                or probe.max_output_bytes > 65_536
                for probe in plan.probes
            )
        ):
            _reject(
                ExpandedCollectionCode.PLAN_INVALID,
                "Expanded Probe plan differs from the fixed privilege group.",
            )
        if self._platform_name != "nt":
            _reject(
                ExpandedCollectionCode.TARGET_CONTEXT_MISMATCH,
                "Expanded Windows Probes can run only on Windows.",
            )
        source = self._verified_source()
        powershell = self._resolve_powershell()
        timeout = min(probe.timeout_seconds for probe in plan.probes)
        max_output = min(probe.max_output_bytes for probe in plan.probes)
        command = (
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            *(
                (
                    "-File",
                    str(self._script_path),
                    "-SelectedProbeIdsCsv",
                    ",".join(expected_ids),
                )
                if self._privilege == "ADMINISTRATOR"
                else (
                    "-Command",
                    "$source = [Console]::In.ReadToEnd(); "
                    "& ([ScriptBlock]::Create($source))",
                )
            ),
        )
        try:
            completed = self._executor(
                command,
                timeout,
                b"" if self._privilege == "ADMINISTRATOR" else source.encode("ascii"),
                max_output,
            )
        except BoundedExecutionError as exc:
            code = {
                BoundedExecutionCode.START_FAILED: (
                    ExpandedCollectionCode.POWERSHELL_UNAVAILABLE
                ),
                BoundedExecutionCode.STDIN_FAILED: (
                    ExpandedCollectionCode.PROBE_EXECUTION_FAILED
                ),
                BoundedExecutionCode.TIMEOUT: ExpandedCollectionCode.PROBE_TIMEOUT,
                BoundedExecutionCode.OUTPUT_TOO_LARGE: (
                    ExpandedCollectionCode.OUTPUT_TOO_LARGE
                ),
            }[exc.code]
            raise ExpandedCollectionError(code, str(exc)) from exc
        if completed.returncode != 0:
            _reject(
                ExpandedCollectionCode.PROBE_EXECUTION_FAILED,
                "Expanded Windows Probe group could not complete.",
            )
        try:
            parsed = load_strict_json(completed.stdout)
        except PackageValidationError as exc:
            raise ExpandedCollectionError(
                ExpandedCollectionCode.PROBE_OUTPUT_INVALID,
                "Expanded Windows Probe returned invalid strict JSON.",
            ) from exc
        root = _mapping(parsed)
        if frozenset(root) != {"schema_version", "context", "results"}:
            _reject(
                ExpandedCollectionCode.PROBE_OUTPUT_INVALID,
                "Expanded Probe envelope is invalid.",
            )
        if root.get("schema_version") != "1.0.0":
            _reject(
                ExpandedCollectionCode.PROBE_OUTPUT_INVALID,
                "Expanded Probe output version is unsupported.",
            )
        context = _context(root.get("context"))
        context.adapter_selection()
        if (
            context.os_family != "WINDOWS"
            or context.os_version not in {"10", "11"}
            or context.architecture != "x86_64"
        ):
            _reject(
                ExpandedCollectionCode.TARGET_CONTEXT_MISMATCH,
                "Expanded Probe host is outside the Windows 10/11 x64 target.",
            )
        expected_admin = self._privilege == "ADMINISTRATOR"
        if context.is_administrator is not expected_admin:
            _reject(
                ExpandedCollectionCode.PRIVILEGE_CONTEXT_MISMATCH,
                "Expanded Probe process privilege differs from its plan.",
            )
        raw_results = _sequence(root.get("results"))
        if len(raw_results) != len(plan.probes):
            _reject(
                ExpandedCollectionCode.PROBE_OUTPUT_INVALID,
                "Expanded Probe result coverage is incomplete.",
            )
        results = tuple(
            self._validate_result(raw, probe)
            for raw, probe in zip(raw_results, plan.probes, strict=True)
        )
        return ExpandedWindowsCollection(
            context=context,
            privilege=self._privilege,
            real_os_access=True,
            settings_modified=False,
            official_finding_created=False,
            results=results,
        )

    def _validate_result(
        self,
        value: object,
        probe: VerifiedProbeRequest,
    ) -> ExpandedProbeResult:
        raw = _mapping(value)
        if frozenset(raw) != _SAFE_RESULT_KEYS:
            _reject(
                ExpandedCollectionCode.PROBE_OUTPUT_INVALID,
                "Expanded Probe result fields are invalid.",
            )
        probe_id = _string(raw.get("probe_id"))
        expected_id = probe.probe_id
        expected_controls = tuple(probe.control_ids)
        if (
            probe_id != expected_id
            or raw.get("probe_version") != probe.probe_version
            or tuple(_string(item) for item in _sequence(raw.get("control_ids")))
            != expected_controls
        ):
            _reject(
                ExpandedCollectionCode.PROBE_OUTPUT_INVALID,
                "Expanded Probe result is not bound to its verified request.",
            )
        status = _string(raw.get("collection_status"))
        error_code = _string(raw.get("error_code"))
        if (
            status not in _COLLECTION_STATUSES
            or error_code not in _ERROR_CODES
            or (status == "COLLECTED") != (error_code == "NONE")
        ):
            _reject(
                ExpandedCollectionCode.PROBE_OUTPUT_INVALID,
                "Expanded Probe status and error code conflict.",
            )
        adapter_id = _string(raw.get("adapter_id"))
        adapter_version = _string(raw.get("adapter_version"))
        if (adapter_id, adapter_version) != _EXPECTED_ADAPTERS[probe_id]:
            _reject(
                ExpandedCollectionCode.PROBE_OUTPUT_INVALID,
                "Expanded Probe Adapter is not allowlisted.",
            )
        raw_records = _sequence(raw.get("records"))
        if len(raw_records) > 2048 or (status == "COLLECTED" and not raw_records):
            _reject(
                ExpandedCollectionCode.PROBE_OUTPUT_INVALID,
                "Expanded Probe record count is invalid.",
            )
        return ExpandedProbeResult(
            probe_id=probe_id,
            probe_version=_string(raw.get("probe_version")),
            control_ids=expected_controls,
            collection_status=status,
            error_code=error_code,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            coverage=_string(raw.get("coverage")),
            records=tuple(_record(item) for item in raw_records),
        )

    def _verified_source(self) -> str:
        expected_hash = (
            STANDARD_SCRIPT_SHA256
            if self._privilege == "STANDARD_USER"
            else ADMINISTRATOR_SCRIPT_SHA256
        )
        try:
            source_bytes = self._script_path.read_bytes()
        except OSError as exc:
            raise ExpandedCollectionError(
                ExpandedCollectionCode.SCRIPT_INTEGRITY_MISMATCH,
                "Expanded Probe source is unavailable.",
            ) from exc
        if hashlib.sha256(source_bytes).hexdigest() != expected_hash:
            _reject(
                ExpandedCollectionCode.SCRIPT_INTEGRITY_MISMATCH,
                "Expanded Probe source hash is not allowlisted.",
            )
        try:
            return source_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ExpandedCollectionError(
                ExpandedCollectionCode.SCRIPT_INTEGRITY_MISMATCH,
                "Expanded Probe source encoding is not fixed ASCII.",
            ) from exc

    def _resolve_powershell(self) -> Path:
        if self._powershell_path is not None:
            candidate = self._powershell_path.resolve()
        else:
            system_root = os.environ.get("SystemRoot")
            if not system_root:
                _reject(
                    ExpandedCollectionCode.POWERSHELL_UNAVAILABLE,
                    "Trusted Windows system directory is unavailable.",
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
                ExpandedCollectionCode.POWERSHELL_UNAVAILABLE,
                "Trusted Windows PowerShell is unavailable.",
            )
        return candidate
