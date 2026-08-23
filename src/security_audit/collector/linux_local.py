"""Linux 원샷 점검기의 고정 명령 로컬 실행 경계.

이 모듈은 판정을 만들지 않습니다. 배포판별 ``ReadOnlyCommandPlan``에 이미
등록된 argv만 셸 없이 실행하고, 성공 출력 또는 안전한 수집 오류만 반환합니다.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import signal
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from threading import Event, Lock, Timer
from typing import Literal

from security_audit.platforms.discovery import discover_linux_platform
from security_audit.platforms.linux_adapters import (
    LinuxDistribution,
    detect_linux_distribution,
    linux_adapter_for,
)
from security_audit.platforms.linux_kisa import control_ids_for_probe
from security_audit.platforms.readonly_plan import ReadOnlyCommand, ReadOnlyCommandPlan

LinuxPrivilege = Literal["STANDARD_USER", "ELEVATED_ADMIN"]
CollectionStatus = Literal["COLLECTED", "ERROR", "SKIPPED"]
LocalExecution = Callable[[Sequence[str], int, int], tuple[int, bytes, bool, bool]]

_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_SAFE_ENV = {
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}
_SECRET_ASSIGNMENT = re.compile(
    r"(?im)^(?P<prefix>[^\n]*(?:token|secret|cookie|private[_ -]?key)\s*[:=]\s*)\S+.*$"
)
_COMMUNITY_VALUE = re.compile(r"(?im)^(?P<prefix>\s*(?:ro|rw)community\s+)\S+.*$")
_HOME_USER = re.compile(r"(?P<prefix>/(?:home|users)/)[^/\s]+")


class LinuxCollectionErrorCode(StrEnum):
    PLATFORM_UNSUPPORTED = "PLATFORM_UNSUPPORTED"
    ARCHITECTURE_UNSUPPORTED = "ARCHITECTURE_UNSUPPORTED"
    DISTRIBUTION_UNSUPPORTED = "DISTRIBUTION_UNSUPPORTED"
    DISTRIBUTION_MISMATCH = "DISTRIBUTION_MISMATCH"
    INVALID_PLAN = "INVALID_PLAN"


class LinuxCollectionError(ValueError):
    def __init__(self, code: LinuxCollectionErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class LinuxProbeContract:
    probe_id: str
    probe_version: str
    control_ids: tuple[str, ...]
    required_privilege: LinuxPrivilege
    exact_argv: tuple[str, ...]
    timeout_seconds: int
    max_output_bytes: int
    accepted_exit_codes: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class LinuxProbeOutcome:
    probe_id: str
    probe_version: str
    control_ids: tuple[str, ...]
    required_privilege: LinuxPrivilege
    executed_privilege: Literal["STANDARD_USER", "ELEVATED_ADMIN", "NOT_EXECUTED"]
    collection_status: CollectionStatus
    error_code: str
    exit_code: int | None
    raw_output_sha256: str
    normalized_sha256: str
    redaction_applied: bool
    normalized_value: str


@dataclass(frozen=True, slots=True)
class LinuxLocalCollectionBatch:
    outcomes: tuple[LinuxProbeOutcome, ...]
    cancelled: bool = False

    @property
    def outputs(self) -> dict[str, bytes]:
        return {
            item.probe_id: item.normalized_value.encode("utf-8")
            for item in self.outcomes
            if item.collection_status == "COLLECTED"
        }

    @property
    def failures(self) -> dict[str, str]:
        return {
            item.probe_id: item.error_code
            for item in self.outcomes
            if item.collection_status != "COLLECTED"
        }


@dataclass(frozen=True, slots=True)
class LinuxRuntimeIdentity:
    distribution: LinuxDistribution
    version: str
    os_release: bytes
    machine: str


def _privilege(command: ReadOnlyCommand) -> LinuxPrivilege:
    return "STANDARD_USER" if command.privilege == "STANDARD_USER" else "ELEVATED_ADMIN"


def linux_probe_contracts(
    distribution: LinuxDistribution | str,
) -> tuple[LinuxProbeContract, ...]:
    """SSH 시험 경로와 동일한 42개 배포판별 계획을 불변 계약으로 변환합니다."""

    adapter = linux_adapter_for(distribution)
    return tuple(
        LinuxProbeContract(
            probe_id=command.command_id,
            probe_version="1.0.0",
            control_ids=control_ids_for_probe(command.command_id),
            required_privilege=_privilege(command),
            exact_argv=command.command,
            timeout_seconds=command.timeout_seconds,
            max_output_bytes=command.maximum_output_bytes,
            accepted_exit_codes=command.accepted_exit_codes,
        )
        for command in adapter.plan.commands
    )


def validate_linux_runtime(
    *,
    os_release: bytes,
    machine: str,
    expected: LinuxDistribution | str | None = None,
    system_name: str = "Linux",
) -> LinuxDistribution:
    if system_name.casefold() != "linux":
        raise LinuxCollectionError(
            LinuxCollectionErrorCode.PLATFORM_UNSUPPORTED,
            "Linux 시스템에서만 실행할 수 있습니다.",
        )
    if machine.casefold() not in {"x86_64", "amd64"}:
        raise LinuxCollectionError(
            LinuxCollectionErrorCode.ARCHITECTURE_UNSUPPORTED,
            "현재는 x86_64 Linux만 지원합니다.",
        )
    try:
        detected = detect_linux_distribution(os_release)
    except ValueError as exc:
        raise LinuxCollectionError(
            LinuxCollectionErrorCode.DISTRIBUTION_UNSUPPORTED,
            "지원하지 않는 Linux 배포판 또는 버전입니다.",
        ) from exc
    if expected is not None and detected is not LinuxDistribution(expected):
        raise LinuxCollectionError(
            LinuxCollectionErrorCode.DISTRIBUTION_MISMATCH,
            "선택한 배포판과 실제 서버가 다릅니다.",
        )
    return detected


def detect_current_linux_runtime(
    expected: LinuxDistribution | str | None = None,
) -> LinuxDistribution:
    return current_linux_runtime_identity(expected).distribution


def current_linux_runtime_identity(
    expected: LinuxDistribution | str | None = None,
) -> LinuxRuntimeIdentity:
    try:
        os_release = open("/etc/os-release", "rb").read(8193)  # noqa: PTH123
    except OSError as exc:
        raise LinuxCollectionError(
            LinuxCollectionErrorCode.DISTRIBUTION_UNSUPPORTED,
            "Linux 배포판 정보를 읽을 수 없습니다.",
        ) from exc
    if len(os_release) > 8192:
        raise LinuxCollectionError(
            LinuxCollectionErrorCode.DISTRIBUTION_UNSUPPORTED,
            "Linux 배포판 정보가 허용 크기를 초과했습니다.",
        )
    machine = platform.machine()
    detected = validate_linux_runtime(
        os_release=os_release,
        machine=machine,
        system_name=platform.system(),
        expected=expected,
    )
    fingerprint = discover_linux_platform(os_release, machine=machine)
    return LinuxRuntimeIdentity(
        distribution=detected,
        version=fingerprint.version,
        os_release=os_release,
        machine=machine,
    )


def normalize_linux_output(probe_id: str, output: bytes) -> tuple[str, bool]:
    """판정에 필요한 줄 구조는 유지하고 흔한 secret·홈 사용자명은 제거합니다."""

    del probe_id
    text = output.decode("utf-8", errors="replace").replace("\x00", "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = _SECRET_ASSIGNMENT.sub(r"\g<prefix><redacted>", text)
    normalized = _COMMUNITY_VALUE.sub(r"\g<prefix><redacted>", normalized)
    normalized = _HOME_USER.sub(r"\g<prefix><user>", normalized)
    normalized = normalized.rstrip("\n") + ("\n" if normalized else "")
    return normalized, normalized != text


class LocalProcessSupervisor:
    """활성 자식 process tree를 취소 시 함께 종료합니다."""

    def __init__(self) -> None:
        self._process: subprocess.Popen[bytes] | None = None
        self._lock = Lock()

    def run(
        self,
        arguments: Sequence[str],
        timeout_seconds: int,
        maximum_output_bytes: int,
    ) -> tuple[int, bytes, bool, bool]:
        process = subprocess.Popen(  # noqa: S603 - 검증된 고정 argv만 전달됩니다.
            list(arguments),
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            env=_SAFE_ENV,
            start_new_session=True,
        )
        with self._lock:
            self._process = process
        if process.stdout is None:
            self.cancel()
            return 1, b"", False, False
        timed_out = Event()

        def stop_after_timeout() -> None:
            timed_out.set()
            self.cancel()

        timer = Timer(timeout_seconds, stop_after_timeout)
        timer.daemon = True
        timer.start()
        try:
            output = process.stdout.read(maximum_output_bytes + 1)
            output_exceeded = len(output) > maximum_output_bytes
            if output_exceeded:
                self.cancel()
            return_code = process.wait()
            return return_code, output[:maximum_output_bytes], timed_out.is_set(), output_exceeded
        finally:
            timer.cancel()
            with self._lock:
                self._process = None

    def cancel(self) -> None:
        with self._lock:
            process = self._process
        if process is None or process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            process.kill()


def _skipped(command: ReadOnlyCommand, error_code: str) -> LinuxProbeOutcome:
    return LinuxProbeOutcome(
        probe_id=command.command_id,
        probe_version="1.0.0",
        control_ids=control_ids_for_probe(command.command_id),
        required_privilege=_privilege(command),
        executed_privilege="NOT_EXECUTED",
        collection_status="SKIPPED",
        error_code=error_code,
        exit_code=None,
        raw_output_sha256=_EMPTY_SHA256,
        normalized_sha256=_EMPTY_SHA256,
        redaction_applied=False,
        normalized_value="",
    )


def collect_linux_plan_locally(
    plan: ReadOnlyCommandPlan,
    *,
    include_elevated: bool,
    elevated_consent: bool,
    execute: LocalExecution | None = None,
    effective_user_id: int | None = None,
    should_cancel: Callable[[], bool] | None = None,
    on_probe: Callable[[str, str], None] | None = None,
    process_supervisor: LocalProcessSupervisor | None = None,
) -> LinuxLocalCollectionBatch:
    """일반 권한을 먼저 끝낸 후 명시적으로 동의한 추가 권한만 실행합니다."""

    if plan.platform != "LINUX" or not plan.commands:
        raise LinuxCollectionError(
            LinuxCollectionErrorCode.INVALID_PLAN,
            "Linux 점검 계획이 올바르지 않습니다.",
        )
    supervisor = process_supervisor or LocalProcessSupervisor()
    runner = execute or supervisor.run
    user_id = os.geteuid() if effective_user_id is None else effective_user_id
    standard = tuple(item for item in plan.commands if item.privilege == "STANDARD_USER")
    elevated = tuple(item for item in plan.commands if item.privilege != "STANDARD_USER")
    outcomes: list[LinuxProbeOutcome] = []

    for command in (*standard, *elevated):
        if should_cancel is not None and should_cancel():
            supervisor.cancel()
            return LinuxLocalCollectionBatch(tuple(outcomes), cancelled=True)
        required = _privilege(command)
        if required == "ELEVATED_ADMIN" and not (include_elevated and elevated_consent):
            outcomes.append(_skipped(command, "USER_DECLINED"))
            continue
        if on_probe is not None:
            on_probe(command.command_id, "STARTED")
        arguments: tuple[str, ...] = command.command
        executed_privilege: Literal["STANDARD_USER", "ELEVATED_ADMIN"] = "STANDARD_USER"
        if required == "ELEVATED_ADMIN":
            executed_privilege = "ELEVATED_ADMIN"
            if user_id != 0:
                arguments = ("/usr/bin/sudo", "--", *command.command)
        return_code, output, timed_out, output_exceeded = runner(
            arguments,
            command.timeout_seconds,
            command.maximum_output_bytes,
        )
        raw_sha256 = hashlib.sha256(output).hexdigest()
        normalized, redacted = normalize_linux_output(command.command_id, output)
        if timed_out:
            status: CollectionStatus = "ERROR"
            error_code = "PROBE_TIMEOUT"
            normalized = ""
        elif output_exceeded:
            status = "ERROR"
            error_code = "OUTPUT_LIMIT_EXCEEDED"
            normalized = ""
        elif return_code not in command.accepted_exit_codes:
            status = "ERROR"
            error_code = (
                "PERMISSION_DENIED"
                if required == "ELEVATED_ADMIN" and user_id != 0
                else "COMMAND_FAILED"
            )
            normalized = ""
        else:
            status = "COLLECTED"
            error_code = "NONE"
        normalized_sha256 = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        outcome = LinuxProbeOutcome(
            probe_id=command.command_id,
            probe_version="1.0.0",
            control_ids=control_ids_for_probe(command.command_id),
            required_privilege=required,
            executed_privilege=executed_privilege,
            collection_status=status,
            error_code=error_code,
            exit_code=return_code if 0 <= return_code <= 255 else None,
            raw_output_sha256=raw_sha256,
            normalized_sha256=normalized_sha256,
            redaction_applied=redacted,
            normalized_value=normalized,
        )
        outcomes.append(outcome)
        if on_probe is not None:
            on_probe(command.command_id, "COMPLETED" if status == "COLLECTED" else "FAILED")
    return LinuxLocalCollectionBatch(tuple(outcomes))


def collect_current_linux(
    distribution: LinuxDistribution | str,
    *,
    include_elevated: bool,
    elevated_consent: bool,
    should_cancel: Callable[[], bool] | None = None,
    on_probe: Callable[[str, str], None] | None = None,
) -> LinuxLocalCollectionBatch:
    selected = detect_current_linux_runtime(distribution)
    return collect_linux_plan_locally(
        linux_adapter_for(selected).plan,
        include_elevated=include_elevated,
        elevated_consent=elevated_consent,
        should_cancel=should_cancel,
        on_probe=on_probe,
    )
