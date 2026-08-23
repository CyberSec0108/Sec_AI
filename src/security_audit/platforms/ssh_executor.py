"""고정된 읽기 전용 계획만 SSH로 실행하는 Linux·스위치 수집 경계."""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Timer

from .contracts import PlatformContractError
from .readonly_plan import ReadOnlyCommand, ReadOnlyCommandPlan

_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|"
    r"\d{1,3}(?:\.\d{1,3}){3})$"
)
_USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SshExecution = Callable[[list[str], int, int], tuple[int, bytes, bool]]


@dataclass(frozen=True, slots=True)
class SshReadOnlyTarget:
    host: str
    username: str
    private_key: Path
    known_hosts: Path
    port: int = 22

    def __post_init__(self) -> None:
        if _HOST.fullmatch(self.host) is None:
            raise PlatformContractError("SSH 대상 주소가 올바르지 않습니다.")
        if _USERNAME.fullmatch(self.username) is None:
            raise PlatformContractError("SSH 사용자 이름이 올바르지 않습니다.")
        if not 1 <= self.port <= 65_535:
            raise PlatformContractError("SSH 포트가 올바르지 않습니다.")


@dataclass(frozen=True, slots=True)
class ReadOnlyCollectionBatch:
    outputs: dict[str, bytes]
    failures: dict[str, str]
    cancelled: bool = False


def _bounded_process(
    arguments: list[str],
    timeout_seconds: int,
    maximum_output_bytes: int,
) -> tuple[int, bytes, bool]:
    process = subprocess.Popen(  # noqa: S603 -- 셸 없이 고정 SSH 실행 파일만 호출합니다.
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    if process.stdout is None:
        process.kill()
        return 1, b"", False
    timed_out = Event()

    def stop_after_timeout() -> None:
        timed_out.set()
        process.kill()

    timer = Timer(timeout_seconds, stop_after_timeout)
    timer.daemon = True
    timer.start()
    try:
        output = process.stdout.read(maximum_output_bytes + 1)
        if len(output) > maximum_output_bytes:
            process.kill()
        return_code = process.wait()
    finally:
        timer.cancel()
    return return_code, output, timed_out.is_set()


def _remote_command(command: ReadOnlyCommand) -> str:
    if command.privilege == "PRIVILEGED_EXEC":
        return command.command[0]
    fixed = shlex.join(command.command)
    if command.privilege == "ROOT":
        return f"sudo -n -- {fixed}"
    return fixed


def collect_plan_over_ssh(
    plan: ReadOnlyCommandPlan,
    target: SshReadOnlyTarget,
    *,
    execute: SshExecution = _bounded_process,
    on_command: Callable[[str, str], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> ReadOnlyCollectionBatch:
    """사용자 명령 입력 없이 allowlist 계획 전체를 순서대로 실행합니다."""

    if not target.private_key.is_file() or not target.known_hosts.is_file():
        raise PlatformContractError("SSH 키 또는 known_hosts 파일을 찾을 수 없습니다.")
    ssh = shutil.which("ssh")
    if ssh is None:
        raise PlatformContractError("OpenSSH 실행 파일을 찾을 수 없습니다.")
    outputs: dict[str, bytes] = {}
    failures: dict[str, str] = {}
    for command in plan.commands:
        if should_cancel is not None and should_cancel():
            return ReadOnlyCollectionBatch(
                outputs=outputs,
                failures=failures,
                cancelled=True,
            )
        if on_command is not None:
            on_command(command.command_id, "STARTED")
        arguments = [
            ssh,
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            f"UserKnownHostsFile={target.known_hosts}",
            "-i",
            str(target.private_key),
            "-p",
            str(target.port),
            "--",
            f"{target.username}@{target.host}",
            _remote_command(command),
        ]
        return_code, output, timed_out = execute(
            arguments,
            command.timeout_seconds,
            command.maximum_output_bytes,
        )
        if timed_out:
            failures[command.command_id] = "TIMEOUT"
        elif len(output) > command.maximum_output_bytes:
            failures[command.command_id] = "OUTPUT_LIMIT_EXCEEDED"
        elif return_code not in command.accepted_exit_codes:
            failures[command.command_id] = "COMMAND_FAILED"
        else:
            outputs[command.command_id] = output
        if on_command is not None:
            on_command(
                command.command_id,
                "FAILED" if command.command_id in failures else "COMPLETED",
            )
    return ReadOnlyCollectionBatch(outputs=outputs, failures=failures)
