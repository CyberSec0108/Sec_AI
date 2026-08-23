"""장비별 고정 명령만 실행할 수 있는 읽기 전용 계획 계약."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .contracts import PlatformContractError, PlatformFamily

Privilege = Literal["STANDARD_USER", "ADMINISTRATOR", "ROOT", "PRIVILEGED_EXEC"]


@dataclass(frozen=True, slots=True)
class ReadOnlyCommand:
    command_id: str
    command: tuple[str, ...]
    privilege: Privilege
    timeout_seconds: int
    maximum_output_bytes: int
    accepted_exit_codes: tuple[int, ...] = (0,)

    def __post_init__(self) -> None:
        if not self.command or not 1 <= self.timeout_seconds <= 180:
            raise PlatformContractError("읽기 전용 명령 계약이 올바르지 않습니다.")
        if not 1 <= self.maximum_output_bytes <= 1024 * 1024:
            raise PlatformContractError("명령 출력 제한이 올바르지 않습니다.")
        if (
            not self.accepted_exit_codes
            or len(set(self.accepted_exit_codes)) != len(self.accepted_exit_codes)
            or any(code < 0 or code > 255 for code in self.accepted_exit_codes)
        ):
            raise PlatformContractError("허용 종료 코드 계약이 올바르지 않습니다.")
        if any("\n" in part or "\r" in part or "\x00" in part for part in self.command):
            raise PlatformContractError("명령 인자에 허용되지 않은 문자가 있습니다.")
        if self.privilege == "PRIVILEGED_EXEC" and (
            len(self.command) != 1 or not self.command[0].casefold().startswith("show ")
        ):
            raise PlatformContractError("스위치는 고정된 show 명령만 허용합니다.")


@dataclass(frozen=True, slots=True)
class ReadOnlyCommandPlan:
    platform: PlatformFamily
    commands: tuple[ReadOnlyCommand, ...]

    def command(self, command_id: str) -> ReadOnlyCommand:
        matches = [item for item in self.commands if item.command_id == command_id]
        if len(matches) != 1:
            raise PlatformContractError("허용 목록에 없는 확인 명령입니다.")
        return matches[0]
