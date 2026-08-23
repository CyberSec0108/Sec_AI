"""Cisco IOS와 Aruba AOS-CX의 읽기 전용 구성 점검 파서."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from .contracts import (
    AssessmentStatus,
    DeviceControlResult,
    EvidenceTrace,
    PlatformContractError,
)
from .readonly_plan import ReadOnlyCommand, ReadOnlyCommandPlan


@dataclass(frozen=True, slots=True)
class SwitchAdapter:
    adapter_id: str
    platform: str
    plan: ReadOnlyCommandPlan
    running_config_command_id: str


CISCO_IOS = SwitchAdapter(
    adapter_id="secai.cisco-ios.readonly.v1",
    platform="CISCO_IOS",
    plan=ReadOnlyCommandPlan(
        platform="CISCO_IOS",
        commands=(
            ReadOnlyCommand(
                "cisco.show-version",
                ("show version",),
                "PRIVILEGED_EXEC",
                20,
                262_144,
            ),
            ReadOnlyCommand(
                "cisco.running-config",
                ("show running-config",),
                "PRIVILEGED_EXEC",
                30,
                1_048_576,
            ),
            ReadOnlyCommand(
                "cisco.logging",
                ("show logging",),
                "PRIVILEGED_EXEC",
                20,
                262_144,
            ),
            ReadOnlyCommand(
                "cisco.ntp",
                ("show ntp associations",),
                "PRIVILEGED_EXEC",
                20,
                262_144,
            ),
        ),
    ),
    running_config_command_id="cisco.running-config",
)

ARUBA_AOS_CX = SwitchAdapter(
    adapter_id="secai.aruba-aos-cx.readonly.v1",
    platform="ARUBA_AOS_CX",
    plan=ReadOnlyCommandPlan(
        platform="ARUBA_AOS_CX",
        commands=(
            ReadOnlyCommand(
                "aruba.show-version",
                ("show version",),
                "PRIVILEGED_EXEC",
                20,
                262_144,
            ),
            ReadOnlyCommand(
                "aruba.running-config",
                ("show running-config",),
                "PRIVILEGED_EXEC",
                30,
                1_048_576,
            ),
            ReadOnlyCommand(
                "aruba.logging",
                ("show logging",),
                "PRIVILEGED_EXEC",
                20,
                262_144,
            ),
            ReadOnlyCommand(
                "aruba.ntp",
                ("show ntp associations",),
                "PRIVILEGED_EXEC",
                20,
                262_144,
            ),
        ),
    ),
    running_config_command_id="aruba.running-config",
)

SWITCH_ADAPTERS = {
    "CISCO_IOS": CISCO_IOS,
    "ARUBA_AOS_CX": ARUBA_AOS_CX,
}


def adapter_for(platform: str) -> SwitchAdapter:
    adapter = SWITCH_ADAPTERS.get(platform)
    if adapter is None:
        raise PlatformContractError("지원하지 않는 스위치 운영체제입니다.")
    return adapter


def _has(config: str, pattern: str) -> bool:
    return re.search(pattern, config, flags=re.IGNORECASE | re.MULTILINE) is not None


def _evidence(
    adapter: SwitchAdapter,
    *,
    output: bytes | None,
    summary: str,
    captured_at: datetime,
) -> EvidenceTrace:
    command = adapter.plan.command(adapter.running_config_command_id)
    return EvidenceTrace.build(
        probe_id=adapter.running_config_command_id,
        probe_version="1.0.0",
        method_code="NETWORK_CLI_FIXED_COMMAND",
        method_summary="고정된 네트워크 장비 조회 명령으로 적용 구성을 확인합니다.",
        source_label="실행 중인 스위치 구성",
        technical_locator=command.command[0],
        observed_summary=summary,
        collected_at=captured_at,
        collection_status="COLLECTED" if output is not None else "ERROR",
        raw_output=output or b"",
        redaction_applied=True,
    )


def evaluate_switch_baseline(
    platform: str,
    outputs: Mapping[str, bytes],
    *,
    captured_at: datetime,
) -> tuple[DeviceControlResult, ...]:
    """두 제조사에 같은 의미의 기준을 적용하되 문법은 어댑터별로 해석합니다."""

    adapter = adapter_for(platform)
    raw = outputs.get(adapter.running_config_command_id)
    config = raw.decode("utf-8", errors="replace") if raw is not None else ""
    if platform == "CISCO_IOS":
        facts = (
            (
                "SW-01",
                "관리자 인증 보호",
                r"^\s*enable secret\s+\S+",
                "enable secret 설정",
            ),
            (
                "SW-02",
                "원격 관리 SSH 사용",
                r"^\s*transport input\s+ssh(?:\s|$)",
                "VTY SSH 전용",
            ),
            (
                "SW-03",
                "안전한 SNMP 설정",
                r"^\s*snmp-server\s+(?:group\s+\S+\s+v3|user\s+\S+\s+\S+\s+v3)",
                "SNMPv3 구성",
            ),
            (
                "SW-04",
                "원격 로그 전송",
                r"^\s*(?:logging host|logging)\s+\d{1,3}(?:\.\d{1,3}){3}",
                "원격 로그 서버 설정",
            ),
            ("SW-05", "시각 동기화", r"^\s*ntp server\s+\S+", "NTP 서버 설정"),
            (
                "SW-06",
                "암호화된 비밀번호 저장",
                r"^\s*service password-encryption\s*$",
                "비밀번호 암호화 서비스",
            ),
        )
    else:
        facts = (
            (
                "SW-01",
                "관리자 인증 보호",
                r"^\s*user\s+\S+\s+group\s+administrators\s+password\s+ciphertext\s+\S+",
                "관리자 암호문 저장",
            ),
            ("SW-02", "원격 관리 SSH 사용", r"^\s*ssh server vrf\s+\S+", "SSH 서버 설정"),
            ("SW-03", "안전한 SNMP 설정", r"^\s*snmpv3\s+user\s+\S+", "SNMPv3 사용자 구성"),
            (
                "SW-04",
                "원격 로그 전송",
                r"^\s*logging\s+\d{1,3}(?:\.\d{1,3}){3}",
                "원격 로그 서버 설정",
            ),
            ("SW-05", "시각 동기화", r"^\s*ntp server\s+\S+", "NTP 서버 설정"),
            (
                "SW-06",
                "관리 세션 시간 제한",
                r"^\s*session-timeout\s+\d+",
                "관리 세션 시간 제한",
            ),
        )
    results: list[DeviceControlResult] = []
    for control_id, title, pattern, expected in facts:
        passed = None if raw is None else _has(config, pattern)
        observed = (
            "필요한 보안 설정을 확인했습니다."
            if passed is True
            else (
                "필요한 보안 설정을 확인하지 못했습니다."
                if passed is False
                else "실행 중인 구성을 읽지 못했습니다."
            )
        )
        status: AssessmentStatus = (
            "ERROR" if passed is None else ("PASS" if passed else "FAIL")
        )
        suffix = (
            "COLLECTION_FAILED"
            if passed is None
            else ("COMPLIANT" if passed else "NON_COMPLIANT")
        )
        results.append(
            DeviceControlResult(
                control_id=control_id,
                title=title,
                status=status,
                result_code=f"{control_id.replace('-', '_')}_{suffix}",
                expected_summary=expected,
                observed_summary=observed,
                action_guidance=(
                    "현재 관리 접속 경로를 보존한 상태에서 제조사 절차에 따라 설정을 검토하세요."
                ),
                evidence=(
                    _evidence(
                        adapter,
                        output=raw,
                        summary=observed,
                        captured_at=captured_at,
                    ),
                ),
            )
        )
    return tuple(results)
