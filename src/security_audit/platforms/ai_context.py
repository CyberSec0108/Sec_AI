"""장비별 공식 판정을 변경하지 않는 AI 설명 입력."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import cast

from security_audit.common.canonical_json import JsonValue, canonical_sha256

from .contracts import DeviceAuditResult

_SOURCE_GRADES = frozenset(
    {"ACTUAL_EVIDENCE", "RULE", "APPROVED_GUIDE", "VENDOR_DOCUMENT", "GENERAL_KNOWLEDGE"}
)


@dataclass(frozen=True, slots=True)
class DeviceAIMessageContract:
    system_prompt: str
    user_payload: str
    context_sha256: str


def build_device_ai_context(
    result: DeviceAuditResult,
    *,
    evidence_sources: tuple[dict[str, JsonValue], ...],
) -> dict[str, JsonValue]:
    """LLM에 비식별 결과·증적 계보·승인 근거만 전달합니다."""

    for source in evidence_sources:
        grade = source.get("source_grade")
        if grade not in _SOURCE_GRADES or any(
            "raw" in key.casefold() or "secret" in key.casefold()
            for key in source
        ):
            raise ValueError("DEVICE_AI_SOURCE_INVALID")
    result_json = result.to_json()
    controls = cast(list[JsonValue], result_json["controls"])
    context: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "asset": result_json["asset"],
        "benchmark": result_json["benchmark"],
        "criteria_sha256": result_json["criteria_sha256"],
        "controls": controls,
        "evidence_sources": cast(list[JsonValue], list(evidence_sources)),
        "instructions": {
            "status_authority": "RULE_ENGINE",
            "may_change_status": False,
            "may_execute_remediation": False,
            "explain_each_control": True,
            "explain_overall_after_controls": True,
            "separate_observed_fact_rule_source_and_general_knowledge": True,
        },
        "raw_evidence_included": False,
    }
    context["context_sha256"] = canonical_sha256(context)
    return context


def build_device_ai_messages(
    result: DeviceAuditResult,
    *,
    evidence_sources: tuple[dict[str, JsonValue], ...],
) -> DeviceAIMessageContract:
    """장비 문법은 구분하고 판정은 바꾸지 않는 LLM 메시지를 만듭니다."""

    context = build_device_ai_context(result, evidence_sources=evidence_sources)
    asset = cast(dict[str, JsonValue], context["asset"])
    platform = str(asset["platform"])
    platform_notes = {
        "WINDOWS": "PowerShell·레지스트리·Windows 정책 위치를 구분해 설명합니다.",
        "LINUX": "Linux 파일·systemd·OpenSSH의 실제 확인 방법을 구분해 설명합니다.",
        "CISCO_IOS": "Cisco IOS 명령 문법과 설정 모드를 혼동하지 않습니다.",
        "ARUBA_AOS_CX": "Aruba AOS-CX 문법을 Cisco IOS 문법과 섞지 않습니다.",
    }
    system_prompt = " ".join(
        (
            "당신은 읽기 전용 보안 점검 결과 설명자입니다.",
            "RULE_ENGINE 판정과 실제 확인값을 절대 변경하거나 추정하지 마세요.",
            "각 항목을 확인값, 기준, 의미, 다음 행동 순서로 쉬운 한국어로 설명하세요.",
            "실제 증적·규칙·승인 가이드·제조사 문서·일반 지식의 출처 등급을 구분하세요.",
            "근거가 없으면 모른다고 말하고 명령 실행이나 자동 수정은 제안만 하세요.",
            platform_notes[platform],
        )
    )
    payload = json.dumps(context, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return DeviceAIMessageContract(
        system_prompt=system_prompt,
        user_payload=payload,
        context_sha256=str(context["context_sha256"]),
    )
