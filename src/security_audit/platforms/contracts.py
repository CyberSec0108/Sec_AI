"""장비 종류와 무관하게 사용하는 읽기 전용 점검 결과 계약.

장비별 수집 명령과 파서는 이 계약 밖에 둔다. 공통 계약은 판정 상태, 비식별
확인값, 증적 해시, 기준 스냅샷 및 계보만 보존하며 원문 명령 출력은 포함하지
않는다.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast
from uuid import UUID

from security_audit.common.canonical_json import JsonValue, canonical_sha256

AssetType = Literal["WINDOWS_PC", "LINUX_SERVER", "NETWORK_SWITCH"]
PlatformFamily = Literal["WINDOWS", "LINUX", "CISCO_IOS", "ARUBA_AOS_CX"]
AssessmentStatus = Literal["PASS", "FAIL", "ERROR", "REVIEW", "N/A"]
CollectionStatus = Literal["COLLECTED", "ERROR", "UNSUPPORTED"]

_CONTROL_ID = re.compile(r"^(?:PC|LIN|SW|U|N)-[0-9]{2}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SAFE_CODE = re.compile(r"^[A-Z0-9_.:-]{1,128}$")
_PROHIBITED_LABELS = ("password", "secret", "token", "private_key", "cookie")


class PlatformContractError(ValueError):
    """허용되지 않은 장비 결과 또는 증적 표현을 거부합니다."""


def _safe_text(value: str, *, label: str, maximum: int) -> str:
    normalized = " ".join(value.strip().split())
    if not normalized or len(normalized) > maximum or "\x00" in normalized:
        raise PlatformContractError(f"{label} 값이 올바르지 않습니다.")
    return normalized


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PlatformContractError("증적 시각에는 시간대가 필요합니다.")
    return value.isoformat()


@dataclass(frozen=True, slots=True)
class AssetContext:
    asset_id: UUID
    asset_type: AssetType
    platform: PlatformFamily
    platform_version: str
    vendor: str
    product_family: str

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "asset_id": str(self.asset_id),
            "asset_type": self.asset_type,
            "platform": self.platform,
            "platform_version": _safe_text(
                self.platform_version,
                label="플랫폼 버전",
                maximum=128,
            ),
            "vendor": _safe_text(self.vendor, label="제조사", maximum=80),
            "product_family": _safe_text(
                self.product_family,
                label="제품군",
                maximum=80,
            ),
        }


@dataclass(frozen=True, slots=True)
class EvidenceTrace:
    probe_id: str
    probe_version: str
    method_code: str
    method_summary: str
    source_label: str
    technical_locator: str
    observed_summary: str
    collected_at: datetime
    collection_status: CollectionStatus
    raw_output_sha256: str
    normalized_sha256: str
    redaction_applied: bool

    @classmethod
    def build(
        cls,
        *,
        probe_id: str,
        probe_version: str,
        method_code: str,
        method_summary: str,
        source_label: str,
        technical_locator: str,
        observed_summary: str,
        collected_at: datetime,
        collection_status: CollectionStatus,
        raw_output: bytes,
        redaction_applied: bool,
    ) -> EvidenceTrace:
        summary = _safe_text(
            observed_summary,
            label="비식별 확인값",
            maximum=2_000,
        )
        if not _SAFE_CODE.fullmatch(method_code):
            raise PlatformContractError("확인 방법 코드가 올바르지 않습니다.")
        if any(term in source_label.casefold() for term in _PROHIBITED_LABELS):
            raise PlatformContractError("민감한 증적 이름은 표시할 수 없습니다.")
        if len(raw_output) > 4 * 1024 * 1024:
            raise PlatformContractError("원문 증적이 허용 크기를 초과했습니다.")
        return cls(
            probe_id=_safe_text(probe_id, label="Probe", maximum=128),
            probe_version=_safe_text(probe_version, label="Probe 버전", maximum=32),
            method_code=method_code,
            method_summary=_safe_text(
                method_summary,
                label="확인 방법",
                maximum=400,
            ),
            source_label=_safe_text(source_label, label="확인 위치", maximum=200),
            technical_locator=_safe_text(
                technical_locator,
                label="기술 확인 위치",
                maximum=400,
            ),
            observed_summary=summary,
            collected_at=collected_at,
            collection_status=collection_status,
            raw_output_sha256=hashlib.sha256(raw_output).hexdigest(),
            normalized_sha256=hashlib.sha256(summary.encode("utf-8")).hexdigest(),
            redaction_applied=redaction_applied,
        )

    def to_json(self) -> dict[str, JsonValue]:
        if not _SHA256.fullmatch(self.raw_output_sha256) or not _SHA256.fullmatch(
            self.normalized_sha256
        ):
            raise PlatformContractError("증적 확인값이 올바르지 않습니다.")
        return {
            "probe_id": self.probe_id,
            "probe_version": self.probe_version,
            "method_code": self.method_code,
            "method_summary": self.method_summary,
            "source_label": self.source_label,
            "technical_locator": self.technical_locator,
            "observed_summary": self.observed_summary,
            "collected_at": _timestamp(self.collected_at),
            "collection_status": self.collection_status,
            "raw_output_sha256": self.raw_output_sha256,
            "normalized_sha256": self.normalized_sha256,
            "redaction_applied": self.redaction_applied,
            "raw_output_included": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceControlResult:
    control_id: str
    title: str
    status: AssessmentStatus
    result_code: str
    expected_summary: str
    observed_summary: str
    action_guidance: str
    evidence: tuple[EvidenceTrace, ...]

    def to_json(self) -> dict[str, JsonValue]:
        if _CONTROL_ID.fullmatch(self.control_id) is None:
            raise PlatformContractError("점검 항목 번호가 올바르지 않습니다.")
        if not self.evidence:
            raise PlatformContractError("점검 결과에는 증적 계보가 필요합니다.")
        if not _SAFE_CODE.fullmatch(self.result_code):
            raise PlatformContractError("내부 판정 코드가 올바르지 않습니다.")
        evidence = cast(list[JsonValue], [item.to_json() for item in self.evidence])
        return {
            "control_id": self.control_id,
            "title": _safe_text(self.title, label="점검 항목", maximum=160),
            "status": self.status,
            "status_authority": "RULE_ENGINE",
            "result_code": self.result_code,
            "result_code_visibility": "TECHNICAL_ONLY",
            "expected_summary": _safe_text(
                self.expected_summary,
                label="안전 기준",
                maximum=2_000,
            ),
            "observed_summary": _safe_text(
                self.observed_summary,
                label="확인값",
                maximum=2_000,
            ),
            "action_guidance": _safe_text(
                self.action_guidance,
                label="다음 행동",
                maximum=2_000,
            ),
            "evidence": evidence,
            "official_finding_write_allowed": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceAuditResult:
    schema_version: str
    run_id: UUID
    asset: AssetContext
    benchmark_id: str
    benchmark_version: str
    criteria_profile_id: UUID | None
    criteria_sha256: str
    started_at: datetime
    completed_at: datetime
    controls: tuple[DeviceControlResult, ...]
    criteria_summary: Mapping[str, JsonValue] | None = None

    def to_json(self) -> dict[str, JsonValue]:
        if self.schema_version != "1.0.0":
            raise PlatformContractError("지원하지 않는 결과 계약 버전입니다.")
        if self.completed_at < self.started_at:
            raise PlatformContractError("점검 완료 시각이 시작 시각보다 빠릅니다.")
        if not _SHA256.fullmatch(self.criteria_sha256):
            raise PlatformContractError("점검 기준 확인값이 올바르지 않습니다.")
        controls = cast(list[JsonValue], [item.to_json() for item in self.controls])
        typed_controls = cast(list[dict[str, JsonValue]], controls)
        control_ids = [str(item["control_id"]) for item in typed_controls]
        if not controls or len(control_ids) != len(set(control_ids)):
            raise PlatformContractError("점검 항목이 없거나 중복되었습니다.")
        body: dict[str, JsonValue] = {
            "schema_version": self.schema_version,
            "run_id": str(self.run_id),
            "asset": self.asset.to_json(),
            "benchmark": {
                "id": _safe_text(self.benchmark_id, label="기준", maximum=128),
                "version": _safe_text(
                    self.benchmark_version,
                    label="기준 버전",
                    maximum=64,
                ),
            },
            "criteria_profile_id": (
                str(self.criteria_profile_id)
                if self.criteria_profile_id is not None
                else None
            ),
            "criteria_sha256": self.criteria_sha256,
            "started_at": _timestamp(self.started_at),
            "completed_at": _timestamp(self.completed_at),
            "controls": controls,
            "raw_evidence_included": False,
            "status_authority": "RULE_ENGINE",
        }
        if self.criteria_summary is not None:
            body["criteria_summary"] = dict(self.criteria_summary)
        body["result_sha256"] = canonical_sha256(body)
        return body
