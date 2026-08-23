"""IMP-043 explicit-consent administrator scan contract."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from security_audit.collector.expanded import ADMINISTRATOR_PROBES

CONSENT_VERSION: Final = "imp043-v1"


class AdministratorConsentError(ValueError):
    """Fail-closed administrator consent or result error."""


@dataclass(frozen=True, slots=True)
class AdministratorProbeDisclosure:
    probe_id: str
    control_id: str
    title: str
    reason: str
    collected_summary: str

    def public_view(self) -> dict[str, str]:
        return {
            "probe_id": self.probe_id,
            "control_id": self.control_id,
            "title": self.title,
            "reason": self.reason,
            "collected_summary": self.collected_summary,
        }


_DISCLOSURES: Final[tuple[AdministratorProbeDisclosure, ...]] = (
    AdministratorProbeDisclosure(
        "win.security.password-policy",
        "PC-02",
        "비밀번호 관리정책",
        "컴퓨터 전체에 적용되는 암호 정책은 관리자 권한으로 읽어야 합니다.",
        "최소 길이·최대 사용 기간과 정책 적용 상태",
    ),
    AdministratorProbeDisclosure(
        "win.network.smb-shares",
        "PC-04",
        "공유 폴더와 접근 권한",
        "모든 공유와 접근 권한을 빠짐없이 보려면 관리자 권한이 필요합니다.",
        "공유 개수·관리 공유·제한 없는 Everyone 접근 개수",
    ),
    AdministratorProbeDisclosure(
        "win.software.messengers",
        "PC-06",
        "설치된 메신저 제품",
        "컴퓨터 전체 사용자 범위의 설치 제품 목록을 확인합니다.",
        "설치 제품 개수와 승인된 제품 목록 비교 준비 상태",
    ),
    AdministratorProbeDisclosure(
        "win.boot.entries",
        "PC-08",
        "Windows 부팅 항목",
        "부팅 구성 저장소는 관리자만 읽을 수 있습니다.",
        "부팅 가능한 운영체제 항목 개수",
    ),
    AdministratorProbeDisclosure(
        "win.update.compliance",
        "PC-10",
        "Windows 업데이트 이력",
        "컴퓨터 전체의 업데이트 기록과 재시작 대기 상태를 확인합니다.",
        "업데이트 이력 개수·최근 이력 시각·자동 업데이트·재시작 대기",
    ),
)

_BY_PROBE: Final = {item.probe_id: item for item in _DISCLOSURES}
_COLLECTION_MESSAGES: Final = {
    "PERMISSION_DENIED": "Windows가 해당 정보를 읽을 권한을 허용하지 않았습니다.",
    "SOURCE_UNAVAILABLE": "이 PC에서 점검에 필요한 Windows 기능을 찾지 못했습니다.",
    "ADAPTER_UNSUPPORTED": (
        "현재 점검 도구가 이 Windows 환경의 자료 형식을 지원하지 않습니다."
    ),
    "QUERY_FAILED": "Windows에서 점검 정보를 읽는 과정이 실패했습니다.",
}


def administrator_probe_disclosures() -> list[dict[str, str]]:
    return [item.public_view() for item in _DISCLOSURES]


def validate_administrator_selection(values: Sequence[object]) -> tuple[str, ...]:
    selected = tuple(value for value in values if isinstance(value, str))
    expected = tuple(
        probe_id for probe_id in ADMINISTRATOR_PROBES if probe_id in selected
    )
    if (
        len(selected) != len(values)
        or not selected
        or len(set(selected)) != len(selected)
        or selected != expected
    ):
        raise AdministratorConsentError(
            "Administrator Probe selection is invalid or reordered."
        )
    return selected


def validate_administrator_consent_request(
    value: Mapping[str, object],
) -> tuple[str, ...]:
    if frozenset(value) != {"consent", "consent_version", "probe_ids"}:
        raise AdministratorConsentError("Administrator consent fields are invalid.")
    probe_ids = value.get("probe_ids")
    if (
        value.get("consent") is not True
        or value.get("consent_version") != CONSENT_VERSION
        or not isinstance(probe_ids, Sequence)
        or isinstance(probe_ids, (str, bytes, bytearray))
    ):
        raise AdministratorConsentError("Explicit administrator consent is required.")
    return validate_administrator_selection(probe_ids)


def build_administrator_results(
    receipt: Mapping[str, object],
    *,
    assessments: Mapping[str, Mapping[str, object]] | None = None,
) -> dict[str, object]:
    if (
        receipt.get("explicit_consent") is not True
        or receipt.get("settings_diff_count") != 0
    ):
        raise AdministratorConsentError("Administrator receipt is unsafe.")
    values = receipt.get("results")
    selected = receipt.get("selected_probe_ids")
    if (
        not isinstance(values, Sequence)
        or isinstance(values, (str, bytes, bytearray))
        or not isinstance(selected, Sequence)
        or isinstance(selected, (str, bytes, bytearray))
    ):
        raise AdministratorConsentError("Administrator receipt is invalid.")
    selected_ids = validate_administrator_selection(selected)
    if len(values) != len(selected_ids):
        raise AdministratorConsentError("Administrator result coverage is incomplete.")

    results: list[dict[str, object]] = []
    collected = 0
    review_required = 0
    collection_error_count = 0
    assessment_review_count = 0
    for value, expected_probe_id in zip(values, selected_ids, strict=True):
        if not isinstance(value, Mapping):
            raise AdministratorConsentError("Administrator result is invalid.")
        status = value.get("collection_status")
        if (
            value.get("probe_id") != expected_probe_id
            or value.get("privilege") != "ADMINISTRATOR"
            or status not in {"COLLECTED", "ERROR", "UNSUPPORTED"}
        ):
            raise AdministratorConsentError(
                "Administrator result identity or status is invalid."
            )
        disclosure = _BY_PROBE[expected_probe_id]
        if status == "COLLECTED":
            display_status = "EVIDENCE_COLLECTED"
            status_label = "관리자 자료 확인 완료"
            collected += 1
        else:
            display_status = "REVIEW_REQUIRED"
            status_label = "추가 확인 필요"
            review_required += 1
            collection_error_count += 1
        row: dict[str, object] = {
            **disclosure.public_view(),
            "display_status": display_status,
            "status_label": status_label,
            "collection_status": status,
            "collection_status_label": (
                "자료 수집 완료" if status == "COLLECTED" else "자료 수집 실패"
            ),
            "judgement_explanation": (
                "관리자 권한으로 필요한 자료를 읽었습니다."
                if status == "COLLECTED"
                else _COLLECTION_MESSAGES.get(
                    str(value.get("error_code")),
                    "관리자 점검 자료를 가져오지 못했습니다.",
                )
            ),
        }
        assessment = (
            assessments.get(disclosure.control_id)
            if assessments is not None
            else None
        )
        if assessment is not None:
            assessment_status = assessment.get("status")
            if assessment_status not in {"PASS", "FAIL", "ERROR", "REVIEW", "N/A"}:
                raise AdministratorConsentError(
                    "Administrator assessment status is invalid."
                )
            if assessment_status == "REVIEW":
                assessment_review_count += 1
            row.update(
                {
                    "assessment_status": assessment_status,
                    "assessment_label": assessment.get("status_label"),
                    "actual": assessment.get("actual"),
                    "expected": assessment.get("expected"),
                    "result_code": assessment.get("result_code"),
                    "assessment_kind": assessment.get("assessment_kind"),
                    "judgement_explanation": assessment.get(
                        "judgement_explanation",
                        row["judgement_explanation"],
                    ),
                }
            )
            additional_criteria = assessment.get("additional_criteria")
            if isinstance(additional_criteria, Mapping):
                row["additional_criteria"] = dict(additional_criteria)
        results.append(row)

    observed_at = receipt.get("observed_at_utc")
    return {
        "status": "COMPLETED",
        "observed_at_utc": (
            observed_at if isinstance(observed_at, str) else "UNKNOWN"
        ),
        "selected_probe_count": len(selected_ids),
        "collected_probe_count": collected,
        "review_required_count": review_required,
        "collection_error_count": collection_error_count,
        "assessment_review_count": assessment_review_count,
        "results": results,
        "settings_modified": False,
        "raw_values_persisted": False,
        "official_finding_created": False,
    }
