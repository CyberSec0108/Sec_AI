"""PRODUCT-AI-04 일반 사용자용 점검 결과 설명 projection."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Never, cast

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)

_CONTROL_IDS = tuple(f"PC-{number:02d}" for number in range(1, 19))
_RULE_STATUSES = frozenset({"PASS", "FAIL", "ERROR", "REVIEW", "N/A"})
_STATUS_LABELS = {
    "PASS": "양호",
    "FAIL": "취약",
    "ERROR": "확인 필요",
    "REVIEW": "기준 확인 필요",
    "N/A": "해당 없음",
}
_STATUS_EXPLANATIONS = {
    "PASS": "내 PC에서 확인한 내용이 적용된 안전 기준을 충족해 양호로 판정했습니다.",
    "FAIL": "내 PC에서 확인한 내용이 적용된 안전 기준을 충족하지 않아 취약으로 판정했습니다.",
    "ERROR": "필요한 자료를 확인하지 못해 안전 또는 취약으로 확정하지 않았습니다.",
    "REVIEW": "조직 기준이나 적용 범위를 추가로 확인해야 하므로 판정을 확정하지 않았습니다.",
    "N/A": "현재 PC에는 이 점검 항목이 적용되지 않아 해당 없음으로 분류했습니다.",
}


class ResultExplanationPresentationError(ValueError):
    """일반 사용자 화면 projection을 만들기 전에 거부되는 계약 오류."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: str) -> Never:
    raise ResultExplanationPresentationError(code)


def _object(path: Path) -> dict[str, JsonValue]:
    value = load_strict_json(path.read_bytes())
    if not isinstance(value, dict):
        _reject("RESULT_PRESENTATION_SOURCE_INVALID")
    return value


def _text(value: object, code: str, *, maximum: int = 4_000) -> str:
    if not isinstance(value, str):
        _reject(code)
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > maximum:
        _reject(code)
    return normalized


def _objects(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        _reject("RESULT_PRESENTATION_SOURCE_INVALID")
    result: list[Mapping[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            _reject("RESULT_PRESENTATION_SOURCE_INVALID")
        result.append(cast(Mapping[str, object], item))
    return result


def _source_contract(
    project_root: Path,
) -> dict[str, list[Mapping[str, object]]]:
    contract = _object(
        project_root
        / "collectors"
        / "one_shot"
        / "contracts"
        / "product_ai_01_explanation_sources.json"
    )
    by_control: dict[str, list[Mapping[str, object]]] = {
        control_id: [] for control_id in _CONTROL_IDS
    }
    for source in _objects(contract.get("sources")):
        control_id = source.get("control_id")
        if control_id not in by_control:
            _reject("RESULT_PRESENTATION_SOURCE_INVALID")
        by_control[control_id].append(source)
    if any(not values for values in by_control.values()):
        _reject("RESULT_PRESENTATION_SOURCE_INVALID")
    return by_control


def _kisa_sources(project_root: Path) -> dict[str, dict[str, JsonValue]]:
    mapping = _object(
        project_root
        / "guides"
        / "mappings"
        / "kisa_2026_pc_control_sources.json"
    )
    guide = mapping.get("guide")
    if not isinstance(guide, Mapping):
        _reject("RESULT_PRESENTATION_KISA_SOURCE_INVALID")
    result: dict[str, dict[str, JsonValue]] = {}
    for source in _objects(mapping.get("mappings")):
        control_id = source.get("control_id")
        page_start = source.get("page_start")
        page_end = source.get("page_end")
        if (
            control_id not in _CONTROL_IDS
            or control_id in result
            or not isinstance(page_start, int)
            or not isinstance(page_end, int)
        ):
            _reject("RESULT_PRESENTATION_KISA_SOURCE_INVALID")
        page_label = (
            f"{page_start}쪽"
            if page_start == page_end
            else f"{page_start}~{page_end}쪽"
        )
        result[control_id] = {
            "guide_version": guide.get("version"),
            "document_code": cast(
                JsonValue,
                source.get("source_document_code"),
            ),
            "page_start": page_start,
            "page_end": page_end,
            "page_label": page_label,
            "section_label": cast(JsonValue, source.get("section_label")),
        }
    if tuple(sorted(result)) != _CONTROL_IDS:
        _reject("RESULT_PRESENTATION_KISA_SOURCE_INVALID")
    return result


def _strings(
    sources: Sequence[Mapping[str, object]],
    field: str,
) -> list[JsonValue]:
    values = [
        _text(source.get(field), "RESULT_PRESENTATION_SOURCE_INVALID")
        for source in sources
    ]
    return list(dict.fromkeys(values))


def _locations(
    sources: Sequence[Mapping[str, object]],
) -> list[JsonValue]:
    values: list[str] = []
    for source in sources:
        for location in _objects(source.get("source_locations")):
            values.append(
                _text(
                    location.get("user_label"),
                    "RESULT_PRESENTATION_SOURCE_INVALID",
                )
            )
    return list(dict.fromkeys(values))


def build_result_explanation_presentations(
    project_root: Path,
    *,
    controls: Sequence[Mapping[str, object]],
) -> list[dict[str, JsonValue]]:
    """규칙 결과와 확인 방법을 내부 코드 없이 사용자 화면용으로 변환한다."""

    indexed: dict[str, Mapping[str, object]] = {}
    for control in controls:
        control_id = control.get("control_id")
        if not isinstance(control_id, str) or control_id in indexed:
            _reject("RESULT_PRESENTATION_COVERAGE_INVALID")
        indexed[control_id] = control
    if tuple(sorted(indexed)) != _CONTROL_IDS:
        _reject("RESULT_PRESENTATION_COVERAGE_INVALID")

    sources = _source_contract(project_root)
    kisa_sources = _kisa_sources(project_root)
    results: list[dict[str, JsonValue]] = []
    for control_id in _CONTROL_IDS:
        control = indexed[control_id]
        status = _text(
            control.get("assessment_status"),
            "RESULT_PRESENTATION_RULE_STATUS_INVALID",
            maximum=6,
        )
        if status not in _RULE_STATUSES:
            _reject("RESULT_PRESENTATION_RULE_STATUS_INVALID")
        limitations: list[JsonValue] = []
        if status == "ERROR":
            limitations.append(
                "필요한 자료를 확인하지 못해 안전 여부를 확정하지 않았습니다."
            )
        elif status == "REVIEW":
            limitations.append(
                "조직 기준이나 관리자 권한으로 추가 확인해야 합니다."
            )
        payload: dict[str, JsonValue] = {
            "schema_version": "1.0.0",
            "control_id": control_id,
            "title": _text(
                control.get("title"),
                "RESULT_PRESENTATION_CONTROL_INVALID",
            ),
            "importance": _text(
                control.get("importance"),
                "RESULT_PRESENTATION_CONTROL_INVALID",
                maximum=4,
            ),
            "official_status": status,
            "official_status_label": _STATUS_LABELS[status],
            "status_authority": "RULE_ENGINE",
            "what_was_checked": _text(
                control.get("checked_summary"),
                "RESULT_PRESENTATION_CONTROL_INVALID",
            ),
            "collection_methods": _strings(sources[control_id], "method_summary"),
            "execution_tools": _strings(sources[control_id], "tool_name"),
            "source_locations": _locations(sources[control_id]),
            "observed_summary": _text(
                control.get("actual"),
                "RESULT_PRESENTATION_RULE_RESULT_INVALID",
            ),
            "expected_summary": _text(
                control.get("expected"),
                "RESULT_PRESENTATION_RULE_RESULT_INVALID",
            ),
            "judgement_explanation": _STATUS_EXPLANATIONS[status],
            "collection_limitations": limitations,
            "allowed_actions": [
                _text(
                    control.get("action_guidance"),
                    "RESULT_PRESENTATION_CONTROL_INVALID",
                )
            ],
            "kisa_source": kisa_sources[control_id],
            "assessment_kind": _text(
                control.get("assessment_kind"),
                "RESULT_PRESENTATION_RULE_RESULT_INVALID",
            ),
        }
        payload["presentation_sha256"] = canonical_sha256_without_fields(
            payload,
            {"presentation_sha256"},
        )
        results.append(payload)
    return results
