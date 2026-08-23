"""PRODUCT-AI-01 점검 결과 설명 입력 계약.

규칙 엔진이 만든 상태를 바꾸지 않고 안전한 실제값, 수집 방법·도구·위치,
내부 추적 코드와 KISA 페이지 계보를 하나의 결정론적 입력으로 묶는다.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Never, cast

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256,
    canonical_sha256_without_fields,
)

_CONTROL_IDS = tuple(f"PC-{number:02d}" for number in range(1, 19))
_RULE_STATUSES = frozenset({"PASS", "FAIL", "ERROR", "REVIEW", "N/A"})
_COLLECTION_STATUSES = frozenset({"COLLECTED", "ERROR", "UNSUPPORTED"})
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_IMPORTANCE = {"상": "HIGH", "중": "MEDIUM", "하": "LOW"}
_PROHIBITED_FIELD_TERMS = frozenset(
    {
        "authorization",
        "password_content",
        "default_password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "private_key",
        "credential",
        "cookie",
        "session",
        "user_sid",
        "process_sid",
        "username",
        "user_name",
        "hostname",
        "host_name",
        "volume_label",
        "serial_number",
        "product_key",
    }
)
_STATUS_EXPLANATIONS = {
    "PASS": "내 PC에서 확인한 내용이 적용된 안전 기준을 충족해 양호로 판정했습니다.",
    "FAIL": "내 PC에서 확인한 내용이 적용된 안전 기준을 충족하지 않아 취약으로 판정했습니다.",
    "ERROR": "필요한 자료를 확인하지 못해 안전 또는 취약으로 확정하지 않았습니다.",
    "REVIEW": "조직 기준이나 적용 범위를 추가로 확인해야 하므로 판정을 확정하지 않았습니다.",
    "N/A": "현재 PC에는 이 점검 항목이 적용되지 않아 해당 없음으로 분류했습니다.",
}
_COLLECTION_LIMITATIONS = {
    "ERROR": "점검 도구가 필요한 Windows 정보를 읽지 못했습니다.",
    "UNSUPPORTED": "현재 Windows 환경에서는 이 확인 방법을 지원하지 않습니다.",
}


class ExplanationInputError(ValueError):
    """설명 입력을 만들기 전에 거부되는 안전한 계약 오류."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: str) -> Never:
    raise ExplanationInputError(code)


def _load_object(path: Path) -> dict[str, JsonValue]:
    value = load_strict_json(path.read_bytes())
    if not isinstance(value, dict):
        _reject("EXPLANATION_SOURCE_CONTRACT_INVALID")
    return value


def _has_prohibited_field(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if any(term == normalized or term in normalized for term in _PROHIBITED_FIELD_TERMS):
                return True
            if _has_prohibited_field(child):
                return True
    elif isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        return any(_has_prohibited_field(child) for child in value)
    return False


def _text(value: object, code: str, *, maximum: int = 4_000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        _reject(code)
    return value.strip()


def _mapping_sequence(value: object, code: str) -> list[Mapping[str, object]]:
    if not isinstance(value, Sequence) or isinstance(
        value,
        (str, bytes, bytearray),
    ):
        _reject(code)
    result: list[Mapping[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            _reject(code)
        result.append(cast(Mapping[str, object], item))
    return result


def _indexed_controls(
    controls: Sequence[Mapping[str, object]],
) -> dict[str, Mapping[str, object]]:
    if _has_prohibited_field(controls):
        _reject("EXPLANATION_INPUT_CONTAINS_PROHIBITED_FIELD")
    result: dict[str, Mapping[str, object]] = {}
    for item in controls:
        control_id = item.get("control_id")
        if not isinstance(control_id, str) or control_id in result:
            _reject("EXPLANATION_CONTROL_COVERAGE_INVALID")
        result[control_id] = item
    if tuple(sorted(result)) != _CONTROL_IDS:
        _reject("EXPLANATION_CONTROL_COVERAGE_INVALID")
    return result


def _indexed_probes(
    probe_results: Sequence[Mapping[str, object]],
    expected_probe_ids: frozenset[str],
) -> dict[str, Mapping[str, object]]:
    if _has_prohibited_field(probe_results):
        _reject("EXPLANATION_INPUT_CONTAINS_PROHIBITED_FIELD")
    result: dict[str, Mapping[str, object]] = {}
    for item in probe_results:
        probe_id = item.get("probe_id")
        if not isinstance(probe_id, str) or probe_id in result:
            _reject("EXPLANATION_PROBE_COVERAGE_INVALID")
        status = item.get("collection_status")
        if status not in _COLLECTION_STATUSES:
            _reject("EXPLANATION_PROBE_STATUS_INVALID")
        result[probe_id] = item
    if frozenset(result) != expected_probe_ids:
        _reject("EXPLANATION_PROBE_COVERAGE_INVALID")
    return result


def _source_contract(
    project_root: Path,
) -> tuple[dict[str, list[Mapping[str, object]]], dict[str, JsonValue]]:
    contract = _load_object(
        project_root
        / "collectors"
        / "one_shot"
        / "contracts"
        / "product_ai_01_explanation_sources.json"
    )
    if (
        contract.get("schema_version") != "1.0.0"
        or contract.get("contract_version") != "1.0.0"
        or contract.get("execution_mode") != "WINDOWS_READ_ONLY"
    ):
        _reject("EXPLANATION_SOURCE_CONTRACT_INVALID")
    sources = _mapping_sequence(
        contract.get("sources"),
        "EXPLANATION_SOURCE_CONTRACT_INVALID",
    )
    by_control: dict[str, list[Mapping[str, object]]] = {
        control_id: [] for control_id in _CONTROL_IDS
    }
    seen_probes: set[str] = set()
    for source in sources:
        control_id = source.get("control_id")
        probe_id = source.get("probe_id")
        if (
            control_id not in by_control
            or not isinstance(probe_id, str)
            or probe_id in seen_probes
        ):
            _reject("EXPLANATION_SOURCE_CONTRACT_INVALID")
        seen_probes.add(probe_id)
        by_control[control_id].append(source)
    if any(not entries for entries in by_control.values()):
        _reject("EXPLANATION_SOURCE_CONTRACT_INVALID")
    return by_control, contract


def _kisa_sources(project_root: Path) -> dict[str, dict[str, JsonValue]]:
    mapping = _load_object(
        project_root
        / "guides"
        / "mappings"
        / "kisa_2026_pc_control_sources.json"
    )
    guide = mapping.get("guide")
    if not isinstance(guide, Mapping):
        _reject("EXPLANATION_KISA_MAPPING_INVALID")
    entries = _mapping_sequence(
        mapping.get("mappings"),
        "EXPLANATION_KISA_MAPPING_INVALID",
    )
    result: dict[str, dict[str, JsonValue]] = {}
    for entry in entries:
        control_id = entry.get("control_id")
        if not isinstance(control_id, str) or control_id in result:
            _reject("EXPLANATION_KISA_MAPPING_INVALID")
        result[control_id] = {
            "guide_id": guide.get("guide_id"),
            "guide_version": guide.get("version"),
            "source_sha256": guide.get("source_sha256"),
            "document_code": cast(JsonValue, entry.get("source_document_code")),
            "page_start": cast(JsonValue, entry.get("page_start")),
            "page_end": cast(JsonValue, entry.get("page_end")),
            "section_label": cast(JsonValue, entry.get("section_label")),
            "mapping_status": cast(JsonValue, entry.get("mapping_status")),
        }
    if tuple(sorted(result)) != _CONTROL_IDS:
        _reject("EXPLANATION_KISA_MAPPING_INVALID")
    return result


def _trace_payload(
    sources: Sequence[Mapping[str, object]],
    probes: Mapping[str, Mapping[str, object]],
    contract: Mapping[str, JsonValue],
) -> tuple[
    list[JsonValue],
    list[JsonValue],
    list[JsonValue],
    list[JsonValue],
    list[JsonValue],
]:
    methods: list[JsonValue] = []
    tools: list[JsonValue] = []
    locations: list[JsonValue] = []
    limitations: list[JsonValue] = []
    evidence_trace: list[JsonValue] = []
    for source in sources:
        probe_id = _text(source.get("probe_id"), "EXPLANATION_SOURCE_CONTRACT_INVALID")
        probe = probes[probe_id]
        probe_version = _text(
            source.get("probe_version"),
            "EXPLANATION_SOURCE_CONTRACT_INVALID",
        )
        if (
            probe.get("probe_version") != probe_version
            or probe.get("control_ids") != [source.get("control_id")]
        ):
            _reject("EXPLANATION_PROBE_BINDING_INVALID")
        for field in ("adapter_id", "adapter_version"):
            supplied = probe.get(field)
            if supplied is not None and supplied != source.get(field):
                _reject("EXPLANATION_PROBE_BINDING_INVALID")
        status = _text(
            probe.get("collection_status"),
            "EXPLANATION_PROBE_STATUS_INVALID",
        )
        methods.append(
            {
                "probe_id": probe_id,
                "method_code": _text(
                    source.get("method_code"),
                    "EXPLANATION_SOURCE_CONTRACT_INVALID",
                ),
                "method_summary": _text(
                    source.get("method_summary"),
                    "EXPLANATION_SOURCE_CONTRACT_INVALID",
                ),
                "collection_status": status,
            }
        )
        tools.append(
            {
                "probe_id": probe_id,
                "probe_version": probe_version,
                "tool_name": _text(
                    source.get("tool_name"),
                    "EXPLANATION_SOURCE_CONTRACT_INVALID",
                ),
                "collector_name": _text(
                    contract.get("collector_name"),
                    "EXPLANATION_SOURCE_CONTRACT_INVALID",
                ),
                "collector_version": _text(
                    contract.get("collector_version"),
                    "EXPLANATION_SOURCE_CONTRACT_INVALID",
                ),
                "adapter_id": _text(
                    source.get("adapter_id"),
                    "EXPLANATION_SOURCE_CONTRACT_INVALID",
                ),
                "adapter_version": _text(
                    source.get("adapter_version"),
                    "EXPLANATION_SOURCE_CONTRACT_INVALID",
                ),
            }
        )
        source_labels: list[str] = []
        for location in _mapping_sequence(
            source.get("source_locations"),
            "EXPLANATION_SOURCE_CONTRACT_INVALID",
        ):
            user_label = _text(
                location.get("user_label"),
                "EXPLANATION_SOURCE_CONTRACT_INVALID",
            )
            source_labels.append(user_label)
            locations.append(
                {
                    "probe_id": probe_id,
                    "user_label": user_label,
                    "technical_locator": _text(
                        location.get("technical_locator"),
                        "EXPLANATION_SOURCE_CONTRACT_INVALID",
                    ),
                }
            )
        collected_at = probe.get("collected_at_utc")
        if collected_at is not None and (
            not isinstance(collected_at, str)
            or not collected_at.strip()
            or len(collected_at) > 64
        ):
            _reject("EXPLANATION_EVIDENCE_TRACE_INVALID")
        normalized_sha256 = probe.get("normalized_records_sha256")
        if normalized_sha256 is not None and (
            not isinstance(normalized_sha256, str)
            or _SHA256_PATTERN.fullmatch(normalized_sha256) is None
        ):
            _reject("EXPLANATION_EVIDENCE_TRACE_INVALID")
        raw_evidence_available = probe.get("raw_evidence_available", False)
        if raw_evidence_available is not False:
            _reject("EXPLANATION_RAW_EVIDENCE_NOT_ALLOWED")
        evidence_trace.append(
            {
                "probe_id": probe_id,
                "collection_status": status,
                "collected_at_utc": collected_at,
                "normalized_records_sha256": normalized_sha256,
                "source_labels": cast(JsonValue, source_labels),
                "raw_evidence_available": False,
            }
        )
        if status != "COLLECTED":
            limitations.append(
                _COLLECTION_LIMITATIONS.get(
                    status,
                    "점검 자료의 수집 상태를 추가로 확인해야 합니다.",
                )
            )
    return (
        methods,
        tools,
        locations,
        list(dict.fromkeys(limitations)),
        evidence_trace,
    )


def _build_one(
    control: Mapping[str, object],
    *,
    sources: Sequence[Mapping[str, object]],
    probes: Mapping[str, Mapping[str, object]],
    source_contract: Mapping[str, JsonValue],
    citation: Mapping[str, JsonValue],
) -> dict[str, JsonValue]:
    control_id = _text(control.get("control_id"), "EXPLANATION_CONTROL_INVALID")
    status = _text(control.get("assessment_status"), "EXPLANATION_RULE_RESULT_INVALID")
    if status not in _RULE_STATUSES:
        _reject("EXPLANATION_RULE_RESULT_INVALID")
    result_code = _text(
        control.get("result_code"),
        "EXPLANATION_RULE_RESULT_INVALID",
    )
    actual = _text(control.get("actual"), "EXPLANATION_RULE_RESULT_INVALID")
    expected = _text(control.get("expected"), "EXPLANATION_RULE_RESULT_INVALID")
    assessment_kind = _text(
        control.get("assessment_kind"),
        "EXPLANATION_RULE_RESULT_INVALID",
    )
    importance_source = _text(control.get("importance"), "EXPLANATION_CONTROL_INVALID")
    importance = _IMPORTANCE.get(importance_source)
    if importance is None:
        _reject("EXPLANATION_CONTROL_INVALID")
    methods, tools, locations, limitations, evidence_trace = _trace_payload(
        sources,
        probes,
        source_contract,
    )
    if status == "ERROR":
        limitations.append(
            "필요한 자료가 부족해 안전 여부를 확정하지 않았습니다."
        )
    elif status == "REVIEW":
        limitations.append(
            "조직 기준이나 적용 범위를 추가로 확인해야 합니다."
        )
    rule_result = {
        "rule_status": status,
        "result_code": result_code,
        "actual": actual,
        "expected": expected,
        "assessment_kind": assessment_kind,
    }
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "control_id": control_id,
        "title": _text(control.get("title"), "EXPLANATION_CONTROL_INVALID"),
        "importance": importance,
        "what_was_checked": _text(
            control.get("checked_summary"),
            "EXPLANATION_CONTROL_INVALID",
        ),
        "observed_summary": actual,
        "normalized_facts": {"actual_summary": actual},
        "collection_methods": methods,
        "execution_tools": tools,
        "source_locations": locations,
        "evidence_trace": evidence_trace,
        "rule_status": status,
        "status_authority": "RULE_ENGINE",
        "result_code": result_code,
        "result_code_visibility": "TECHNICAL_ONLY",
        "expected_summary": expected,
        "judgement_explanation": _STATUS_EXPLANATIONS[status],
        "collection_limitations": list(dict.fromkeys(limitations)),
        "importance_source": importance_source,
        "kisa_citations": [dict(citation)],
        "allowed_actions": [
            _text(control.get("action_guidance"), "EXPLANATION_CONTROL_INVALID")
        ],
        "assessment_kind": assessment_kind,
        "source_rule_result_sha256": canonical_sha256(cast(JsonValue, rule_result)),
        "official_finding_write_allowed": False,
        "safety": {
            "raw_evidence_included": False,
            "sensitive_identifiers_included": False,
            "rule_status_unchanged": True,
            "internal_reason_code_user_visible": False,
        },
    }
    payload["explanation_input_sha256"] = canonical_sha256_without_fields(
        payload,
        {"explanation_input_sha256"},
    )
    return payload


def build_explanation_inputs(
    project_root: Path,
    *,
    controls: Sequence[Mapping[str, object]],
    probe_results: Sequence[Mapping[str, object]],
) -> list[dict[str, JsonValue]]:
    """PC-01~18 결과를 결정론적·비식별 설명 입력 DTO로 변환한다."""

    indexed_controls = _indexed_controls(controls)
    sources, source_contract = _source_contract(project_root)
    expected_probes = frozenset(
        _text(item.get("probe_id"), "EXPLANATION_SOURCE_CONTRACT_INVALID")
        for entries in sources.values()
        for item in entries
    )
    indexed_probes = _indexed_probes(probe_results, expected_probes)
    citations = _kisa_sources(project_root)
    return [
        _build_one(
            indexed_controls[control_id],
            sources=sources[control_id],
            probes=indexed_probes,
            source_contract=source_contract,
            citation=citations[control_id],
        )
        for control_id in _CONTROL_IDS
    ]


def build_scan_explanation_inputs(
    project_root: Path,
    *,
    controls: Sequence[Mapping[str, object]],
    collected_probe_results: Sequence[Mapping[str, object]],
) -> list[dict[str, JsonValue]]:
    """일반 점검에서 실제로 수행한 Probe만 받아 전체 설명 입력을 안전하게 만든다.

    관리자 권한 때문에 일반 점검에서 실행하지 않은 Probe는 ``UNSUPPORTED``로
    명시한다. 호출자가 보낸 부가 필드는 복사하지 않고 계약에 고정된 식별정보와
    수집 상태만 사용하므로 원시 증적이나 PC 식별정보가 AI 입력에 섞이지 않는다.
    """

    if _has_prohibited_field(collected_probe_results):
        _reject("EXPLANATION_INPUT_CONTAINS_PROHIBITED_FIELD")
    sources, _ = _source_contract(project_root)
    source_by_probe = {
        _text(source.get("probe_id"), "EXPLANATION_SOURCE_CONTRACT_INVALID"): source
        for entries in sources.values()
        for source in entries
    }
    supplied_statuses: dict[str, str] = {}
    for result in collected_probe_results:
        probe_id = _text(
            result.get("probe_id"),
            "EXPLANATION_PROBE_COVERAGE_INVALID",
        )
        if probe_id not in source_by_probe or probe_id in supplied_statuses:
            _reject("EXPLANATION_PROBE_COVERAGE_INVALID")
        status = _text(
            result.get("collection_status"),
            "EXPLANATION_PROBE_STATUS_INVALID",
        )
        if status not in _COLLECTION_STATUSES:
            _reject("EXPLANATION_PROBE_STATUS_INVALID")
        source = source_by_probe[probe_id]
        supplied_version = result.get("probe_version")
        if supplied_version is not None and supplied_version != source.get(
            "probe_version"
        ):
            _reject("EXPLANATION_PROBE_BINDING_INVALID")
        supplied_controls = result.get("control_ids")
        if supplied_controls is not None and supplied_controls != [
            source.get("control_id")
        ]:
            _reject("EXPLANATION_PROBE_BINDING_INVALID")
        supplied_statuses[probe_id] = status

    supplied_trace: dict[str, dict[str, object]] = {}
    for result in collected_probe_results:
        probe_id = cast(str, result["probe_id"])
        supplied_trace[probe_id] = {
            key: result[key]
            for key in (
                "collected_at_utc",
                "normalized_records_sha256",
                "raw_evidence_available",
            )
            if key in result
        }

    normalized_probes = []
    for probe_id, source in sorted(source_by_probe.items()):
        normalized_probe: dict[str, object] = {
            "probe_id": probe_id,
            "probe_version": source["probe_version"],
            "control_ids": [source["control_id"]],
            "collection_status": supplied_statuses.get(probe_id, "UNSUPPORTED"),
        }
        normalized_probe.update(supplied_trace.get(probe_id, {}))
        normalized_probes.append(normalized_probe)
    return build_explanation_inputs(
        project_root,
        controls=controls,
        probe_results=normalized_probes,
    )


def build_user_explanation_projection(
    value: Mapping[str, JsonValue],
) -> dict[str, JsonValue]:
    """내부 코드·Probe·Adapter 식별자를 제외한 사용자 표시용 projection."""

    return {
        "schema_version": value["schema_version"],
        "control_id": value["control_id"],
        "title": value["title"],
        "importance": value["importance"],
        "rule_status": value["rule_status"],
        "what_was_checked": value["what_was_checked"],
        "collection_methods": [
            cast(Mapping[str, JsonValue], item)["method_summary"]
            for item in cast(list[JsonValue], value["collection_methods"])
        ],
        "execution_tools": [
            cast(Mapping[str, JsonValue], item)["tool_name"]
            for item in cast(list[JsonValue], value["execution_tools"])
        ],
        "source_locations": [
            cast(Mapping[str, JsonValue], item)["user_label"]
            for item in cast(list[JsonValue], value["source_locations"])
        ],
        "evidence_trace": [
            {
                "collection_status": cast(Mapping[str, JsonValue], item)[
                    "collection_status"
                ],
                "collected_at_utc": cast(Mapping[str, JsonValue], item)[
                    "collected_at_utc"
                ],
                "normalized_records_sha256": cast(
                    Mapping[str, JsonValue], item
                )["normalized_records_sha256"],
                "source_labels": cast(Mapping[str, JsonValue], item)[
                    "source_labels"
                ],
                "raw_evidence_available": False,
            }
            for item in cast(list[JsonValue], value["evidence_trace"])
        ],
        "observed_summary": value["observed_summary"],
        "expected_summary": value["expected_summary"],
        "judgement_explanation": value["judgement_explanation"],
        "collection_limitations": value["collection_limitations"],
        "allowed_actions": value["allowed_actions"],
        "kisa_citations": value["kisa_citations"],
        "assessment_kind": value["assessment_kind"],
    }
