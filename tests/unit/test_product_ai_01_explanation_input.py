from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from referencing import Registry, Resource

from security_audit.application.result_explanation_input import (
    ExplanationInputError,
    build_explanation_inputs,
    build_user_explanation_projection,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"


def _probe_results() -> list[dict[str, object]]:
    allowlist = json.loads(
        (
            PROJECT_ROOT
            / "collectors"
            / "one_shot"
            / "contracts"
            / "imp031_probe_allowlist.json"
        ).read_text(encoding="utf-8")
    )
    return [
        {
            "probe_id": probe["probe_id"],
            "probe_version": probe["probe_version"],
            "control_ids": probe["control_ids"],
            "collection_status": "COLLECTED",
            "error_code": "NONE",
        }
        for probe in allowlist["probes"]
    ]


def _control_results() -> list[dict[str, object]]:
    statuses = ("PASS", "FAIL", "ERROR", "REVIEW", "N/A")
    return [
        {
            "control_id": f"PC-{index:02d}",
            "title": f"PC-{index:02d} 점검 항목",
            "importance": "상" if index % 3 else "중",
            "checked_summary": f"PC-{index:02d}에서 적용 중인 보안 설정을 확인했습니다.",
            "evidence_summary": f"PC-{index:02d} 확인 자료",
            "action_guidance": "결과를 확인하고 필요한 경우 조직 담당자에게 문의하세요.",
            "assessment_status": statuses[(index - 1) % len(statuses)],
            "actual": f"안전하게 정규화된 실제 확인값 {index}",
            "expected": f"KISA 안전 기준값 {index}",
            "result_code": f"PC{index:02d}_INTERNAL_REASON",
            "assessment_kind": "DEVELOPMENT_DRAFT",
        }
        for index in range(1, 19)
    ]


def _serialized(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _explanation_input_validator() -> Draft202012Validator:
    catalog = json.loads(
        (SCHEMA_ROOT / "schema-catalog.json").read_text(encoding="utf-8")
    )
    resources: list[tuple[str, Resource[Any]]] = []
    target: dict[str, Any] | None = None
    for entry in catalog["schemas"]:
        schema = json.loads(
            (SCHEMA_ROOT / entry["file"]).read_text(encoding="utf-8")
        )
        resources.append((entry["id"], Resource.from_contents(schema)))
        if entry["file"] == "finding_explanation_input.schema.json":
            target = schema
    assert target is not None
    return Draft202012Validator(
        target,
        registry=Registry().with_resources(resources),
        format_checker=FormatChecker(),
    )


def test_product_ai_01_builds_exact_pc01_to_pc18_contract() -> None:
    inputs = build_explanation_inputs(
        PROJECT_ROOT,
        controls=_control_results(),
        probe_results=_probe_results(),
    )

    assert [item["control_id"] for item in inputs] == [
        f"PC-{index:02d}" for index in range(1, 19)
    ]
    assert len(inputs) == 18
    assert all(item["schema_version"] == "1.0.0" for item in inputs)
    assert all(item["status_authority"] == "RULE_ENGINE" for item in inputs)
    assert all(item["result_code_visibility"] == "TECHNICAL_ONLY" for item in inputs)
    assert all(item["official_finding_write_allowed"] is False for item in inputs)
    assert all(item["collection_methods"] for item in inputs)
    assert all(item["execution_tools"] for item in inputs)
    assert all(item["source_locations"] for item in inputs)
    assert all(item["kisa_citations"] for item in inputs)
    assert all(len(str(item["explanation_input_sha256"])) == 64 for item in inputs)


def test_product_ai_01_generated_inputs_are_schema_valid() -> None:
    validator = _explanation_input_validator()
    inputs = build_explanation_inputs(
        PROJECT_ROOT,
        controls=_control_results(),
        probe_results=_probe_results(),
    )

    assert [
        error.message
        for item in inputs
        for error in validator.iter_errors(item)
    ] == []


def test_product_ai_01_hash_is_canonical_and_binds_every_explanation_field() -> None:
    controls = _control_results()
    probes = _probe_results()
    first = build_explanation_inputs(
        PROJECT_ROOT,
        controls=controls,
        probe_results=probes,
    )[0]
    reordered = build_explanation_inputs(
        PROJECT_ROOT,
        controls=[dict(reversed(list(item.items()))) for item in controls],
        probe_results=[dict(reversed(list(item.items()))) for item in probes],
    )[0]

    assert first["explanation_input_sha256"] == canonical_sha256_without_fields(
        first,
        {"explanation_input_sha256"},
    )
    assert first["explanation_input_sha256"] == reordered["explanation_input_sha256"]

    changed = deepcopy(first)
    changed["observed_summary"] = "다른 실제 확인값"
    assert canonical_sha256_without_fields(
        changed,
        {"explanation_input_sha256"},
    ) != first["explanation_input_sha256"]


def test_product_ai_01_is_deterministic_for_one_hundred_rebuilds() -> None:
    fingerprints = {
        tuple(
            str(item["explanation_input_sha256"])
            for item in build_explanation_inputs(
                PROJECT_ROOT,
                controls=_control_results(),
                probe_results=_probe_results(),
            )
        )
        for _ in range(100)
    }

    assert len(fingerprints) == 1


def test_product_ai_01_preserves_rule_status_and_source_objects() -> None:
    controls = _control_results()
    probes = _probe_results()
    controls_before = deepcopy(controls)
    probes_before = deepcopy(probes)

    inputs = build_explanation_inputs(
        PROJECT_ROOT,
        controls=controls,
        probe_results=probes,
    )

    assert [item["rule_status"] for item in inputs] == [
        item["assessment_status"] for item in controls
    ]
    assert controls == controls_before
    assert probes == probes_before


def test_product_ai_01_records_real_collection_method_tool_and_location() -> None:
    inputs = {
        str(item["control_id"]): item
        for item in build_explanation_inputs(
            PROJECT_ROOT,
            controls=_control_results(),
            probe_results=_probe_results(),
        )
    }

    pc01_methods = cast(
        list[dict[str, JsonValue]],
        inputs["PC-01"]["collection_methods"],
    )
    pc02_methods = cast(
        list[dict[str, JsonValue]],
        inputs["PC-02"]["collection_methods"],
    )
    pc07_methods = cast(
        list[dict[str, JsonValue]],
        inputs["PC-07"]["collection_methods"],
    )

    assert pc01_methods[0]["method_code"] == "WINDOWS_API"
    assert "NetUserModalsGet" in _serialized(inputs["PC-01"])
    assert pc02_methods[0]["method_code"] == "WINDOWS_ADSI"
    assert "레지스트리" in _serialized(inputs["PC-03"])
    assert len(pc07_methods) == 3
    assert "Get-Disk" in _serialized(inputs["PC-07"])
    assert "Get-NetFirewallProfile" in _serialized(inputs["PC-15"])


def test_product_ai_01_internal_reason_code_never_enters_user_projection() -> None:
    technical = build_explanation_inputs(
        PROJECT_ROOT,
        controls=_control_results(),
        probe_results=_probe_results(),
    )[1]

    user = build_user_explanation_projection(technical)
    serialized = _serialized(user)

    assert technical["result_code"] == "PC02_INTERNAL_REASON"
    assert "PC02_INTERNAL_REASON" not in serialized
    assert "result_code" not in serialized
    assert "probe_id" not in serialized
    assert "adapter_id" not in serialized
    assert user["judgement_explanation"]
    assert user["observed_summary"]


@pytest.mark.parametrize(
    "forbidden",
    (
        {"api_token": "forbidden"},
        {"credential": {"value": "forbidden"}},
        {"normalized": {"private_key": "forbidden"}},
        {"user_sid": "S-1-5-21-1000"},
        {"hostname": "private-pc"},
    ),
)
def test_product_ai_01_rejects_sensitive_input_before_projection(
    forbidden: dict[str, object],
) -> None:
    controls = _control_results()
    controls[0].update(forbidden)

    with pytest.raises(ExplanationInputError) as captured:
        build_explanation_inputs(
            PROJECT_ROOT,
            controls=controls,
            probe_results=_probe_results(),
        )

    assert captured.value.code == "EXPLANATION_INPUT_CONTAINS_PROHIBITED_FIELD"


def test_product_ai_01_rejects_missing_or_duplicate_control_coverage() -> None:
    with pytest.raises(ExplanationInputError) as missing:
        build_explanation_inputs(
            PROJECT_ROOT,
            controls=_control_results()[:-1],
            probe_results=_probe_results(),
        )
    assert missing.value.code == "EXPLANATION_CONTROL_COVERAGE_INVALID"

    duplicated = _control_results()
    duplicated[-1] = deepcopy(duplicated[0])
    with pytest.raises(ExplanationInputError) as duplicate:
        build_explanation_inputs(
            PROJECT_ROOT,
            controls=duplicated,
            probe_results=_probe_results(),
        )
    assert duplicate.value.code == "EXPLANATION_CONTROL_COVERAGE_INVALID"


def test_product_ai_01_payload_is_json_value() -> None:
    inputs = build_explanation_inputs(
        PROJECT_ROOT,
        controls=_control_results(),
        probe_results=_probe_results(),
    )

    assert isinstance(inputs, list)
    payload = cast(JsonValue, inputs)
    assert payload
