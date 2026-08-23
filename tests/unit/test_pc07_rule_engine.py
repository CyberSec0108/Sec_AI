from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, cast

import pytest

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.analysis.rule_engine import (
    DecisionCandidate,
    RuleEngineCode,
    RuleEngineError,
    RuleRegistry,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "fixtures"
PACK_PATH = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "src" / "pack.json"


def _load_object(path: Path) -> dict[str, Any]:
    value = load_strict_json(path.read_bytes())
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _control() -> dict[str, Any]:
    pack = _load_object(PACK_PATH)
    controls = cast(list[dict[str, Any]], pack["controls"])
    assert len(controls) == 1
    return controls[0]


def _evaluate(
    input_document: dict[str, Any],
    *,
    applicability_rule: dict[str, Any] | None = None,
    evaluation_rule: dict[str, Any] | None = None,
) -> DecisionCandidate:
    control = _control()
    return RuleRegistry().evaluate(
        control_id=cast(str, input_document["control_id"]),
        applicability_rule=applicability_rule or control["applicability_rule"],
        evaluation_rule=evaluation_rule or control["evaluation_rule"],
        evidence=cast(list[dict[str, Any]], input_document["evidence"]),
    )


def _projection(decision: DecisionCandidate) -> dict[str, Any]:
    return {
        "expected_status": decision.status,
        "expected_applicability": {
            "status": decision.applicability.status,
            "reason_code": decision.applicability.reason_code,
        },
        "expected_subject": {
            "scope": decision.subject_scope,
            "subject_key": decision.subject_key,
        },
        "expected_result_code": decision.result_code,
        "candidate_volume_ids": list(decision.applicability.candidate_volume_ids),
        "evaluated_volume_ids": list(decision.evaluated_volume_ids),
        "excluded_volumes": [
            {"subject_id": item.subject_id, "reason_code": item.reason_code}
            for item in decision.applicability.excluded_volumes
        ],
        "violating_volume_ids": list(decision.violating_volume_ids),
        "error_codes": list(decision.error_codes),
        "rationale_code": decision.rationale_code,
    }


def test_all_approved_pc07_fixtures_match_decision_projection() -> None:
    index = _load_object(FIXTURE_ROOT / "index.json")
    entries = cast(list[dict[str, str]], index["cases"])

    for entry in entries:
        input_document = _load_object(FIXTURE_ROOT / entry["input_path"])
        expected = _load_object(FIXTURE_ROOT / entry["expected_path"])
        expected_projection = {
            key: value
            for key, value in expected.items()
            if key not in {"fixture_version", "case_id", "control_id"}
        }

        assert _projection(_evaluate(input_document)) == expected_projection, entry["case_id"]


@pytest.mark.parametrize(
    ("rule_kind", "field", "value"),
    [
        ("applicability", "rule_id", "pc07.unapproved"),
        ("applicability", "rule_version", "9.9.9"),
        ("evaluation", "rule_id", "pc07.unapproved"),
        ("evaluation", "rule_version", "9.9.9"),
    ],
)
def test_registry_rejects_unallowlisted_rule_identity(
    rule_kind: str, field: str, value: str
) -> None:
    control = _control()
    rule_key = f"{rule_kind}_rule"
    rule = copy.deepcopy(cast(dict[str, Any], control[rule_key]))
    rule[field] = value
    input_document = _load_object(FIXTURE_ROOT / "pc07/input/pc07-pass.json")

    with pytest.raises(RuleEngineError) as captured:
        if rule_kind == "applicability":
            _evaluate(input_document, applicability_rule=rule)
        else:
            _evaluate(input_document, evaluation_rule=rule)

    assert captured.value.code is RuleEngineCode.RULE_NOT_ALLOWED


def test_registry_rejects_parameter_drift_for_allowlisted_rule_version() -> None:
    control = _control()
    rule = copy.deepcopy(cast(dict[str, Any], control["evaluation_rule"]))
    parameters = cast(dict[str, Any], rule["parameters"])
    parameters["required_filesystem"] = "FAT32"
    input_document = _load_object(FIXTURE_ROOT / "pc07/input/pc07-pass.json")

    with pytest.raises(RuleEngineError) as captured:
        _evaluate(input_document, evaluation_rule=rule)

    assert captured.value.code is RuleEngineCode.RULE_PARAMETERS_INVALID


def test_result_is_order_independent_and_input_is_not_mutated() -> None:
    input_document = _load_object(FIXTURE_ROOT / "pc07/input/pc07-excluded-efi.json")
    reversed_document = copy.deepcopy(input_document)
    reversed_document["evidence"] = list(reversed(reversed_document["evidence"]))
    before = copy.deepcopy(reversed_document)

    assert _evaluate(input_document) == _evaluate(reversed_document)
    assert reversed_document == before


def test_untrusted_partition_identity_is_not_silently_excluded() -> None:
    input_document = _load_object(FIXTURE_ROOT / "pc07/input/pc07-excluded-efi.json")
    evidence = cast(list[dict[str, Any]], input_document["evidence"])
    partition = next(
        item
        for item in evidence
        if item["subject"]["subject_key"] == "vol-efi"
        and item["probe_id"] == "win.storage.partitions"
    )
    partition["normalized_value"]["trusted_role_identity"] = False

    decision = _evaluate(input_document)

    assert decision.status == "ERROR"
    assert decision.applicability.status == "UNDETERMINED"
    assert decision.applicability.reason_code == "VOLUME_CLASSIFICATION_INCOMPLETE"
    assert decision.applicability.excluded_volumes == ()
    assert decision.result_code == "VOLUME_CLASSIFICATION_INCOMPLETE"
    assert decision.error_codes == ("EVIDENCE_INCOMPLETE",)


def test_duplicate_subject_probe_evidence_is_rejected() -> None:
    input_document = _load_object(FIXTURE_ROOT / "pc07/input/pc07-pass.json")
    evidence = cast(list[dict[str, Any]], input_document["evidence"])
    evidence.append(copy.deepcopy(evidence[0]))

    with pytest.raises(RuleEngineError) as captured:
        _evaluate(input_document)

    assert captured.value.code is RuleEngineCode.EVALUATION_INPUT_INVALID


def test_missing_required_probe_never_becomes_partial_pass() -> None:
    input_document = _load_object(FIXTURE_ROOT / "pc07/input/pc07-pass.json")
    evidence = cast(list[dict[str, Any]], input_document["evidence"])
    input_document["evidence"] = [
        item
        for item in evidence
        if not (
            item["subject"]["subject_key"] == "vol-data"
            and item["probe_id"] == "win.storage.partitions"
        )
    ]

    decision = _evaluate(input_document)

    assert decision.status == "ERROR"
    assert decision.applicability.status == "UNDETERMINED"
    assert decision.applicability.reason_code == "VOLUME_EVIDENCE_INCOMPLETE"
    assert decision.result_code == "VOLUME_COLLECTION_FAILED"
    assert decision.error_codes == ("EVIDENCE_INCOMPLETE",)


def test_classification_probe_error_code_is_preserved() -> None:
    input_document = _load_object(FIXTURE_ROOT / "pc07/input/pc07-pass.json")
    evidence = cast(list[dict[str, Any]], input_document["evidence"])
    disk = next(
        item
        for item in evidence
        if item["subject"]["subject_key"] == "vol-data"
        and item["probe_id"] == "win.storage.disks"
    )
    disk["collection_status"] = "ERROR"
    disk["error_code"] = "PERMISSION_DENIED"
    del disk["normalized_value"]

    decision = _evaluate(input_document)

    assert decision.status == "ERROR"
    assert decision.applicability.status == "UNDETERMINED"
    assert decision.result_code == "VOLUME_CLASSIFICATION_INCOMPLETE"
    assert decision.error_codes == ("PERMISSION_DENIED",)
