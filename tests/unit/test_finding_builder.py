from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, cast

import pytest

from security_audit.analysis.finding import (
    FindingBuildCode,
    FindingBuildContext,
    FindingBuilder,
    FindingBuildError,
    canonical_finding_output_sha256,
)
from security_audit.analysis.package_validation import (
    PackageSchemaCatalog,
    PackageValidationCode,
)
from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.analysis.rule_engine import DecisionCandidate, RuleRegistry
from security_audit.common.canonical_json import JsonValue, canonical_sha256

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
FIXTURE_ROOT = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "fixtures"
PACK_PATH = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "src" / "pack.json"


def _load_object(path: Path) -> dict[str, Any]:
    value = load_strict_json(path.read_bytes())
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _context(*, evaluated_at: str = "2026-07-22T09:00:00Z") -> FindingBuildContext:
    return FindingBuildContext(
        organization_id="70000000-0000-4000-8000-000000000001",
        evaluation_as_of="2026-07-22T08:00:00Z",
        evaluated_at=evaluated_at,
        engine_version="0.1.0",
        engine_artifact_sha256="a" * 64,
    )


def _control(pack: dict[str, Any]) -> dict[str, Any]:
    controls = cast(list[dict[str, Any]], pack["controls"])
    assert len(controls) == 1
    return controls[0]


def _decision(pack: dict[str, Any], input_document: dict[str, Any]) -> DecisionCandidate:
    control = _control(pack)
    return RuleRegistry().evaluate(
        control_id=cast(str, input_document["control_id"]),
        applicability_rule=cast(dict[str, Any], control["applicability_rule"]),
        evaluation_rule=cast(dict[str, Any], control["evaluation_rule"]),
        evidence=cast(list[dict[str, Any]], input_document["evidence"]),
    )


def _builder() -> FindingBuilder:
    return FindingBuilder(PackageSchemaCatalog(SCHEMA_ROOT))


def _build(
    pack: dict[str, Any],
    input_document: dict[str, Any],
    *,
    context: FindingBuildContext | None = None,
) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        _builder().build(
            pack=pack,
            control_id=cast(str, input_document["control_id"]),
            evidence=cast(list[dict[str, Any]], input_document["evidence"]),
            decision=_decision(pack, input_document),
            context=context or _context(),
            allow_draft=True,
        ),
    )


def test_all_pc07_fixtures_build_schema_valid_traceable_findings() -> None:
    pack = _load_object(PACK_PATH)
    index = _load_object(FIXTURE_ROOT / "index.json")
    entries = cast(list[dict[str, str]], index["cases"])
    schemas = PackageSchemaCatalog(SCHEMA_ROOT)

    for entry in entries:
        input_document = _load_object(FIXTURE_ROOT / entry["input_path"])
        expected = _load_object(FIXTURE_ROOT / entry["expected_path"])
        finding = _build(pack, input_document)

        schemas.validate(
            finding,
            "finding.schema.json",
            PackageValidationCode.DESCRIPTOR_SCHEMA_INVALID,
        )
        assert finding["status"] == expected["expected_status"], entry["case_id"]
        assert finding["subject"] == expected["expected_subject"]
        assert finding["rule_result"]["result_code"] == expected["expected_result_code"]
        assert finding["rule_result"]["expected"] == "NTFS"
        assert finding["rule_result"]["rationale_code"] == expected["rationale_code"]
        assert finding["rule_result"]["citations"] == _control(pack)["citations"]
        assert finding["rule_result"]["citations"][0]["page_start"] == 571
        assert finding["rule_result"]["citations"][0]["page_end"] == 572
        assert finding["rule_result"]["output_sha256"] == (
            canonical_finding_output_sha256(finding)
        )

        refs = cast(list[dict[str, str]], finding["evidence_refs"])
        assert refs == sorted(refs, key=lambda item: item["id"])
        assert finding["evidence_set_sha256"] == canonical_sha256(cast(JsonValue, refs))

        actual = cast(dict[str, str], finding["rule_result"]["actual"])
        assert sorted(actual) == expected["evaluated_volume_ids"]


def test_input_and_output_hashes_ignore_order_and_execution_timestamp() -> None:
    pack = _load_object(PACK_PATH)
    input_document = _load_object(FIXTURE_ROOT / "pc07/input/pc07-pass.json")
    reordered = copy.deepcopy(input_document)
    reordered["evidence"] = list(reversed(reordered["evidence"]))

    first = _build(pack, input_document)
    second = _build(
        pack,
        reordered,
        context=_context(evaluated_at="2026-07-22T10:30:00Z"),
    )

    assert first["rule_result"]["input_sha256"] == second["rule_result"]["input_sha256"]
    assert first["rule_result"]["output_sha256"] == second["rule_result"]["output_sha256"]
    assert first["id"] == second["id"]
    assert first["evaluated_at"] != second["evaluated_at"]


def test_canonical_input_hash_binds_the_full_normalized_evidence() -> None:
    pack = _load_object(PACK_PATH)
    input_document = _load_object(FIXTURE_ROOT / "pc07/input/pc07-pass.json")
    changed = copy.deepcopy(input_document)
    changed["evidence"][0]["source_locator"]["locator"] += ":changed"

    original = _build(pack, input_document)
    modified = _build(pack, changed)

    assert original["evidence_set_sha256"] == modified["evidence_set_sha256"]
    assert original["rule_result"]["input_sha256"] != modified["rule_result"]["input_sha256"]
    assert original["rule_result"]["output_sha256"] != modified["rule_result"]["output_sha256"]


def test_output_hash_excludes_only_execution_envelope_and_its_own_field() -> None:
    pack = _load_object(PACK_PATH)
    input_document = _load_object(FIXTURE_ROOT / "pc07/input/pc07-fail-fat32.json")
    finding = _build(pack, input_document)
    original_hash = cast(str, finding["rule_result"]["output_sha256"])

    execution_only = copy.deepcopy(finding)
    execution_only["created_at"] = "2026-07-23T00:00:00Z"
    execution_only["evaluated_at"] = "2026-07-23T00:00:00Z"
    execution_only["correlation_id"] = "70000000-0000-4000-8000-000000000099"
    execution_only["rule_result"]["output_sha256"] = "0" * 64
    assert canonical_finding_output_sha256(execution_only) == original_hash

    decision_tampered = copy.deepcopy(finding)
    decision_tampered["rule_result"]["actual"]["vol-data"] = "NTFS"
    assert canonical_finding_output_sha256(decision_tampered) != original_hash


def test_draft_pack_requires_explicit_development_opt_in() -> None:
    pack = _load_object(PACK_PATH)
    input_document = _load_object(FIXTURE_ROOT / "pc07/input/pc07-pass.json")

    with pytest.raises(FindingBuildError) as captured:
        _builder().build(
            pack=pack,
            control_id="PC-07",
            evidence=cast(list[dict[str, Any]], input_document["evidence"]),
            decision=_decision(pack, input_document),
            context=_context(),
        )

    assert captured.value.code is FindingBuildCode.PACK_NOT_APPROVED


def test_pack_content_hash_drift_is_rejected_before_finding_creation() -> None:
    pack = _load_object(PACK_PATH)
    pack["name"] = "tampered"
    input_document = _load_object(FIXTURE_ROOT / "pc07/input/pc07-pass.json")

    with pytest.raises(FindingBuildError) as captured:
        _builder().build(
            pack=pack,
            control_id="PC-07",
            evidence=cast(list[dict[str, Any]], input_document["evidence"]),
            decision=_decision(pack, input_document),
            context=_context(),
            allow_draft=True,
        )

    assert captured.value.code is FindingBuildCode.PACK_HASH_MISMATCH


def test_common_finding_builder_supports_non_pc07_decision() -> None:
    pack = _load_object(
        PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "src" / "pack-0.6.0.json"
    )
    input_document = _load_object(FIXTURE_ROOT / "pc07/input/pc07-pass.json")
    evidence = [copy.deepcopy(cast(list[dict[str, Any]], input_document["evidence"])[0])]
    evidence[0].update(
        {
            "control_id": "PC-01",
            "probe_id": "win.security.password-age",
            "subject": {"scope": "POLICY"},
            "policy_source": "WINDOWS_EFFECTIVE",
            "normalized_value": {
                "maximum_password_age_days": 90,
                "policy_defined": True,
                "policy_source": "WINDOWS_EFFECTIVE",
            },
        }
    )

    finding = _builder().build_common(
        pack=pack,
        control_id="PC-01",
        evidence=evidence,
        decision={
            "status": "PASS",
            "result_code": "PASSWORD_CHANGE_PERIOD_WITHIN_90_DAYS",
            "actual": "90일마다 변경",
            "expected": "1~90일 이내에 변경",
            "rationale_code": "PASSWORD_CHANGE_PERIOD_WITHIN_90_DAYS",
            "error_codes": [],
        },
        context=_context(),
        allow_draft=True,
    )

    assert finding["subject"] == {"scope": "POLICY"}
    assert finding["status"] == "PASS"
    rule_result = cast(dict[str, JsonValue], finding["rule_result"])
    assert rule_result["actual"] == "90일마다 변경"
    assert rule_result["expected"] == "1~90일 이내에 변경"
