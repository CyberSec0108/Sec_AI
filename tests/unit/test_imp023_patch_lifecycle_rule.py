from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, cast

import pytest

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.analysis.rule_engine.patch_lifecycle import (
    PatchLifecycleRuleError,
    PatchLifecycleRuleRegistry,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BASE = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc"
PACK_PATH = BASE / "src" / "pack-0.4.0.json"
FIXTURE_PATH = BASE / "fixtures" / "patch_lifecycle" / "cases.json"
SNAPSHOT_PATH = BASE / "reference_snapshots" / "microsoft_windows_11" / "2026-07-23.json"


def _load(path: Path) -> dict[str, Any]:
    value = load_strict_json(path.read_bytes())
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _inputs() -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    pack = _load(PACK_PATH)
    controls = {item["control_id"]: item for item in pack["controls"]}
    return controls, _load(FIXTURE_PATH)["cases"], _load(SNAPSHOT_PATH)


def _evaluate(
    control: dict[str, Any],
    case: dict[str, Any],
    snapshot: dict[str, Any] | None,
) -> dict[str, object]:
    return PatchLifecycleRuleRegistry().evaluate(
        control_id=case["control_id"],
        applicability_rule=control["applicability_rule"],
        evaluation_rule=control["evaluation_rule"],
        evidence=case["evidence"],
        reference_snapshot=snapshot,
        organization_policy=case.get("organization_policy"),
    ).as_dict()


def test_imp023_all_twelve_cases_match_expected_and_are_deterministic() -> None:
    controls, cases, snapshot = _inputs()

    for case in cases:
        first = _evaluate(controls[case["control_id"]], case, snapshot)
        assert first["status"] == case["expected"]["status"], case["case_id"]
        assert first["result_code"] == case["expected"]["result_code"], case["case_id"]
        for _ in range(100):
            assert _evaluate(controls[case["control_id"]], case, snapshot) == first


def test_imp023_reference_missing_or_expired_never_becomes_pass() -> None:
    controls, cases, snapshot = _inputs()
    case = copy.deepcopy(
        next(item for item in cases if item["case_id"] == "pc10-pass-current-baseline")
    )

    assert _evaluate(controls["PC-10"], case, None)["status"] == "REVIEW"
    case["evidence"]["collected_at"] = "2026-08-11T00:00:00Z"
    assert _evaluate(controls["PC-10"], case, snapshot)["status"] == "REVIEW"


def test_imp023_snapshot_payload_or_rule_parameter_tampering_is_rejected() -> None:
    controls, cases, snapshot = _inputs()
    case = next(item for item in cases if item["case_id"] == "pc10-pass-current-baseline")
    changed_snapshot = copy.deepcopy(snapshot)
    changed_snapshot["patch_baselines"][1]["minimum_ubr"] = 1
    with pytest.raises(PatchLifecycleRuleError, match="integrity"):
        _evaluate(controls["PC-10"], case, changed_snapshot)

    changed_control = copy.deepcopy(controls["PC-10"])
    changed_control["evaluation_rule"]["parameters"]["automatic_updates_required"] = False
    with pytest.raises(PatchLifecycleRuleError, match="parameters"):
        _evaluate(changed_control, case, snapshot)


def test_imp023_get_hotfix_alone_is_not_accepted() -> None:
    controls, cases, snapshot = _inputs()
    case = copy.deepcopy(
        next(item for item in cases if item["case_id"] == "pc10-pass-current-baseline")
    )
    case["evidence"]["normalized_value"]["update_inventory_source"] = "GET_HOTFIX"

    decision = _evaluate(controls["PC-10"], case, snapshot)
    assert decision["status"] == "ERROR"
    assert decision["result_code"] == "PATCH_INVENTORY_SOURCE_INSUFFICIENT"


def test_imp023_same_23h2_version_has_edition_specific_lifecycle() -> None:
    controls, cases, snapshot = _inputs()
    home = next(item for item in cases if item["case_id"] == "pc11-fail-home-pro-eol")
    enterprise = next(
        item for item in cases if item["case_id"] == "pc11-pass-enterprise-23h2-supported"
    )

    assert _evaluate(controls["PC-11"], home, snapshot)["status"] == "FAIL"
    assert _evaluate(controls["PC-11"], enterprise, snapshot)["status"] == "PASS"


def test_imp023_collection_failure_remains_error() -> None:
    controls, cases, snapshot = _inputs()
    for case in cases:
        if case["expected"]["status"] != "ERROR":
            continue
        decision = _evaluate(controls[case["control_id"]], case, snapshot)
        assert decision["status"] == "ERROR"
        assert decision["error_codes"]
