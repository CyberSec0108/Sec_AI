from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, cast

import pytest

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.analysis.rule_engine.service_management import (
    ServiceManagementRuleError,
    ServiceManagementRuleRegistry,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACK_PATH = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "src" / "pack-0.3.0.json"
FIXTURE_PATH = (
    PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "fixtures" / "service_management" / "cases.json"
)


def _load(path: Path) -> dict[str, Any]:
    value = load_strict_json(path.read_bytes())
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _inputs() -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    pack = _load(PACK_PATH)
    controls = {item["control_id"]: item for item in pack["controls"]}
    return controls, _load(FIXTURE_PATH)["cases"]


def _evaluate(control: dict[str, Any], case: dict[str, Any]) -> dict[str, object]:
    return ServiceManagementRuleRegistry().evaluate(
        control_id=case["control_id"],
        applicability_rule=control["applicability_rule"],
        evaluation_rule=control["evaluation_rule"],
        evidence=case["evidence"],
        organization_policy=case.get("organization_policy"),
    ).as_dict()


def test_imp022_all_twenty_cases_match_expected_and_are_deterministic() -> None:
    controls, cases = _inputs()
    assert len(cases) == 20

    for case in cases:
        first = _evaluate(controls[case["control_id"]], case)
        assert first["status"] == case["expected"]["status"], case["case_id"]
        assert first["result_code"] == case["expected"]["result_code"], case["case_id"]
        for _ in range(100):
            assert _evaluate(controls[case["control_id"]], case) == first


def test_imp022_missing_organization_policy_never_becomes_pass() -> None:
    controls, cases = _inputs()
    for case in cases:
        if case["control_id"] not in {"PC-04", "PC-05", "PC-06"}:
            continue
        if case["evidence"]["collection_status"] != "COLLECTED":
            continue
        without_policy = copy.deepcopy(case)
        without_policy.pop("organization_policy", None)
        decision = _evaluate(controls[case["control_id"]], without_policy)
        assert decision["status"] == "REVIEW"


def test_imp022_collection_failure_never_becomes_fail() -> None:
    controls, cases = _inputs()
    for case in cases:
        if case["expected"]["status"] != "ERROR" or "collection" not in case["case_id"]:
            continue
        decision = _evaluate(controls[case["control_id"]], case)
        assert decision["status"] == "ERROR"
        assert decision["error_codes"]


def test_imp022_rule_parameter_tampering_is_rejected() -> None:
    controls, cases = _inputs()
    case = next(item for item in cases if item["case_id"] == "pc04-pass-approved-least-privilege")
    control = copy.deepcopy(controls["PC-04"])
    control["evaluation_rule"]["parameters"]["default_admin_share_count_maximum"] = 1

    with pytest.raises(ServiceManagementRuleError, match="parameters"):
        _evaluate(control, case)


def test_imp022_pc08_excludes_recovery_diagnostic_and_virtualization_entries() -> None:
    controls, cases = _inputs()
    case = next(item for item in cases if item["case_id"] == "pc08-pass-single-os-with-recovery")
    decision = _evaluate(controls["PC-08"], case)

    assert decision["status"] == "PASS"
    assert "복구 1" in str(decision["actual"])
    assert "가상화 1" in str(decision["actual"])


def test_imp022_pc09_na_requires_confirmed_non_use() -> None:
    controls, cases = _inputs()
    case = copy.deepcopy(
        next(item for item in cases if item["case_id"] == "pc09-na-wininet-unused")
    )
    assert _evaluate(controls["PC-09"], case)["status"] == "N/A"
    case["evidence"]["normalized_value"]["organization_scope_confirmed"] = False
    assert _evaluate(controls["PC-09"], case)["status"] == "REVIEW"


def test_imp022_pc09_incomplete_user_scope_never_becomes_pass() -> None:
    controls, cases = _inputs()
    case = copy.deepcopy(
        next(item for item in cases if item["case_id"] == "pc09-pass-cache-on-exit")
    )
    case["evidence"]["normalized_value"]["organization_scope_confirmed"] = False

    decision = _evaluate(controls["PC-09"], case)

    assert decision["status"] == "REVIEW"
    assert decision["result_code"] == "WININET_USER_COVERAGE_REVIEW_REQUIRED"
