from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, cast

import pytest

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.analysis.rule_engine.endpoint_protection import (
    EndpointProtectionRuleError,
    EndpointProtectionRuleRegistry,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BASE = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc"
PACK_PATH = BASE / "src" / "pack-0.5.0.json"
FIXTURE_PATH = BASE / "fixtures" / "endpoint_protection" / "cases.json"
CATALOG_PATH = BASE / "adapter_catalogs" / "endpoint_protection" / "0.1.0.json"


def _load(path: Path) -> dict[str, Any]:
    value = load_strict_json(path.read_bytes())
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _inputs() -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    pack = _load(PACK_PATH)
    controls = {item["control_id"]: item for item in pack["controls"]}
    return controls, _load(FIXTURE_PATH)["cases"], _load(CATALOG_PATH)


def _evaluate(
    control: dict[str, Any],
    case: dict[str, Any],
    catalog: dict[str, Any] | None,
) -> dict[str, object]:
    return EndpointProtectionRuleRegistry().evaluate(
        control_id=case["control_id"],
        applicability_rule=control["applicability_rule"],
        evaluation_rule=control["evaluation_rule"],
        evidence=case["evidence"],
        adapter_catalog=catalog,
        organization_policy=case.get("organization_policy"),
    ).as_dict()


def test_imp024_all_eighteen_cases_match_expected_and_are_deterministic() -> None:
    controls, cases, catalog = _inputs()

    for case in cases:
        selected_catalog = None if case["control_id"] == "PC-12" else catalog
        first = _evaluate(controls[case["control_id"]], case, selected_catalog)
        assert first["status"] == case["expected"]["status"], case["case_id"]
        assert first["result_code"] == case["expected"]["result_code"], case["case_id"]
        for _ in range(100):
            assert _evaluate(
                controls[case["control_id"]], case, selected_catalog
            ) == first


def test_imp024_pc12_never_collects_password_content() -> None:
    controls, cases, _ = _inputs()
    case = copy.deepcopy(next(item for item in cases if item["case_id"] == "pc12-fail-enabled"))
    case["evidence"]["normalized_value"].update(
        {"default_password_value": "must-never-be-collected"}
    )

    with pytest.raises(EndpointProtectionRuleError, match="secret"):
        _evaluate(controls["PC-12"], case, None)


def test_imp024_missing_or_tampered_catalog_never_becomes_pass() -> None:
    controls, cases, catalog = _inputs()
    case = next(item for item in cases if item["case_id"] == "pc13-pass-defender-current")

    decision = _evaluate(controls["PC-13"], case, None)
    assert decision["status"] == "REVIEW"

    changed = copy.deepcopy(catalog)
    changed["adapters"][0]["adapter_version"] = "9.9.9"
    with pytest.raises(EndpointProtectionRuleError, match="integrity"):
        _evaluate(controls["PC-13"], case, changed)


def test_imp024_unsupported_products_and_passive_mode_remain_review() -> None:
    controls, cases, catalog = _inputs()
    unsupported = next(
        item for item in cases if item["case_id"] == "pc13-review-unsupported-product"
    )
    passive = next(
        item for item in cases if item["case_id"] == "pc14-review-defender-passive"
    )

    assert _evaluate(controls["PC-13"], unsupported, catalog)["status"] == "REVIEW"
    assert _evaluate(controls["PC-14"], passive, catalog)["status"] == "REVIEW"


def test_imp024_firewall_uses_active_store_and_complete_profile_coverage() -> None:
    controls, cases, catalog = _inputs()
    passing = next(
        item for item in cases if item["case_id"] == "pc15-pass-windows-firewall"
    )
    passing_decision = _evaluate(controls["PC-15"], passing, catalog)
    assert "적용 프로필 3개(도메인, 개인, 공용)" in cast(
        str, passing_decision["actual"]
    )
    assert "Windows 방화벽 비활성 없음" in cast(
        str, passing_decision["actual"]
    )

    case = copy.deepcopy(
        passing
    )
    case["evidence"]["normalized_value"]["policy_store"] = "PERSISTENT_STORE"
    assert _evaluate(controls["PC-15"], case, catalog)["status"] == "ERROR"

    case = copy.deepcopy(
        passing
    )
    del case["evidence"]["normalized_value"]["public_enabled"]
    assert _evaluate(controls["PC-15"], case, catalog)["status"] == "ERROR"


def test_imp024_synthetic_alternative_firewall_cannot_pass_as_production() -> None:
    controls, cases, catalog = _inputs()
    case = copy.deepcopy(
        next(
            item
            for item in cases
            if item["case_id"] == "pc15-pass-synthetic-alternative-firewall"
        )
    )
    case["evidence"]["normalized_value"]["synthetic_test_case"] = False

    decision = _evaluate(controls["PC-15"], case, catalog)
    assert decision["status"] == "REVIEW"
    assert decision["adapter_coverage"] == "SYNTHETIC_TEST_ONLY"


def test_imp024_collection_failure_remains_error() -> None:
    controls, cases, catalog = _inputs()
    for case in cases:
        if case["expected"]["status"] != "ERROR":
            continue
        selected_catalog = None if case["control_id"] == "PC-12" else catalog
        decision = _evaluate(controls[case["control_id"]], case, selected_catalog)
        assert decision["status"] == "ERROR"
        assert decision["error_codes"]
