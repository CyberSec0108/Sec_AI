from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, cast

import pytest

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.analysis.rule_engine.account_policy import (
    AccountPolicyDecision,
    AccountPolicyRuleError,
    AccountPolicyRuleRegistry,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACK_PATH = (
    PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "src" / "pack-0.2.0.json"
)
FIXTURE_PATH = (
    PROJECT_ROOT
    / "audit_packs"
    / "kisa_2026_pc"
    / "fixtures"
    / "account_policy"
    / "cases.json"
)


def _load(path: Path) -> dict[str, Any]:
    value = load_strict_json(path.read_bytes())
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _controls() -> dict[str, dict[str, Any]]:
    return {item["control_id"]: item for item in _load(PACK_PATH)["controls"]}


def _evaluate(case: dict[str, Any]) -> AccountPolicyDecision:
    control = _controls()[case["control_id"]]
    return AccountPolicyRuleRegistry().evaluate(
        control_id=case["control_id"],
        applicability_rule=control["applicability_rule"],
        evaluation_rule=control["evaluation_rule"],
        evidence=case["evidence"],
        organization_policy=case.get("organization_policy"),
    )


def test_all_imp021_fixtures_match_the_deterministic_rule_result() -> None:
    for case in _load(FIXTURE_PATH)["cases"]:
        decision = _evaluate(case)
        assert decision.as_dict() == case["expected"], case["case_id"]


def test_same_account_policy_input_returns_the_same_result_100_times() -> None:
    case = _load(FIXTURE_PATH)["cases"][0]
    results = {_evaluate(case) for _ in range(100)}

    assert len(results) == 1


def test_pc02_without_organization_standard_is_review_not_pass() -> None:
    case = next(
        item
        for item in _load(FIXTURE_PATH)["cases"]
        if item["case_id"] == "pc02-review-no-standard"
    )

    decision = _evaluate(case)

    assert decision.status == "REVIEW"
    assert decision.result_code == "ORGANIZATION_PASSWORD_STANDARD_REQUIRED"


def test_collection_failure_is_error_not_security_failure() -> None:
    error_cases = [
        item
        for item in _load(FIXTURE_PATH)["cases"]
        if item["expected"]["status"] == "ERROR"
    ]

    assert len(error_cases) == 3
    assert all(_evaluate(case).status == "ERROR" for case in error_cases)


def test_account_policy_registry_rejects_unapproved_rule_version() -> None:
    case = _load(FIXTURE_PATH)["cases"][0]
    control = copy.deepcopy(_controls()[case["control_id"]])
    control["evaluation_rule"]["rule_version"] = "9.9.9"

    with pytest.raises(AccountPolicyRuleError, match="allowlisted"):
        AccountPolicyRuleRegistry().evaluate(
            control_id=case["control_id"],
            applicability_rule=control["applicability_rule"],
            evaluation_rule=control["evaluation_rule"],
            evidence=case["evidence"],
        )
