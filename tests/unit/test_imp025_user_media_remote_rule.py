from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, cast

import pytest

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.analysis.rule_engine.user_media_remote import (
    UserMediaRemoteRuleError,
    UserMediaRemoteRuleRegistry,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BASE = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc"
PACK_PATH = BASE / "src" / "pack-0.6.0.json"
FIXTURE_PATH = BASE / "fixtures" / "user_media_remote" / "cases.json"


def _load(path: Path) -> dict[str, Any]:
    value = load_strict_json(path.read_bytes())
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _inputs() -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    pack = _load(PACK_PATH)
    controls = {item["control_id"]: item for item in pack["controls"]}
    return controls, _load(FIXTURE_PATH)["cases"]


def _evaluate(control: dict[str, Any], case: dict[str, Any]) -> dict[str, object]:
    return UserMediaRemoteRuleRegistry().evaluate(
        control_id=case["control_id"],
        applicability_rule=control["applicability_rule"],
        evaluation_rule=control["evaluation_rule"],
        evidence=case["evidence"],
        organization_policy=case.get("organization_policy"),
    ).as_dict()


def test_imp025_all_fifteen_cases_match_expected_and_are_deterministic() -> None:
    controls, cases = _inputs()

    for case in cases:
        first = _evaluate(controls[case["control_id"]], case)
        assert first["status"] == case["expected"]["status"], case["case_id"]
        assert first["result_code"] == case["expected"]["result_code"], case["case_id"]
        for _ in range(100):
            assert _evaluate(controls[case["control_id"]], case) == first


def test_imp025_pc16_known_failure_is_not_hidden_by_incomplete_coverage() -> None:
    controls, cases = _inputs()
    case = copy.deepcopy(
        next(item for item in cases if item["case_id"] == "pc16-pass-policy-lock")
    )
    case["evidence"]["normalized_value"]["screen_saver_is_secure"] = "0"
    case["evidence"]["normalized_value"]["user_coverage_complete"] = False

    decision = _evaluate(controls["PC-16"], case)
    assert decision["status"] == "FAIL"
    assert decision["result_code"] == "SCREEN_SAVER_LOCK_POLICY_VIOLATION"


def test_imp025_pc17_technical_failure_is_not_hidden_by_missing_procedure() -> None:
    controls, cases = _inputs()
    case = copy.deepcopy(
        next(item for item in cases if item["case_id"] == "pc17-pass-autoplay-and-procedure")
    )
    case.pop("organization_policy")
    case["evidence"]["normalized_value"]["turn_off_autoplay_enabled"] = False

    decision = _evaluate(controls["PC-17"], case)
    assert decision["status"] == "FAIL"


def test_imp025_pc18_missing_policy_never_becomes_pass() -> None:
    controls, cases = _inputs()
    case = next(item for item in cases if item["case_id"] == "pc18-review-not-configured")

    decision = _evaluate(controls["PC-18"], case)
    assert decision["status"] == "REVIEW"
    assert decision["coverage"] == "POLICY_NOT_CONFIGURED"


def test_imp025_quick_assist_and_remote_desktop_are_not_rule_inputs() -> None:
    controls, cases = _inputs()
    case = copy.deepcopy(
        next(item for item in cases if item["case_id"] == "pc18-pass-both-disabled")
    )
    case["evidence"]["normalized_value"]["quick_assist_enabled"] = True

    assert _evaluate(controls["PC-18"], case)["status"] == "PASS"


def test_imp025_rule_parameter_or_subject_tampering_is_rejected() -> None:
    controls, cases = _inputs()
    control = copy.deepcopy(controls["PC-16"])
    case = copy.deepcopy(
        next(item for item in cases if item["case_id"] == "pc16-pass-policy-lock")
    )
    control["evaluation_rule"]["parameters"]["maximum_timeout_seconds"] = 601
    with pytest.raises(UserMediaRemoteRuleError, match="parameters"):
        _evaluate(control, case)

    control = controls["PC-16"]
    case["evidence"]["subject"] = {"scope": "ASSET"}
    with pytest.raises(UserMediaRemoteRuleError, match="subject"):
        _evaluate(control, case)


def test_imp025_collection_failures_remain_error() -> None:
    controls, cases = _inputs()
    for case in cases:
        if case["expected"]["status"] != "ERROR":
            continue
        decision = _evaluate(controls[case["control_id"]], case)
        assert decision["status"] == "ERROR"
        assert decision["error_codes"]


def test_imp025_pc16_missing_timeout_is_error_not_crash_or_pass() -> None:
    controls, cases = _inputs()
    case = copy.deepcopy(
        next(item for item in cases if item["case_id"] == "pc16-pass-policy-lock")
    )
    case["evidence"]["normalized_value"]["screen_save_timeout_seconds"] = None

    decision = _evaluate(controls["PC-16"], case)

    assert decision["status"] == "ERROR"
    assert decision["result_code"] == "SCREEN_SAVER_POLICY_INCOMPLETE"
    assert decision["error_codes"] == ["EVIDENCE_INCOMPLETE"]
