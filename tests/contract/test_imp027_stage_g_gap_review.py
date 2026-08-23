from __future__ import annotations

from pathlib import Path
from typing import cast

from security_audit.application.stage_g_gap_review import StageGGapReview
from security_audit.common.canonical_json import JsonValue

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_imp027_stage_g_acceptance_checks_all_pass() -> None:
    report = StageGGapReview(PROJECT_ROOT).run()
    checks = cast(list[dict[str, JsonValue]], report["checks"])

    assert report["stage"] == "G"
    assert report["imp"] == "IMP-027"
    assert report["acceptance_status"] == "PASS_WITH_DEFERRED_GAPS"
    assert report["stage_g_blocker_count"] == 0
    assert len(checks) == 8
    assert {check["check_id"] for check in checks} == {
        f"STAGEG-C{number:02d}" for number in range(1, 9)
    }
    assert all(check["passed"] is True for check in checks)


def test_imp027_false_pass_review_keeps_non_pass_states_separate() -> None:
    report = StageGGapReview(PROJECT_ROOT).run()
    review = cast(dict[str, JsonValue], report["false_pass_review"])

    assert review["non_pass_oracle_count"] == 64
    assert review["false_pass_count"] == 0
    assert review["missing_required_branch_controls"] == []
    assert review["status_result_code_collision_count"] == 0
    assert review["status_result_code_collisions"] == []
    assert review["not_applicable_controls"] == ["PC-09"]
    assert cast(dict[str, JsonValue], report["pack"])["approval_status"] == "DRAFT"


def test_imp027_deferred_gaps_are_explicit_and_do_not_claim_production_ready() -> None:
    report = StageGGapReview(PROJECT_ROOT).run()
    gaps = cast(list[dict[str, JsonValue]], report["deferred_gaps"])

    assert report["deferred_gap_count"] == 5
    assert report["next_imp"] == "IMP-028"
    assert {gap["gap_id"] for gap in gaps} == {
        f"STAGEG-G{number:02d}" for number in range(1, 6)
    }
    assert all(gap["disposition"] == "DEFERRED" for gap in gaps)
    assert any("수집기" in cast(str, gap["title"]) for gap in gaps)
    assert any("운영 승인" in cast(str, gap["title"]) for gap in gaps)
