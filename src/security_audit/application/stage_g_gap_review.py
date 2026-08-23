"""IMP-027 Stage G demonstration acceptance and false-PASS gap review."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import cast

from security_audit.common.canonical_json import JsonValue

from .full_pack_regression import FullPackRegression, FullPackRegressionError

_CONTROL_IDS = tuple(f"PC-{number:02d}" for number in range(1, 19))
_REQUIRED_BRANCHES = frozenset({"PASS", "FAIL", "ERROR"})
_NON_PASS_STATES = frozenset({"FAIL", "ERROR", "REVIEW", "N/A"})


class StageGGapReviewError(ValueError):
    """Reject a Stage G demonstration that violates an acceptance boundary."""


class StageGGapReview:
    """Produce an evidence-backed Stage G handoff decision."""

    def __init__(self, project_root: Path) -> None:
        self._regression = FullPackRegression(project_root)

    def run(self) -> dict[str, JsonValue]:
        """Execute the complete acceptance review and return a stable projection."""

        results = self._regression.evaluate_all()
        coverage = self._regression.coverage_report()
        determinism = self._regression.verify_determinism()
        pack = self._regression.pack_metadata

        statuses_by_control: dict[str, set[str]] = defaultdict(set)
        statuses_by_result_code: dict[str, set[str]] = defaultdict(set)
        for result in results:
            control_id = cast(str, result["control_id"])
            status = cast(str, result["status"])
            result_code = cast(str, result["result_code"])
            statuses_by_control[control_id].add(status)
            statuses_by_result_code[result_code].add(status)

        missing_branches = [
            control_id
            for control_id in _CONTROL_IDS
            if not _REQUIRED_BRANCHES <= statuses_by_control[control_id]
        ]
        status_code_collisions = sorted(
            result_code
            for result_code, statuses in statuses_by_result_code.items()
            if len(statuses) != 1
        )
        non_pass_count = sum(
            cast(str, result["status"]) in _NON_PASS_STATES for result in results
        )
        na_controls = sorted(
            {
                cast(str, result["control_id"])
                for result in results
                if result["status"] == "N/A"
            }
        )

        checks: list[dict[str, JsonValue]] = [
            {
                "check_id": "STAGEG-C01",
                "label": "PC-01~18 누락·중복 없음",
                "passed": coverage["all_controls_exactly_once"] is True,
                "actual": cast(int, coverage["control_count"]),
                "expected": 18,
            },
            {
                "check_id": "STAGEG-C02",
                "label": "전체 합성 사례와 Pack 참조 연결",
                "passed": (
                    coverage["fixture_count"] == 92
                    and coverage["all_fixture_references_resolved"] is True
                    and coverage["all_oracles_matched"] is True
                ),
                "actual": cast(int, coverage["fixture_count"]),
                "expected": 92,
            },
            {
                "check_id": "STAGEG-C03",
                "label": "모든 Control에 PASS·FAIL·ERROR 방어 분기 존재",
                "passed": not missing_branches,
                "actual": len(_CONTROL_IDS) - len(missing_branches),
                "expected": 18,
            },
            {
                "check_id": "STAGEG-C04",
                "label": "비-PASS oracle의 false PASS 없음",
                "passed": non_pass_count == 64,
                "actual": non_pass_count,
                "expected": 64,
            },
            {
                "check_id": "STAGEG-C05",
                "label": "결과 코드의 상태 충돌 없음",
                "passed": not status_code_collisions,
                "actual": len(status_code_collisions),
                "expected": 0,
            },
            {
                "check_id": "STAGEG-C06",
                "label": "N/A는 승인된 PC-09 범위에만 존재",
                "passed": na_controls == ["PC-09"],
                "actual": cast(JsonValue, na_controls),
                "expected": cast(JsonValue, ["PC-09"]),
            },
            {
                "check_id": "STAGEG-C07",
                "label": "전체 결과 100회 결정론",
                "passed": (
                    determinism["iterations"] == 100
                    and determinism["unique_fingerprint_count"] == 1
                ),
                "actual": cast(int, determinism["unique_fingerprint_count"]),
                "expected": 1,
            },
            {
                "check_id": "STAGEG-C08",
                "label": "DRAFT·합성시험 경계 유지",
                "passed": (
                    pack["approval_status"] == "DRAFT"
                    and coverage["synthetic_only"] is True
                ),
                "actual": cast(str, pack["approval_status"]),
                "expected": "DRAFT",
            },
        ]
        failed_checks = [
            cast(str, check["check_id"]) for check in checks if check["passed"] is not True
        ]
        if failed_checks:
            raise StageGGapReviewError(
                f"Stage G acceptance checks failed: {', '.join(failed_checks)}"
            )

        deferred_gaps: list[dict[str, JsonValue]] = [
            {
                "gap_id": "STAGEG-G01",
                "title": "실제 Windows 자료 수집기 없음",
                "risk": "현재 결과로 실제 PC의 보안 상태를 주장할 수 없음",
                "disposition": "DEFERRED",
                "target": "IMP-028~031",
            },
            {
                "gap_id": "STAGEG-G02",
                "title": "권한 분리와 Probe 무변경 안전성 미인수",
                "risk": "관리자 권한이 필요한 실제 수집의 영향이 아직 검증되지 않음",
                "disposition": "DEFERRED",
                "target": "IMP-030",
            },
            {
                "gap_id": "STAGEG-G03",
                "title": "실제 제품 Adapter와 조직 정책 신뢰 연결 없음",
                "risk": "미지원 백신·방화벽 또는 미승인 조직 기준은 자동 PASS 불가",
                "disposition": "DEFERRED",
                "target": "IMP-031",
            },
            {
                "gap_id": "STAGEG-G04",
                "title": "온라인·오프라인 제출과 서명 검증 없음",
                "risk": "실제 수집 Package의 출처·재전송·변조 방어를 아직 인수하지 않음",
                "disposition": "DEFERRED",
                "target": "IMP-032~035",
            },
            {
                "gap_id": "STAGEG-G05",
                "title": "Audit Pack 운영 승인·서명 없음",
                "risk": "DRAFT 결과는 운영 공식 Finding으로 사용할 수 없음",
                "disposition": "DEFERRED",
                "target": "운영 Pack release Gate",
            },
        ]
        return {
            "stage": "G",
            "imp": "IMP-027",
            "acceptance_status": "PASS_WITH_DEFERRED_GAPS",
            "stage_g_blocker_count": 0,
            "deferred_gap_count": len(deferred_gaps),
            "checks": cast(JsonValue, checks),
            "false_pass_review": {
                "non_pass_oracle_count": non_pass_count,
                "false_pass_count": 0,
                "missing_required_branch_controls": cast(
                    JsonValue, missing_branches
                ),
                "status_result_code_collision_count": len(status_code_collisions),
                "status_result_code_collisions": cast(
                    JsonValue, status_code_collisions
                ),
                "not_applicable_controls": cast(JsonValue, na_controls),
            },
            "pack": pack,
            "coverage": coverage,
            "determinism": determinism,
            "deferred_gaps": cast(JsonValue, deferred_gaps),
            "next_imp": "IMP-028",
        }


def run_stage_g_gap_review(project_root: Path) -> dict[str, JsonValue]:
    """Convenience entry point with a stable application-level exception."""

    try:
        return StageGGapReview(project_root).run()
    except FullPackRegressionError as exc:
        raise StageGGapReviewError(str(exc)) from exc
