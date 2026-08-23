from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from security_audit.application.demo_evaluation import SyntheticPc07Pipeline

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("case_id", "expected_status"),
    [
        ("pc07-pass", "PASS"),
        ("pc07-fail-fat32", "FAIL"),
        ("pc07-error-collection", "ERROR"),
    ],
)
def test_synthetic_package_runs_through_validation_normalization_and_finding(
    case_id: str,
    expected_status: str,
) -> None:
    result = SyntheticPc07Pipeline(PROJECT_ROOT).evaluate(case_id)
    finding = cast(dict[str, Any], result.finding)
    audit_pack = cast(dict[str, Any], finding["audit_pack"])
    rule_result = cast(dict[str, Any], finding["rule_result"])

    assert result.case_id == case_id
    assert result.package_validated is True
    assert result.normalized_evidence_count > 0
    assert finding["status"] == expected_status
    assert finding["control_id"] == "PC-07"
    assert audit_pack["version"] == "0.1.0"
    assert rule_result["input_sha256"]
    assert rule_result["output_sha256"]


def test_demo_pipeline_rejects_case_ids_outside_the_fixed_allowlist() -> None:
    with pytest.raises(ValueError, match="allowlisted"):
        SyntheticPc07Pipeline(PROJECT_ROOT).evaluate("../../arbitrary")
