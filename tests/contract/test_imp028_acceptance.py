from pathlib import Path

from security_audit.application.mock_collector_acceptance import (
    run_mock_collector_acceptance,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_imp028_acceptance_report_passes_all_eight_gates() -> None:
    report = run_mock_collector_acceptance(PROJECT_ROOT)

    assert report["imp"] == "IMP-028"
    assert report["acceptance_status"] == "PASS"
    assert report["official_finding_created"] is False
    assert report["next_imp"] == "IMP-029"
    assert len(report["checks"]) == 8
    assert all(item["passed"] for item in report["checks"])
