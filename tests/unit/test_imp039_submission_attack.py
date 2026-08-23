from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from security_audit.application.submission_attack_acceptance import (
    run_submission_attack_acceptance,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    return run_submission_attack_acceptance(PROJECT_ROOT)


def test_attack_matrix_blocks_every_input_before_downstream_processing(
    report: dict[str, Any],
) -> None:

    assert report["imp"] == "IMP-039"
    assert report["acceptance_status"] == "PASS"
    assert report["summary"]["attack_count"] >= 20
    assert report["summary"]["blocked_count"] == report["summary"]["attack_count"]
    assert report["summary"]["escaped_count"] == 0
    assert {
        attack["category"]
        for attack in report["attacks"]
    } >= {
        "PACKAGE_TAMPER",
        "EXPIRY",
        "REPLAY",
        "SCOPE",
        "SIGNATURE",
        "USER_AUTH",
    }
    assert all(attack["blocked"] for attack in report["attacks"])
    assert all(attack["actual_code"] in attack["expected_codes"] for attack in report["attacks"])

    boundary = report["downstream_boundary"]
    assert boundary == {
        "attack_submissions_accepted": 0,
        "objects_persisted": 0,
        "normalizer_runs": 0,
        "rule_runs": 0,
        "finding_writes": 0,
        "official_findings_created": 0,
    }


def test_attack_report_is_stable_and_contains_no_secret_or_raw_evidence(
    report: dict[str, Any],
) -> None:
    serialized = json.dumps(report, ensure_ascii=False).casefold()

    attack_ids = [attack["id"] for attack in report["attacks"]]
    assert attack_ids == [
        *(f"IMP039-ON-{number:02d}" for number in range(1, 14)),
        *(f"IMP039-OFF-{number:02d}" for number in range(1, 16)),
    ]
    assert len(attack_ids) == len(set(attack_ids))
    assert report["safe_reporting"]["credential_exposed"] is False
    assert report["safe_reporting"]["private_key_exposed"] is False
    assert report["safe_reporting"]["certificate_body_exposed"] is False
    assert report["safe_reporting"]["raw_evidence_exposed"] is False
    assert report["safe_reporting"]["temporary_path_exposed"] is False
    assert "secai_job_v1." not in serialized
    assert "begin private key" not in serialized
    assert "leaf_certificate_der_base64url" not in serialized
    assert "redacted-device-summary" not in serialized
    assert "\\appdata\\" not in serialized
    assert f"{Path('/').as_posix()}tmp/" not in serialized
    assert report_only_public_fields(report)


def report_only_public_fields(report: dict[str, Any]) -> bool:
    attacks = report["attacks"]
    assert isinstance(attacks, list)
    allowed = {
        "id",
        "surface",
        "category",
        "title",
        "expected_codes",
        "actual_code",
        "blocked",
        "user_message",
    }
    return all(isinstance(item, dict) and set(item) == allowed for item in attacks)


def test_report_keeps_development_and_finding_boundaries_closed(
    report: dict[str, Any],
) -> None:
    assert report["test_data_only"] is True
    assert report["production_upload_endpoint_enabled"] is False
    assert report["original_evidence_persisted"] is False
    assert report["official_finding_created"] is False
    assert report["next_imp"] == "IMP-040"


def test_static_ui_report_matches_fresh_attack_run(report: dict[str, Any]) -> None:
    stored = json.loads(
        (
            PROJECT_ROOT
            / "apps"
            / "web"
            / "data"
            / "imp039_submission_attack.json"
        ).read_text(encoding="utf-8")
    )

    assert stored == report
