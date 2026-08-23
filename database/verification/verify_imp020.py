"""Run the complete IMP-020 synthetic demonstration against live PostgreSQL."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from sqlalchemy import create_engine

from security_audit.analysis.finding import FindingReplayAction
from security_audit.analysis.package_validation import PackageValidationCode
from security_audit.application.demo_evaluation import SyntheticPc07Pipeline
from security_audit.application.finding_pipeline_verification import (
    FindingPipelineVerificationService,
)
from security_audit.common.service_settings import ServiceSettings

_EXPECTED_STATUSES = {
    "pc07-pass": "PASS",
    "pc07-fail-fat32": "FAIL",
    "pc07-error-collection": "ERROR",
}


def _assert_detail_contract(detail: dict[str, Any]) -> None:
    document = cast(dict[str, Any], detail["document"])
    rule_result = cast(dict[str, Any], document["rule_result"])
    audit_pack = cast(dict[str, Any], document["audit_pack"])
    citations = cast(list[dict[str, Any]], detail["citations"])
    if audit_pack["version"] != "0.1.0" or rule_result["rule_version"] != "0.1.0":
        raise AssertionError("The exact demo Pack and rule versions were not retained.")
    if not citations or citations[0]["page_start"] != 571 or citations[0]["page_end"] != 572:
        raise AssertionError("The KISA PC-07 page citation is missing.")
    for field in ("input_sha256", "output_sha256", "evidence_set_sha256"):
        value = detail[field]
        if not isinstance(value, str) or len(value) != 64:
            raise AssertionError(f"A required detail hash is invalid: {field}")


def main() -> None:
    engine = create_engine(ServiceSettings.from_environment().postgres_url())
    service = FindingPipelineVerificationService(engine, Path.cwd())
    outcomes: dict[str, dict[str, str]] = {}

    for case_id, expected_status in _EXPECTED_STATUSES.items():
        result = service.run_case(case_id)
        if result["status"] != expected_status:
            raise AssertionError(f"Unexpected demonstration status: {case_id}")
        outcomes[case_id] = {
            "status": cast(str, result["status"]),
            "action": str(result["action"]),
            "finding_id": cast(str, result["finding_id"]),
        }

    replay = service.run_case("pc07-pass")
    if replay["action"] is not FindingReplayAction.RETURN_EXISTING:
        raise AssertionError("Identical Package replay did not return the existing Finding.")

    findings_before_tamper = service.list_findings()
    tamper_code = SyntheticPc07Pipeline(Path.cwd()).verify_archive_tamper_rejected(
        "pc07-pass"
    )
    findings_after_tamper = service.list_findings()
    if tamper_code is not PackageValidationCode.ARCHIVE_HASH_MISMATCH:
        raise AssertionError("The tampered Package failed for an unexpected reason.")
    if len(findings_after_tamper) != len(findings_before_tamper):
        raise AssertionError("A rejected Package changed the Finding row count.")

    ids = {cast(str, finding["id"]) for finding in findings_after_tamper}
    if len(findings_after_tamper) != 3 or len(ids) != 3:
        raise AssertionError("The demo organization does not contain exactly three Findings.")
    detail = service.get_finding(cast(str, replay["finding_id"]))
    if detail is None:
        raise AssertionError("The replayed Finding detail is unavailable.")
    _assert_detail_contract(detail)
    engine.dispose()

    print(
        json.dumps(
            {
                "cases": outcomes,
                "replay_action": str(replay["action"]),
                "tamper_rejection": tamper_code,
                "finding_count_before_tamper": len(findings_before_tamper),
                "finding_count_after_tamper": len(findings_after_tamper),
                "detail_gate": "PASS",
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
