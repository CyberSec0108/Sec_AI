from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
from sqlalchemy import Table
from sqlalchemy.dialects import postgresql

from security_audit.analysis.finding import FindingBuildContext, FindingBuilder
from security_audit.analysis.package_validation import PackageSchemaCatalog
from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.analysis.rule_engine import RuleRegistry
from security_audit.persistence.database import (
    AppendFindingCommand,
    Base,
    FindingPersistenceCode,
    FindingPersistenceError,
    FindingVersionRecord,
    build_finding_insert_statement,
    finding_record_values,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
PACK_PATH = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "src" / "pack.json"
INPUT_PATH = (
    PROJECT_ROOT
    / "audit_packs"
    / "kisa_2026_pc"
    / "fixtures"
    / "pc07"
    / "input"
    / "pc07-pass.json"
)


def _load_object(path: Path) -> dict[str, Any]:
    value = load_strict_json(path.read_bytes())
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _finding() -> dict[str, Any]:
    pack = _load_object(PACK_PATH)
    input_document = _load_object(INPUT_PATH)
    control = cast(list[dict[str, Any]], pack["controls"])[0]
    evidence = cast(list[dict[str, Any]], input_document["evidence"])
    decision = RuleRegistry().evaluate(
        control_id="PC-07",
        applicability_rule=cast(dict[str, Any], control["applicability_rule"]),
        evaluation_rule=cast(dict[str, Any], control["evaluation_rule"]),
        evidence=evidence,
    )
    return cast(
        dict[str, Any],
        FindingBuilder(PackageSchemaCatalog(SCHEMA_ROOT)).build(
            pack=pack,
            control_id="PC-07",
            evidence=evidence,
            decision=decision,
            context=FindingBuildContext(
                organization_id="70000000-0000-4000-8000-000000000001",
                evaluation_as_of="2026-07-22T08:00:00Z",
                evaluated_at="2026-07-22T09:00:00Z",
                engine_version="0.1.0",
                engine_artifact_sha256="a" * 64,
            ),
            allow_draft=True,
        ),
    )


def _command(**overrides: object) -> AppendFindingCommand:
    values: dict[str, object] = {
        "organization_id": "70000000-0000-4000-8000-000000000001",
        "engine_artifact_sha256": "a" * 64,
        "finding_version": 1,
    }
    values.update(overrides)
    return AppendFindingCommand(**values)  # type: ignore[arg-type]


def test_metadata_has_only_approved_persistence_tables() -> None:
    assert set(Base.metadata.tables) == {
        "organizations",
        "assets",
        "audit_jobs",
        "finding_versions",
        "finding_current",
        "workflow_steps",
        "outbox_events",
        "task_executions",
        "workflow_results",
        "storage_recovery_runs",
        "evidence_artifacts",
        "user_accounts",
        "user_role_assignments",
        "user_asset_assignments",
        "browser_sessions",
        "authentication_audit_events",
        "chat_threads",
        "chat_messages",
        "chat_generation_runs",
        "chat_citations",
        "chat_thread_management_events",
        "result_report_snapshots",
        "result_reports",
        "result_report_access_events",
        "assessment_criteria_profiles",
        "assessment_criteria_selections",
        "audit_history_policies",
        "windows_audit_snapshots",
        "windows_audit_presentations",
    }


def test_finding_model_has_atomic_idempotency_and_version_constraints() -> None:
    constraint_names = {
        constraint.name
        for constraint in cast(Table, FindingVersionRecord.__table__).constraints
    }

    assert "uq_finding_versions_input_sha256" in constraint_names
    assert "uq_finding_versions_subject_version" in constraint_names
    assert "ck_finding_versions_document_identity" in constraint_names
    assert "ck_finding_versions_predecessor_reason" in constraint_names


def test_finding_record_values_preserve_hash_lineage_and_document_copy() -> None:
    finding = _finding()
    values = finding_record_values(_command(), finding)

    assert str(values["id"]) == finding["id"]
    assert values["input_sha256"] == finding["rule_result"]["input_sha256"]
    assert values["output_sha256"] == finding["rule_result"]["output_sha256"]
    assert values["evidence_set_sha256"] == finding["evidence_set_sha256"]
    assert values["finding_document"] == finding
    assert values["finding_document"] is not finding


def test_postgresql_insert_is_create_once_on_the_named_input_hash_constraint() -> None:
    statement = build_finding_insert_statement(finding_record_values(_command(), _finding()))
    compiled = str(
        statement.compile(
            dialect=postgresql.dialect(),  # type: ignore[no-untyped-call]
            compile_kwargs={"literal_binds": False},
        )
    )

    assert "ON CONFLICT ON CONSTRAINT uq_finding_versions_input_sha256 DO NOTHING" in compiled
    assert "RETURNING finding_versions.id" in compiled


@pytest.mark.parametrize(
    "command",
    [
        _command(finding_version=0),
        _command(
            predecessor_id="70000000-0000-4000-8000-000000000099",
            change_reason=None,
        ),
        _command(predecessor_id=None, change_reason="RECHECK"),
    ],
)
def test_invalid_version_or_partial_predecessor_lineage_is_rejected(
    command: AppendFindingCommand,
) -> None:
    with pytest.raises(FindingPersistenceError) as captured:
        finding_record_values(command, _finding())

    assert captured.value.code is FindingPersistenceCode.PERSISTENCE_INPUT_INVALID
