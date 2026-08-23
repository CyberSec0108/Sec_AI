"""실제 PostgreSQL에서 통합 이력의 멱등성·RLS·append-only를 검증합니다."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import create_engine, delete, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from security_audit.application.audit_history import (
    validate_windows_audit_presentation,
    validate_windows_audit_snapshot,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.audit_history_repository import (
    append_windows_audit_presentation,
    append_windows_audit_snapshot,
    list_audit_history,
    set_audit_history_scope,
)
from security_audit.persistence.database.models import (
    AssetRecord,
    OrganizationRecord,
    UserAccountRecord,
    WindowsAuditPresentationRecord,
    WindowsAuditSnapshotRecord,
)

ORGANIZATION_ID = UUID("71000000-0000-4000-8000-000000000001")
USER_ID = UUID("71000000-0000-4000-8000-000000000002")
OTHER_USER_ID = UUID("71000000-0000-4000-8000-000000000003")
ASSET_ID = UUID("71000000-0000-4000-8000-000000000004")
LINUX_RUN_ID = UUID("71000000-0000-4000-8000-000000000005")
SWITCH_RUN_ID = UUID("71000000-0000-4000-8000-000000000006")


def _result() -> dict[str, object]:
    controls = [
        {
            "control_id": f"PC-{index:02d}",
            "title": f"합성 점검 {index}",
            "assessment_status": "PASS" if index % 2 else "FAIL",
            "administrator_required": False,
        }
        for index in range(1, 19)
    ]
    explanations: list[dict[str, JsonValue]] = []
    ai_inputs: list[dict[str, JsonValue]] = []
    for control in controls:
        explanation: dict[str, JsonValue] = {
            "schema_version": "1.0.0",
            "control_id": str(control["control_id"]),
            "title": str(control["title"]),
            "official_status": str(control["assessment_status"]),
            "status_authority": "RULE_ENGINE",
            "observed_summary": "합성 비식별 확인값",
            "expected_summary": "합성 안전 기준",
            "judgement_explanation": "규칙 엔진의 합성 판정 설명",
        }
        explanation["presentation_sha256"] = canonical_sha256_without_fields(
            explanation,
            {"presentation_sha256"},
        )
        explanations.append(explanation)
        ai_input: dict[str, JsonValue] = {
            "schema_version": "1.0.0",
            "control_id": str(control["control_id"]),
            "title": str(control["title"]),
            "rule_status": str(control["assessment_status"]),
            "status_authority": "RULE_ENGINE",
            "observed_summary": "합성 비식별 확인값",
            "expected_summary": "합성 안전 기준",
            "judgement_explanation": "규칙 엔진의 합성 판정 설명",
            "safety": {
                "raw_evidence_included": False,
                "sensitive_identifiers_included": False,
                "rule_status_unchanged": True,
            },
        }
        ai_input["explanation_input_sha256"] = canonical_sha256_without_fields(
            ai_input,
            {"explanation_input_sha256"},
        )
        ai_inputs.append(ai_input)
    return {
        "result_id": "fedcba9876543210",
        "sequence": 1,
        "attempt": 1,
        "observed_at_utc": "2026-08-07T02:00:00Z",
        "controls": controls,
        "explanations": explanations,
        "ai_explanation_inputs": ai_inputs,
        "raw_values_persisted": False,
        "settings_modified": False,
        "official_finding_created": False,
        "result_kind": "LIVE_DRAFT_ASSESSMENT",
        "criteria_context": {"criteria_sha256": "b" * 64},
    }


def _presentation() -> dict[str, object]:
    administrator_report = {
        "status": "COMPLETED",
        "observed_at_utc": "2026-08-07T02:01:00Z",
        "selected_probe_count": 1,
        "collected_probe_count": 1,
        "review_required_count": 0,
        "collection_error_count": 0,
        "assessment_review_count": 0,
        "results": [
            {
                "control_id": "PC-02",
                "probe_id": "verification.administrator-probe",
                "title": "합성 관리자 점검",
                "collection_status": "COLLECTED",
                "assessment_status": "PASS",
                "actual": "합성 비식별 확인값",
                "expected": "합성 안전 기준",
                "judgement_explanation": "관리자 자료를 규칙으로 판정했습니다.",
            }
        ],
        "settings_modified": False,
        "raw_values_persisted": False,
        "official_finding_created": False,
    }
    return {
        "result_id": "fedcba9876543210",
        "result_version": 1,
        "presentation_kind": "AI_COMPLETED",
        "administrator_report": administrator_report,
        "ai_screen": {
            "version": 1,
            "generation_key": "fedcba9876543210:1:PC-02:COLLECTED:PASS",
            "summary_source": "## 합성 종합 설명\n\n저장 결과입니다.[1]",
            "controls": [
                {
                    "control_id": f"PC-{index:02d}",
                    "source": f"## 합성 항목 설명\n\nPC-{index:02d} 저장 결과입니다.[1]",
                    "knowledge_sources": [],
                }
                for index in range(1, 19)
            ],
        },
        "test_environment_result": True,
    }


def _assert_mutation_rejected(session: Session, statement: Any) -> None:
    try:
        with session.begin_nested():
            session.execute(statement)
    except DBAPIError as exc:
        reason = str(exc.orig).casefold()
        if "append-only" not in reason and "permission denied" not in reason:
            raise AssertionError("mutation failed for the wrong reason") from exc
    else:
        raise AssertionError("append-only snapshot accepted a mutation")


def _fixtures(session: Session) -> None:
    now = datetime(2026, 8, 7, 2, 0, tzinfo=UTC)
    set_audit_history_scope(session, ORGANIZATION_ID, USER_ID)
    session.add(OrganizationRecord(id=ORGANIZATION_ID, created_at=now))
    session.flush()
    session.add(AssetRecord(id=ASSET_ID, organization_id=ORGANIZATION_ID, created_at=now))
    session.add(
        UserAccountRecord(
            id=USER_ID,
            organization_id=ORGANIZATION_ID,
            username_canonical="audit-history-verification-user",
            display_name="합성 이력 검증 사용자",
            status="ACTIVE",
            password_hash=USER_ID.hex,
            credential_version=1,
            role_assignment_version=1,
            password_changed_at=now,
            failed_attempts=0,
            created_at=now,
            updated_at=now,
        )
    )
    session.flush()
    linux_result = {
        "criteria_sha256": "c" * 64,
        "controls": [
            {"control_id": "U-01", "title": "합성 Linux 항목", "status": "PASS"}
        ],
    }
    switch_result = {
        "criteria_sha256": "d" * 64,
        "controls": [
            {"control_id": "N-01", "title": "합성 Switch 항목", "status": "FAIL"}
        ],
    }
    session.execute(
        text(
            "INSERT INTO linux_audit_runs "
            "(id, organization_id, owner_user_id, asset_key, asset_id, distribution, "
            "benchmark_id, status, result_json, result_sha256, created_at, started_at, "
            "completed_at) VALUES "
            "(:id, :organization_id, :owner_user_id, 'ubuntu24', :asset_id, "
            "'UBUNTU_24_04', 'verification-linux', 'COMPLETED', "
            "CAST(:result_json AS jsonb), :result_sha256, :created_at, :created_at, "
            ":created_at)"
        ),
        {
            "id": LINUX_RUN_ID,
            "organization_id": ORGANIZATION_ID,
            "owner_user_id": USER_ID,
            "asset_id": ASSET_ID,
            "result_json": json.dumps(linux_result, ensure_ascii=False),
            "result_sha256": "e" * 64,
            "created_at": now,
        },
    )
    session.execute(
        text(
            "INSERT INTO switch_audit_runs "
            "(id, organization_id, owner_user_id, asset_key, asset_id, platform, "
            "platform_version, benchmark_id, status, result_json, result_sha256, "
            "created_at, started_at, completed_at) VALUES "
            "(:id, :organization_id, :owner_user_id, "
            "'aruba-aos-cx-10.13.1170-lab', :asset_id, 'ARUBA_AOS_CX', "
            "'10.13.1170', 'verification-switch', 'COMPLETED', "
            "CAST(:result_json AS jsonb), :result_sha256, :created_at, :created_at, "
            ":created_at)"
        ),
        {
            "id": SWITCH_RUN_ID,
            "organization_id": ORGANIZATION_ID,
            "owner_user_id": USER_ID,
            "asset_id": ASSET_ID,
            "result_json": json.dumps(switch_result, ensure_ascii=False),
            "result_sha256": "f" * 64,
            "created_at": now,
        },
    )


def _verify(session: Session) -> dict[str, object]:
    _fixtures(session)
    session.execute(text("SET LOCAL ROLE secai_runtime"))
    if session.scalar(text("SELECT current_user")) != "secai_runtime":
        raise AssertionError("runtime role could not be activated for RLS verification")
    snapshot = validate_windows_audit_snapshot(_result())
    first = append_windows_audit_snapshot(
        session,
        organization_id=ORGANIZATION_ID,
        owner_user_id=USER_ID,
        asset_id=ASSET_ID,
        snapshot=snapshot,
    )
    replay = append_windows_audit_snapshot(
        session,
        organization_id=ORGANIZATION_ID,
        owner_user_id=USER_ID,
        asset_id=ASSET_ID,
        snapshot=snapshot,
    )
    presentation = validate_windows_audit_presentation(_presentation())
    first_presentation = append_windows_audit_presentation(
        session,
        organization_id=ORGANIZATION_ID,
        owner_user_id=USER_ID,
        presentation=presentation,
    )
    replay_presentation = append_windows_audit_presentation(
        session,
        organization_id=ORGANIZATION_ID,
        owner_user_id=USER_ID,
        presentation=presentation,
    )
    history = list_audit_history(
        session,
        organization_id=ORGANIZATION_ID,
        owner_user_id=USER_ID,
        platform="WINDOWS",
        completed_from=None,
        completed_before=None,
        limit=10,
        offset=0,
    )
    unified_history = list_audit_history(
        session,
        organization_id=ORGANIZATION_ID,
        owner_user_id=USER_ID,
        platform=None,
        completed_from=None,
        completed_before=None,
        limit=10,
        offset=0,
    )
    if not first.created or replay.created or first.id != replay.id:
        raise AssertionError("identical Windows replay was not idempotent")
    if (
        not first_presentation.created
        or replay_presentation.created
        or first_presentation.id != replay_presentation.id
    ):
        raise AssertionError("identical Windows presentation replay was not idempotent")
    if len(history) != 1 or history[0].result_sha256 != snapshot.result_sha256:
        raise AssertionError("unified history did not return the owner snapshot")
    if {record.platform for record in unified_history} != {
        "WINDOWS",
        "LINUX",
        "SWITCH",
    }:
        raise AssertionError("unified history did not return all three platforms")

    set_audit_history_scope(session, ORGANIZATION_ID, OTHER_USER_ID)
    hidden_count = session.scalar(select(WindowsAuditSnapshotRecord.id))
    hidden_presentation_count = session.scalar(
        select(WindowsAuditPresentationRecord.id)
    )
    hidden_history = list_audit_history(
        session,
        organization_id=ORGANIZATION_ID,
        owner_user_id=OTHER_USER_ID,
        platform=None,
        completed_from=None,
        completed_before=None,
        limit=10,
        offset=0,
    )
    if (
        hidden_count is not None
        or hidden_presentation_count is not None
        or hidden_history
    ):
        raise AssertionError("another login could read an owner audit result")
    set_audit_history_scope(session, ORGANIZATION_ID, USER_ID)

    _assert_mutation_rejected(
        session,
        update(WindowsAuditSnapshotRecord)
        .where(WindowsAuditSnapshotRecord.id == first.id)
        .values(pass_count=17),
    )
    _assert_mutation_rejected(
        session,
        update(WindowsAuditPresentationRecord)
        .where(WindowsAuditPresentationRecord.id == first_presentation.id)
        .values(presentation_version=2),
    )
    _assert_mutation_rejected(
        session,
        delete(WindowsAuditPresentationRecord).where(
            WindowsAuditPresentationRecord.id == first_presentation.id
        ),
    )
    _assert_mutation_rejected(
        session,
        delete(WindowsAuditSnapshotRecord).where(
            WindowsAuditSnapshotRecord.id == first.id
        ),
    )
    delete_grants = session.scalar(
        text(
            "SELECT count(*) FROM information_schema.role_table_grants "
            "WHERE grantee = 'secai_runtime' "
            "AND table_name IN ("
            "'windows_audit_snapshots', 'windows_audit_presentations', "
            "'audit_history_policies') "
            "AND privilege_type = 'DELETE'"
        )
    )
    if delete_grants != 0:
        raise AssertionError("runtime role unexpectedly has history DELETE permission")
    return {
        "migration": "0033_windows_presentations",
        "database_role": "secai_runtime",
        "first_append": "CREATED",
        "identical_replay": "RETURNED_EXISTING",
        "presentation_append": "CREATED",
        "presentation_replay": "RETURNED_EXISTING",
        "owner_history_rows": len(history),
        "unified_history_rows": len(unified_history),
        "unified_platforms": sorted(record.platform for record in unified_history),
        "other_login_visibility": 0,
        "update": "REJECTED",
        "delete": "REJECTED",
        "runtime_delete_grants": delete_grants,
        "fixtures_retained": False,
    }


def main() -> None:
    engine = create_engine(ServiceSettings.from_environment().postgres_url())
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
                result = _verify(session)
        finally:
            transaction.rollback()
    engine.dispose()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
