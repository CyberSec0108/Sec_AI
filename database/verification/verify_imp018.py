"""Verify IMP-018 against the live PostgreSQL service without retaining fixtures."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from sqlalchemy import create_engine, delete, func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from security_audit.analysis.finding import (
    FindingReplayAction,
    canonical_finding_output_sha256,
    deterministic_finding_id,
)
from security_audit.common.canonical_json import JsonValue
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database import (
    AppendFindingCommand,
    AssetRecord,
    AuditJobRecord,
    FindingPersistenceCode,
    FindingPersistenceError,
    FindingVersionRecord,
    OrganizationRecord,
    append_or_get_finding,
)

EXAMPLE_PATH = Path("database/schemas/examples/valid/finding.json")
ORGANIZATION_ID = UUID("70000000-0000-4000-8000-000000000001")
JOB_ID = UUID("10000000-0000-4000-8000-000000000003")
ASSET_ID = UUID("10000000-0000-4000-8000-000000000004")


def _finding() -> dict[str, JsonValue]:
    document = cast(dict[str, JsonValue], json.loads(EXAMPLE_PATH.read_text("utf-8")))
    rule_result = cast(dict[str, JsonValue], document["rule_result"])
    output_sha256 = canonical_finding_output_sha256(document)
    rule_result["output_sha256"] = output_sha256
    document["id"] = deterministic_finding_id(
        cast(str, rule_result["input_sha256"]),
        output_sha256,
    )
    return document


def _conflicting_finding(finding: dict[str, JsonValue]) -> dict[str, JsonValue]:
    conflict = copy.deepcopy(finding)
    conflict["status"] = "FAIL"
    rule_result = cast(dict[str, JsonValue], conflict["rule_result"])
    rule_result["result_code"] = "CONFLICTING_REPLAY_FOR_VERIFICATION"
    output_sha256 = canonical_finding_output_sha256(conflict)
    rule_result["output_sha256"] = output_sha256
    conflict["id"] = deterministic_finding_id(
        cast(str, rule_result["input_sha256"]),
        output_sha256,
    )
    return conflict


def _assert_mutation_rejected(session: Session, statement: Any, operation: str) -> None:
    try:
        with session.begin_nested():
            session.execute(statement)
    except DBAPIError as exc:
        reason = str(exc.orig).lower()
        if "append-only" not in reason and "permission denied" not in reason:
            raise AssertionError(f"{operation} failed for the wrong reason") from exc
    else:
        raise AssertionError(f"{operation} unexpectedly changed finding_versions")


def _verify(session: Session) -> dict[str, object]:
    now = datetime(2026, 7, 22, 9, 0, tzinfo=UTC)
    if session.get(OrganizationRecord, ORGANIZATION_ID) is None:
        session.add(OrganizationRecord(id=ORGANIZATION_ID, created_at=now))
        session.flush()
    if session.get(AssetRecord, ASSET_ID) is None:
        session.add(
            AssetRecord(id=ASSET_ID, organization_id=ORGANIZATION_ID, created_at=now)
        )
        session.flush()
    if session.get(AuditJobRecord, JOB_ID) is None:
        session.add(
            AuditJobRecord(
                id=JOB_ID,
                organization_id=ORGANIZATION_ID,
                asset_id=ASSET_ID,
                evaluation_as_of=now,
                created_at=now,
            )
        )
        session.flush()

    finding = _finding()
    command = AppendFindingCommand(
        organization_id=str(ORGANIZATION_ID),
        engine_artifact_sha256="a" * 64,
        finding_version=1,
    )
    first = append_or_get_finding(session, command, finding)
    replay = append_or_get_finding(session, command, finding)
    rule_result = cast(dict[str, JsonValue], finding["rule_result"])
    input_sha256 = cast(str, rule_result["input_sha256"])
    row_count = session.scalar(
        select(func.count())
        .select_from(FindingVersionRecord)
        .where(FindingVersionRecord.input_sha256 == input_sha256)
    )

    if first.action is not FindingReplayAction.CREATE:
        raise AssertionError("first append did not create a Finding")
    if replay.action is not FindingReplayAction.RETURN_EXISTING:
        raise AssertionError("identical replay did not return the existing Finding")
    if row_count != 1:
        raise AssertionError("identical replay created a duplicate Finding")

    try:
        append_or_get_finding(session, command, _conflicting_finding(finding))
    except FindingPersistenceError as exc:
        if exc.code is not FindingPersistenceCode.REPLAY_REJECTED:
            raise
    else:
        raise AssertionError("conflicting replay was not rejected")

    finding_id = UUID(cast(str, finding["id"]))
    _assert_mutation_rejected(
        session,
        update(FindingVersionRecord)
        .where(FindingVersionRecord.id == finding_id)
        .values(status="FAIL"),
        "UPDATE",
    )
    _assert_mutation_rejected(
        session,
        delete(FindingVersionRecord).where(FindingVersionRecord.id == finding_id),
        "DELETE",
    )

    constraint_count = session.scalar(
        text(
            "SELECT count(*) FROM pg_constraint "
            "WHERE conrelid = 'finding_versions'::regclass "
            "AND conname = 'uq_finding_versions_input_sha256'"
        )
    )
    trigger_names = set(
        session.scalars(
            text(
                "SELECT tgname FROM pg_trigger "
                "WHERE tgrelid = 'finding_versions'::regclass AND NOT tgisinternal"
            )
        )
    )
    expected_triggers = {
        "trg_finding_versions_reject_row_mutation",
        "trg_finding_versions_reject_truncate",
    }
    if constraint_count != 1 or not expected_triggers.issubset(trigger_names):
        raise AssertionError("database idempotency or append-only objects are missing")

    return {
        "migration": "0001_imp018",
        "first_action": first.action,
        "replay_action": replay.action,
        "finding_rows": row_count,
        "conflicting_replay": "REJECTED",
        "update": "REJECTED",
        "delete": "REJECTED",
        "unique_constraint": "PRESENT",
        "append_only_triggers": sorted(expected_triggers),
        "fixtures_retained": False,
    }


def main() -> None:
    engine = create_engine(ServiceSettings.from_environment().postgres_url())
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            with Session(
                bind=connection,
                join_transaction_mode="create_savepoint",
            ) as session:
                result = _verify(session)
        finally:
            transaction.rollback()
    engine.dispose()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
