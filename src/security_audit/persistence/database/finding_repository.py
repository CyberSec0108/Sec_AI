"""Atomic append-or-return repository contract for PostgreSQL Findings."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from re import fullmatch
from typing import Any, NoReturn, cast
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session
from sqlalchemy.sql.dml import ReturningInsert

from security_audit.analysis.finding import (
    FindingReplayAction,
    FindingReplayError,
    FindingReplayResolution,
    finding_fingerprint,
    resolve_finding_replay,
)
from security_audit.common.canonical_json import JsonValue

from .models import FindingVersionRecord

_CHANGE_REASONS = frozenset(
    {"RECHECK", "POLICY_UPDATED", "PACK_UPDATED", "ENGINE_UPDATED", "CORRECTION"}
)


class FindingPersistenceCode(StrEnum):
    """Stable persistence failures that must not become Control results."""

    PERSISTENCE_INPUT_INVALID = "PERSISTENCE_INPUT_INVALID"
    REPLAY_REJECTED = "REPLAY_REJECTED"
    IDEMPOTENT_ROW_MISSING = "IDEMPOTENT_ROW_MISSING"


class FindingPersistenceError(ValueError):
    def __init__(self, code: FindingPersistenceCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class AppendFindingCommand:
    """Trusted application context not present in the Finding JSON document."""

    organization_id: str
    engine_artifact_sha256: str
    finding_version: int
    predecessor_id: str | None = None
    change_reason: str | None = None


def _reject(code: FindingPersistenceCode, message: str) -> NoReturn:
    raise FindingPersistenceError(code, message)


def _object(mapping: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = mapping.get(key)
    if not isinstance(value, dict):
        _reject(FindingPersistenceCode.PERSISTENCE_INPUT_INVALID, f"Invalid object: {key}.")
    return cast(dict[str, Any], value)


def _string(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        _reject(FindingPersistenceCode.PERSISTENCE_INPUT_INVALID, f"Invalid field: {key}.")
    return value


def _uuid(value: str, field_name: str) -> UUID:
    try:
        return UUID(value)
    except ValueError as exc:
        raise FindingPersistenceError(
            FindingPersistenceCode.PERSISTENCE_INPUT_INVALID,
            f"Invalid UUID: {field_name}.",
        ) from exc


def _timestamp(value: str, field_name: str) -> datetime:
    if not value.endswith("Z"):
        _reject(
            FindingPersistenceCode.PERSISTENCE_INPUT_INVALID,
            f"Invalid UTC timestamp: {field_name}.",
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise FindingPersistenceError(
            FindingPersistenceCode.PERSISTENCE_INPUT_INVALID,
            f"Invalid UTC timestamp: {field_name}.",
        ) from exc
    return parsed


def finding_record_values(
    command: AppendFindingCommand,
    finding: Mapping[str, JsonValue],
) -> dict[str, object]:
    """Map an integrity-checked Finding to immutable PostgreSQL columns."""

    if command.finding_version <= 0:
        _reject(
            FindingPersistenceCode.PERSISTENCE_INPUT_INVALID,
            "finding_version must be positive.",
        )
    if (command.predecessor_id is None) != (command.change_reason is None):
        _reject(
            FindingPersistenceCode.PERSISTENCE_INPUT_INVALID,
            "predecessor_id and change_reason must be supplied together.",
        )
    if command.change_reason is not None and command.change_reason not in _CHANGE_REASONS:
        _reject(
            FindingPersistenceCode.PERSISTENCE_INPUT_INVALID,
            "change_reason is not allowlisted.",
        )
    if fullmatch(r"[a-f0-9]{64}", command.engine_artifact_sha256) is None:
        _reject(
            FindingPersistenceCode.PERSISTENCE_INPUT_INVALID,
            "engine_artifact_sha256 is invalid.",
        )
    try:
        fingerprint = finding_fingerprint(finding)
    except FindingReplayError as exc:
        raise FindingPersistenceError(
            FindingPersistenceCode.PERSISTENCE_INPUT_INVALID,
            "Finding identity validation failed.",
        ) from exc

    document = cast(dict[str, Any], copy.deepcopy(dict(finding)))
    subject = _object(document, "subject")
    audit_pack = _object(document, "audit_pack")
    return {
        "id": _uuid(fingerprint.finding_id, "id"),
        "organization_id": _uuid(command.organization_id, "organization_id"),
        "job_id": _uuid(_string(document, "job_id"), "job_id"),
        "asset_id": _uuid(_string(document, "asset_id"), "asset_id"),
        "control_id": _string(document, "control_id"),
        "subject_scope": _string(subject, "scope"),
        "subject_key": _string(subject, "subject_key"),
        "finding_version": command.finding_version,
        "status": _string(document, "status"),
        "schema_version": _string(document, "schema_version"),
        "producer_name": _string(document, "producer_name"),
        "producer_version": _string(document, "producer_version"),
        "engine_artifact_sha256": command.engine_artifact_sha256,
        "audit_pack_id": _uuid(_string(audit_pack, "id"), "audit_pack.id"),
        "audit_pack_version": _string(audit_pack, "version"),
        "audit_pack_sha256": _string(audit_pack, "sha256"),
        "evidence_set_sha256": _string(document, "evidence_set_sha256"),
        "input_sha256": fingerprint.idempotency_key,
        "output_sha256": fingerprint.output_sha256,
        "finding_document": document,
        "predecessor_id": (
            _uuid(command.predecessor_id, "predecessor_id")
            if command.predecessor_id is not None
            else None
        ),
        "change_reason": command.change_reason,
        "evaluated_at": _timestamp(_string(document, "evaluated_at"), "evaluated_at"),
        "created_at": _timestamp(_string(document, "created_at"), "created_at"),
    }


def build_finding_insert_statement(
    values: Mapping[str, object],
) -> ReturningInsert[tuple[UUID]]:
    """Build the single-statement PostgreSQL create-once operation."""

    return (
        insert(FindingVersionRecord)
        .values(**values)
        .on_conflict_do_nothing(constraint="uq_finding_versions_input_sha256")
        .returning(FindingVersionRecord.id)
    )


def append_or_get_finding(
    session: Session,
    command: AppendFindingCommand,
    finding: Mapping[str, JsonValue],
) -> FindingReplayResolution:
    """Append once or return an existing identical Finding in the caller transaction."""

    values = finding_record_values(command, finding)
    inserted_id = session.execute(build_finding_insert_statement(values)).scalar_one_or_none()
    if inserted_id is not None:
        fingerprint = finding_fingerprint(finding)
        return FindingReplayResolution(FindingReplayAction.CREATE, fingerprint)

    input_sha256 = cast(str, values["input_sha256"])
    existing_document = session.execute(
        select(FindingVersionRecord.finding_document).where(
            FindingVersionRecord.input_sha256 == input_sha256
        )
    ).scalar_one_or_none()
    if existing_document is None:
        _reject(
            FindingPersistenceCode.IDEMPOTENT_ROW_MISSING,
            "Unique conflict occurred without a readable existing Finding.",
        )
    try:
        return resolve_finding_replay(
            existing=cast(dict[str, JsonValue], existing_document),
            candidate=finding,
        )
    except FindingReplayError as exc:
        raise FindingPersistenceError(
            FindingPersistenceCode.REPLAY_REJECTED,
            "Existing Finding conflicts with the replay candidate.",
        ) from exc
