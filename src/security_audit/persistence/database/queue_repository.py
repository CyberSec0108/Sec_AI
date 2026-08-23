"""PostgreSQL truth and idempotent transitions for IMP-044 recovery."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, cast
from uuid import UUID, uuid4

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from security_audit.common.canonical_json import JsonValue, canonical_sha256

from .models import (
    AssetRecord,
    AuditJobRecord,
    FindingVersionRecord,
    OrganizationRecord,
    OutboxEventRecord,
    TaskExecutionRecord,
    WorkflowResultRecord,
    WorkflowStepRecord,
)

RECOVERY_TASK_NAME = "secai.maintenance.verify_delivery"
RECOVERY_STEP_NAME = "IMP044_RECOVERY_PROBE"
RECOVERY_QUEUE_NAME = "maintenance"
RECOVERY_SCHEMA_VERSION = "1.0"
RECOVERY_INPUT_VERSION = 1
_MESSAGE_FIELDS = frozenset(
    {
        "schema_version",
        "task_name",
        "job_id",
        "asset_id",
        "workflow_step",
        "expected_input_version",
        "idempotency_key",
        "correlation_id",
        "created_at",
    }
)


class QueueRecoveryCode(StrEnum):
    INVALID_MESSAGE = "INVALID_MESSAGE"
    EVENT_NOT_FOUND = "EVENT_NOT_FOUND"
    EVENT_STATE_INVALID = "EVENT_STATE_INVALID"
    STEP_NOT_FOUND = "STEP_NOT_FOUND"
    DELIVERY_NOT_FOUND = "DELIVERY_NOT_FOUND"
    ACTIVE_WORKER_INVALID = "ACTIVE_WORKER_INVALID"


class QueueRecoveryError(RuntimeError):
    def __init__(self, code: QueueRecoveryCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class RecoveryProbeReference:
    job_id: UUID
    step_id: UUID
    outbox_event_id: UUID
    baseline_finding_count: int


@dataclass(frozen=True, slots=True)
class RecoveryAttempt:
    execution_id: UUID
    attempt_no: int
    should_hold_for_worker_loss: bool
    result_already_exists: bool


def _now() -> datetime:
    return datetime.now(UTC)


def _uuid(value: object, field: str) -> UUID:
    if not isinstance(value, str):
        raise QueueRecoveryError(
            QueueRecoveryCode.INVALID_MESSAGE,
            f"Queue message field is invalid: {field}.",
        )
    try:
        return UUID(value)
    except ValueError as exc:
        raise QueueRecoveryError(
            QueueRecoveryCode.INVALID_MESSAGE,
            f"Queue message UUID is invalid: {field}.",
        ) from exc


def validate_recovery_message(value: Mapping[str, object]) -> dict[str, object]:
    """Validate the fixed identifier-only task message without coercion."""

    if frozenset(value) != _MESSAGE_FIELDS:
        raise QueueRecoveryError(
            QueueRecoveryCode.INVALID_MESSAGE,
            "Queue message fields are invalid.",
        )
    job_id = _uuid(value.get("job_id"), "job_id")
    asset_id = _uuid(value.get("asset_id"), "asset_id")
    correlation_id = _uuid(value.get("correlation_id"), "correlation_id")
    idempotency_key = f"job:{job_id}:{RECOVERY_STEP_NAME}:v1"
    created_at = value.get("created_at")
    if (
        value.get("schema_version") != RECOVERY_SCHEMA_VERSION
        or value.get("task_name") != RECOVERY_TASK_NAME
        or value.get("workflow_step") != RECOVERY_STEP_NAME
        or value.get("expected_input_version") != RECOVERY_INPUT_VERSION
        or value.get("idempotency_key") != idempotency_key
        or not isinstance(created_at, str)
        or not created_at.endswith("Z")
    ):
        raise QueueRecoveryError(
            QueueRecoveryCode.INVALID_MESSAGE,
            "Queue message binding is invalid.",
        )
    try:
        datetime.fromisoformat(created_at[:-1] + "+00:00")
    except ValueError as exc:
        raise QueueRecoveryError(
            QueueRecoveryCode.INVALID_MESSAGE,
            "Queue message timestamp is invalid.",
        ) from exc
    return {
        **dict(value),
        "job_id": str(job_id),
        "asset_id": str(asset_id),
        "correlation_id": str(correlation_id),
    }


def prepare_recovery_probe(session: Session) -> RecoveryProbeReference:
    """Atomically create a synthetic Job, Step and pending Outbox event."""

    organization_id = uuid4()
    asset_id = uuid4()
    job_id = uuid4()
    step_id = uuid4()
    event_id = uuid4()
    correlation_id = uuid4()
    now = _now()
    idempotency_key = f"job:{job_id}:{RECOVERY_STEP_NAME}:v1"
    payload = validate_recovery_message(
        {
            "schema_version": RECOVERY_SCHEMA_VERSION,
            "task_name": RECOVERY_TASK_NAME,
            "job_id": str(job_id),
            "asset_id": str(asset_id),
            "workflow_step": RECOVERY_STEP_NAME,
            "expected_input_version": RECOVERY_INPUT_VERSION,
            "idempotency_key": idempotency_key,
            "correlation_id": str(correlation_id),
            "created_at": now.isoformat().replace("+00:00", "Z"),
        }
    )
    baseline = session.scalar(
        select(func.count()).select_from(FindingVersionRecord)
    )
    session.add(OrganizationRecord(id=organization_id))
    session.flush()
    session.add(AssetRecord(id=asset_id, organization_id=organization_id))
    session.flush()
    session.add(
        AuditJobRecord(
            id=job_id,
            organization_id=organization_id,
            asset_id=asset_id,
            evaluation_as_of=now,
        )
    )
    session.flush()
    session.add(
        WorkflowStepRecord(
            id=step_id,
            organization_id=organization_id,
            job_id=job_id,
            asset_id=asset_id,
            step_name=RECOVERY_STEP_NAME,
            status="DISPATCH_PENDING",
            expected_input_version=RECOVERY_INPUT_VERSION,
            idempotency_key=idempotency_key,
            attempt_count=0,
            created_at=now,
            updated_at=now,
        )
    )
    session.flush()
    session.add(
        OutboxEventRecord(
            id=event_id,
            organization_id=organization_id,
            job_id=job_id,
            workflow_step_id=step_id,
            event_type="workflow.step.requested",
            schema_version=RECOVERY_SCHEMA_VERSION,
            task_name=RECOVERY_TASK_NAME,
            queue_name=RECOVERY_QUEUE_NAME,
            payload=payload,
            status="PENDING",
            publish_attempts=0,
            created_at=now,
            updated_at=now,
        )
    )
    return RecoveryProbeReference(
        job_id=job_id,
        step_id=step_id,
        outbox_event_id=event_id,
        baseline_finding_count=int(baseline or 0),
    )


def pending_event_payload(
    session: Session,
    event_id: UUID,
) -> tuple[dict[str, object], str, str]:
    event = session.get(OutboxEventRecord, event_id)
    if event is None:
        raise QueueRecoveryError(
            QueueRecoveryCode.EVENT_NOT_FOUND,
            "Outbox event is unavailable.",
        )
    if event.status not in {"PENDING", "RETRY_PENDING"}:
        raise QueueRecoveryError(
            QueueRecoveryCode.EVENT_STATE_INVALID,
            "Outbox event is not pending.",
        )
    payload = validate_recovery_message(event.payload)
    return payload, event.task_name, event.queue_name


def record_event_publish_attempt(session: Session, event_id: UUID) -> None:
    result = cast(
        CursorResult[Any],
        session.execute(
            update(OutboxEventRecord)
            .where(
                OutboxEventRecord.id == event_id,
                OutboxEventRecord.status.in_(("PENDING", "RETRY_PENDING")),
            )
            .values(
                status="PENDING",
                publish_attempts=OutboxEventRecord.publish_attempts + 1,
                last_error_code=None,
                updated_at=_now(),
            )
        ),
    )
    changed = result.rowcount
    if changed != 1:
        raise QueueRecoveryError(
            QueueRecoveryCode.EVENT_STATE_INVALID,
            "Outbox event cannot start another publish attempt.",
        )


def mark_event_published(session: Session, event_id: UUID) -> None:
    now = _now()
    result = cast(
        CursorResult[Any],
        session.execute(
            update(OutboxEventRecord)
            .where(
                OutboxEventRecord.id == event_id,
                OutboxEventRecord.status.in_(("PENDING", "RETRY_PENDING")),
            )
            .values(
                status="PUBLISHED",
                published_at=now,
                last_error_code=None,
                updated_at=now,
            )
        ),
    )
    changed = result.rowcount
    if changed != 1:
        raise QueueRecoveryError(
            QueueRecoveryCode.EVENT_STATE_INVALID,
            "Outbox publish acknowledgement lost its pending event.",
        )
    event = session.get(OutboxEventRecord, event_id)
    if event is None:
        raise QueueRecoveryError(
            QueueRecoveryCode.EVENT_NOT_FOUND,
            "Outbox event disappeared after publication.",
        )
    session.execute(
        update(WorkflowStepRecord)
        .where(WorkflowStepRecord.id == event.workflow_step_id)
        .values(status="QUEUED", updated_at=now)
    )


def mark_event_retry_pending(session: Session, event_id: UUID) -> None:
    result = cast(
        CursorResult[Any],
        session.execute(
            update(OutboxEventRecord)
            .where(
                OutboxEventRecord.id == event_id,
                OutboxEventRecord.status == "PENDING",
            )
            .values(
                status="RETRY_PENDING",
                last_error_code="BROKER_PUBLISH_FAILED",
                updated_at=_now(),
            )
        ),
    )
    changed = result.rowcount
    if changed != 1:
        raise QueueRecoveryError(
            QueueRecoveryCode.EVENT_STATE_INVALID,
            "Outbox event cannot be scheduled for retry.",
        )


def begin_recovery_attempt(
    session: Session,
    *,
    event_id: UUID,
    delivery_id: UUID,
) -> RecoveryAttempt:
    """Record one delivery and reconcile an abandoned RUNNING attempt."""

    event = session.execute(
        select(OutboxEventRecord)
        .where(OutboxEventRecord.id == event_id)
        .with_for_update()
    ).scalar_one_or_none()
    if event is None:
        raise QueueRecoveryError(
            QueueRecoveryCode.EVENT_NOT_FOUND,
            "Outbox event is unavailable.",
        )
    message = validate_recovery_message(event.payload)
    step = session.execute(
        select(WorkflowStepRecord)
        .where(WorkflowStepRecord.id == event.workflow_step_id)
        .with_for_update()
    ).scalar_one_or_none()
    if step is None:
        raise QueueRecoveryError(
            QueueRecoveryCode.STEP_NOT_FOUND,
            "Workflow step is unavailable.",
        )
    if (
        str(step.job_id) != message["job_id"]
        or str(step.asset_id) != message["asset_id"]
        or step.step_name != message["workflow_step"]
        or step.expected_input_version != message["expected_input_version"]
        or step.idempotency_key != message["idempotency_key"]
    ):
        raise QueueRecoveryError(
            QueueRecoveryCode.INVALID_MESSAGE,
            "Queue message differs from PostgreSQL workflow truth.",
        )
    now = _now()
    session.execute(
        update(TaskExecutionRecord)
        .where(
            TaskExecutionRecord.workflow_step_id == step.id,
            TaskExecutionRecord.status == "RUNNING",
        )
        .values(
            status="WORKER_LOST",
            error_code="WORKER_PROCESS_LOST",
            completed_at=now,
        )
    )
    result_exists = (
        session.scalar(
            select(WorkflowResultRecord.id).where(
                WorkflowResultRecord.idempotency_key == step.idempotency_key
            )
        )
        is not None
    )
    attempt_no = step.attempt_count + 1
    execution_id = uuid4()
    execution_status = "RETURN_EXISTING" if result_exists else "RUNNING"
    session.add(
        TaskExecutionRecord(
            id=execution_id,
            organization_id=step.organization_id,
            job_id=step.job_id,
            workflow_step_id=step.id,
            delivery_id=delivery_id,
            attempt_no=attempt_no,
            status=execution_status,
            worker_pid=os.getpid(),
            started_at=now,
            completed_at=now if result_exists else None,
        )
    )
    step.attempt_count = attempt_no
    step.status = "SUCCEEDED" if result_exists else "RUNNING"
    step.last_error_code = None
    step.updated_at = now
    return RecoveryAttempt(
        execution_id=execution_id,
        attempt_no=attempt_no,
        should_hold_for_worker_loss=attempt_no == 1 and not result_exists,
        result_already_exists=result_exists,
    )


def complete_recovery_attempt(
    session: Session,
    *,
    execution_id: UUID,
) -> bool:
    """Create the logical result once, then mark the attempt successful."""

    execution = session.execute(
        select(TaskExecutionRecord)
        .where(TaskExecutionRecord.id == execution_id)
        .with_for_update()
    ).scalar_one_or_none()
    if execution is None or execution.status != "RUNNING":
        raise QueueRecoveryError(
            QueueRecoveryCode.DELIVERY_NOT_FOUND,
            "Running task execution is unavailable.",
        )
    step = session.execute(
        select(WorkflowStepRecord)
        .where(WorkflowStepRecord.id == execution.workflow_step_id)
        .with_for_update()
    ).scalar_one()
    result_payload = {
        "schema_version": "1.0",
        "job_id": str(step.job_id),
        "workflow_step": step.step_name,
        "expected_input_version": step.expected_input_version,
        "idempotency_key": step.idempotency_key,
        "result": "DELIVERY_VERIFIED",
    }
    result_sha256 = canonical_sha256(cast(dict[str, JsonValue], result_payload))
    inserted = session.execute(
        insert(WorkflowResultRecord)
        .values(
            id=uuid4(),
            organization_id=step.organization_id,
            job_id=step.job_id,
            workflow_step_id=step.id,
            idempotency_key=step.idempotency_key,
            result_sha256=result_sha256,
            created_at=_now(),
        )
        .on_conflict_do_nothing(
            constraint="uq_workflow_results_idempotency_key"
        )
        .returning(WorkflowResultRecord.id)
    ).scalar_one_or_none()
    now = _now()
    execution.status = "SUCCEEDED" if inserted is not None else "RETURN_EXISTING"
    execution.completed_at = now
    execution.worker_pid = None
    step.status = "SUCCEEDED"
    step.last_error_code = None
    step.updated_at = now
    return inserted is not None


def recovery_probe_status(
    session: Session,
    job_id: UUID,
) -> dict[str, object]:
    step = session.scalar(
        select(WorkflowStepRecord).where(
            WorkflowStepRecord.job_id == job_id,
            WorkflowStepRecord.step_name == RECOVERY_STEP_NAME,
        )
    )
    if step is None:
        raise QueueRecoveryError(
            QueueRecoveryCode.STEP_NOT_FOUND,
            "Recovery workflow is unavailable.",
        )
    event = session.scalar(
        select(OutboxEventRecord).where(
            OutboxEventRecord.workflow_step_id == step.id
        )
    )
    if event is None:
        raise QueueRecoveryError(
            QueueRecoveryCode.EVENT_NOT_FOUND,
            "Recovery Outbox event is unavailable.",
        )
    executions = list(
        session.scalars(
            select(TaskExecutionRecord)
            .where(TaskExecutionRecord.workflow_step_id == step.id)
            .order_by(TaskExecutionRecord.attempt_no)
        )
    )
    result_count = int(
        session.scalar(
            select(func.count())
            .select_from(WorkflowResultRecord)
            .where(WorkflowResultRecord.workflow_step_id == step.id)
        )
        or 0
    )
    finding_count = int(
        session.scalar(select(func.count()).select_from(FindingVersionRecord))
        or 0
    )
    active_pid = next(
        (
            execution.worker_pid
            for execution in reversed(executions)
            if execution.status == "RUNNING"
        ),
        None,
    )
    return {
        "status": step.status,
        "job_id": str(step.job_id),
        "step_id": str(step.id),
        "outbox_event_id": str(event.id),
        "outbox_status": event.status,
        "publish_attempts": event.publish_attempts,
        "attempt_count": step.attempt_count,
        "worker_lost_count": sum(
            execution.status == "WORKER_LOST" for execution in executions
        ),
        "return_existing_count": sum(
            execution.status == "RETURN_EXISTING" for execution in executions
        ),
        "result_count": result_count,
        "finding_count": finding_count,
        "active_worker_pid": active_pid,
        "settings_modified": False,
        "official_finding_created": False,
    }
