"""PostgreSQL truth and hash-only inventories for IMP-045 recovery."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from security_audit.common.canonical_json import JsonValue, canonical_sha256

from .models import (
    AssetRecord,
    AuditJobRecord,
    EvidenceArtifactRecord,
    FindingVersionRecord,
    OrganizationRecord,
    StorageRecoveryRunRecord,
)


@dataclass(frozen=True, slots=True)
class StorageRecoveryReference:
    run_id: UUID
    organization_id: UUID
    asset_id: UUID
    job_id: UUID


def _now() -> datetime:
    return datetime.now(UTC)


def prepare_storage_recovery_run(session: Session) -> StorageRecoveryReference:
    """Create a synthetic-only recovery scope in dependency order."""

    run_id = uuid4()
    organization_id = uuid4()
    asset_id = uuid4()
    job_id = uuid4()
    now = _now()
    session.add(
        StorageRecoveryRunRecord(
            id=run_id,
            status="PREPARING",
            postgres_status="PENDING",
            redis_status="PENDING",
            aistor_status="PENDING",
            finding_lineage_reproduced=False,
            object_hash_reproduced=False,
            pending_outbox_reconciled=False,
            independent_failure_domain=False,
            production_gate_complete=False,
            started_at=now,
            created_at=now,
            updated_at=now,
        )
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
    return StorageRecoveryReference(
        run_id=run_id,
        organization_id=organization_id,
        asset_id=asset_id,
        job_id=job_id,
    )


def add_synthetic_artifact(
    session: Session,
    reference: StorageRecoveryReference,
    *,
    artifact_id: UUID,
    bucket_name: str,
    object_key: str,
    source_version_id: str,
    object_sha256: str,
    size_bytes: int,
) -> None:
    session.add(
        EvidenceArtifactRecord(
            id=artifact_id,
            recovery_run_id=reference.run_id,
            organization_id=reference.organization_id,
            job_id=reference.job_id,
            asset_id=reference.asset_id,
            classification="SYNTHETIC_DEV_ONLY",
            bucket_name=bucket_name,
            object_key=object_key,
            source_version_id=source_version_id,
            object_sha256=object_sha256,
            size_bytes=size_bytes,
            backup_status="VERIFIED",
        )
    )


def _count(session: Session, model: type[object]) -> int:
    value = session.scalar(select(func.count()).select_from(model))
    return int(value or 0)


def database_inventory(session: Session) -> dict[str, JsonValue]:
    """Return counts and canonical lineage hashes without evidence bodies."""

    finding_rows = session.execute(
        select(
            FindingVersionRecord.id,
            FindingVersionRecord.job_id,
            FindingVersionRecord.control_id,
            FindingVersionRecord.subject_scope,
            FindingVersionRecord.subject_key,
            FindingVersionRecord.finding_version,
            FindingVersionRecord.input_sha256,
            FindingVersionRecord.output_sha256,
            FindingVersionRecord.evidence_set_sha256,
            FindingVersionRecord.predecessor_id,
            FindingVersionRecord.change_reason,
        ).order_by(FindingVersionRecord.id)
    ).all()
    finding_lineage: list[JsonValue] = [
        {
            "id": str(row.id),
            "job_id": str(row.job_id),
            "control_id": row.control_id,
            "subject_scope": row.subject_scope,
            "subject_key": row.subject_key,
            "finding_version": row.finding_version,
            "input_sha256": row.input_sha256,
            "output_sha256": row.output_sha256,
            "evidence_set_sha256": row.evidence_set_sha256,
            "predecessor_id": (
                str(row.predecessor_id) if row.predecessor_id is not None else None
            ),
            "change_reason": row.change_reason,
        }
        for row in finding_rows
    ]
    artifact_rows = session.execute(
        select(
            EvidenceArtifactRecord.id,
            EvidenceArtifactRecord.recovery_run_id,
            EvidenceArtifactRecord.job_id,
            EvidenceArtifactRecord.bucket_name,
            EvidenceArtifactRecord.object_key,
            EvidenceArtifactRecord.source_version_id,
            EvidenceArtifactRecord.object_sha256,
            EvidenceArtifactRecord.size_bytes,
        ).order_by(EvidenceArtifactRecord.id)
    ).all()
    artifact_inventory: list[JsonValue] = [
        {
            "id": str(row.id),
            "recovery_run_id": str(row.recovery_run_id),
            "job_id": str(row.job_id),
            "bucket_name": row.bucket_name,
            "object_key": row.object_key,
            "source_version_id": row.source_version_id,
            "object_sha256": row.object_sha256,
            "size_bytes": row.size_bytes,
        }
        for row in artifact_rows
    ]
    return {
        "organization_count": _count(session, OrganizationRecord),
        "asset_count": _count(session, AssetRecord),
        "audit_job_count": _count(session, AuditJobRecord),
        "finding_count": len(finding_rows),
        "finding_lineage_sha256": canonical_sha256(finding_lineage),
        "artifact_count": len(artifact_rows),
        "artifact_inventory_sha256": canonical_sha256(artifact_inventory),
    }


def alembic_version(session: Session) -> str:
    value = session.scalar(text("SELECT version_num FROM alembic_version"))
    if not isinstance(value, str):
        raise RuntimeError("Database migration version is unavailable.")
    return value


def get_recovery_run(session: Session, run_id: UUID) -> StorageRecoveryRunRecord:
    record = session.get(StorageRecoveryRunRecord, run_id)
    if record is None:
        raise RuntimeError("Storage recovery run is unavailable.")
    return record


def mark_component(
    session: Session,
    run_id: UUID,
    *,
    component: str,
    status: str,
    seconds: int | None = None,
) -> None:
    record = get_recovery_run(session, run_id)
    allowed = {
        "postgres": {"OUTAGE_OBSERVED", "RECOVERED", "RESTORED", "FAILED"},
        "redis": {"OUTAGE_OBSERVED", "REBUILT", "FAILED"},
        "aistor": {"OUTAGE_OBSERVED", "RECOVERED", "RESTORED", "FAILED"},
    }
    if component not in allowed or status not in allowed[component]:
        raise ValueError("Storage recovery component transition is invalid.")
    setattr(record, f"{component}_status", status)
    if seconds is not None:
        duration_field = {
            "postgres": "postgres_rto_seconds",
            "redis": "redis_rebuild_seconds",
            "aistor": "evidence_rto_seconds",
        }[component]
        setattr(record, duration_field, seconds)
    if status == "OUTAGE_OBSERVED":
        record.status = "OUTAGE_TESTING"
    elif status in {"RESTORED", "REBUILT"}:
        record.status = "RESTORE_VALIDATING"
    elif status == "FAILED":
        record.status = "FAILED"
    record.updated_at = _now()


def mark_backup_created(
    session: Session,
    run_id: UUID,
    *,
    evidence_rpo_seconds: int,
) -> None:
    record = get_recovery_run(session, run_id)
    record.status = "BACKUP_CREATED"
    record.evidence_rpo_seconds = evidence_rpo_seconds
    record.updated_at = _now()


def mark_artifact_restored(
    session: Session,
    run_id: UUID,
    *,
    restored_version_id: str,
) -> None:
    artifact = session.scalar(
        select(EvidenceArtifactRecord).where(
            EvidenceArtifactRecord.recovery_run_id == run_id
        )
    )
    if artifact is None:
        raise RuntimeError("Synthetic recovery artifact is unavailable.")
    artifact.restored_version_id = restored_version_id
    artifact.backup_status = "RESTORED"


def complete_recovery_run(
    session: Session,
    run_id: UUID,
    *,
    postgres_rpo_seconds: int,
    postgres_rto_seconds: int,
    evidence_rpo_seconds: int,
    evidence_rto_seconds: int,
    redis_rebuild_seconds: int,
) -> None:
    measured_seconds = {
        "PostgreSQL RPO": (postgres_rpo_seconds, 900),
        "PostgreSQL RTO": (postgres_rto_seconds, 14_400),
        "evidence RPO": (evidence_rpo_seconds, 3_600),
        "evidence RTO": (evidence_rto_seconds, 28_800),
    }
    for metric, (measured, target) in measured_seconds.items():
        if measured < 0 or measured > target:
            raise RuntimeError(f"{metric} target was not met.")
    if redis_rebuild_seconds < 0:
        raise RuntimeError("Redis rebuild duration is invalid.")

    record = get_recovery_run(session, run_id)
    required = (
        record.postgres_status == "RESTORED",
        record.redis_status == "REBUILT",
        record.aistor_status == "RESTORED",
    )
    if not all(required):
        raise RuntimeError("Storage recovery components have not converged.")
    record.status = "SUCCEEDED"
    record.postgres_rpo_seconds = postgres_rpo_seconds
    record.postgres_rto_seconds = postgres_rto_seconds
    record.evidence_rpo_seconds = evidence_rpo_seconds
    record.evidence_rto_seconds = evidence_rto_seconds
    record.redis_rebuild_seconds = redis_rebuild_seconds
    record.finding_lineage_reproduced = True
    record.object_hash_reproduced = True
    record.pending_outbox_reconciled = True
    record.independent_failure_domain = False
    record.production_gate_complete = False
    record.last_error_code = None
    record.completed_at = _now()
    record.updated_at = record.completed_at


def public_run_values(record: StorageRecoveryRunRecord) -> dict[str, object]:
    return {
        "status": record.status,
        "postgres_status": record.postgres_status,
        "redis_status": record.redis_status,
        "aistor_status": record.aistor_status,
        "postgres_rpo_seconds": record.postgres_rpo_seconds,
        "postgres_rto_seconds": record.postgres_rto_seconds,
        "evidence_rpo_seconds": record.evidence_rpo_seconds,
        "evidence_rto_seconds": record.evidence_rto_seconds,
        "redis_rebuild_seconds": record.redis_rebuild_seconds,
        "finding_lineage_reproduced": record.finding_lineage_reproduced,
        "object_hash_reproduced": record.object_hash_reproduced,
        "pending_outbox_reconciled": record.pending_outbox_reconciled,
        "independent_failure_domain": record.independent_failure_domain,
        "production_gate_complete": record.production_gate_complete,
    }
