"""Minimal Stage F PostgreSQL models for append-only Finding persistence."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Shared metadata for the first PostgreSQL migration."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class OrganizationRecord(Base):
    __tablename__ = "organizations"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class AssetRecord(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_assets_id_organization"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class AuditJobRecord(Base):
    __tablename__ = "audit_jobs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            ondelete="RESTRICT",
            name="fk_audit_jobs_asset_scope",
        ),
        UniqueConstraint(
            "id",
            "organization_id",
            "asset_id",
            name="uq_audit_jobs_id_scope",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    evaluation_as_of: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class WorkflowStepRecord(Base):
    __tablename__ = "workflow_steps"
    __table_args__ = (
        ForeignKeyConstraint(
            ["job_id", "organization_id", "asset_id"],
            ["audit_jobs.id", "audit_jobs.organization_id", "audit_jobs.asset_id"],
            ondelete="RESTRICT",
            name="fk_workflow_steps_job_scope",
        ),
        UniqueConstraint(
            "id",
            "organization_id",
            "job_id",
            name="uq_workflow_steps_id_scope",
        ),
        UniqueConstraint(
            "job_id",
            "step_name",
            "expected_input_version",
            name="uq_workflow_steps_logical_step",
        ),
        UniqueConstraint(
            "idempotency_key",
            name="uq_workflow_steps_idempotency_key",
        ),
        CheckConstraint(
            "status IN "
            "('DISPATCH_PENDING', 'QUEUED', 'RUNNING', 'SUCCEEDED', "
            "'FAILED', 'QUARANTINED')",
            name="status_allowed",
        ),
        CheckConstraint(
            "expected_input_version > 0 AND attempt_count >= 0",
            name="version_attempt_nonnegative",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    job_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    step_name: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    expected_input_version: Mapped[int] = mapped_column(Integer, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default="0",
    )
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class OutboxEventRecord(Base):
    __tablename__ = "outbox_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["workflow_step_id", "organization_id", "job_id"],
            [
                "workflow_steps.id",
                "workflow_steps.organization_id",
                "workflow_steps.job_id",
            ],
            ondelete="RESTRICT",
            name="fk_outbox_events_step_scope",
        ),
        CheckConstraint(
            "status IN ('PENDING', 'PUBLISHED', 'RETRY_PENDING')",
            name="status_allowed",
        ),
        CheckConstraint(
            "publish_attempts >= 0",
            name="publish_attempts_nonnegative",
        ),
        CheckConstraint(
            "jsonb_typeof(payload) = 'object'",
            name="payload_object",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    job_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    workflow_step_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False)
    task_name: Mapped[str] = mapped_column(String(128), nullable=False)
    queue_name: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    publish_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default="0",
    )
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class TaskExecutionRecord(Base):
    __tablename__ = "task_executions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["workflow_step_id", "organization_id", "job_id"],
            [
                "workflow_steps.id",
                "workflow_steps.organization_id",
                "workflow_steps.job_id",
            ],
            ondelete="RESTRICT",
            name="fk_task_executions_step_scope",
        ),
        UniqueConstraint(
            "workflow_step_id",
            "attempt_no",
            name="uq_task_executions_step_attempt",
        ),
        CheckConstraint(
            "status IN "
            "('RUNNING', 'WORKER_LOST', 'SUCCEEDED', 'RETURN_EXISTING', "
            "'FAILED', 'QUARANTINED')",
            name="status_allowed",
        ),
        CheckConstraint("attempt_no > 0", name="attempt_positive"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    job_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    workflow_step_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
    )
    delivery_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
    )
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    worker_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class WorkflowResultRecord(Base):
    __tablename__ = "workflow_results"
    __table_args__ = (
        ForeignKeyConstraint(
            ["workflow_step_id", "organization_id", "job_id"],
            [
                "workflow_steps.id",
                "workflow_steps.organization_id",
                "workflow_steps.job_id",
            ],
            ondelete="RESTRICT",
            name="fk_workflow_results_step_scope",
        ),
        UniqueConstraint(
            "idempotency_key",
            name="uq_workflow_results_idempotency_key",
        ),
        CheckConstraint(
            "result_sha256 ~ '^[a-f0-9]{64}$'",
            name="sha256_format",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    job_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    workflow_step_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
    )
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    result_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class StorageRecoveryRunRecord(Base):
    __tablename__ = "storage_recovery_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN "
            "('PREPARING', 'BACKUP_CREATED', 'OUTAGE_TESTING', "
            "'RESTORE_VALIDATING', 'SUCCEEDED', 'FAILED')",
            name="status_allowed",
        ),
        CheckConstraint(
            "postgres_status IN "
            "('PENDING', 'OUTAGE_OBSERVED', 'RECOVERED', 'RESTORED', 'FAILED') "
            "AND redis_status IN "
            "('PENDING', 'OUTAGE_OBSERVED', 'REBUILT', 'FAILED') "
            "AND aistor_status IN "
            "('PENDING', 'OUTAGE_OBSERVED', 'RECOVERED', 'RESTORED', 'FAILED')",
            name="component_status_allowed",
        ),
        CheckConstraint(
            "(postgres_rpo_seconds IS NULL OR postgres_rpo_seconds >= 0) "
            "AND (postgres_rto_seconds IS NULL OR postgres_rto_seconds >= 0) "
            "AND (evidence_rpo_seconds IS NULL OR evidence_rpo_seconds >= 0) "
            "AND (evidence_rto_seconds IS NULL OR evidence_rto_seconds >= 0) "
            "AND (redis_rebuild_seconds IS NULL OR redis_rebuild_seconds >= 0)",
            name="duration_nonnegative",
        ),
        CheckConstraint(
            "production_gate_complete = false",
            name="development_gate_only",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    postgres_status: Mapped[str] = mapped_column(String(32), nullable=False)
    redis_status: Mapped[str] = mapped_column(String(32), nullable=False)
    aistor_status: Mapped[str] = mapped_column(String(32), nullable=False)
    postgres_rpo_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    postgres_rto_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence_rpo_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence_rto_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    redis_rebuild_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    finding_lineage_reproduced: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="false",
    )
    object_hash_reproduced: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="false",
    )
    pending_outbox_reconciled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="false",
    )
    independent_failure_domain: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="false",
    )
    production_gate_complete: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="false",
    )
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class EvidenceArtifactRecord(Base):
    __tablename__ = "evidence_artifacts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["job_id", "organization_id", "asset_id"],
            ["audit_jobs.id", "audit_jobs.organization_id", "audit_jobs.asset_id"],
            ondelete="RESTRICT",
            name="fk_evidence_artifacts_job_scope",
        ),
        ForeignKeyConstraint(
            ["recovery_run_id"],
            ["storage_recovery_runs.id"],
            ondelete="RESTRICT",
            name="fk_evidence_artifacts_recovery_run",
        ),
        UniqueConstraint(
            "bucket_name",
            "object_key",
            "source_version_id",
            name="uq_evidence_artifacts_object_version",
        ),
        CheckConstraint(
            "classification = 'SYNTHETIC_DEV_ONLY'",
            name="synthetic_only",
        ),
        CheckConstraint(
            "backup_status IN ('PENDING', 'VERIFIED', 'RESTORED', 'FAILED')",
            name="backup_status_allowed",
        ),
        CheckConstraint(
            "object_sha256 ~ '^[a-f0-9]{64}$'",
            name="sha256_format",
        ),
        CheckConstraint("size_bytes > 0", name="size_positive"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    recovery_run_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=False,
    )
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    job_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    classification: Mapped[str] = mapped_column(String(32), nullable=False)
    bucket_name: Mapped[str] = mapped_column(String(63), nullable=False)
    object_key: Mapped[str] = mapped_column(String(256), nullable=False)
    source_version_id: Mapped[str] = mapped_column(String(256), nullable=False)
    restored_version_id: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
    )
    object_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    backup_status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class FindingVersionRecord(Base):
    __tablename__ = "finding_versions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["job_id", "organization_id", "asset_id"],
            ["audit_jobs.id", "audit_jobs.organization_id", "audit_jobs.asset_id"],
            ondelete="RESTRICT",
            name="fk_finding_versions_job_scope",
        ),
        UniqueConstraint(
            "input_sha256",
            name="uq_finding_versions_input_sha256",
        ),
        UniqueConstraint(
            "job_id",
            "control_id",
            "subject_scope",
            "subject_key",
            "finding_version",
            name="uq_finding_versions_subject_version",
        ),
        UniqueConstraint(
            "id",
            "organization_id",
            "job_id",
            "control_id",
            "subject_scope",
            "subject_key",
            name="uq_finding_versions_current_scope",
        ),
        CheckConstraint(
            "finding_version > 0",
            name="finding_version_positive",
        ),
        CheckConstraint(
            "status IN ('PASS', 'FAIL', 'REVIEW', 'ERROR', 'N/A')",
            name="status_allowed",
        ),
        CheckConstraint(
            "input_sha256 ~ '^[a-f0-9]{64}$' "
            "AND output_sha256 ~ '^[a-f0-9]{64}$' "
            "AND evidence_set_sha256 ~ '^[a-f0-9]{64}$' "
            "AND audit_pack_sha256 ~ '^[a-f0-9]{64}$' "
            "AND engine_artifact_sha256 ~ '^[a-f0-9]{64}$'",
            name="sha256_format",
        ),
        CheckConstraint(
            "((predecessor_id IS NULL AND change_reason IS NULL) OR "
            "(predecessor_id IS NOT NULL AND change_reason IS NOT NULL))",
            name="predecessor_reason",
        ),
        CheckConstraint(
            "change_reason IS NULL OR change_reason IN "
            "('RECHECK', 'POLICY_UPDATED', 'PACK_UPDATED', 'ENGINE_UPDATED', 'CORRECTION')",
            name="change_reason_allowed",
        ),
        CheckConstraint(
            "finding_document ->> 'id' = id::text "
            "AND finding_document ->> 'job_id' = job_id::text "
            "AND finding_document ->> 'asset_id' = asset_id::text "
            "AND finding_document ->> 'control_id' = control_id "
            "AND finding_document ->> 'status' = status "
            "AND finding_document #>> '{rule_result,input_sha256}' = input_sha256 "
            "AND finding_document #>> '{rule_result,output_sha256}' = output_sha256 "
            "AND finding_document ->> 'evidence_set_sha256' = evidence_set_sha256 "
            "AND finding_document #>> '{audit_pack,id}' = audit_pack_id::text "
            "AND finding_document #>> '{audit_pack,version}' = audit_pack_version "
            "AND finding_document #>> '{audit_pack,sha256}' = audit_pack_sha256",
            name="document_identity",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    job_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    control_id: Mapped[str] = mapped_column(String(16), nullable=False)
    subject_scope: Mapped[str] = mapped_column(String(16), nullable=False)
    subject_key: Mapped[str] = mapped_column(String(128), nullable=False)
    finding_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    producer_name: Mapped[str] = mapped_column(String(128), nullable=False)
    producer_version: Mapped[str] = mapped_column(String(64), nullable=False)
    engine_artifact_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    audit_pack_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    audit_pack_version: Mapped[str] = mapped_column(String(64), nullable=False)
    audit_pack_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_set_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    output_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    finding_document: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    predecessor_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("finding_versions.id", ondelete="RESTRICT"),
        nullable=True,
    )
    change_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FindingCurrentRecord(Base):
    __tablename__ = "finding_current"
    __table_args__ = (
        ForeignKeyConstraint(
            [
                "finding_id",
                "organization_id",
                "job_id",
                "control_id",
                "subject_scope",
                "subject_key",
            ],
            [
                "finding_versions.id",
                "finding_versions.organization_id",
                "finding_versions.job_id",
                "finding_versions.control_id",
                "finding_versions.subject_scope",
                "finding_versions.subject_key",
            ],
            ondelete="RESTRICT",
            name="fk_finding_current_finding_scope",
        ),
        CheckConstraint("revision > 0", name="revision_positive"),
    )

    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    job_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    control_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    subject_scope: Mapped[str] = mapped_column(String(16), primary_key=True)
    subject_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    finding_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, unique=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class UserAccountRecord(Base):
    """Named local account; credentials are never shared with service identities."""

    __tablename__ = "user_accounts"
    __table_args__ = (
        UniqueConstraint(
            "id",
            "organization_id",
            name="uq_user_accounts_id_organization",
        ),
        CheckConstraint(
            "status IN ('PENDING_APPROVAL', 'ACTIVE', 'TEMP_LOCKED', "
            "'DISABLED', 'REJECTED')",
            name="status_allowed",
        ),
        CheckConstraint(
            "credential_version > 0 AND role_assignment_version > 0 "
            "AND failed_attempts >= 0",
            name="versions_attempts_valid",
        ),
        CheckConstraint(
            "(mfa_code_hash IS NULL AND mfa_issued_at IS NULL AND "
            "mfa_expires_at IS NULL) OR (length(mfa_code_hash) = 64 AND "
            "mfa_issued_at IS NOT NULL AND mfa_expires_at > mfa_issued_at)",
            name="mfa_code_valid",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    username_canonical: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        unique=True,
    )
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    credential_version: Mapped[int] = mapped_column(Integer, nullable=False)
    role_assignment_version: Mapped[int] = mapped_column(Integer, nullable=False)
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    failed_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default="0",
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    mfa_code_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_issued_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    mfa_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class AssessmentCriteriaProfileRecord(Base):
    """사용자·조직이 발행한 append-only 점검 기준 버전입니다."""

    __tablename__ = "assessment_criteria_profiles"
    __table_args__ = (
        ForeignKeyConstraint(
            ["owner_user_id", "organization_id"],
            ["user_accounts.id", "user_accounts.organization_id"],
            ondelete="RESTRICT",
            name="fk_assessment_criteria_profile_owner_scope",
        ),
        ForeignKeyConstraint(
            ["created_by", "organization_id"],
            ["user_accounts.id", "user_accounts.organization_id"],
            ondelete="RESTRICT",
            name="fk_assessment_criteria_profile_creator_scope",
        ),
        CheckConstraint(
            "scope IN ('ORGANIZATION', 'PERSONAL')",
            name="scope_allowed",
        ),
        CheckConstraint(
            "(scope = 'ORGANIZATION' AND owner_user_id IS NULL) OR "
            "(scope = 'PERSONAL' AND owner_user_id IS NOT NULL)",
            name="owner_matches_scope",
        ),
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint(
            "document_sha256 ~ '^[a-f0-9]{64}$'",
            name="document_sha256_valid",
        ),
        UniqueConstraint(
            "id",
            "organization_id",
            "owner_user_id",
            name="uq_criteria_profile_selection_scope",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    owner_user_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    criteria_document: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    document_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    change_reason: Mapped[str] = mapped_column(String(256), nullable=False)
    created_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class AssessmentCriteriaSelectionRecord(Base):
    """사용자가 실제 점검에 선택한 기준의 append-only 이력입니다."""

    __tablename__ = "assessment_criteria_selections"
    __table_args__ = (
        ForeignKeyConstraint(
            ["user_id", "organization_id"],
            ["user_accounts.id", "user_accounts.organization_id"],
            ondelete="RESTRICT",
            name="fk_criteria_selection_user_scope",
        ),
        ForeignKeyConstraint(
            ["personal_profile_id", "organization_id", "user_id"],
            [
                "assessment_criteria_profiles.id",
                "assessment_criteria_profiles.organization_id",
                "assessment_criteria_profiles.owner_user_id",
            ],
            ondelete="RESTRICT",
            name="fk_criteria_selection_profile_scope",
        ),
        CheckConstraint(
            "selection_kind IN ('KISA_DEFAULT', 'ORGANIZATION', 'PERSONAL')",
            name="selection_kind_allowed",
        ),
        CheckConstraint(
            "(selection_kind IN ('KISA_DEFAULT', 'ORGANIZATION') "
            "AND personal_profile_id IS NULL) OR "
            "(selection_kind = 'PERSONAL' AND personal_profile_id IS NOT NULL)",
            name="profile_matches_kind",
        ),
        CheckConstraint(
            "criteria_sha256 ~ '^[a-f0-9]{64}$'",
            name="criteria_sha256_valid",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    selection_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    personal_profile_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
    )
    criteria_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    selected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    source: Mapped[str] = mapped_column(String(32), nullable=False)


class UserRoleAssignmentRecord(Base):
    __tablename__ = "user_role_assignments"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "role_name",
            "organization_id",
            name="uq_user_role_assignments_active_scope",
        ),
        CheckConstraint(
            "role_name IN ('USER', 'SECURITY_OFFICER', 'APPROVER', 'ADMIN')",
            name="role_allowed",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("user_accounts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    role_name: Mapped[str] = mapped_column(String(32), nullable=False)
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class UserAssetAssignmentRecord(Base):
    __tablename__ = "user_asset_assignments"
    __table_args__ = (
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            ondelete="RESTRICT",
            name="fk_user_asset_assignments_asset_scope",
        ),
        UniqueConstraint(
            "user_id",
            "asset_id",
            name="uq_user_asset_assignments_user_asset",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("user_accounts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class BrowserSessionRecord(Base):
    __tablename__ = "browser_sessions"
    __table_args__ = (
        CheckConstraint(
            "phase IN ('PRE_AUTH', 'MFA_PENDING', 'AUTHENTICATED')",
            name="phase_allowed",
        ),
        CheckConstraint(
            "length(session_id_hash) = 64 AND length(csrf_token_hash) = 64",
            name="hash_lengths",
        ),
        CheckConstraint(
            "mfa_attempts >= 0 AND credential_version >= 0 "
            "AND role_assignment_version >= 0",
            name="counters_valid",
        ),
    )

    session_id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("user_accounts.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    active_organization_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=True,
    )
    phase: Mapped[str] = mapped_column(String(24), nullable=False)
    credential_version: Mapped[int] = mapped_column(Integer, nullable=False)
    role_assignment_version: Mapped[int] = mapped_column(Integer, nullable=False)
    auth_methods: Mapped[str] = mapped_column(String(128), nullable=False)
    csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    mfa_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default="0",
    )
    authenticated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    reauthenticated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idle_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoke_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AuthenticationAuditEventRecord(Base):
    __tablename__ = "authentication_audit_events"
    __table_args__ = (
        CheckConstraint(
            "outcome IN ('ALLOW', 'DENY')",
            name="outcome_allowed",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    user_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("user_accounts.id", ondelete="RESTRICT"),
        nullable=True,
    )
    organization_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(8), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    session_reference: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class ChatThreadRecord(Base):
    """Owner-scoped conversation root; physical deletion is not granted."""

    __tablename__ = "chat_threads"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    owner_user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    guide_id: Mapped[str] = mapped_column(String(128), nullable=False)
    guide_version: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(128), nullable=False)
    profile: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    retention_status: Mapped[str] = mapped_column(String(32), nullable=False)
    is_pinned: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="false",
    )
    folder_name: Mapped[str | None] = mapped_column(String(80), nullable=True)
    status_before_tombstone: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
    )
    branch_from_thread_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), nullable=True
    )
    branch_from_message_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), nullable=True
    )
    audit_trace_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), nullable=False, unique=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    tombstoned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ChatThreadManagementEventRecord(Base):
    """Append-only audit record for recent-chat management actions."""

    __tablename__ = "chat_thread_management_events"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    thread_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    owner_user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    before_state: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    after_state: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class ChatMessageRecord(Base):
    """Append-only message body with mutable lifecycle status only."""

    __tablename__ = "chat_messages"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    thread_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    owner_user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    branch_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    parent_message_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), nullable=True
    )
    edit_of_message_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), nullable=True
    )
    retry_of_message_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), nullable=True
    )
    request_idempotency_key: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ChatGenerationRunRecord(Base):
    """Durable generation attempt metadata; stream deltas stay ephemeral."""

    __tablename__ = "chat_generation_runs"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    thread_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    owner_user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    user_message_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    response_message_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), nullable=True, unique=True
    )
    retry_of_message_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), nullable=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model_profile: Mapped[str] = mapped_column(String(16), nullable=False)
    answer_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    model_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    prompt_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    input_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    output_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    external_data_transfer: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    stop_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ChatCitationRecord(Base):
    """Exact immutable answer-to-guide location."""

    __tablename__ = "chat_citations"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    message_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    thread_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    owner_user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    guide_id: Mapped[str] = mapped_column(String(128), nullable=False)
    guide_version: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(128), nullable=False)
    chunk_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    pdf_page_number: Mapped[int] = mapped_column(Integer, nullable=False)
    section_label: Mapped[str] = mapped_column(String(256), nullable=False)
    paragraph_ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    paragraph_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    text_start: Mapped[int] = mapped_column(Integer, nullable=False)
    text_end: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ResultReportSnapshotRecord(Base):
    """Immutable browser result snapshot bound to its owner and assigned asset."""

    __tablename__ = "result_report_snapshots"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    owner_user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    result_id: Mapped[str] = mapped_column(String(16), nullable=False)
    result_version: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_payload: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ResultReportRecord(Base):
    """Append-only PDF artifact; regeneration always creates a new version."""

    __tablename__ = "result_reports"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    snapshot_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    owner_user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    report_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    report_version: Mapped[int] = mapped_column(Integer, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    pdf_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    pdf_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    model_manifest: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    generated_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ResultReportAccessEventRecord(Base):
    """Append-only allow/deny audit event for report generation and download."""

    __tablename__ = "result_report_access_events"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    owner_user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    requested_report_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), nullable=True
    )
    report_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    outcome: Mapped[str] = mapped_column(String(8), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    event_metadata: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AuditHistoryPolicyRecord(Base):
    """조직별 보존·백업·삭제 방식을 새 version으로만 추가하는 정책입니다."""

    __tablename__ = "audit_history_policies"
    __table_args__ = (
        ForeignKeyConstraint(
            ["created_by", "organization_id"],
            ["user_accounts.id", "user_accounts.organization_id"],
            ondelete="RESTRICT",
            name="fk_audit_history_policy_creator",
        ),
        UniqueConstraint(
            "organization_id",
            "version",
            name="uq_audit_history_policy_version",
        ),
        UniqueConstraint("id", "organization_id", name="uq_audit_history_policy_scope"),
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint(
            "retention_days BETWEEN 30 AND 3650",
            name="retention_range",
        ),
        CheckConstraint(
            "deletion_mode IN ('HOLD', 'TOMBSTONE_AFTER_BACKUP')",
            name="deletion_mode_allowed",
        ),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    backup_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    deletion_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    created_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class WindowsAuditSnapshotRecord(Base):
    """Windows Launcher의 비식별 결과를 소유자 범위로 보존하는 불변 snapshot입니다."""

    __tablename__ = "windows_audit_snapshots"
    __table_args__ = (
        ForeignKeyConstraint(
            ["owner_user_id", "organization_id"],
            ["user_accounts.id", "user_accounts.organization_id"],
            ondelete="RESTRICT",
            name="fk_windows_audit_owner_scope",
        ),
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            ondelete="RESTRICT",
            name="fk_windows_audit_asset_scope",
        ),
        ForeignKeyConstraint(
            ["retention_policy_id", "organization_id"],
            ["audit_history_policies.id", "audit_history_policies.organization_id"],
            ondelete="RESTRICT",
            name="fk_windows_audit_policy_scope",
        ),
        UniqueConstraint(
            "organization_id",
            "owner_user_id",
            "result_id",
            "result_version",
            name="uq_windows_audit_result_identity",
        ),
        UniqueConstraint(
            "id",
            "organization_id",
            "owner_user_id",
            name="uq_windows_audit_snapshot_owner_scope",
        ),
        CheckConstraint("result_version > 0", name="result_version_positive"),
        CheckConstraint("total_count = 18", name="control_count"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    owner_user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    asset_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    retention_policy_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), nullable=False
    )
    result_id: Mapped[str] = mapped_column(String(16), nullable=False)
    result_version: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    result_json: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    result_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    criteria_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    total_count: Mapped[int] = mapped_column(Integer, nullable=False)
    pass_count: Mapped[int] = mapped_column(Integer, nullable=False)
    fail_count: Mapped[int] = mapped_column(Integer, nullable=False)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False)
    review_count: Mapped[int] = mapped_column(Integer, nullable=False)
    not_applicable_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class WindowsAuditPresentationRecord(Base):
    """Windows 관리자 결과와 AI 완성 화면의 append-only version입니다."""

    __tablename__ = "windows_audit_presentations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["owner_user_id", "organization_id"],
            ["user_accounts.id", "user_accounts.organization_id"],
            ondelete="RESTRICT",
            name="fk_windows_audit_presentation_owner_scope",
        ),
        ForeignKeyConstraint(
            ["windows_snapshot_id", "organization_id", "owner_user_id"],
            [
                "windows_audit_snapshots.id",
                "windows_audit_snapshots.organization_id",
                "windows_audit_snapshots.owner_user_id",
            ],
            ondelete="RESTRICT",
            name="fk_windows_audit_presentation_snapshot_scope",
        ),
        UniqueConstraint(
            "windows_snapshot_id",
            "presentation_kind",
            "presentation_version",
            name="uq_windows_audit_presentation_version",
        ),
        UniqueConstraint(
            "windows_snapshot_id",
            "presentation_kind",
            "payload_sha256",
            name="uq_windows_audit_presentation_payload",
        ),
        CheckConstraint(
            "presentation_kind IN ('ADMINISTRATOR', 'AI_COMPLETED')",
            name="presentation_kind_allowed",
        ),
        CheckConstraint("presentation_version > 0", name="presentation_version_positive"),
    )

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    owner_user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    windows_snapshot_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), nullable=False
    )
    presentation_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    presentation_version: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_json: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
