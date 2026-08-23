"""Add IMP-045 synthetic storage recovery inventory and status truth."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_imp045"
down_revision: str | None = "0003_imp044"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "storage_recovery_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("postgres_status", sa.String(length=32), nullable=False),
        sa.Column("redis_status", sa.String(length=32), nullable=False),
        sa.Column("aistor_status", sa.String(length=32), nullable=False),
        sa.Column("postgres_rpo_seconds", sa.Integer(), nullable=True),
        sa.Column("postgres_rto_seconds", sa.Integer(), nullable=True),
        sa.Column("evidence_rpo_seconds", sa.Integer(), nullable=True),
        sa.Column("evidence_rto_seconds", sa.Integer(), nullable=True),
        sa.Column("redis_rebuild_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "finding_lineage_reproduced",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.Column(
            "object_hash_reproduced",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.Column(
            "pending_outbox_reconciled",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.Column(
            "independent_failure_domain",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.Column(
            "production_gate_complete",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN "
            "('PREPARING', 'BACKUP_CREATED', 'OUTAGE_TESTING', "
            "'RESTORE_VALIDATING', 'SUCCEEDED', 'FAILED')",
            name="ck_storage_recovery_runs_status_allowed",
        ),
        sa.CheckConstraint(
            "postgres_status IN "
            "('PENDING', 'OUTAGE_OBSERVED', 'RECOVERED', 'RESTORED', 'FAILED') "
            "AND redis_status IN "
            "('PENDING', 'OUTAGE_OBSERVED', 'REBUILT', 'FAILED') "
            "AND aistor_status IN "
            "('PENDING', 'OUTAGE_OBSERVED', 'RECOVERED', 'RESTORED', 'FAILED')",
            name="ck_storage_recovery_runs_component_status_allowed",
        ),
        sa.CheckConstraint(
            "(postgres_rpo_seconds IS NULL OR postgres_rpo_seconds >= 0) "
            "AND (postgres_rto_seconds IS NULL OR postgres_rto_seconds >= 0) "
            "AND (evidence_rpo_seconds IS NULL OR evidence_rpo_seconds >= 0) "
            "AND (evidence_rto_seconds IS NULL OR evidence_rto_seconds >= 0) "
            "AND (redis_rebuild_seconds IS NULL OR redis_rebuild_seconds >= 0)",
            name="ck_storage_recovery_runs_duration_nonnegative",
        ),
        sa.CheckConstraint(
            "production_gate_complete = false",
            name="ck_storage_recovery_runs_development_gate_only",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_storage_recovery_runs"),
    )
    op.create_table(
        "evidence_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "recovery_run_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("classification", sa.String(length=32), nullable=False),
        sa.Column("bucket_name", sa.String(length=63), nullable=False),
        sa.Column("object_key", sa.String(length=256), nullable=False),
        sa.Column("source_version_id", sa.String(length=256), nullable=False),
        sa.Column("restored_version_id", sa.String(length=256), nullable=True),
        sa.Column("object_sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("backup_status", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "classification = 'SYNTHETIC_DEV_ONLY'",
            name="ck_evidence_artifacts_synthetic_only",
        ),
        sa.CheckConstraint(
            "backup_status IN ('PENDING', 'VERIFIED', 'RESTORED', 'FAILED')",
            name="ck_evidence_artifacts_backup_status_allowed",
        ),
        sa.CheckConstraint(
            "object_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_evidence_artifacts_sha256_format",
        ),
        sa.CheckConstraint(
            "size_bytes > 0",
            name="ck_evidence_artifacts_size_positive",
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "organization_id", "asset_id"],
            ["audit_jobs.id", "audit_jobs.organization_id", "audit_jobs.asset_id"],
            name="fk_evidence_artifacts_job_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["recovery_run_id"],
            ["storage_recovery_runs.id"],
            name="fk_evidence_artifacts_recovery_run",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evidence_artifacts"),
        sa.UniqueConstraint(
            "bucket_name",
            "object_key",
            "source_version_id",
            name="uq_evidence_artifacts_object_version",
        ),
    )
    op.create_index(
        "ix_storage_recovery_runs_created_at",
        "storage_recovery_runs",
        ["created_at"],
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON "
        "storage_recovery_runs, evidence_artifacts TO secai_runtime"
    )
    op.execute("GRANT SELECT ON alembic_version TO secai_runtime")


def downgrade() -> None:
    op.execute(
        "REVOKE ALL PRIVILEGES ON "
        "storage_recovery_runs, evidence_artifacts FROM secai_runtime"
    )
    op.drop_table("evidence_artifacts")
    op.drop_index(
        "ix_storage_recovery_runs_created_at",
        table_name="storage_recovery_runs",
    )
    op.drop_table("storage_recovery_runs")
