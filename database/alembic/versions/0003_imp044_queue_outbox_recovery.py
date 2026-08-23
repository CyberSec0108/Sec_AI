"""Add the IMP-044 PostgreSQL queue and Outbox recovery truth."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_imp044"
down_revision: str | None = "0002_imp019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workflow_steps",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("step_name", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("expected_input_version", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column(
            "attempt_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
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
            "('DISPATCH_PENDING', 'QUEUED', 'RUNNING', 'SUCCEEDED', "
            "'FAILED', 'QUARANTINED')",
            name="ck_workflow_steps_status_allowed",
        ),
        sa.CheckConstraint(
            "expected_input_version > 0 AND attempt_count >= 0",
            name="ck_workflow_steps_version_attempt_nonnegative",
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "organization_id", "asset_id"],
            ["audit_jobs.id", "audit_jobs.organization_id", "audit_jobs.asset_id"],
            name="fk_workflow_steps_job_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_workflow_steps"),
        sa.UniqueConstraint(
            "id",
            "organization_id",
            "job_id",
            name="uq_workflow_steps_id_scope",
        ),
        sa.UniqueConstraint(
            "job_id",
            "step_name",
            "expected_input_version",
            name="uq_workflow_steps_logical_step",
        ),
        sa.UniqueConstraint(
            "idempotency_key",
            name="uq_workflow_steps_idempotency_key",
        ),
    )
    op.create_table(
        "outbox_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "workflow_step_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("task_name", sa.String(length=128), nullable=False),
        sa.Column("queue_name", sa.String(length=64), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column(
            "publish_attempts",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
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
            "status IN ('PENDING', 'PUBLISHED', 'RETRY_PENDING')",
            name="ck_outbox_events_status_allowed",
        ),
        sa.CheckConstraint(
            "publish_attempts >= 0",
            name="ck_outbox_events_publish_attempts_nonnegative",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object'",
            name="ck_outbox_events_payload_object",
        ),
        sa.ForeignKeyConstraint(
            ["workflow_step_id", "organization_id", "job_id"],
            [
                "workflow_steps.id",
                "workflow_steps.organization_id",
                "workflow_steps.job_id",
            ],
            name="fk_outbox_events_step_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_outbox_events"),
    )
    op.create_index(
        "ix_outbox_events_pending_created",
        "outbox_events",
        ["status", "created_at"],
    )
    op.create_table(
        "task_executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "workflow_step_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "delivery_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("attempt_no", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("worker_pid", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN "
            "('RUNNING', 'WORKER_LOST', 'SUCCEEDED', 'RETURN_EXISTING', "
            "'FAILED', 'QUARANTINED')",
            name="ck_task_executions_status_allowed",
        ),
        sa.CheckConstraint(
            "attempt_no > 0",
            name="ck_task_executions_attempt_positive",
        ),
        sa.ForeignKeyConstraint(
            ["workflow_step_id", "organization_id", "job_id"],
            [
                "workflow_steps.id",
                "workflow_steps.organization_id",
                "workflow_steps.job_id",
            ],
            name="fk_task_executions_step_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_task_executions"),
        sa.UniqueConstraint(
            "workflow_step_id",
            "attempt_no",
            name="uq_task_executions_step_attempt",
        ),
    )
    op.create_table(
        "workflow_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "workflow_step_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("result_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "result_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_workflow_results_sha256_format",
        ),
        sa.ForeignKeyConstraint(
            ["workflow_step_id", "organization_id", "job_id"],
            [
                "workflow_steps.id",
                "workflow_steps.organization_id",
                "workflow_steps.job_id",
            ],
            name="fk_workflow_results_step_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_workflow_results"),
        sa.UniqueConstraint(
            "idempotency_key",
            name="uq_workflow_results_idempotency_key",
        ),
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON "
        "workflow_steps, outbox_events, task_executions, workflow_results "
        "TO secai_runtime"
    )


def downgrade() -> None:
    op.execute(
        "REVOKE ALL PRIVILEGES ON "
        "workflow_steps, outbox_events, task_executions, workflow_results "
        "FROM secai_runtime"
    )
    op.drop_table("workflow_results")
    op.drop_table("task_executions")
    op.drop_index("ix_outbox_events_pending_created", table_name="outbox_events")
    op.drop_table("outbox_events")
    op.drop_table("workflow_steps")
