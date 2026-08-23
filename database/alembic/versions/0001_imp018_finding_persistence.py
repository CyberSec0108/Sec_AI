"""Create the IMP-018 atomic append-only Finding persistence contract."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_imp018"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_organizations"),
    )
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_assets_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_assets"),
        sa.UniqueConstraint("id", "organization_id", name="uq_assets_id_organization"),
    )
    op.create_index("ix_assets_organization_id", "assets", ["organization_id"])
    op.create_table(
        "audit_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("evaluation_as_of", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_audit_jobs_asset_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_jobs"),
        sa.UniqueConstraint(
            "id", "organization_id", "asset_id", name="uq_audit_jobs_id_scope"
        ),
    )
    op.create_table(
        "finding_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("control_id", sa.String(length=16), nullable=False),
        sa.Column("subject_scope", sa.String(length=16), nullable=False),
        sa.Column("subject_key", sa.String(length=128), nullable=False),
        sa.Column("finding_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.Column("producer_name", sa.String(length=128), nullable=False),
        sa.Column("producer_version", sa.String(length=64), nullable=False),
        sa.Column("engine_artifact_sha256", sa.String(length=64), nullable=False),
        sa.Column("audit_pack_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("audit_pack_version", sa.String(length=64), nullable=False),
        sa.Column("audit_pack_sha256", sa.String(length=64), nullable=False),
        sa.Column("evidence_set_sha256", sa.String(length=64), nullable=False),
        sa.Column("input_sha256", sa.String(length=64), nullable=False),
        sa.Column("output_sha256", sa.String(length=64), nullable=False),
        sa.Column("finding_document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("predecessor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("change_reason", sa.String(length=32), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "finding_version > 0",
            name="ck_finding_versions_finding_version_positive",
        ),
        sa.CheckConstraint(
            "status IN ('PASS', 'FAIL', 'REVIEW', 'ERROR', 'N/A')",
            name="ck_finding_versions_status_allowed",
        ),
        sa.CheckConstraint(
            "input_sha256 ~ '^[a-f0-9]{64}$' AND output_sha256 ~ '^[a-f0-9]{64}$' "
            "AND evidence_set_sha256 ~ '^[a-f0-9]{64}$' "
            "AND audit_pack_sha256 ~ '^[a-f0-9]{64}$' "
            "AND engine_artifact_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_finding_versions_sha256_format",
        ),
        sa.CheckConstraint(
            "((predecessor_id IS NULL AND change_reason IS NULL) OR "
            "(predecessor_id IS NOT NULL AND change_reason IS NOT NULL))",
            name="ck_finding_versions_predecessor_reason",
        ),
        sa.CheckConstraint(
            "change_reason IS NULL OR change_reason IN "
            "('RECHECK', 'POLICY_UPDATED', 'PACK_UPDATED', 'ENGINE_UPDATED', 'CORRECTION')",
            name="ck_finding_versions_change_reason_allowed",
        ),
        sa.CheckConstraint(
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
            name="ck_finding_versions_document_identity",
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "organization_id", "asset_id"],
            ["audit_jobs.id", "audit_jobs.organization_id", "audit_jobs.asset_id"],
            name="fk_finding_versions_job_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["predecessor_id"],
            ["finding_versions.id"],
            name="fk_finding_versions_predecessor_id_finding_versions",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_finding_versions"),
        sa.UniqueConstraint("input_sha256", name="uq_finding_versions_input_sha256"),
        sa.UniqueConstraint(
            "job_id",
            "control_id",
            "subject_scope",
            "subject_key",
            "finding_version",
            name="uq_finding_versions_subject_version",
        ),
        sa.UniqueConstraint(
            "id",
            "organization_id",
            "job_id",
            "control_id",
            "subject_scope",
            "subject_key",
            name="uq_finding_versions_current_scope",
        ),
    )
    op.create_table(
        "finding_current",
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("control_id", sa.String(length=16), nullable=False),
        sa.Column("subject_scope", sa.String(length=16), nullable=False),
        sa.Column("subject_key", sa.String(length=128), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint("revision > 0", name="ck_finding_current_revision_positive"),
        sa.ForeignKeyConstraint(
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
            name="fk_finding_current_finding_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "organization_id",
            "job_id",
            "control_id",
            "subject_scope",
            "subject_key",
            name="pk_finding_current",
        ),
        sa.UniqueConstraint("finding_id", name="uq_finding_current_finding_id"),
    )
    op.execute(
        """
        CREATE FUNCTION secai_reject_finding_versions_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'finding_versions is append-only; % is forbidden', TG_OP
                USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_finding_versions_reject_row_mutation
        BEFORE UPDATE OR DELETE ON finding_versions
        FOR EACH ROW EXECUTE FUNCTION secai_reject_finding_versions_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_finding_versions_reject_truncate
        BEFORE TRUNCATE ON finding_versions
        FOR EACH STATEMENT EXECUTE FUNCTION secai_reject_finding_versions_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER trg_finding_versions_reject_truncate ON finding_versions")
    op.execute("DROP TRIGGER trg_finding_versions_reject_row_mutation ON finding_versions")
    op.execute("DROP FUNCTION secai_reject_finding_versions_mutation()")
    op.drop_table("finding_current")
    op.drop_table("finding_versions")
    op.drop_table("audit_jobs")
    op.drop_index("ix_assets_organization_id", table_name="assets")
    op.drop_table("assets")
    op.drop_table("organizations")
