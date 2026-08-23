"""Add append-only Windows administrator and completed AI presentations."""

from collections.abc import Sequence

from alembic import op

revision: str = "0033_windows_presentations"
down_revision: str | None = "0032_linux_auto_discovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE windows_audit_snapshots
        ADD CONSTRAINT uq_windows_audit_snapshot_owner_scope
        UNIQUE (id, organization_id, owner_user_id)
        """
    )
    op.execute(
        """
        CREATE TABLE windows_audit_presentations (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            owner_user_id uuid NOT NULL,
            windows_snapshot_id uuid NOT NULL,
            presentation_kind varchar(24) NOT NULL,
            presentation_version integer NOT NULL,
            payload_json jsonb NOT NULL,
            payload_sha256 char(64) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT fk_windows_audit_presentation_owner_scope
                FOREIGN KEY (owner_user_id, organization_id)
                REFERENCES user_accounts(id, organization_id) ON DELETE RESTRICT,
            CONSTRAINT fk_windows_audit_presentation_snapshot_scope
                FOREIGN KEY (windows_snapshot_id, organization_id, owner_user_id)
                REFERENCES windows_audit_snapshots(id, organization_id, owner_user_id)
                ON DELETE RESTRICT,
            CONSTRAINT uq_windows_audit_presentation_version
                UNIQUE (windows_snapshot_id, presentation_kind, presentation_version),
            CONSTRAINT uq_windows_audit_presentation_payload
                UNIQUE (windows_snapshot_id, presentation_kind, payload_sha256),
            CONSTRAINT ck_windows_audit_presentation_kind CHECK (
                presentation_kind IN ('ADMINISTRATOR', 'AI_COMPLETED')
            ),
            CONSTRAINT ck_windows_audit_presentation_version
                CHECK (presentation_version > 0),
            CONSTRAINT ck_windows_audit_presentation_payload
                CHECK (jsonb_typeof(payload_json) = 'object'),
            CONSTRAINT ck_windows_audit_presentation_hash
                CHECK (payload_sha256 ~ '^[a-f0-9]{64}$')
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_windows_audit_presentation_owner_time
        ON windows_audit_presentations (
            organization_id, owner_user_id, created_at DESC
        )
        """
    )
    op.execute(
        """
        ALTER TABLE windows_audit_presentations ENABLE ROW LEVEL SECURITY
        """
    )
    op.execute(
        """
        ALTER TABLE windows_audit_presentations FORCE ROW LEVEL SECURITY
        """
    )
    op.execute(
        """
        CREATE POLICY windows_audit_presentations_owner_scope
        ON windows_audit_presentations
        USING (
            organization_id = NULLIF(current_setting('secai.organization_id', true), '')::uuid
            AND owner_user_id = NULLIF(current_setting('secai.user_id', true), '')::uuid
        )
        WITH CHECK (
            organization_id = NULLIF(current_setting('secai.organization_id', true), '')::uuid
            AND owner_user_id = NULLIF(current_setting('secai.user_id', true), '')::uuid
        )
        """
    )
    op.execute(
        """
        CREATE FUNCTION secai_reject_windows_audit_presentation_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'windows_audit_presentations is append-only; % is forbidden', TG_OP;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_windows_audit_presentation_reject_row_mutation
        BEFORE UPDATE OR DELETE ON windows_audit_presentations
        FOR EACH ROW EXECUTE FUNCTION secai_reject_windows_audit_presentation_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_windows_audit_presentation_reject_truncate
        BEFORE TRUNCATE ON windows_audit_presentations
        FOR EACH STATEMENT EXECUTE FUNCTION secai_reject_windows_audit_presentation_mutation()
        """
    )
    op.execute("GRANT SELECT, INSERT ON windows_audit_presentations TO secai_runtime")


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_windows_audit_presentation_reject_truncate "
        "ON windows_audit_presentations"
    )
    op.execute(
        "DROP TRIGGER trg_windows_audit_presentation_reject_row_mutation "
        "ON windows_audit_presentations"
    )
    op.execute("DROP FUNCTION secai_reject_windows_audit_presentation_mutation()")
    op.execute("DROP TABLE windows_audit_presentations")
    op.execute(
        "ALTER TABLE windows_audit_snapshots "
        "DROP CONSTRAINT uq_windows_audit_snapshot_owner_scope"
    )
