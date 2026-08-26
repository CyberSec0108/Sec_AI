"""Persist completed Windows AI explanations like Linux and Switch already do."""

from collections.abc import Sequence

from alembic import op

revision: str = "0036_windows_ai_outputs"
down_revision: str | None = "0035_platform_expansion"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE windows_audit_ai_outputs (
            snapshot_id uuid NOT NULL,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            output_key varchar(32) NOT NULL,
            content text NOT NULL,
            content_sha256 char(64) NOT NULL,
            completed_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (snapshot_id, output_key),
            CONSTRAINT fk_windows_ai_output_snapshot_scope
                FOREIGN KEY (snapshot_id, organization_id, owner_user_id)
                REFERENCES windows_audit_snapshots (id, organization_id, owner_user_id)
                ON DELETE RESTRICT,
            CHECK (output_key ~ '^(PC-[0-9]{2}|SUMMARY)$'),
            CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),
            CHECK (length(btrim(content)) > 0)
        )
        """
    )
    op.execute("ALTER TABLE windows_audit_ai_outputs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE windows_audit_ai_outputs FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY windows_audit_ai_outputs_owner_scope
        ON windows_audit_ai_outputs
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
        "GRANT SELECT, INSERT ON windows_audit_ai_outputs TO secai_runtime"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS windows_audit_ai_outputs")
