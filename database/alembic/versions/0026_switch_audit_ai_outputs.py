"""Persist owner-scoped append-only Switch AI explanation outputs."""

from collections.abc import Sequence

from alembic import op

revision: str = "0026_switch_audit_ai_outputs"
down_revision: str | None = "0025_switch_audit_ui"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE switch_audit_ai_outputs (
            run_id uuid NOT NULL REFERENCES switch_audit_runs(id) ON DELETE RESTRICT,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            output_key varchar(40) NOT NULL,
            content text NOT NULL,
            content_sha256 char(64) NOT NULL,
            completed_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (run_id, output_key),
            CHECK (output_key ~ '^V1:(SW-0[1-6]|SUMMARY)$'),
            CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),
            CHECK (length(btrim(content)) > 0)
        )
        """
    )
    op.execute("ALTER TABLE switch_audit_ai_outputs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE switch_audit_ai_outputs FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY switch_audit_ai_outputs_owner_scope
        ON switch_audit_ai_outputs
        USING (
            organization_id = NULLIF(
                current_setting('secai.organization_id', true), ''
            )::uuid
            AND owner_user_id = NULLIF(
                current_setting('secai.user_id', true), ''
            )::uuid
        )
        WITH CHECK (
            organization_id = NULLIF(
                current_setting('secai.organization_id', true), ''
            )::uuid
            AND owner_user_id = NULLIF(
                current_setting('secai.user_id', true), ''
            )::uuid
        )
        """
    )
    op.execute("GRANT SELECT, INSERT ON switch_audit_ai_outputs TO secai_runtime")


def downgrade() -> None:
    op.execute("DROP TABLE switch_audit_ai_outputs")
