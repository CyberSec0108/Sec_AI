"""Append-only Linux audit runs, reconnectable events, and AI outputs."""

from collections.abc import Sequence

from alembic import op

revision: str = "0018_linux_audits"
down_revision: str | None = "0017_parallel_vectors"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE linux_audit_runs (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            owner_user_id uuid NOT NULL,
            asset_key varchar(32) NOT NULL,
            asset_id uuid NOT NULL,
            distribution varchar(32) NOT NULL,
            benchmark_id varchar(128) NOT NULL,
            status varchar(24) NOT NULL,
            result_json jsonb NULL,
            result_sha256 char(64) NULL,
            cancellation_requested boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL DEFAULT now(),
            started_at timestamptz NULL,
            completed_at timestamptz NULL,
            CONSTRAINT fk_linux_audit_owner_scope
                FOREIGN KEY (owner_user_id, organization_id)
                REFERENCES user_accounts(id, organization_id) ON DELETE RESTRICT,
            CONSTRAINT ck_linux_audit_asset CHECK (asset_key IN ('ubuntu24', 'rocky9')),
            CONSTRAINT ck_linux_audit_distribution CHECK (
                distribution IN ('UBUNTU_24_04', 'ROCKY_9')
            ),
            CONSTRAINT ck_linux_audit_status CHECK (
                status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')
            ),
            CONSTRAINT ck_linux_audit_result_hash CHECK (
                result_sha256 IS NULL OR result_sha256 ~ '^[a-f0-9]{64}$'
            )
        )
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX uq_linux_audit_one_active
        ON linux_audit_runs (organization_id, owner_user_id, asset_key)
        WHERE status IN ('QUEUED', 'RUNNING')
        """
    )
    op.execute(
        """
        CREATE TABLE linux_audit_events (
            run_id uuid NOT NULL REFERENCES linux_audit_runs(id) ON DELETE RESTRICT,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            sequence integer NOT NULL,
            event_type varchar(40) NOT NULL,
            payload jsonb NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (run_id, sequence),
            CHECK (sequence > 0)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE linux_audit_ai_outputs (
            run_id uuid NOT NULL REFERENCES linux_audit_runs(id) ON DELETE RESTRICT,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            output_key varchar(32) NOT NULL,
            content text NOT NULL,
            content_sha256 char(64) NOT NULL,
            completed_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (run_id, output_key),
            CHECK (output_key ~ '^(U-[0-9]{2}|SUMMARY)$'),
            CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),
            CHECK (length(btrim(content)) > 0)
        )
        """
    )
    for table in ("linux_audit_runs", "linux_audit_events", "linux_audit_ai_outputs"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {table}_owner_scope ON {table}
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
    op.execute("GRANT SELECT, INSERT, UPDATE ON linux_audit_runs TO secai_runtime")
    op.execute("GRANT SELECT, INSERT ON linux_audit_events TO secai_runtime")
    op.execute("GRANT SELECT, INSERT ON linux_audit_ai_outputs TO secai_runtime")


def downgrade() -> None:
    op.execute("DROP TABLE linux_audit_ai_outputs")
    op.execute("DROP TABLE linux_audit_events")
    op.execute("DROP TABLE linux_audit_runs")
