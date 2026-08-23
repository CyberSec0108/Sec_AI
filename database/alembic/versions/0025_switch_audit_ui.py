"""Persist owner-scoped Aruba switch REST audit runs and events."""

from collections.abc import Sequence

from alembic import op

revision: str = "0025_switch_audit_ui"
down_revision: str | None = "0024_linux_oneshot_active"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE switch_audit_runs (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            owner_user_id uuid NOT NULL,
            asset_key varchar(64) NOT NULL,
            asset_id uuid NOT NULL,
            platform varchar(32) NOT NULL,
            platform_version varchar(32) NOT NULL,
            benchmark_id varchar(128) NOT NULL,
            status varchar(24) NOT NULL,
            result_json jsonb NULL,
            result_sha256 char(64) NULL,
            error_code varchar(128) NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            started_at timestamptz NULL,
            completed_at timestamptz NULL,
            CONSTRAINT fk_switch_audit_owner_scope
                FOREIGN KEY (owner_user_id, organization_id)
                REFERENCES user_accounts(id, organization_id) ON DELETE RESTRICT,
            CONSTRAINT ck_switch_audit_asset CHECK (
                asset_key = 'aruba-aos-cx-10.13.1170-lab'
            ),
            CONSTRAINT ck_switch_audit_platform CHECK (platform = 'ARUBA_AOS_CX'),
            CONSTRAINT ck_switch_audit_status CHECK (
                status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED')
            ),
            CONSTRAINT ck_switch_audit_result_hash CHECK (
                result_sha256 IS NULL OR result_sha256 ~ '^[a-f0-9]{64}$'
            ),
            CONSTRAINT ck_switch_audit_error_code CHECK (
                error_code IS NULL OR error_code ~ '^[A-Z0-9_]{1,128}$'
            )
        )
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX uq_switch_audit_one_active
        ON switch_audit_runs (organization_id, asset_key)
        WHERE status IN ('QUEUED', 'RUNNING')
        """
    )
    op.execute(
        """
        CREATE TABLE switch_audit_events (
            run_id uuid NOT NULL REFERENCES switch_audit_runs(id) ON DELETE RESTRICT,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            sequence integer NOT NULL,
            event_type varchar(40) NOT NULL,
            payload jsonb NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (run_id, sequence),
            CHECK (sequence > 0),
            CHECK (event_type IN ('RUN_STARTED', 'RUN_COMPLETED', 'RUN_FAILED'))
        )
        """
    )
    for table in ("switch_audit_runs", "switch_audit_events"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {table}_owner_scope ON {table}
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
    op.execute("GRANT SELECT, INSERT, UPDATE ON switch_audit_runs TO secai_runtime")
    op.execute("GRANT SELECT, INSERT ON switch_audit_events TO secai_runtime")


def downgrade() -> None:
    op.execute("DROP TABLE switch_audit_events")
    op.execute("DROP TABLE switch_audit_runs")
