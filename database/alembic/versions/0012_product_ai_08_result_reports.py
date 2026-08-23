"""Add immutable owner-scoped result report snapshots and append-only PDFs."""

from collections.abc import Sequence

from alembic import op

revision: str = "0012_product_ai_08"
down_revision: str | None = "0011_product_ai_07"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCOPE_POLICY = """
    organization_id = NULLIF(
        current_setting('secai.organization_id', true), ''
    )::uuid
    AND owner_user_id = NULLIF(
        current_setting('secai.user_id', true), ''
    )::uuid
"""


def _enable_owner_rls(table_name: str) -> None:
    op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"""
        CREATE POLICY {table_name}_owner_scope
        ON {table_name}
        USING ({_SCOPE_POLICY})
        WITH CHECK ({_SCOPE_POLICY})
        """
    )


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE result_report_snapshots (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            asset_id uuid NOT NULL,
            result_id char(16) NOT NULL,
            result_version integer NOT NULL,
            snapshot_sha256 char(64) NOT NULL,
            snapshot_payload jsonb NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT uq_result_report_snapshot_identity
                UNIQUE (
                    organization_id, owner_user_id, result_id, result_version
                ),
            CONSTRAINT uq_result_report_snapshot_scope
                UNIQUE (id, organization_id, owner_user_id, asset_id),
            CONSTRAINT fk_result_report_snapshot_owner
                FOREIGN KEY (owner_user_id, organization_id)
                REFERENCES user_accounts (id, organization_id)
                ON DELETE RESTRICT,
            CONSTRAINT fk_result_report_snapshot_asset
                FOREIGN KEY (asset_id, organization_id)
                REFERENCES assets (id, organization_id)
                ON DELETE RESTRICT,
            CONSTRAINT ck_result_report_snapshot_identity
                CHECK (
                    result_id ~ '^[a-f0-9]{16}$'
                    AND result_version > 0
                    AND snapshot_sha256 ~ '^[a-f0-9]{64}$'
                )
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_result_report_snapshots_owner_time
        ON result_report_snapshots (
            organization_id, owner_user_id, created_at DESC
        )
        """
    )
    op.execute(
        """
        CREATE TABLE result_reports (
            id uuid PRIMARY KEY,
            snapshot_id uuid NOT NULL,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            asset_id uuid NOT NULL,
            report_kind varchar(16) NOT NULL,
            report_version integer NOT NULL,
            content_sha256 char(64) NOT NULL,
            pdf_sha256 char(64) NOT NULL,
            pdf_bytes bytea NOT NULL,
            model_manifest jsonb NOT NULL,
            generated_by uuid NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT uq_result_reports_snapshot_version
                UNIQUE (snapshot_id, report_kind, report_version),
            CONSTRAINT uq_result_reports_scope
                UNIQUE (id, organization_id, owner_user_id),
            CONSTRAINT fk_result_reports_snapshot_scope
                FOREIGN KEY (
                    snapshot_id, organization_id, owner_user_id, asset_id
                )
                REFERENCES result_report_snapshots (
                    id, organization_id, owner_user_id, asset_id
                )
                ON DELETE RESTRICT,
            CONSTRAINT fk_result_reports_generator
                FOREIGN KEY (generated_by, organization_id)
                REFERENCES user_accounts (id, organization_id)
                ON DELETE RESTRICT,
            CONSTRAINT ck_result_reports_kind
                CHECK (report_kind IN ('USER', 'TECHNICAL')),
            CONSTRAINT ck_result_reports_integrity
                CHECK (
                    report_version > 0
                    AND content_sha256 ~ '^[a-f0-9]{64}$'
                    AND pdf_sha256 ~ '^[a-f0-9]{64}$'
                    AND octet_length(pdf_bytes) BETWEEN 1 AND 10485760
                )
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_result_reports_owner_time
        ON result_reports (
            organization_id, owner_user_id, created_at DESC
        )
        """
    )
    op.execute(
        """
        CREATE TABLE result_report_access_events (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            requested_report_id uuid NULL,
            report_id uuid NULL,
            event_type varchar(40) NOT NULL,
            outcome varchar(8) NOT NULL,
            reason_code varchar(64) NOT NULL,
            event_metadata jsonb NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT fk_result_report_event_owner
                FOREIGN KEY (owner_user_id, organization_id)
                REFERENCES user_accounts (id, organization_id)
                ON DELETE RESTRICT,
            CONSTRAINT fk_result_report_event_report
                FOREIGN KEY (report_id, organization_id, owner_user_id)
                REFERENCES result_reports (id, organization_id, owner_user_id)
                ON DELETE RESTRICT,
            CONSTRAINT ck_result_report_event_type
                CHECK (
                    event_type IN (
                        'GENERATED', 'DOWNLOADED', 'MANIFEST_DOWNLOADED',
                        'GENERATE_DENIED', 'DOWNLOAD_DENIED'
                    )
                ),
            CONSTRAINT ck_result_report_event_outcome
                CHECK (outcome IN ('ALLOW', 'DENY'))
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_result_report_events_owner_time
        ON result_report_access_events (
            organization_id, owner_user_id, created_at DESC
        )
        """
    )
    for table_name in (
        "result_report_snapshots",
        "result_reports",
        "result_report_access_events",
    ):
        _enable_owner_rls(table_name)
    op.execute(
        """
        GRANT SELECT, INSERT ON
            result_report_snapshots,
            result_reports,
            result_report_access_events
        TO secai_runtime
        """
    )


def downgrade() -> None:
    op.execute(
        """
        REVOKE ALL PRIVILEGES ON
            result_report_access_events,
            result_reports,
            result_report_snapshots
        FROM secai_runtime
        """
    )
    op.drop_table("result_report_access_events")
    op.drop_table("result_reports")
    op.drop_table("result_report_snapshots")
