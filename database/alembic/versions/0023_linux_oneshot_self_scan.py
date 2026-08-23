"""Owner-scoped Linux one-shot self-scan submissions and normalized Evidence."""

from collections.abc import Sequence

from alembic import op

revision: str = "0023_linux_oneshot"
down_revision: str | None = "0022_report_snapshots"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE linux_audit_runs
            ADD COLUMN run_mode varchar(24) NOT NULL DEFAULT 'SSH_LAB',
            ADD COLUMN manifest_id uuid NULL,
            ADD COLUMN manifest_json jsonb NULL,
            ADD COLUMN manifest_sha256 char(64) NULL,
            ADD COLUMN execution_attempt_id uuid NULL,
            ADD COLUMN package_sha256 char(64) NULL,
            ADD COLUMN submission_profile varchar(32) NULL,
            ADD COLUMN assurance_level varchar(12) NULL,
            ADD COLUMN received_at timestamptz NULL,
            ADD COLUMN deleted_at timestamptz NULL
        """
    )
    op.execute("ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_audit_asset")
    op.execute("ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_audit_status")
    op.execute(
        """
        ALTER TABLE linux_audit_runs ADD CONSTRAINT ck_linux_audit_asset
        CHECK (asset_key IN ('ubuntu24', 'rocky9', 'self-ubuntu24', 'self-rocky9'))
        """
    )
    op.execute(
        """
        ALTER TABLE linux_audit_runs ADD CONSTRAINT ck_linux_audit_status
        CHECK (status IN (
            'QUEUED', 'RUNNING', 'WAITING_UPLOAD', 'VALIDATING',
            'COMPLETED', 'FAILED', 'CANCELLED'
        ))
        """
    )
    op.execute(
        """
        ALTER TABLE linux_audit_runs ADD CONSTRAINT ck_linux_audit_run_mode
        CHECK (run_mode IN ('SSH_LAB', 'ONESHOT_SELF'))
        """
    )
    op.execute(
        """
        ALTER TABLE linux_audit_runs ADD CONSTRAINT ck_linux_oneshot_manifest
        CHECK (
            run_mode = 'SSH_LAB' OR (
                manifest_id IS NOT NULL
                AND manifest_json IS NOT NULL
                AND manifest_sha256 ~ '^[a-f0-9]{64}$'
                AND execution_attempt_id IS NOT NULL
            )
        )
        """
    )
    op.execute(
        """
        ALTER TABLE linux_audit_runs ADD CONSTRAINT ck_linux_oneshot_assurance
        CHECK (
            assurance_level IS NULL OR assurance_level IN ('LOW', 'MEDIUM')
        )
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX uq_linux_oneshot_package_sha256
        ON linux_audit_runs (organization_id, owner_user_id, package_sha256)
        WHERE run_mode = 'ONESHOT_SELF' AND package_sha256 IS NOT NULL
        """
    )
    op.execute(
        """
        CREATE TABLE linux_oneshot_submissions (
            run_id uuid PRIMARY KEY REFERENCES linux_audit_runs(id) ON DELETE RESTRICT,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            asset_id uuid NOT NULL,
            package_id uuid NOT NULL,
            manifest_id uuid NOT NULL,
            execution_attempt_id uuid NOT NULL,
            nonce varchar(128) NOT NULL,
            archive_sha256 char(64) NOT NULL,
            descriptor_sha256 char(64) NOT NULL,
            descriptor_json jsonb NOT NULL,
            submission_profile varchar(32) NOT NULL,
            assurance_level varchar(12) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT uq_linux_oneshot_nonce
                UNIQUE (organization_id, asset_id, run_id, nonce),
            CONSTRAINT ck_linux_oneshot_submission_hashes CHECK (
                archive_sha256 ~ '^[a-f0-9]{64}$'
                AND descriptor_sha256 ~ '^[a-f0-9]{64}$'
            ),
            CONSTRAINT ck_linux_oneshot_submission_profile CHECK (
                submission_profile IN ('ONLINE-AUTHENTICATED', 'OFFLINE-USER-SUBMITTED')
            ),
            CONSTRAINT ck_linux_oneshot_submission_assurance CHECK (
                assurance_level IN ('LOW', 'MEDIUM')
            )
        )
        """
    )
    op.execute(
        """
        CREATE TABLE linux_oneshot_evidence (
            evidence_id uuid PRIMARY KEY,
            run_id uuid NOT NULL REFERENCES linux_audit_runs(id) ON DELETE RESTRICT,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            probe_id varchar(128) NOT NULL,
            collection_status varchar(16) NOT NULL,
            error_code varchar(40) NOT NULL,
            raw_output_sha256 char(64) NOT NULL,
            normalized_sha256 char(64) NOT NULL,
            redaction_applied boolean NOT NULL,
            normalized_value text NOT NULL,
            collected_at timestamptz NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT uq_linux_oneshot_probe UNIQUE (run_id, probe_id),
            CONSTRAINT ck_linux_oneshot_evidence_status CHECK (
                collection_status IN ('COLLECTED', 'ERROR', 'SKIPPED')
            ),
            CONSTRAINT ck_linux_oneshot_evidence_hashes CHECK (
                raw_output_sha256 ~ '^[a-f0-9]{64}$'
                AND normalized_sha256 ~ '^[a-f0-9]{64}$'
            ),
            CONSTRAINT ck_linux_oneshot_no_error_payload CHECK (
                collection_status = 'COLLECTED' OR normalized_value = ''
            )
        )
        """
    )
    for table in ("linux_oneshot_submissions", "linux_oneshot_evidence"):
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
    op.execute("GRANT SELECT, INSERT ON linux_oneshot_submissions TO secai_runtime")
    op.execute("GRANT SELECT, INSERT ON linux_oneshot_evidence TO secai_runtime")


def downgrade() -> None:
    op.execute("DROP TABLE linux_oneshot_evidence")
    op.execute("DROP TABLE linux_oneshot_submissions")
    op.execute("DROP INDEX uq_linux_oneshot_package_sha256")
    op.execute("ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_oneshot_assurance")
    op.execute("ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_oneshot_manifest")
    op.execute("ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_audit_run_mode")
    op.execute("ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_audit_status")
    op.execute("ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_audit_asset")
    op.execute(
        """
        ALTER TABLE linux_audit_runs ADD CONSTRAINT ck_linux_audit_asset
        CHECK (asset_key IN ('ubuntu24', 'rocky9'))
        """
    )
    op.execute(
        """
        ALTER TABLE linux_audit_runs ADD CONSTRAINT ck_linux_audit_status
        CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED'))
        """
    )
    op.execute(
        """
        ALTER TABLE linux_audit_runs
            DROP COLUMN deleted_at,
            DROP COLUMN received_at,
            DROP COLUMN assurance_level,
            DROP COLUMN submission_profile,
            DROP COLUMN package_sha256,
            DROP COLUMN execution_attempt_id,
            DROP COLUMN manifest_sha256,
            DROP COLUMN manifest_json,
            DROP COLUMN manifest_id,
            DROP COLUMN run_mode
        """
    )
