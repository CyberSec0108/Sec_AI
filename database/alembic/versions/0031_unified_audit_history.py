"""Add owner-scoped Windows snapshots and versioned audit history policy."""

from collections.abc import Sequence

from alembic import op

revision: str = "0031_unified_audit_history"
down_revision: str | None = "0030_component_vulnerability"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE audit_history_policies (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            version integer NOT NULL,
            retention_days integer NOT NULL,
            backup_required boolean NOT NULL,
            deletion_mode varchar(32) NOT NULL,
            created_by uuid NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT fk_audit_history_policy_creator
                FOREIGN KEY (created_by, organization_id)
                REFERENCES user_accounts(id, organization_id) ON DELETE RESTRICT,
            CONSTRAINT uq_audit_history_policy_version
                UNIQUE (organization_id, version),
            CONSTRAINT uq_audit_history_policy_scope
                UNIQUE (id, organization_id),
            CONSTRAINT ck_audit_history_policy_version CHECK (version > 0),
            CONSTRAINT ck_audit_history_policy_retention
                CHECK (retention_days BETWEEN 30 AND 3650),
            CONSTRAINT ck_audit_history_policy_deletion CHECK (
                deletion_mode IN ('HOLD', 'TOMBSTONE_AFTER_BACKUP')
            )
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_audit_history_policy_latest
        ON audit_history_policies (organization_id, version DESC)
        """
    )
    op.execute(
        """
        CREATE TABLE windows_audit_snapshots (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            owner_user_id uuid NOT NULL,
            asset_id uuid NOT NULL,
            retention_policy_id uuid NOT NULL,
            result_id char(16) NOT NULL,
            result_version integer NOT NULL,
            observed_at timestamptz NOT NULL,
            result_json jsonb NOT NULL,
            result_sha256 char(64) NOT NULL,
            criteria_sha256 char(64) NULL,
            total_count integer NOT NULL,
            pass_count integer NOT NULL,
            fail_count integer NOT NULL,
            error_count integer NOT NULL,
            review_count integer NOT NULL,
            not_applicable_count integer NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT fk_windows_audit_owner_scope
                FOREIGN KEY (owner_user_id, organization_id)
                REFERENCES user_accounts(id, organization_id) ON DELETE RESTRICT,
            CONSTRAINT fk_windows_audit_asset_scope
                FOREIGN KEY (asset_id, organization_id)
                REFERENCES assets(id, organization_id) ON DELETE RESTRICT,
            CONSTRAINT fk_windows_audit_policy_scope
                FOREIGN KEY (retention_policy_id, organization_id)
                REFERENCES audit_history_policies(id, organization_id) ON DELETE RESTRICT,
            CONSTRAINT uq_windows_audit_result_identity
                UNIQUE (organization_id, owner_user_id, result_id, result_version),
            CONSTRAINT ck_windows_audit_result_id
                CHECK (result_id ~ '^[a-f0-9]{16}$'),
            CONSTRAINT ck_windows_audit_result_version CHECK (result_version > 0),
            CONSTRAINT ck_windows_audit_result_hash
                CHECK (result_sha256 ~ '^[a-f0-9]{64}$'),
            CONSTRAINT ck_windows_audit_criteria_hash
                CHECK (criteria_sha256 IS NULL OR criteria_sha256 ~ '^[a-f0-9]{64}$'),
            CONSTRAINT ck_windows_audit_result_json
                CHECK (jsonb_typeof(result_json) = 'object'),
            CONSTRAINT ck_windows_audit_counts CHECK (
                total_count = pass_count + fail_count + error_count
                    + review_count + not_applicable_count
                AND total_count = 18
                AND pass_count >= 0
                AND fail_count >= 0
                AND error_count >= 0
                AND review_count >= 0
                AND not_applicable_count >= 0
            )
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_windows_audit_history_owner_time
        ON windows_audit_snapshots (
            organization_id, owner_user_id, observed_at DESC, created_at DESC
        )
        """
    )

    for table in ("audit_history_policies", "windows_audit_snapshots"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

    op.execute(
        """
        CREATE POLICY audit_history_policies_organization_scope
        ON audit_history_policies
        USING (
            organization_id = NULLIF(current_setting('secai.organization_id', true), '')::uuid
        )
        WITH CHECK (
            organization_id = NULLIF(current_setting('secai.organization_id', true), '')::uuid
            AND created_by = NULLIF(current_setting('secai.user_id', true), '')::uuid
        )
        """
    )
    op.execute(
        """
        CREATE POLICY windows_audit_snapshots_owner_scope
        ON windows_audit_snapshots
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
        CREATE FUNCTION secai_reject_audit_history_policy_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit_history_policies is append-only; % is forbidden', TG_OP;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_history_policy_reject_row_mutation
        BEFORE UPDATE OR DELETE ON audit_history_policies
        FOR EACH ROW EXECUTE FUNCTION secai_reject_audit_history_policy_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_history_policy_reject_truncate
        BEFORE TRUNCATE ON audit_history_policies
        FOR EACH STATEMENT EXECUTE FUNCTION secai_reject_audit_history_policy_mutation()
        """
    )
    op.execute(
        """
        CREATE FUNCTION secai_reject_windows_audit_snapshot_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'windows_audit_snapshots is append-only; % is forbidden', TG_OP;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_windows_audit_snapshot_reject_row_mutation
        BEFORE UPDATE OR DELETE ON windows_audit_snapshots
        FOR EACH ROW EXECUTE FUNCTION secai_reject_windows_audit_snapshot_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_windows_audit_snapshot_reject_truncate
        BEFORE TRUNCATE ON windows_audit_snapshots
        FOR EACH STATEMENT EXECUTE FUNCTION secai_reject_windows_audit_snapshot_mutation()
        """
    )

    op.execute("GRANT SELECT, INSERT ON audit_history_policies TO secai_runtime")
    op.execute("GRANT SELECT, INSERT ON windows_audit_snapshots TO secai_runtime")


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_windows_audit_snapshot_reject_truncate "
        "ON windows_audit_snapshots"
    )
    op.execute(
        "DROP TRIGGER trg_windows_audit_snapshot_reject_row_mutation "
        "ON windows_audit_snapshots"
    )
    op.execute("DROP FUNCTION secai_reject_windows_audit_snapshot_mutation()")
    op.execute(
        "DROP TRIGGER trg_audit_history_policy_reject_truncate "
        "ON audit_history_policies"
    )
    op.execute(
        "DROP TRIGGER trg_audit_history_policy_reject_row_mutation "
        "ON audit_history_policies"
    )
    op.execute("DROP FUNCTION secai_reject_audit_history_policy_mutation()")
    op.execute("DROP TABLE windows_audit_snapshots")
    op.execute("DROP TABLE audit_history_policies")

