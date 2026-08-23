"""Add append-only organization and personal assessment criteria profiles."""

from collections.abc import Sequence

from alembic import op

revision: str = "0015_criteria_profiles"
down_revision: str | None = "0014_user_mfa_codes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE assessment_criteria_profiles (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL,
            owner_user_id uuid NULL,
            scope varchar(16) NOT NULL,
            name varchar(80) NOT NULL,
            version integer NOT NULL,
            criteria_document jsonb NOT NULL,
            document_sha256 char(64) NOT NULL,
            change_reason varchar(256) NOT NULL,
            created_by uuid NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT fk_assessment_criteria_profile_organization
                FOREIGN KEY (organization_id)
                REFERENCES organizations (id) ON DELETE RESTRICT,
            CONSTRAINT fk_assessment_criteria_profile_owner_scope
                FOREIGN KEY (owner_user_id, organization_id)
                REFERENCES user_accounts (id, organization_id) ON DELETE RESTRICT,
            CONSTRAINT fk_assessment_criteria_profile_creator_scope
                FOREIGN KEY (created_by, organization_id)
                REFERENCES user_accounts (id, organization_id) ON DELETE RESTRICT,
            CONSTRAINT ck_assessment_criteria_profiles_scope_allowed
                CHECK (scope IN ('ORGANIZATION', 'PERSONAL')),
            CONSTRAINT ck_assessment_criteria_profiles_owner_matches_scope
                CHECK (
                    (scope = 'ORGANIZATION' AND owner_user_id IS NULL)
                    OR (scope = 'PERSONAL' AND owner_user_id IS NOT NULL)
                ),
            CONSTRAINT ck_assessment_criteria_profiles_version_positive
                CHECK (version > 0),
            CONSTRAINT ck_assessment_criteria_profiles_document_sha256_valid
                CHECK (document_sha256 ~ '^[a-f0-9]{64}$')
        )
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX uq_assessment_criteria_org_version
        ON assessment_criteria_profiles (organization_id, name, version)
        WHERE scope = 'ORGANIZATION'
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX uq_assessment_criteria_personal_version
        ON assessment_criteria_profiles (
            organization_id, owner_user_id, name, version
        )
        WHERE scope = 'PERSONAL'
        """
    )
    op.execute(
        """
        CREATE INDEX ix_assessment_criteria_scope_time
        ON assessment_criteria_profiles (
            organization_id, owner_user_id, scope, created_at DESC
        )
        """
    )
    op.execute("ALTER TABLE assessment_criteria_profiles ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE assessment_criteria_profiles FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY assessment_criteria_profiles_read_scope
        ON assessment_criteria_profiles FOR SELECT
        USING (
            organization_id = NULLIF(
                current_setting('secai.organization_id', true), ''
            )::uuid
            AND (
                scope = 'ORGANIZATION'
                OR owner_user_id = NULLIF(
                    current_setting('secai.user_id', true), ''
                )::uuid
            )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY assessment_criteria_profiles_insert_scope
        ON assessment_criteria_profiles FOR INSERT
        WITH CHECK (
            organization_id = NULLIF(
                current_setting('secai.organization_id', true), ''
            )::uuid
            AND created_by = NULLIF(
                current_setting('secai.user_id', true), ''
            )::uuid
            AND (
                (
                    scope = 'PERSONAL'
                    AND owner_user_id = NULLIF(
                        current_setting('secai.user_id', true), ''
                    )::uuid
                )
                OR (
                    scope = 'ORGANIZATION'
                    AND owner_user_id IS NULL
                    AND current_setting('secai.is_administrator', true) = 'true'
                )
            )
        )
        """
    )
    op.execute(
        """
        GRANT SELECT, INSERT ON assessment_criteria_profiles TO secai_runtime
        """
    )


def downgrade() -> None:
    op.execute(
        "REVOKE ALL PRIVILEGES ON assessment_criteria_profiles FROM secai_runtime"
    )
    op.drop_table("assessment_criteria_profiles")
