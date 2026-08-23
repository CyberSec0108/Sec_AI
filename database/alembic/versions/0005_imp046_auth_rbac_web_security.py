"""Add IMP-046 local authentication, RBAC scope and server sessions."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_imp046"
down_revision: str | None = "0004_imp045"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "user_accounts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("username_canonical", sa.String(length=128), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("credential_version", sa.Integer(), nullable=False),
        sa.Column("role_assignment_version", sa.Integer(), nullable=False),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'TEMP_LOCKED', 'DISABLED')",
            name="ck_user_accounts_status_allowed",
        ),
        sa.CheckConstraint(
            "credential_version > 0 AND role_assignment_version > 0 "
            "AND failed_attempts >= 0",
            name="ck_user_accounts_versions_attempts_valid",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_user_accounts_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_accounts"),
        sa.UniqueConstraint(
            "username_canonical",
            name="uq_user_accounts_username_canonical",
        ),
    )
    op.create_index(
        "ix_user_accounts_organization_id",
        "user_accounts",
        ["organization_id"],
    )
    op.create_table(
        "user_role_assignments",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_name", sa.String(length=32), nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "role_name IN ('USER', 'SECURITY_OFFICER', 'APPROVER', 'ADMIN')",
            name="ck_user_role_assignments_role_allowed",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_user_role_assignments_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user_accounts.id"],
            name="fk_user_role_assignments_user_id_user_accounts",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_role_assignments"),
        sa.UniqueConstraint(
            "user_id",
            "role_name",
            "organization_id",
            name="uq_user_role_assignments_active_scope",
        ),
    )
    op.create_index(
        "ix_user_role_assignments_user_id",
        "user_role_assignments",
        ["user_id"],
    )
    op.create_table(
        "user_asset_assignments",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_user_asset_assignments_asset_scope",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user_accounts.id"],
            name="fk_user_asset_assignments_user_id_user_accounts",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_asset_assignments"),
        sa.UniqueConstraint(
            "user_id",
            "asset_id",
            name="uq_user_asset_assignments_user_asset",
        ),
    )
    op.create_index(
        "ix_user_asset_assignments_user_id",
        "user_asset_assignments",
        ["user_id"],
    )
    op.create_table(
        "browser_sessions",
        sa.Column("session_id_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "active_organization_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("phase", sa.String(length=24), nullable=False),
        sa.Column("credential_version", sa.Integer(), nullable=False),
        sa.Column("role_assignment_version", sa.Integer(), nullable=False),
        sa.Column("auth_methods", sa.String(length=128), nullable=False),
        sa.Column("csrf_token_hash", sa.String(length=64), nullable=False),
        sa.Column("mfa_attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reauthenticated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "phase IN ('PRE_AUTH', 'MFA_PENDING', 'AUTHENTICATED')",
            name="ck_browser_sessions_phase_allowed",
        ),
        sa.CheckConstraint(
            "length(session_id_hash) = 64 AND length(csrf_token_hash) = 64",
            name="ck_browser_sessions_hash_lengths",
        ),
        sa.CheckConstraint(
            "mfa_attempts >= 0 AND credential_version >= 0 "
            "AND role_assignment_version >= 0",
            name="ck_browser_sessions_counters_valid",
        ),
        sa.ForeignKeyConstraint(
            ["active_organization_id"],
            ["organizations.id"],
            name="fk_browser_sessions_active_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user_accounts.id"],
            name="fk_browser_sessions_user_id_user_accounts",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "session_id_hash",
            name="pk_browser_sessions",
        ),
    )
    op.create_index(
        "ix_browser_sessions_user_id",
        "browser_sessions",
        ["user_id"],
    )
    op.create_table(
        "authentication_audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=8), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("session_reference", sa.String(length=16), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "outcome IN ('ALLOW', 'DENY')",
            name="ck_authentication_audit_events_outcome_allowed",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_authentication_audit_events_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user_accounts.id"],
            name="fk_authentication_audit_events_user_id_user_accounts",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_authentication_audit_events"),
    )
    op.create_index(
        "ix_authentication_audit_events_created_at",
        "authentication_audit_events",
        ["created_at"],
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON "
        "user_accounts, user_role_assignments, user_asset_assignments, "
        "browser_sessions TO secai_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT ON authentication_audit_events TO secai_runtime"
    )
    op.execute("GRANT SELECT ON alembic_version TO secai_runtime")


def downgrade() -> None:
    op.execute(
        "REVOKE ALL PRIVILEGES ON "
        "user_accounts, user_role_assignments, user_asset_assignments, "
        "browser_sessions, authentication_audit_events FROM secai_runtime"
    )
    op.drop_index(
        "ix_authentication_audit_events_created_at",
        table_name="authentication_audit_events",
    )
    op.drop_table("authentication_audit_events")
    op.drop_index("ix_browser_sessions_user_id", table_name="browser_sessions")
    op.drop_table("browser_sessions")
    op.drop_index(
        "ix_user_asset_assignments_user_id",
        table_name="user_asset_assignments",
    )
    op.drop_table("user_asset_assignments")
    op.drop_index(
        "ix_user_role_assignments_user_id",
        table_name="user_role_assignments",
    )
    op.drop_table("user_role_assignments")
    op.drop_index("ix_user_accounts_organization_id", table_name="user_accounts")
    op.drop_table("user_accounts")
