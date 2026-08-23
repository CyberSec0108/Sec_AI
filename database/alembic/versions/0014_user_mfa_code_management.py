"""Add administrator-managed per-user MFA verification codes."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_user_mfa_codes"
down_revision: str | None = "0013_account_management"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "user_accounts",
        sa.Column("mfa_code_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "user_accounts",
        sa.Column("mfa_issued_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "user_accounts",
        sa.Column("mfa_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        "ck_user_accounts_mfa_code_valid",
        "user_accounts",
        "(mfa_code_hash IS NULL AND mfa_issued_at IS NULL AND mfa_expires_at IS NULL) "
        "OR (length(mfa_code_hash) = 64 AND mfa_issued_at IS NOT NULL "
        "AND mfa_expires_at > mfa_issued_at)",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_user_accounts_mfa_code_valid",
        "user_accounts",
        type_="check",
    )
    op.drop_column("user_accounts", "mfa_expires_at")
    op.drop_column("user_accounts", "mfa_issued_at")
    op.drop_column("user_accounts", "mfa_code_hash")
