"""Add pending and rejected states for administrator-approved accounts."""

from collections.abc import Sequence

from alembic import op

revision: str = "0013_account_management"
down_revision: str | None = "0012_product_ai_08"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        "ck_user_accounts_status_allowed",
        "user_accounts",
        type_="check",
    )
    op.create_check_constraint(
        "ck_user_accounts_status_allowed",
        "user_accounts",
        "status IN ('PENDING_APPROVAL', 'ACTIVE', 'TEMP_LOCKED', 'DISABLED', 'REJECTED')",
    )


def downgrade() -> None:
    op.execute(
        "UPDATE user_accounts SET status = 'DISABLED' "
        "WHERE status IN ('PENDING_APPROVAL', 'REJECTED')"
    )
    op.drop_constraint(
        "ck_user_accounts_status_allowed",
        "user_accounts",
        type_="check",
    )
    op.create_check_constraint(
        "ck_user_accounts_status_allowed",
        "user_accounts",
        "status IN ('ACTIVE', 'TEMP_LOCKED', 'DISABLED')",
    )
