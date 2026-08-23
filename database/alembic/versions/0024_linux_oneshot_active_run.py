"""Prevent duplicate active one-shot runs per owner and distribution."""

from collections.abc import Sequence

from alembic import op

revision: str = "0024_linux_oneshot_active"
down_revision: str | None = "0023_linux_oneshot"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE UNIQUE INDEX uq_linux_oneshot_one_active
        ON linux_audit_runs (organization_id, owner_user_id, asset_key)
        WHERE run_mode = 'ONESHOT_SELF'
          AND deleted_at IS NULL
          AND status IN ('WAITING_UPLOAD', 'VALIDATING')
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX uq_linux_oneshot_one_active")
