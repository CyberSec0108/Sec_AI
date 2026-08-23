"""Set the DEV-only pgAdmin role's default organization scope."""

from collections.abc import Sequence

from alembic import op

revision: str = "0008_imp048"
down_revision: str | None = "0007_imp048"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DEV_ORGANIZATION_ID = "46000000-0000-4000-8000-000000000001"


def upgrade() -> None:
    op.execute(
        f"""
        DO $block$
        BEGIN
            EXECUTE format(
                'ALTER ROLE secai_db_admin IN DATABASE %I '
                'SET secai.organization_id = %L',
                current_database(),
                '{_DEV_ORGANIZATION_ID}'
            );
        END
        $block$
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $block$
        BEGIN
            EXECUTE format(
                'ALTER ROLE secai_db_admin IN DATABASE %I '
                'RESET secai.organization_id',
                current_database()
            );
        END
        $block$
        """
    )
