"""Grant the IMP-019 runtime role only the required application DML."""

from collections.abc import Sequence

from alembic import op

revision: str = "0002_imp019"
down_revision: str | None = "0001_imp018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("REVOKE CREATE ON SCHEMA public FROM secai_runtime")
    op.execute("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM secai_runtime")
    op.execute("GRANT USAGE ON SCHEMA public TO secai_runtime")
    op.execute(
        "GRANT SELECT, INSERT ON organizations, assets, audit_jobs, finding_versions "
        "TO secai_runtime"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE ON finding_current TO secai_runtime")


def downgrade() -> None:
    op.execute("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM secai_runtime")
    op.execute("REVOKE USAGE ON SCHEMA public FROM secai_runtime")
