"""Preserve append-only report snapshots when administrator results arrive later."""

from collections.abc import Sequence

from alembic import op

revision: str = "0022_report_snapshots"
down_revision: str | None = "0021_linux_ai_v4_keys"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE result_report_snapshots
        DROP CONSTRAINT uq_result_report_snapshot_identity
        """
    )
    op.execute(
        """
        ALTER TABLE result_report_snapshots
        ADD CONSTRAINT uq_result_report_snapshot_identity
        UNIQUE (
            organization_id,
            owner_user_id,
            result_id,
            result_version,
            snapshot_sha256
        )
        """
    )


def downgrade() -> None:
    # 변형 snapshot이 있으면 UNIQUE 생성이 실패하고 트랜잭션이 롤백되어 자료를 보존합니다.
    op.execute(
        """
        ALTER TABLE result_report_snapshots
        DROP CONSTRAINT uq_result_report_snapshot_identity
        """
    )
    op.execute(
        """
        ALTER TABLE result_report_snapshots
        ADD CONSTRAINT uq_result_report_snapshot_identity
        UNIQUE (organization_id, owner_user_id, result_id, result_version)
        """
    )
