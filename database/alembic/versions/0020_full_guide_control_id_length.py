"""Expand guide control identifiers for full KISA classification names."""

from collections.abc import Sequence

from alembic import op

revision: str = "0020_guide_id_length"
down_revision: str | None = "0019_full_guide"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE guide_content.guide_chunks
        ALTER COLUMN control_id TYPE varchar(64)
        """
    )


def downgrade() -> None:
    # 전체 분류 식별자를 절단하지 않도록 비손실 길이를 유지한다.
    op.execute(
        """
        ALTER TABLE guide_content.guide_chunks
        ALTER COLUMN control_id TYPE varchar(64)
        """
    )
