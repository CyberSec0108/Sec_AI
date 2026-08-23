"""Allow every approved KISA 2026 classification control code."""

from collections.abc import Sequence

from alembic import op

revision: str = "0019_full_guide"
down_revision: str | None = "0018_linux_audits"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FULL_CONTROL_PATTERN = (
    "^((PC-(0[1-9]|1[0-8]))|"
    "((U|W|WEB|S|N|C|D|M|HV|CA)-[0-9][0-9])|"
    "((UNIX|WINDOWS|WEB-SERVICE|SECURITY-EQUIPMENT|NETWORK-EQUIPMENT|"
    "CONTROL-SYSTEM|PC|DBMS|MOBILE|WEB-APP|VIRTUALIZATION|CLOUD)-INTRO)|"
    "(CI|SI|DI|EP|IL|XS|CF|SF|BF|IA|IN|PR|PV|FU|FD|IS|SN|CC|AE|AU|WM))$"
)


def _install_full_constraint() -> None:
    op.execute(
        """
        ALTER TABLE guide_content.guide_chunks
        DROP CONSTRAINT IF EXISTS ck_guide_chunks_control_id
        """
    )
    op.execute(
        f"""
        ALTER TABLE guide_content.guide_chunks
        ADD CONSTRAINT ck_guide_chunks_control_id
        CHECK (control_id ~ '{_FULL_CONTROL_PATTERN}')
        """
    )


def upgrade() -> None:
    _install_full_constraint()


def downgrade() -> None:
    # 전체 분류 원문을 삭제하지 않고 되돌릴 수 있도록 데이터 호환 제약은 유지한다.
    _install_full_constraint()
