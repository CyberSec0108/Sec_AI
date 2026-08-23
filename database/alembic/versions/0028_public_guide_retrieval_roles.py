"""Add fail-closed retrieval roles for supplemental public guides."""

from collections.abc import Sequence

from alembic import op

revision: str = "0028_public_guide_roles"
down_revision: str | None = "0027_switch_n01_n38_ai_keys"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CONTROL_PATTERN = (
    "^((PC-(0[1-9]|1[0-8]))|"
    "((U|W|WEB|S|N|C|D|M|HV|CA)-[0-9][0-9])|"
    "((UNIX|WINDOWS|WEB-SERVICE|SECURITY-EQUIPMENT|NETWORK-EQUIPMENT|"
    "CONTROL-SYSTEM|PC|DBMS|MOBILE|WEB-APP|VIRTUALIZATION|CLOUD)-INTRO)|"
    "(CI|SI|DI|EP|IL|XS|CF|SF|BF|IA|IN|PR|PV|FU|FD|IS|SN|CC|AE|AU|WM)|"
    "GUIDE-PAGE)$"
)


def _install_control_constraint() -> None:
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
        CHECK (control_id ~ '{_CONTROL_PATTERN}')
        """
    )


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE guide_content.guide_documents
        ADD COLUMN retrieval_role varchar(32) NOT NULL
            DEFAULT 'OFFICIAL_CHECK_REFERENCE',
        ADD COLUMN decision_authority boolean NOT NULL DEFAULT false,
        ADD CONSTRAINT ck_guide_documents_retrieval_role
            CHECK (
                retrieval_role IN (
                    'OFFICIAL_CHECK_REFERENCE',
                    'SUPPLEMENTAL_EXPLANATION'
                )
            ),
        ADD CONSTRAINT ck_guide_documents_no_decision_authority
            CHECK (decision_authority = false)
        """
    )
    _install_control_constraint()


def downgrade() -> None:
    # 이미 저장된 보완 문서의 계보와 판정 차단 열을 잃지 않도록 비손실 계약을 유지합니다.
    _install_control_constraint()

