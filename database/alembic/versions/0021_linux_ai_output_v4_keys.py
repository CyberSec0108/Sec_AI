"""Allow the current versioned Linux AI output cache keys."""

from collections.abc import Sequence

from alembic import op

revision: str = "0021_linux_ai_v4_keys"
down_revision: str | None = "0020_guide_id_length"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CONSTRAINT = "linux_audit_ai_outputs_output_key_check"
_VERSIONED_KEY_CHECK = (
    "output_key ~ '^((U-[0-9]{2}|SUMMARY)|"
    "V4:(U-(0[1-9]|[1-5][0-9]|6[0-7])|SUMMARY))$'"
)


def _replace_output_key_check() -> None:
    op.drop_constraint(
        op.f(_CONSTRAINT),
        "linux_audit_ai_outputs",
        type_="check",
    )
    op.create_check_constraint(
        op.f(_CONSTRAINT),
        "linux_audit_ai_outputs",
        _VERSIONED_KEY_CHECK,
    )


def upgrade() -> None:
    _replace_output_key_check()


def downgrade() -> None:
    # append-only V4 결과를 삭제하지 않도록 하위 버전에서도 호환 제약을 유지합니다.
    _replace_output_key_check()
