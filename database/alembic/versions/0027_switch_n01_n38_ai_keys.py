"""Allow append-only V2 AI cache keys for KISA network N-01 through N-38."""

from collections.abc import Sequence

from alembic import op

revision: str = "0027_switch_n01_n38_ai_keys"
down_revision: str | None = "0026_switch_audit_ai_outputs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE switch_audit_ai_outputs
        DROP CONSTRAINT switch_audit_ai_outputs_output_key_check
        """
    )
    op.execute(
        """
        ALTER TABLE switch_audit_ai_outputs
        ADD CONSTRAINT ck_switch_audit_ai_outputs_versioned_key
        CHECK (
            output_key ~ '^(V1:(SW-0[1-6]|SUMMARY)|V2:(N-(0[1-9]|[12][0-9]|3[0-8])|SUMMARY))$'
        )
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE switch_audit_ai_outputs
        DROP CONSTRAINT ck_switch_audit_ai_outputs_versioned_key
        """
    )
    op.execute(
        """
        ALTER TABLE switch_audit_ai_outputs
        ADD CONSTRAINT switch_audit_ai_outputs_output_key_check
        CHECK (output_key ~ '^V1:(SW-0[1-6]|SUMMARY)$')
        """
    )
