"""Add completion trace fields for the IMP-053 LIVE guide chat."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_imp053"
down_revision: str | None = "0009_imp051"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "chat_generation_runs",
        sa.Column("answer_mode", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "chat_generation_runs",
        sa.Column("model_id", sa.String(length=200), nullable=True),
    )
    op.add_column(
        "chat_generation_runs",
        sa.Column("prompt_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "chat_generation_runs",
        sa.Column("input_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "chat_generation_runs",
        sa.Column("output_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "chat_generation_runs",
        sa.Column("external_data_transfer", sa.Boolean(), nullable=True),
    )
    op.create_check_constraint(
        "ck_chat_generation_answer_mode",
        "chat_generation_runs",
        "answer_mode IS NULL OR answer_mode IN "
        "('LOCAL_GROUNDED_SUMMARY', 'LOCAL_VLLM', 'REMOTE_OPENROUTER')",
    )
    op.create_check_constraint(
        "ck_chat_generation_trace_hashes",
        "chat_generation_runs",
        "(prompt_sha256 IS NULL OR prompt_sha256 ~ '^[a-f0-9]{64}$') AND "
        "(input_sha256 IS NULL OR input_sha256 ~ '^[a-f0-9]{64}$') AND "
        "(output_sha256 IS NULL OR output_sha256 ~ '^[a-f0-9]{64}$')",
    )
    op.execute(
        """
        CREATE FUNCTION secai_require_chat_generation_trace()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NEW.status = 'COMPLETED'
               AND OLD.status IS DISTINCT FROM 'COMPLETED'
               AND (
                   NEW.answer_mode IS NULL
                   OR NEW.model_id IS NULL
                   OR NEW.prompt_sha256 IS NULL
                   OR NEW.input_sha256 IS NULL
                   OR NEW.output_sha256 IS NULL
                   OR NEW.external_data_transfer IS NULL
               )
            THEN
                RAISE EXCEPTION 'completed chat generation requires exact trace'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_chat_generation_require_trace
        BEFORE UPDATE ON chat_generation_runs
        FOR EACH ROW EXECUTE FUNCTION secai_require_chat_generation_trace()
        """
    )
    op.execute(
        """
        GRANT UPDATE (
            answer_mode, model_id, prompt_sha256, input_sha256,
            output_sha256, external_data_transfer
        )
        ON chat_generation_runs TO secai_runtime
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_chat_generation_require_trace ON chat_generation_runs"
    )
    op.execute("DROP FUNCTION secai_require_chat_generation_trace()")
    op.drop_constraint(
        "ck_chat_generation_trace_hashes",
        "chat_generation_runs",
        type_="check",
    )
    op.drop_constraint(
        "ck_chat_generation_answer_mode",
        "chat_generation_runs",
        type_="check",
    )
    op.drop_column("chat_generation_runs", "external_data_transfer")
    op.drop_column("chat_generation_runs", "output_sha256")
    op.drop_column("chat_generation_runs", "input_sha256")
    op.drop_column("chat_generation_runs", "prompt_sha256")
    op.drop_column("chat_generation_runs", "model_id")
    op.drop_column("chat_generation_runs", "answer_mode")
