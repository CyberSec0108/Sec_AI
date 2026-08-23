"""Add owner-scoped recent-chat management without physical deletion."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_product_ai_07"
down_revision: str | None = "0010_imp053"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCOPE_POLICY = """
    organization_id = NULLIF(
        current_setting('secai.organization_id', true), ''
    )::uuid
    AND owner_user_id = NULLIF(
        current_setting('secai.user_id', true), ''
    )::uuid
"""


def upgrade() -> None:
    op.add_column(
        "chat_threads",
        sa.Column(
            "is_pinned",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "chat_threads",
        sa.Column("folder_name", sa.String(length=80), nullable=True),
    )
    op.add_column(
        "chat_threads",
        sa.Column(
            "status_before_tombstone",
            sa.String(length=16),
            nullable=True,
        ),
    )
    op.create_check_constraint(
        "ck_chat_threads_folder_name",
        "chat_threads",
        "folder_name IS NULL OR length(btrim(folder_name)) BETWEEN 1 AND 80",
    )
    op.create_check_constraint(
        "ck_chat_threads_restore_status",
        "chat_threads",
        "("
        "status = 'TOMBSTONED' "
        "AND status_before_tombstone IN ('ACTIVE', 'ARCHIVED')"
        ") OR ("
        "status <> 'TOMBSTONED' "
        "AND status_before_tombstone IS NULL"
        ")",
    )
    op.create_index(
        "ix_chat_threads_owner_pinned_recent",
        "chat_threads",
        [
            "organization_id",
            "owner_user_id",
            "is_pinned",
            "updated_at",
        ],
    )
    op.create_index(
        "ix_chat_threads_owner_folder",
        "chat_threads",
        ["organization_id", "owner_user_id", "folder_name"],
    )
    op.execute(
        """
        CREATE TABLE chat_thread_management_events (
            id uuid PRIMARY KEY,
            thread_id uuid NOT NULL,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            action varchar(32) NOT NULL,
            before_state jsonb NOT NULL,
            after_state jsonb NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT fk_chat_thread_management_event_scope
                FOREIGN KEY (
                    thread_id, organization_id, owner_user_id
                )
                REFERENCES chat_threads (id, organization_id, owner_user_id)
                ON DELETE RESTRICT,
            CONSTRAINT ck_chat_thread_management_action
                CHECK (
                    action IN (
                        'RENAME', 'PIN', 'UNPIN', 'MOVE',
                        'ARCHIVE', 'RESTORE_ARCHIVE',
                        'TOMBSTONE', 'UNDO_TOMBSTONE'
                    )
                )
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_chat_thread_management_events_owner_time
        ON chat_thread_management_events (
            organization_id, owner_user_id, created_at DESC
        )
        """
    )
    op.execute(
        "ALTER TABLE chat_thread_management_events ENABLE ROW LEVEL SECURITY"
    )
    op.execute(
        "ALTER TABLE chat_thread_management_events FORCE ROW LEVEL SECURITY"
    )
    op.execute(
        f"""
        CREATE POLICY chat_thread_management_events_owner_scope
        ON chat_thread_management_events
        USING ({_SCOPE_POLICY})
        WITH CHECK ({_SCOPE_POLICY})
        """
    )
    op.execute(
        """
        GRANT UPDATE (
            is_pinned, folder_name, status_before_tombstone
        ) ON chat_threads TO secai_runtime
        """
    )
    op.execute(
        """
        GRANT SELECT, INSERT
        ON chat_thread_management_events TO secai_runtime
        """
    )


def downgrade() -> None:
    op.execute(
        """
        REVOKE ALL PRIVILEGES
        ON chat_thread_management_events FROM secai_runtime
        """
    )
    op.drop_table("chat_thread_management_events")
    op.drop_index("ix_chat_threads_owner_folder", table_name="chat_threads")
    op.drop_index(
        "ix_chat_threads_owner_pinned_recent",
        table_name="chat_threads",
    )
    op.drop_constraint(
        "ck_chat_threads_restore_status",
        "chat_threads",
        type_="check",
    )
    op.drop_constraint(
        "ck_chat_threads_folder_name",
        "chat_threads",
        type_="check",
    )
    op.drop_column("chat_threads", "status_before_tombstone")
    op.drop_column("chat_threads", "folder_name")
    op.drop_column("chat_threads", "is_pinned")
