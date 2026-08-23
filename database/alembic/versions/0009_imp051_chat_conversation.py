"""Add owner-scoped, append-only chat conversation persistence."""

from collections.abc import Sequence

from alembic import op

revision: str = "0009_imp051"
down_revision: str | None = "0008_imp048"
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


def _enable_owner_rls(table_name: str) -> None:
    op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"""
        CREATE POLICY {table_name}_owner_scope
        ON {table_name}
        USING ({_SCOPE_POLICY})
        WITH CHECK ({_SCOPE_POLICY})
        """
    )


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE user_accounts
        ADD CONSTRAINT uq_user_accounts_id_organization
        UNIQUE (id, organization_id)
        """
    )
    op.execute(
        """
        CREATE TABLE chat_threads (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            title varchar(160) NOT NULL,
            guide_id varchar(128) NOT NULL,
            guide_version varchar(64) NOT NULL,
            scope_id varchar(128) NOT NULL,
            profile varchar(16) NOT NULL,
            status varchar(16) NOT NULL,
            retention_status varchar(32) NOT NULL DEFAULT 'REVIEW_REQUIRED',
            branch_from_thread_id uuid NULL,
            branch_from_message_id uuid NULL,
            audit_trace_id uuid NOT NULL UNIQUE,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            tombstoned_at timestamptz NULL,
            CONSTRAINT uq_chat_threads_owner_scope
                UNIQUE (id, organization_id, owner_user_id),
            CONSTRAINT fk_chat_threads_owner_scope
                FOREIGN KEY (owner_user_id, organization_id)
                REFERENCES user_accounts (id, organization_id)
                ON DELETE RESTRICT,
            CONSTRAINT fk_chat_threads_branch_owner_scope
                FOREIGN KEY (
                    branch_from_thread_id, organization_id, owner_user_id
                )
                REFERENCES chat_threads (id, organization_id, owner_user_id)
                ON DELETE RESTRICT,
            CONSTRAINT ck_chat_threads_profile
                CHECK (profile IN ('FAST', 'PRECISE')),
            CONSTRAINT ck_chat_threads_status
                CHECK (status IN ('ACTIVE', 'ARCHIVED', 'TOMBSTONED')),
            CONSTRAINT ck_chat_threads_retention
                CHECK (retention_status = 'REVIEW_REQUIRED'),
            CONSTRAINT ck_chat_threads_title
                CHECK (length(btrim(title)) BETWEEN 1 AND 160),
            CONSTRAINT ck_chat_threads_tombstone
                CHECK (
                    (status = 'TOMBSTONED') = (tombstoned_at IS NOT NULL)
                )
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_chat_threads_owner_recent
        ON chat_threads (organization_id, owner_user_id, updated_at DESC)
        """
    )
    op.execute(
        """
        CREATE TABLE chat_messages (
            id uuid PRIMARY KEY,
            thread_id uuid NOT NULL,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            branch_id uuid NOT NULL,
            role varchar(16) NOT NULL,
            status varchar(16) NOT NULL,
            revision integer NOT NULL,
            parent_message_id uuid NULL,
            edit_of_message_id uuid NULL,
            retry_of_message_id uuid NULL,
            request_idempotency_key varchar(128) NULL,
            content text NOT NULL,
            content_sha256 char(64) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT uq_chat_messages_thread_identity
                UNIQUE (id, thread_id),
            CONSTRAINT uq_chat_messages_request
                UNIQUE (thread_id, request_idempotency_key),
            CONSTRAINT fk_chat_messages_thread_scope
                FOREIGN KEY (
                    thread_id, organization_id, owner_user_id
                )
                REFERENCES chat_threads (id, organization_id, owner_user_id)
                ON DELETE RESTRICT,
            CONSTRAINT fk_chat_messages_parent_same_thread
                FOREIGN KEY (parent_message_id, thread_id)
                REFERENCES chat_messages (id, thread_id)
                ON DELETE RESTRICT,
            CONSTRAINT fk_chat_messages_edit_same_thread
                FOREIGN KEY (edit_of_message_id, thread_id)
                REFERENCES chat_messages (id, thread_id)
                ON DELETE RESTRICT,
            CONSTRAINT fk_chat_messages_retry_same_thread
                FOREIGN KEY (retry_of_message_id, thread_id)
                REFERENCES chat_messages (id, thread_id)
                ON DELETE RESTRICT,
            CONSTRAINT ck_chat_messages_role
                CHECK (role IN ('USER', 'ASSISTANT')),
            CONSTRAINT ck_chat_messages_status
                CHECK (
                    status IN (
                        'PENDING', 'COMPLETED', 'STOPPED',
                        'FAILED', 'SUPERSEDED'
                    )
                ),
            CONSTRAINT ck_chat_messages_revision
                CHECK (revision > 0),
            CONSTRAINT ck_chat_messages_content_size
                CHECK (
                    length(content) <= 24000
                    AND (
                        status IN ('PENDING', 'STOPPED', 'FAILED')
                        OR length(btrim(content)) > 0
                    )
                ),
            CONSTRAINT ck_chat_messages_content_hash
                CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),
            CONSTRAINT ck_chat_messages_request_idempotency
                CHECK (
                    request_idempotency_key IS NULL
                    OR request_idempotency_key
                        ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$'
                )
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_chat_messages_thread_history
        ON chat_messages (thread_id, created_at, id)
        """
    )
    op.execute(
        """
        ALTER TABLE chat_threads
        ADD CONSTRAINT fk_chat_threads_branch_message
        FOREIGN KEY (branch_from_message_id)
        REFERENCES chat_messages (id)
        ON DELETE RESTRICT
        """
    )
    op.execute(
        """
        CREATE TABLE chat_generation_runs (
            id uuid PRIMARY KEY,
            thread_id uuid NOT NULL,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            user_message_id uuid NOT NULL,
            response_message_id uuid NULL,
            retry_of_message_id uuid NULL,
            idempotency_key varchar(128) NOT NULL,
            status varchar(16) NOT NULL,
            error_code varchar(64) NULL,
            model_profile varchar(16) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            started_at timestamptz NULL,
            stop_requested_at timestamptz NULL,
            completed_at timestamptz NULL,
            CONSTRAINT uq_chat_generation_request
                UNIQUE (thread_id, idempotency_key),
            CONSTRAINT uq_chat_generation_response
                UNIQUE (response_message_id),
            CONSTRAINT fk_chat_generation_thread_scope
                FOREIGN KEY (
                    thread_id, organization_id, owner_user_id
                )
                REFERENCES chat_threads (id, organization_id, owner_user_id)
                ON DELETE RESTRICT,
            CONSTRAINT fk_chat_generation_user_message
                FOREIGN KEY (user_message_id, thread_id)
                REFERENCES chat_messages (id, thread_id)
                ON DELETE RESTRICT,
            CONSTRAINT fk_chat_generation_response_message
                FOREIGN KEY (response_message_id, thread_id)
                REFERENCES chat_messages (id, thread_id)
                ON DELETE RESTRICT,
            CONSTRAINT fk_chat_generation_retry_message
                FOREIGN KEY (retry_of_message_id, thread_id)
                REFERENCES chat_messages (id, thread_id)
                ON DELETE RESTRICT,
            CONSTRAINT ck_chat_generation_status
                CHECK (
                    status IN (
                        'QUEUED', 'STREAMING', 'COMPLETED', 'STOPPED', 'FAILED'
                    )
                ),
            CONSTRAINT ck_chat_generation_profile
                CHECK (model_profile IN ('FAST', 'PRECISE')),
            CONSTRAINT ck_chat_generation_idempotency
                CHECK (
                    idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$'
                ),
            CONSTRAINT ck_chat_generation_terminal_time
                CHECK (
                    (status IN ('COMPLETED', 'STOPPED', 'FAILED'))
                    = (completed_at IS NOT NULL)
                )
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_chat_generation_thread_status
        ON chat_generation_runs (thread_id, status, created_at)
        """
    )
    op.execute(
        """
        CREATE TABLE chat_citations (
            id uuid PRIMARY KEY,
            message_id uuid NOT NULL,
            thread_id uuid NOT NULL,
            organization_id uuid NOT NULL,
            owner_user_id uuid NOT NULL,
            ordinal integer NOT NULL,
            guide_id varchar(128) NOT NULL,
            guide_version varchar(64) NOT NULL,
            scope_id varchar(128) NOT NULL,
            chunk_id uuid NOT NULL,
            pdf_page_number integer NOT NULL,
            section_label varchar(256) NOT NULL,
            paragraph_ordinal integer NOT NULL,
            paragraph_sha256 char(64) NOT NULL,
            text_start integer NOT NULL,
            text_end integer NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT uq_chat_citations_message_ordinal
                UNIQUE (message_id, ordinal),
            CONSTRAINT fk_chat_citations_message
                FOREIGN KEY (message_id, thread_id)
                REFERENCES chat_messages (id, thread_id)
                ON DELETE RESTRICT,
            CONSTRAINT fk_chat_citations_thread_scope
                FOREIGN KEY (
                    thread_id, organization_id, owner_user_id
                )
                REFERENCES chat_threads (id, organization_id, owner_user_id)
                ON DELETE RESTRICT,
            CONSTRAINT fk_chat_citations_chunk
                FOREIGN KEY (chunk_id)
                REFERENCES guide_content.guide_chunks (chunk_id)
                ON DELETE RESTRICT,
            CONSTRAINT ck_chat_citations_location
                CHECK (
                    ordinal > 0
                    AND pdf_page_number > 0
                    AND paragraph_ordinal > 0
                    AND text_start >= 0
                    AND text_end > text_start
                ),
            CONSTRAINT ck_chat_citations_hash
                CHECK (paragraph_sha256 ~ '^[a-f0-9]{64}$')
        )
        """
    )

    for table_name in (
        "chat_threads",
        "chat_messages",
        "chat_generation_runs",
        "chat_citations",
    ):
        _enable_owner_rls(table_name)

    op.execute(
        """
        GRANT SELECT, INSERT ON
            chat_threads, chat_messages, chat_generation_runs, chat_citations
        TO secai_runtime
        """
    )
    op.execute(
        """
        GRANT UPDATE (title, status, updated_at, tombstoned_at)
        ON chat_threads TO secai_runtime
        """
    )
    op.execute(
        """
        GRANT UPDATE (status)
        ON chat_messages TO secai_runtime
        """
    )
    op.execute(
        """
        GRANT UPDATE (
            response_message_id, status, error_code, started_at,
            stop_requested_at, completed_at
        )
        ON chat_generation_runs TO secai_runtime
        """
    )


def downgrade() -> None:
    op.execute(
        """
        REVOKE ALL PRIVILEGES ON
            chat_threads, chat_messages, chat_generation_runs, chat_citations
        FROM secai_runtime
        """
    )
    op.drop_table("chat_citations")
    op.drop_table("chat_generation_runs")
    op.drop_constraint(
        "fk_chat_threads_branch_message",
        "chat_threads",
        type_="foreignkey",
    )
    op.drop_table("chat_messages")
    op.drop_table("chat_threads")
    op.drop_constraint(
        "uq_user_accounts_id_organization",
        "user_accounts",
        type_="unique",
    )
