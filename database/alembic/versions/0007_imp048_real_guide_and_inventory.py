"""Allow PC section intro pages and expose a safe guide inventory function."""

from collections.abc import Sequence

from alembic import op

revision: str = "0007_imp048"
down_revision: str | None = "0006_imp048"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE guide_content.guide_documents
        DROP CONSTRAINT ck_guide_documents_classification
        """
    )
    op.execute(
        """
        ALTER TABLE guide_content.guide_documents
        ADD CONSTRAINT ck_guide_documents_classification
        CHECK (
            classification IN (
                'PUBLIC_GUIDE',
                'PUBLIC_SOURCE_INTERNAL_APPROVED',
                'SYNTHETIC_DEV_ONLY'
            )
        )
        """
    )
    op.execute(
        """
        ALTER TABLE guide_content.guide_chunks
        DROP CONSTRAINT ck_guide_chunks_control_id
        """
    )
    op.execute(
        """
        ALTER TABLE guide_content.guide_chunks
        ADD CONSTRAINT ck_guide_chunks_control_id
        CHECK (control_id ~ '^(PC-(0[1-9]|1[0-8])|PC-INTRO)$')
        """
    )
    op.execute(
        """
        CREATE FUNCTION vector_store.guide_store_inventory(
            p_organization_id uuid,
            p_guide_id text,
            p_guide_version text,
            p_scope_id text
        )
        RETURNS TABLE (
            postgresql_version text,
            pgvector_version text,
            document_count bigint,
            chunk_count bigint,
            embedding_count bigint,
            active_generation_count bigint,
            generation_status text,
            embedding_model_id text,
            embedding_dimension integer,
            metric_type text
        )
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, guide_content, vector_store
        AS $function$
            SELECT
                current_setting('server_version')::text,
                COALESCE(
                    (SELECT extversion::text FROM pg_extension WHERE extname = 'vector'),
                    'NOT_INSTALLED'
                ),
                (
                    SELECT count(*)
                    FROM guide_content.guide_documents AS document
                    WHERE document.organization_id = p_organization_id
                      AND document.guide_id = p_guide_id
                      AND document.guide_version = p_guide_version
                      AND document.scope_id = p_scope_id
                ),
                (
                    SELECT count(*)
                    FROM guide_content.guide_chunks AS chunk
                    WHERE chunk.organization_id = p_organization_id
                      AND chunk.guide_id = p_guide_id
                      AND chunk.guide_version = p_guide_version
                      AND chunk.scope_id = p_scope_id
                      AND chunk.status = 'READY'
                ),
                (
                    SELECT count(*)
                    FROM vector_store.guide_embeddings AS embedding_row
                    JOIN guide_content.guide_chunks AS chunk
                      ON chunk.chunk_id = embedding_row.chunk_id
                    WHERE embedding_row.organization_id = p_organization_id
                      AND chunk.guide_id = p_guide_id
                      AND chunk.guide_version = p_guide_version
                      AND chunk.scope_id = p_scope_id
                      AND embedding_row.status = 'READY'
                ),
                (
                    SELECT count(*)
                    FROM vector_store.guide_active_generations AS active
                    WHERE active.organization_id = p_organization_id
                      AND active.guide_id = p_guide_id
                      AND active.guide_version = p_guide_version
                      AND active.scope_id = p_scope_id
                ),
                COALESCE(
                    (
                        SELECT generation.status::text
                        FROM vector_store.guide_active_generations AS active
                        JOIN vector_store.guide_vector_generations AS generation
                          ON generation.id = active.vector_generation_id
                        WHERE active.organization_id = p_organization_id
                          AND active.guide_id = p_guide_id
                          AND active.guide_version = p_guide_version
                          AND active.scope_id = p_scope_id
                        LIMIT 1
                    ),
                    'NONE'
                ),
                COALESCE(
                    (
                        SELECT generation.embedding_model_id::text
                        FROM vector_store.guide_active_generations AS active
                        JOIN vector_store.guide_vector_generations AS generation
                          ON generation.id = active.vector_generation_id
                        WHERE active.organization_id = p_organization_id
                          AND active.guide_id = p_guide_id
                          AND active.guide_version = p_guide_version
                          AND active.scope_id = p_scope_id
                        LIMIT 1
                    ),
                    'NONE'
                ),
                COALESCE(
                    (
                        SELECT generation.embedding_dimension
                        FROM vector_store.guide_active_generations AS active
                        JOIN vector_store.guide_vector_generations AS generation
                          ON generation.id = active.vector_generation_id
                        WHERE active.organization_id = p_organization_id
                          AND active.guide_id = p_guide_id
                          AND active.guide_version = p_guide_version
                          AND active.scope_id = p_scope_id
                        LIMIT 1
                    ),
                    0
                ),
                COALESCE(
                    (
                        SELECT generation.metric_type::text
                        FROM vector_store.guide_active_generations AS active
                        JOIN vector_store.guide_vector_generations AS generation
                          ON generation.id = active.vector_generation_id
                        WHERE active.organization_id = p_organization_id
                          AND active.guide_id = p_guide_id
                          AND active.guide_version = p_guide_version
                          AND active.scope_id = p_scope_id
                        LIMIT 1
                    ),
                    'NONE'
                )
            WHERE current_setting('secai.organization_id', true)
                    = p_organization_id::text
        $function$
        """
    )
    op.execute(
        """
        REVOKE ALL ON FUNCTION vector_store.guide_store_inventory(
            uuid, text, text, text
        ) FROM PUBLIC
        """
    )
    op.execute(
        """
        GRANT EXECUTE ON FUNCTION vector_store.guide_store_inventory(
            uuid, text, text, text
        ) TO secai_runtime
        """
    )
    op.execute("GRANT pg_monitor TO secai_db_admin")
    op.execute(
        """
        GRANT USAGE ON SCHEMA public, guide_content, vector_store
        TO secai_db_admin
        """
    )
    op.execute(
        """
        GRANT SELECT ON ALL TABLES IN SCHEMA public
        TO secai_db_admin
        """
    )
    op.execute(
        """
        GRANT SELECT, INSERT, UPDATE, DELETE
        ON ALL TABLES IN SCHEMA guide_content, vector_store
        TO secai_db_admin
        """
    )
    op.execute(
        """
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA vector_store
        TO secai_db_admin
        """
    )
    op.execute(
        """
        ALTER DEFAULT PRIVILEGES FOR ROLE secai_app
        IN SCHEMA guide_content, vector_store
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES
        TO secai_db_admin
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER DEFAULT PRIVILEGES FOR ROLE secai_app
        IN SCHEMA guide_content, vector_store
        REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES
        FROM secai_db_admin
        """
    )
    op.execute(
        """
        REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA vector_store
        FROM secai_db_admin
        """
    )
    op.execute(
        """
        REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA guide_content, vector_store
        FROM secai_db_admin
        """
    )
    op.execute(
        """
        REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public
        FROM secai_db_admin
        """
    )
    op.execute(
        """
        REVOKE USAGE ON SCHEMA public, guide_content, vector_store
        FROM secai_db_admin
        """
    )
    op.execute("REVOKE pg_monitor FROM secai_db_admin")
    op.execute(
        """
        REVOKE EXECUTE ON FUNCTION vector_store.guide_store_inventory(
            uuid, text, text, text
        ) FROM secai_runtime
        """
    )
    op.execute(
        """
        DROP FUNCTION vector_store.guide_store_inventory(
            uuid, text, text, text
        )
        """
    )
    op.execute(
        """
        ALTER TABLE guide_content.guide_chunks
        DROP CONSTRAINT ck_guide_chunks_control_id
        """
    )
    op.execute(
        """
        ALTER TABLE guide_content.guide_documents
        DROP CONSTRAINT ck_guide_documents_classification
        """
    )
    op.execute(
        """
        ALTER TABLE guide_content.guide_documents
        ADD CONSTRAINT ck_guide_documents_classification
        CHECK (classification IN ('PUBLIC_GUIDE', 'SYNTHETIC_DEV_ONLY'))
        """
    )
    op.execute(
        """
        ALTER TABLE guide_content.guide_chunks
        ADD CONSTRAINT ck_guide_chunks_control_id
        CHECK (control_id ~ '^PC-(0[1-9]|1[0-8])$')
        """
    )
