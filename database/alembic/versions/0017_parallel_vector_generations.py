"""Keep independent active 32 and 1024 dimensional guide generations."""

from collections.abc import Sequence

from alembic import op

revision: str = "0017_parallel_vectors"
down_revision: str | None = "0016_platform_search"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE vector_store.guide_active_generations_by_dimension (
            organization_id uuid NOT NULL,
            guide_id varchar(128) NOT NULL,
            guide_version varchar(64) NOT NULL,
            scope_id varchar(128) NOT NULL,
            embedding_dimension integer NOT NULL,
            vector_generation_id uuid NOT NULL
                REFERENCES vector_store.guide_vector_generations(id)
                ON DELETE RESTRICT,
            activated_at timestamptz NOT NULL,
            PRIMARY KEY (
                organization_id, guide_id, guide_version, scope_id,
                embedding_dimension
            ),
            UNIQUE (vector_generation_id),
            CHECK (embedding_dimension IN (32, 1024))
        )
        """
    )
    op.execute(
        """
        INSERT INTO vector_store.guide_active_generations_by_dimension (
            organization_id, guide_id, guide_version, scope_id,
            embedding_dimension, vector_generation_id, activated_at
        )
        SELECT active.organization_id, active.guide_id, active.guide_version,
               active.scope_id, generation.embedding_dimension,
               active.vector_generation_id, active.activated_at
        FROM vector_store.guide_active_generations AS active
        JOIN vector_store.guide_vector_generations AS generation
          ON generation.id = active.vector_generation_id
        ON CONFLICT DO NOTHING
        """
    )
    op.execute(
        "ALTER TABLE vector_store.guide_active_generations_by_dimension ENABLE ROW LEVEL SECURITY"
    )
    op.execute(
        "ALTER TABLE vector_store.guide_active_generations_by_dimension FORCE ROW LEVEL SECURITY"
    )
    op.execute(
        """
        CREATE POLICY organization_scope_active_generation_dimension
        ON vector_store.guide_active_generations_by_dimension
        USING (
            organization_id = NULLIF(
                current_setting('secai.organization_id', true), ''
            )::uuid
        )
        WITH CHECK (
            organization_id = NULLIF(
                current_setting('secai.organization_id', true), ''
            )::uuid
        )
        """
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON "
        "vector_store.guide_active_generations_by_dimension TO secai_runtime"
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION vector_store.search_guide_chunks(
            p_organization_id uuid,
            p_guide_id text,
            p_guide_version text,
            p_scope_id text,
            p_query vector(32),
            p_candidate_limit integer
        )
        RETURNS TABLE (chunk_id uuid, dense_score real)
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, public, guide_content, vector_store
        AS $function$
            SELECT e.chunk_id,
                   GREATEST(0.0, LEAST(1.0, 1.0 - (e.embedding <=> p_query)))::real
            FROM vector_store.guide_active_generations_by_dimension AS active
            JOIN vector_store.guide_vector_generations AS generation
              ON generation.id = active.vector_generation_id
             AND generation.status = 'ACTIVE'
             AND generation.embedding_dimension = 32
            JOIN vector_store.guide_embeddings AS e
              ON e.vector_generation_id = generation.id
             AND e.organization_id = active.organization_id
             AND e.status = 'READY'
            JOIN guide_content.guide_chunks AS chunk
              ON chunk.chunk_id = e.chunk_id
             AND chunk.organization_id = active.organization_id
             AND chunk.status = 'READY'
            JOIN guide_content.guide_documents AS document
              ON document.id = chunk.document_id
             AND document.organization_id = active.organization_id
            WHERE current_setting('secai.organization_id', true)
                    = p_organization_id::text
              AND active.organization_id = p_organization_id
              AND active.guide_id = p_guide_id
              AND active.guide_version = p_guide_version
              AND active.scope_id = p_scope_id
              AND active.embedding_dimension = 32
              AND (document.status = 'APPROVED' OR (
                    document.status = 'SYNTHETIC_TEST_ONLY'
                    AND current_setting('secai.allow_synthetic_guide', true) = 'on'))
            ORDER BY e.embedding <=> p_query, e.chunk_id
            LIMIT LEAST(GREATEST(p_candidate_limit, 1), 100)
        $function$
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION vector_store.search_guide_chunks_bge_m3(
            p_organization_id uuid,
            p_guide_id text,
            p_guide_version text,
            p_scope_id text,
            p_query vector(1024),
            p_candidate_limit integer
        )
        RETURNS TABLE (chunk_id uuid, dense_score real)
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, public, guide_content, vector_store
        AS $function$
            SELECT e.chunk_id,
                   GREATEST(0.0, LEAST(1.0, 1.0 - (e.embedding <=> p_query)))::real
            FROM vector_store.guide_active_generations_by_dimension AS active
            JOIN vector_store.guide_vector_generations AS generation
              ON generation.id = active.vector_generation_id
             AND generation.status = 'ACTIVE'
             AND generation.embedding_dimension = 1024
            JOIN vector_store.guide_embeddings_bge_m3 AS e
              ON e.vector_generation_id = generation.id
             AND e.organization_id = active.organization_id
             AND e.status = 'READY'
            JOIN guide_content.guide_chunks AS chunk
              ON chunk.chunk_id = e.chunk_id
             AND chunk.organization_id = active.organization_id
             AND chunk.status = 'READY'
            JOIN guide_content.guide_documents AS document
              ON document.id = chunk.document_id
             AND document.organization_id = active.organization_id
            WHERE current_setting('secai.organization_id', true)
                    = p_organization_id::text
              AND active.organization_id = p_organization_id
              AND active.guide_id = p_guide_id
              AND active.guide_version = p_guide_version
              AND active.scope_id = p_scope_id
              AND active.embedding_dimension = 1024
              AND (document.status = 'APPROVED' OR (
                    document.status = 'SYNTHETIC_TEST_ONLY'
                    AND current_setting('secai.allow_synthetic_guide', true) = 'on'))
            ORDER BY e.embedding <=> p_query, e.chunk_id
            LIMIT LEAST(GREATEST(p_candidate_limit, 1), 100)
        $function$
        """
    )


def downgrade() -> None:
    op.execute(
        "REVOKE ALL PRIVILEGES ON "
        "vector_store.guide_active_generations_by_dimension FROM secai_runtime"
    )
    op.execute("DROP TABLE vector_store.guide_active_generations_by_dimension")
