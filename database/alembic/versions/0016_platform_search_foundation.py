"""Add criteria selection history and BGE-M3 vector generation storage."""

from collections.abc import Sequence

from alembic import op

revision: str = "0016_platform_search"
down_revision: str | None = "0015_criteria_profiles"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE assessment_criteria_profiles
        ADD CONSTRAINT uq_criteria_profile_selection_scope
        UNIQUE (id, organization_id, owner_user_id)
        """
    )
    op.execute(
        """
        CREATE TABLE assessment_criteria_selections (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL,
            user_id uuid NOT NULL,
            selection_kind varchar(16) NOT NULL,
            personal_profile_id uuid NULL,
            criteria_sha256 char(64) NOT NULL,
            selected_at timestamptz NOT NULL DEFAULT now(),
            source varchar(32) NOT NULL,
            CONSTRAINT fk_criteria_selection_user_scope
                FOREIGN KEY (user_id, organization_id)
                REFERENCES user_accounts (id, organization_id) ON DELETE RESTRICT,
            CONSTRAINT fk_criteria_selection_profile_scope
                FOREIGN KEY (personal_profile_id, organization_id, user_id)
                REFERENCES assessment_criteria_profiles (
                    id, organization_id, owner_user_id
                ) ON DELETE RESTRICT,
            CONSTRAINT ck_criteria_selection_kind
                CHECK (selection_kind IN (
                    'KISA_DEFAULT', 'ORGANIZATION', 'PERSONAL'
                )),
            CONSTRAINT ck_criteria_selection_profile_matches_kind
                CHECK (
                    (selection_kind IN ('KISA_DEFAULT', 'ORGANIZATION')
                        AND personal_profile_id IS NULL)
                    OR (selection_kind = 'PERSONAL' AND personal_profile_id IS NOT NULL)
                ),
            CONSTRAINT ck_criteria_selection_sha256
                CHECK (criteria_sha256 ~ '^[a-f0-9]{64}$'),
            CONSTRAINT ck_criteria_selection_source
                CHECK (source IN ('CRITERIA_PAGE', 'RESET', 'SCAN_START'))
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_criteria_selection_user_time
        ON assessment_criteria_selections (
            organization_id, user_id, selected_at DESC, id DESC
        )
        """
    )
    op.execute("ALTER TABLE assessment_criteria_selections ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE assessment_criteria_selections FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY assessment_criteria_selections_user_scope
        ON assessment_criteria_selections
        USING (
            organization_id = NULLIF(
                current_setting('secai.organization_id', true), ''
            )::uuid
            AND user_id = NULLIF(current_setting('secai.user_id', true), '')::uuid
        )
        WITH CHECK (
            organization_id = NULLIF(
                current_setting('secai.organization_id', true), ''
            )::uuid
            AND user_id = NULLIF(current_setting('secai.user_id', true), '')::uuid
        )
        """
    )
    op.execute(
        "GRANT SELECT, INSERT ON assessment_criteria_selections TO secai_runtime"
    )

    op.execute(
        """
        ALTER TABLE vector_store.guide_vector_generations
        DROP CONSTRAINT ck_guide_vector_generation_dimension
        """
    )
    op.execute(
        """
        ALTER TABLE vector_store.guide_vector_generations
        ADD CONSTRAINT ck_guide_vector_generation_dimension
        CHECK (embedding_dimension IN (32, 1024))
        """
    )
    op.execute(
        """
        CREATE TABLE vector_store.guide_embeddings_bge_m3 (
            vector_generation_id uuid NOT NULL
                REFERENCES vector_store.guide_vector_generations(id)
                ON DELETE RESTRICT,
            chunk_id uuid NOT NULL
                REFERENCES guide_content.guide_chunks(chunk_id)
                ON DELETE RESTRICT,
            organization_id uuid NOT NULL,
            content_fingerprint char(64) NOT NULL,
            status varchar(16) NOT NULL,
            embedding vector(1024) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (vector_generation_id, chunk_id),
            CONSTRAINT ck_guide_embeddings_bge_m3_fingerprint
                CHECK (content_fingerprint ~ '^[a-f0-9]{64}$'),
            CONSTRAINT ck_guide_embeddings_bge_m3_status
                CHECK (status IN ('READY', 'RETIRED'))
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_guide_embeddings_bge_m3_hnsw_cosine
        ON vector_store.guide_embeddings_bge_m3
        USING hnsw (embedding vector_cosine_ops)
        WHERE status = 'READY'
        """
    )
    op.execute("ALTER TABLE vector_store.guide_embeddings_bge_m3 ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE vector_store.guide_embeddings_bge_m3 FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY organization_scope_guide_embeddings_bge_m3
        ON vector_store.guide_embeddings_bge_m3
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
        """
        CREATE FUNCTION vector_store.search_guide_chunks_bge_m3(
            p_organization_id uuid,
            p_guide_id text,
            p_guide_version text,
            p_scope_id text,
            p_query vector(1024),
            p_candidate_limit integer
        )
        RETURNS TABLE (chunk_id uuid, dense_score real)
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, guide_content, vector_store
        AS $function$
            SELECT
                embedding_row.chunk_id,
                GREATEST(
                    0.0,
                    LEAST(1.0, 1.0 - (embedding_row.embedding <=> p_query))
                )::real AS dense_score
            FROM vector_store.guide_active_generations AS active
            JOIN vector_store.guide_vector_generations AS generation
              ON generation.id = active.vector_generation_id
             AND generation.organization_id = active.organization_id
             AND generation.status = 'ACTIVE'
             AND generation.embedding_dimension = 1024
            JOIN vector_store.guide_embeddings_bge_m3 AS embedding_row
              ON embedding_row.vector_generation_id = generation.id
             AND embedding_row.organization_id = active.organization_id
             AND embedding_row.status = 'READY'
            JOIN guide_content.guide_chunks AS chunk
              ON chunk.chunk_id = embedding_row.chunk_id
             AND chunk.organization_id = active.organization_id
             AND chunk.guide_id = active.guide_id
             AND chunk.guide_version = active.guide_version
             AND chunk.scope_id = active.scope_id
             AND chunk.status = 'READY'
            JOIN guide_content.guide_documents AS document
              ON document.id = chunk.document_id
             AND document.organization_id = active.organization_id
             AND document.guide_id = active.guide_id
             AND document.guide_version = active.guide_version
             AND document.scope_id = active.scope_id
            WHERE current_setting('secai.organization_id', true)
                    = p_organization_id::text
              AND active.organization_id = p_organization_id
              AND active.guide_id = p_guide_id
              AND active.guide_version = p_guide_version
              AND active.scope_id = p_scope_id
              AND (
                    document.status = 'APPROVED'
                    OR (
                        document.status = 'SYNTHETIC_TEST_ONLY'
                        AND current_setting(
                            'secai.allow_synthetic_guide', true
                        ) = 'on'
                    )
              )
            ORDER BY embedding_row.embedding <=> p_query, embedding_row.chunk_id
            LIMIT LEAST(GREATEST(p_candidate_limit, 1), 100)
        $function$
        """
    )
    op.execute(
        """
        COMMENT ON FUNCTION vector_store.search_guide_chunks_bge_m3(
            uuid, text, text, text, vector, integer
        ) IS 'BGE-M3 search returns authorized chunk IDs and scores only.'
        """
    )
    op.execute(
        "GRANT INSERT, UPDATE ON vector_store.guide_embeddings_bge_m3 TO secai_runtime"
    )
    op.execute(
        """
        GRANT EXECUTE ON FUNCTION vector_store.search_guide_chunks_bge_m3(
            uuid, text, text, text, vector, integer
        ) TO secai_runtime
        """
    )


def downgrade() -> None:
    op.execute(
        """
        REVOKE EXECUTE ON FUNCTION vector_store.search_guide_chunks_bge_m3(
            uuid, text, text, text, vector, integer
        ) FROM secai_runtime
        """
    )
    op.execute(
        "DROP FUNCTION vector_store.search_guide_chunks_bge_m3"
        "(uuid, text, text, text, vector, integer)"
    )
    op.execute(
        "REVOKE ALL PRIVILEGES ON vector_store.guide_embeddings_bge_m3 FROM secai_runtime"
    )
    op.execute("DROP TABLE vector_store.guide_embeddings_bge_m3")
    op.execute(
        """
        ALTER TABLE vector_store.guide_vector_generations
        DROP CONSTRAINT ck_guide_vector_generation_dimension
        """
    )
    op.execute(
        """
        ALTER TABLE vector_store.guide_vector_generations
        ADD CONSTRAINT ck_guide_vector_generation_dimension
        CHECK (embedding_dimension = 32)
        """
    )
    op.execute(
        "REVOKE ALL PRIVILEGES ON assessment_criteria_selections FROM secai_runtime"
    )
    op.execute("DROP TABLE assessment_criteria_selections")
    op.execute(
        """
        ALTER TABLE assessment_criteria_profiles
        DROP CONSTRAINT uq_criteria_profile_selection_scope
        """
    )
