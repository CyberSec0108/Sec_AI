"""Add IMP-048 PostgreSQL/pgvector guide ingest and retrieval projection."""

from collections.abc import Sequence

from alembic import op

revision: str = "0006_imp048"
down_revision: str | None = "0005_imp046"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCOPED_TABLES = (
    "guide_content.guide_documents",
    "guide_content.guide_chunks",
    "vector_store.guide_vector_generations",
    "vector_store.guide_embeddings",
    "vector_store.guide_active_generations",
)


def _enable_rls(table_name: str) -> None:
    policy_name = "organization_scope_" + table_name.split(".")[-1]
    op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"""
        CREATE POLICY {policy_name} ON {table_name}
        USING (
            organization_id =
            NULLIF(current_setting('secai.organization_id', true), '')::uuid
        )
        WITH CHECK (
            organization_id =
            NULLIF(current_setting('secai.organization_id', true), '')::uuid
        )
        """
    )


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute("CREATE SCHEMA guide_content AUTHORIZATION secai_app")
    op.execute("CREATE SCHEMA vector_store AUTHORIZATION secai_app")

    op.execute(
        """
        CREATE TABLE guide_content.guide_documents (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL
                REFERENCES public.organizations(id) ON DELETE RESTRICT,
            guide_id varchar(128) NOT NULL,
            guide_version varchar(64) NOT NULL,
            source_sha256 char(64) NOT NULL,
            scope_id varchar(128) NOT NULL,
            status varchar(32) NOT NULL,
            license_status varchar(32) NOT NULL,
            derivative_text_storage_allowed boolean NOT NULL,
            malware_scan_status varchar(16) NOT NULL,
            extraction_quality_status varchar(16) NOT NULL,
            classification varchar(32) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT uq_guide_documents_scope
                UNIQUE (organization_id, guide_id, guide_version, scope_id),
            CONSTRAINT ck_guide_documents_source_sha256
                CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
            CONSTRAINT ck_guide_documents_status
                CHECK (status IN ('APPROVED', 'SYNTHETIC_TEST_ONLY', 'RETIRED')),
            CONSTRAINT ck_guide_documents_license
                CHECK (license_status IN ('APPROVED', 'SYNTHETIC_TEST_ONLY')),
            CONSTRAINT ck_guide_documents_ingest_gates
                CHECK (
                    derivative_text_storage_allowed
                    AND malware_scan_status = 'CLEAN'
                    AND extraction_quality_status = 'APPROVED'
                ),
            CONSTRAINT ck_guide_documents_classification
                CHECK (classification IN ('PUBLIC_GUIDE', 'SYNTHETIC_DEV_ONLY'))
        )
        """
    )
    op.execute(
        """
        CREATE TABLE guide_content.guide_chunks (
            chunk_id uuid PRIMARY KEY,
            document_id uuid NOT NULL
                REFERENCES guide_content.guide_documents(id) ON DELETE RESTRICT,
            organization_id uuid NOT NULL,
            guide_id varchar(128) NOT NULL,
            guide_version varchar(64) NOT NULL,
            source_sha256 char(64) NOT NULL,
            scope_id varchar(128) NOT NULL,
            pdf_page_number integer NOT NULL,
            control_id varchar(16) NOT NULL,
            ordinal integer NOT NULL,
            content_text text NOT NULL,
            text_sha256 char(64) NOT NULL,
            chunker_version varchar(64) NOT NULL,
            status varchar(16) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT uq_guide_chunks_document_ordinal
                UNIQUE (document_id, ordinal),
            CONSTRAINT ck_guide_chunks_page_ordinal
                CHECK (pdf_page_number > 0 AND ordinal >= 0),
            CONSTRAINT ck_guide_chunks_control_id
                CHECK (control_id ~ '^PC-(0[1-9]|1[0-8])$'),
            CONSTRAINT ck_guide_chunks_hashes
                CHECK (
                    source_sha256 ~ '^[a-f0-9]{64}$'
                    AND text_sha256 ~ '^[a-f0-9]{64}$'
                ),
            CONSTRAINT ck_guide_chunks_text
                CHECK (length(btrim(content_text)) > 0),
            CONSTRAINT ck_guide_chunks_status
                CHECK (status IN ('READY', 'RETIRED'))
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_guide_chunks_scope
        ON guide_content.guide_chunks (
            organization_id, guide_id, guide_version, scope_id, pdf_page_number
        )
        WHERE status = 'READY'
        """
    )
    op.execute(
        """
        CREATE TABLE vector_store.guide_vector_generations (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL,
            document_id uuid NOT NULL
                REFERENCES guide_content.guide_documents(id) ON DELETE RESTRICT,
            embedding_model_id varchar(128) NOT NULL,
            embedding_dimension integer NOT NULL,
            metric_type varchar(16) NOT NULL,
            status varchar(16) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            activated_at timestamptz NULL,
            CONSTRAINT uq_guide_vector_generation_identity
                UNIQUE (organization_id, document_id, embedding_model_id),
            CONSTRAINT ck_guide_vector_generation_dimension
                CHECK (embedding_dimension = 32),
            CONSTRAINT ck_guide_vector_generation_metric
                CHECK (metric_type = 'COSINE'),
            CONSTRAINT ck_guide_vector_generation_status
                CHECK (
                    status IN (
                        'PLANNED', 'BUILDING', 'VALIDATING', 'READY',
                        'ACTIVE', 'FAILED', 'RETIRED'
                    )
                )
        )
        """
    )
    op.execute(
        """
        CREATE TABLE vector_store.guide_embeddings (
            vector_generation_id uuid NOT NULL
                REFERENCES vector_store.guide_vector_generations(id)
                ON DELETE RESTRICT,
            chunk_id uuid NOT NULL
                REFERENCES guide_content.guide_chunks(chunk_id)
                ON DELETE RESTRICT,
            organization_id uuid NOT NULL,
            content_fingerprint char(64) NOT NULL,
            status varchar(16) NOT NULL,
            embedding vector(32) NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (vector_generation_id, chunk_id),
            CONSTRAINT ck_guide_embeddings_content_fingerprint
                CHECK (content_fingerprint ~ '^[a-f0-9]{64}$'),
            CONSTRAINT ck_guide_embeddings_status
                CHECK (status IN ('READY', 'RETIRED'))
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_guide_embeddings_hnsw_cosine
        ON vector_store.guide_embeddings
        USING hnsw (embedding vector_cosine_ops)
        WHERE status = 'READY'
        """
    )
    op.execute(
        """
        CREATE TABLE vector_store.guide_active_generations (
            organization_id uuid NOT NULL,
            guide_id varchar(128) NOT NULL,
            guide_version varchar(64) NOT NULL,
            scope_id varchar(128) NOT NULL,
            vector_generation_id uuid NOT NULL
                REFERENCES vector_store.guide_vector_generations(id)
                ON DELETE RESTRICT,
            activated_at timestamptz NOT NULL,
            PRIMARY KEY (organization_id, guide_id, guide_version, scope_id),
            CONSTRAINT uq_guide_active_generation
                UNIQUE (vector_generation_id)
        )
        """
    )

    for table_name in _SCOPED_TABLES:
        _enable_rls(table_name)

    op.execute(
        """
        CREATE FUNCTION vector_store.search_guide_chunks(
            p_organization_id uuid,
            p_guide_id text,
            p_guide_version text,
            p_scope_id text,
            p_query vector(32),
            p_candidate_limit integer
        )
        RETURNS TABLE (chunk_id uuid, dense_score real)
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog, public, guide_content, vector_store
        AS $function$
            SELECT
                e.chunk_id,
                GREATEST(
                    0.0,
                    LEAST(1.0, 1.0 - (e.embedding <=> p_query))
                )::real AS dense_score
            FROM vector_store.guide_active_generations AS active
            JOIN vector_store.guide_vector_generations AS generation
              ON generation.id = active.vector_generation_id
             AND generation.organization_id = active.organization_id
             AND generation.status = 'ACTIVE'
            JOIN vector_store.guide_embeddings AS e
              ON e.vector_generation_id = generation.id
             AND e.organization_id = active.organization_id
             AND e.status = 'READY'
            JOIN guide_content.guide_chunks AS chunk
              ON chunk.chunk_id = e.chunk_id
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
            ORDER BY e.embedding <=> p_query, e.chunk_id
            LIMIT LEAST(GREATEST(p_candidate_limit, 1), 100)
        $function$
        """
    )
    op.execute(
        """
        COMMENT ON FUNCTION vector_store.search_guide_chunks(
            uuid, text, text, text, vector, integer
        ) IS 'Returns authorized chunk IDs and scores only; raw embedding export is forbidden.'
        """
    )

    op.execute("GRANT USAGE ON SCHEMA guide_content, vector_store TO secai_runtime")
    op.execute(
        """
        GRANT SELECT, INSERT
        ON guide_content.guide_documents, guide_content.guide_chunks
        TO secai_runtime
        """
    )
    op.execute(
        """
        GRANT SELECT, INSERT, UPDATE
        ON vector_store.guide_vector_generations,
           vector_store.guide_active_generations
        TO secai_runtime
        """
    )
    op.execute(
        """
        GRANT INSERT, UPDATE
        ON vector_store.guide_embeddings
        TO secai_runtime
        """
    )
    op.execute(
        """
        GRANT EXECUTE ON FUNCTION vector_store.search_guide_chunks(
            uuid, text, text, text, vector, integer
        ) TO secai_runtime
        """
    )


def downgrade() -> None:
    op.execute(
        """
        REVOKE EXECUTE ON FUNCTION vector_store.search_guide_chunks(
            uuid, text, text, text, vector, integer
        ) FROM secai_runtime
        """
    )
    op.execute(
        """
        REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA vector_store
        FROM secai_runtime
        """
    )
    op.execute(
        """
        REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA guide_content
        FROM secai_runtime
        """
    )
    op.execute("REVOKE USAGE ON SCHEMA guide_content, vector_store FROM secai_runtime")
    op.execute(
        """
        DROP FUNCTION vector_store.search_guide_chunks(
            uuid, text, text, text, vector, integer
        )
        """
    )
    op.execute("DROP TABLE vector_store.guide_active_generations")
    op.execute("DROP TABLE vector_store.guide_embeddings")
    op.execute("DROP TABLE vector_store.guide_vector_generations")
    op.execute("DROP TABLE guide_content.guide_chunks")
    op.execute("DROP TABLE guide_content.guide_documents")
    op.execute("DROP SCHEMA vector_store")
    op.execute("DROP SCHEMA guide_content")
    op.execute("DROP EXTENSION vector")
