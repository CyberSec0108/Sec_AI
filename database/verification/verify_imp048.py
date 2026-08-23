"""Verify IMP-048 pgvector retrieval against the runtime role and real PostgreSQL."""

from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from security_audit.common.service_settings import ServiceSettings
from security_audit.guides.retrieval import (
    DeterministicTestEmbedder,
    GuideIngestGateInput,
    GuidePageText,
    GuideSearchScope,
    build_guide_chunks,
    vector_literal,
)
from security_audit.persistence.database.guide_repository import search_guide_chunks

ORGANIZATION_ID = UUID("48000000-0000-4000-8000-000000000001")
OTHER_ORGANIZATION_ID = UUID("48000000-0000-4000-8000-000000000002")
DOCUMENT_ID = UUID("48000000-0000-4000-8000-000000000101")
GENERATION_ID = UUID("48000000-0000-4000-8000-000000000102")
GUIDE_ID = "synthetic-kisa-pc-guide"
GUIDE_VERSION = "test-1"
SCOPE_ID = "pc-pages"
SOURCE_SHA256 = "a" * 64


def _gate() -> GuideIngestGateInput:
    return GuideIngestGateInput(
        guide_status="SYNTHETIC_TEST_ONLY",
        license_status="SYNTHETIC_TEST_ONLY",
        derivative_text_storage_allowed=True,
        source_hash_verified=True,
        page_map_verified=True,
        malware_scan_passed=True,
        extraction_quality_approved=True,
        query_scope_enabled=True,
        synthetic_test_only=True,
    )


def _set_scope(session: Session, organization_id: UUID) -> None:
    session.execute(
        text("SELECT set_config('secai.organization_id', :value, true)"),
        {"value": str(organization_id)},
    )


def main() -> None:
    engine = create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )
    embedder = DeterministicTestEmbedder()
    chunks = build_guide_chunks(
        organization_id=ORGANIZATION_ID,
        guide_id=GUIDE_ID,
        guide_version=GUIDE_VERSION,
        source_sha256=SOURCE_SHA256,
        scope_id=SCOPE_ID,
        pages=(
            GuidePageText(555, "PC-01", "비밀번호 변경 주기를 확인합니다."),
            GuidePageText(557, "PC-02", "비밀번호 길이와 복잡성을 확인합니다."),
        ),
        gate=_gate(),
    )

    with Session(engine) as session:
        transaction = session.begin()
        try:
            _set_scope(session, ORGANIZATION_ID)
            session.execute(
                text(
                    """
                    INSERT INTO public.organizations (id)
                    VALUES (:organization_id)
                    ON CONFLICT (id) DO NOTHING
                    """
                ),
                {"organization_id": ORGANIZATION_ID},
            )
            session.execute(
                text(
                    """
                    INSERT INTO guide_content.guide_documents (
                        id, organization_id, guide_id, guide_version,
                        source_sha256, scope_id, status, license_status,
                        derivative_text_storage_allowed, malware_scan_status,
                        extraction_quality_status, classification
                    )
                    VALUES (
                        :id, :organization_id, :guide_id, :guide_version,
                        :source_sha256, :scope_id, 'SYNTHETIC_TEST_ONLY',
                        'SYNTHETIC_TEST_ONLY', true, 'CLEAN', 'APPROVED',
                        'SYNTHETIC_DEV_ONLY'
                    )
                    """
                ),
                {
                    "id": DOCUMENT_ID,
                    "organization_id": ORGANIZATION_ID,
                    "guide_id": GUIDE_ID,
                    "guide_version": GUIDE_VERSION,
                    "source_sha256": SOURCE_SHA256,
                    "scope_id": SCOPE_ID,
                },
            )
            for chunk in chunks:
                session.execute(
                    text(
                        """
                        INSERT INTO guide_content.guide_chunks (
                            chunk_id, document_id, organization_id, guide_id,
                            guide_version, source_sha256, scope_id,
                            pdf_page_number, control_id, ordinal,
                            content_text, text_sha256, chunker_version, status
                        )
                        VALUES (
                            :chunk_id, :document_id, :organization_id, :guide_id,
                            :guide_version, :source_sha256, :scope_id,
                            :pdf_page_number, :control_id, :ordinal,
                            :content_text, :text_sha256, 'page-v1', 'READY'
                        )
                        """
                    ),
                    {
                        "chunk_id": chunk.chunk_id,
                        "document_id": DOCUMENT_ID,
                        "organization_id": ORGANIZATION_ID,
                        "guide_id": GUIDE_ID,
                        "guide_version": GUIDE_VERSION,
                        "source_sha256": SOURCE_SHA256,
                        "scope_id": SCOPE_ID,
                        "pdf_page_number": chunk.pdf_page_number,
                        "control_id": chunk.control_id,
                        "ordinal": chunk.ordinal,
                        "content_text": chunk.text,
                        "text_sha256": chunk.text_sha256,
                    },
                )
            session.execute(
                text(
                    """
                    INSERT INTO vector_store.guide_vector_generations (
                        id, organization_id, document_id, embedding_model_id,
                        embedding_dimension, metric_type, status, activated_at
                    )
                    VALUES (
                        :id, :organization_id, :document_id, :model_id,
                        32, 'COSINE', 'ACTIVE', now()
                    )
                    """
                ),
                {
                    "id": GENERATION_ID,
                    "organization_id": ORGANIZATION_ID,
                    "document_id": DOCUMENT_ID,
                    "model_id": embedder.model_id,
                },
            )
            for chunk in chunks:
                session.execute(
                    text(
                        """
                        INSERT INTO vector_store.guide_embeddings (
                            vector_generation_id, chunk_id, organization_id,
                            content_fingerprint, status, embedding
                        )
                        VALUES (
                            :generation_id, :chunk_id, :organization_id,
                            :content_fingerprint, 'READY',
                            CAST(:embedding AS vector)
                        )
                        """
                    ),
                    {
                        "generation_id": GENERATION_ID,
                        "chunk_id": chunk.chunk_id,
                        "organization_id": ORGANIZATION_ID,
                        "content_fingerprint": chunk.text_sha256,
                        "embedding": vector_literal(embedder.embed(chunk.text)),
                    },
                )
            session.execute(
                text(
                    """
                    INSERT INTO vector_store.guide_active_generations (
                        organization_id, guide_id, guide_version, scope_id,
                        vector_generation_id, activated_at
                    )
                    VALUES (
                        :organization_id, :guide_id, :guide_version, :scope_id,
                        :generation_id, now()
                    )
                    """
                ),
                {
                    "organization_id": ORGANIZATION_ID,
                    "guide_id": GUIDE_ID,
                    "guide_version": GUIDE_VERSION,
                    "scope_id": SCOPE_ID,
                    "generation_id": GENERATION_ID,
                },
            )

            scope = GuideSearchScope(
                organization_id=ORGANIZATION_ID,
                guide_id=GUIDE_ID,
                guide_version=GUIDE_VERSION,
                scope_id=SCOPE_ID,
                query="비밀번호 변경 주기",
                top_k=2,
                allow_synthetic_test_data=True,
            )
            hits = search_guide_chunks(
                session,
                scope,
                embedder.embed(scope.query),
            )
            if [hit.control_id for hit in hits] != ["PC-01", "PC-02"]:
                raise RuntimeError("Expected deterministic scoped PC-01/PC-02 results.")

            cross_organization = search_guide_chunks(
                session,
                GuideSearchScope(
                    organization_id=OTHER_ORGANIZATION_ID,
                    guide_id=GUIDE_ID,
                    guide_version=GUIDE_VERSION,
                    scope_id=SCOPE_ID,
                    query=scope.query,
                    top_k=2,
                    allow_synthetic_test_data=True,
                ),
                embedder.embed(scope.query),
            )
            wrong_scope = search_guide_chunks(
                session,
                GuideSearchScope(
                    organization_id=ORGANIZATION_ID,
                    guide_id=GUIDE_ID,
                    guide_version=GUIDE_VERSION,
                    scope_id="server-pages",
                    query=scope.query,
                    top_k=2,
                    allow_synthetic_test_data=True,
                ),
                embedder.embed(scope.query),
            )
            if cross_organization or wrong_scope:
                raise RuntimeError("Guide scope isolation failed.")

            raw_vector_blocked = False
            try:
                with session.begin_nested():
                    session.execute(
                        text(
                            "SELECT embedding "
                            "FROM vector_store.guide_embeddings LIMIT 1"
                        )
                    ).all()
            except DBAPIError:
                raw_vector_blocked = True
            if not raw_vector_blocked:
                raise RuntimeError("Runtime role could read raw embedding values.")

            extension_version = session.execute(
                text(
                    "SELECT extversion FROM pg_extension WHERE extname = 'vector'"
                )
            ).scalar_one()
            migration = session.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            print(
                json.dumps(
                    {
                        "imp": "IMP-048",
                        "accepted": True,
                        "provider": "POSTGRES_PGVECTOR",
                        "postgresql_migration": migration,
                        "pgvector_version": extension_version,
                        "synthetic_chunks": len(chunks),
                        "search_hits": len(hits),
                        "first_control": hits[0].control_id,
                        "cross_organization_hits": len(cross_organization),
                        "wrong_scope_hits": len(wrong_scope),
                        "raw_vector_read_blocked": raw_vector_blocked,
                        "real_kisa_ingested": False,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        finally:
            transaction.rollback()
    engine.dispose()


if __name__ == "__main__":
    main()
