"""PostgreSQL/pgvector repository boundary for IMP-048 guide retrieval."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast
from uuid import UUID

from sqlalchemy import TextClause, text
from sqlalchemy.orm import Session

from security_audit.guides.retrieval import (
    GuideSearchCandidate,
    GuideSearchHit,
    GuideSearchScope,
    filter_and_rerank,
    vector_literal,
)


@dataclass(frozen=True, slots=True)
class GuideStoreChunk:
    pdf_page_number: int
    control_id: str
    text: str
    text_sha256: str


@dataclass(frozen=True, slots=True)
class GuideStoreSnapshot:
    organization_id: UUID
    postgresql_version: str
    pgvector_version: str
    document_count: int
    chunk_count: int
    embedding_count: int
    active_generation_count: int
    generation_status: str
    embedding_model_id: str
    embedding_dimension: int
    metric_type: str
    guide_id: str
    guide_version: str
    scope_id: str
    chunks: tuple[GuideStoreChunk, ...]


def build_pgvector_search_statement() -> TextClause:
    """Call the restricted function, which never returns raw embedding values."""

    return text(
        """
        SELECT chunk_id, dense_score
        FROM vector_store.search_guide_chunks(
            CAST(:organization_id AS uuid),
            :guide_id,
            :guide_version,
            :scope_id,
            CAST(:query_vector AS vector),
            :candidate_limit
        )
        """
    )


def build_bge_m3_search_statement() -> TextClause:
    """Call the isolated 1024-dimensional BGE-M3 projection."""

    return text(
        """
        SELECT chunk_id, dense_score
        FROM vector_store.search_guide_chunks_bge_m3(
            CAST(:organization_id AS uuid),
            :guide_id,
            :guide_version,
            :scope_id,
            CAST(:query_vector AS vector),
            :candidate_limit
        )
        """
    )


def build_guide_store_inventory_statement() -> TextClause:
    """Return safe counts and version metadata, never embedding values."""

    return text(
        """
        SELECT
            postgresql_version,
            pgvector_version,
            document_count,
            chunk_count,
            embedding_count,
            active_generation_count,
            generation_status,
            embedding_model_id,
            embedding_dimension,
            metric_type
        FROM vector_store.guide_store_inventory(
            CAST(:organization_id AS uuid),
            :guide_id,
            :guide_version,
            :scope_id
        )
        """
    )


def load_guide_store_snapshot(
    session: Session,
    *,
    organization_id: UUID,
    guide_id: str,
    guide_version: str,
    scope_id: str,
) -> GuideStoreSnapshot:
    """Load a read-only UI snapshot inside the caller's organization RLS scope."""

    session.execute(
        text("SELECT set_config('secai.organization_id', :value, true)"),
        {"value": str(organization_id)},
    )
    inventory = session.execute(
        build_guide_store_inventory_statement(),
        {
            "organization_id": str(organization_id),
            "guide_id": guide_id,
            "guide_version": guide_version,
            "scope_id": scope_id,
        },
    ).mappings().one()
    rows = session.execute(
        text(
            """
            SELECT pdf_page_number, control_id, content_text, text_sha256
            FROM guide_content.guide_chunks
            WHERE organization_id = CAST(:organization_id AS uuid)
              AND guide_id = :guide_id
              AND guide_version = :guide_version
              AND scope_id = :scope_id
              AND status = 'READY'
            ORDER BY pdf_page_number, ordinal
            LIMIT 100
            """
        ),
        {
            "organization_id": str(organization_id),
            "guide_id": guide_id,
            "guide_version": guide_version,
            "scope_id": scope_id,
        },
    ).mappings()
    chunks = tuple(
        GuideStoreChunk(
            pdf_page_number=int(row["pdf_page_number"]),
            control_id=str(row["control_id"]),
            text=str(row["content_text"]),
            text_sha256=str(row["text_sha256"]),
        )
        for row in rows
    )
    return GuideStoreSnapshot(
        organization_id=organization_id,
        postgresql_version=str(inventory["postgresql_version"]),
        pgvector_version=str(inventory["pgvector_version"]),
        document_count=int(inventory["document_count"]),
        chunk_count=int(inventory["chunk_count"]),
        embedding_count=int(inventory["embedding_count"]),
        active_generation_count=int(inventory["active_generation_count"]),
        generation_status=str(inventory["generation_status"]),
        embedding_model_id=str(inventory["embedding_model_id"]),
        embedding_dimension=int(inventory["embedding_dimension"]),
        metric_type=str(inventory["metric_type"]),
        guide_id=guide_id,
        guide_version=guide_version,
        scope_id=scope_id,
        chunks=chunks,
    )


def _search_guide_chunks(
    session: Session,
    scope: GuideSearchScope,
    query_vector: list[float] | tuple[float, ...],
    *,
    statement: TextClause,
    expected_dimension: int,
    dense_weight: float = 0.15,
    lexical_weight: float = 0.85,
    candidate_multiplier: int = 4,
    candidate_limit: int = 100,
) -> tuple[GuideSearchHit, ...]:
    """Search an active generation, hydrate authorized text, then rerank."""

    session.execute(
        text("SELECT set_config('secai.organization_id', :value, true)"),
        {"value": str(scope.organization_id)},
    )
    session.execute(
        text("SELECT set_config('secai.allow_synthetic_guide', :value, true)"),
        {"value": "on" if scope.allow_synthetic_test_data else "off"},
    )
    # 결과 설명 검색은 PC 항목을 먼저 고정한 뒤 재정렬한다. 현재 DB 함수는
    # control_id 인자를 받지 않으므로 승인된 단일 가이드의 후보를 모두 가져와
    # 애플리케이션의 권한·control 필터를 먼저 적용한다.
    effective_candidate_limit = (
        candidate_limit
        if scope.control_id is not None
        else min(
            candidate_limit,
            max(scope.top_k * candidate_multiplier, scope.top_k),
        )
    )
    vector_rows = session.execute(
        statement,
        {
            "organization_id": str(scope.organization_id),
            "guide_id": scope.guide_id,
            "guide_version": scope.guide_version,
            "scope_id": scope.scope_id,
            "query_vector": vector_literal(
                query_vector,
                expected_dimension=expected_dimension,
            ),
            "candidate_limit": effective_candidate_limit,
        },
    ).mappings()
    scores = {
        cast(UUID, row["chunk_id"]): float(row["dense_score"])
        for row in vector_rows
    }
    if not scores:
        return ()

    rows = session.execute(
        text(
            """
            SELECT
                chunk_id,
                organization_id,
                guide_id,
                guide_version,
                scope_id,
                pdf_page_number,
                control_id,
                content_text,
                source_sha256,
                text_sha256
            FROM guide_content.guide_chunks
            WHERE organization_id = CAST(:organization_id AS uuid)
              AND guide_id = :guide_id
              AND guide_version = :guide_version
              AND scope_id = :scope_id
              AND status = 'READY'
              AND chunk_id = ANY(CAST(:chunk_ids AS uuid[]))
            """
        ),
        {
            "organization_id": str(scope.organization_id),
            "guide_id": scope.guide_id,
            "guide_version": scope.guide_version,
            "scope_id": scope.scope_id,
            "chunk_ids": [str(chunk_id) for chunk_id in scores],
        },
    ).mappings()
    candidates = tuple(
        GuideSearchCandidate(
            chunk_id=cast(UUID, row["chunk_id"]),
            organization_id=cast(UUID, row["organization_id"]),
            guide_id=str(row["guide_id"]),
            guide_version=str(row["guide_version"]),
            scope_id=str(row["scope_id"]),
            pdf_page_number=int(row["pdf_page_number"]),
            control_id=str(row["control_id"]),
            text=str(row["content_text"]),
            dense_score=scores[cast(UUID, row["chunk_id"])],
            source_sha256=str(row["source_sha256"]),
            text_sha256=str(row["text_sha256"]),
        )
        for row in rows
    )
    return filter_and_rerank(
        scope,
        candidates,
        dense_weight=dense_weight,
        lexical_weight=lexical_weight,
    )


def search_guide_chunks(
    session: Session,
    scope: GuideSearchScope,
    query_vector: list[float] | tuple[float, ...],
) -> tuple[GuideSearchHit, ...]:
    """Search the legacy 32-dimensional deterministic projection."""

    return _search_guide_chunks(
        session,
        scope,
        query_vector,
        statement=build_pgvector_search_statement(),
        expected_dimension=32,
    )


def search_guide_chunks_bge_m3(
    session: Session,
    scope: GuideSearchScope,
    query_vector: list[float] | tuple[float, ...],
    *,
    dense_weight: float = 0.15,
    lexical_weight: float = 0.85,
    candidate_multiplier: int = 4,
    candidate_limit: int = 100,
) -> tuple[GuideSearchHit, ...]:
    """Search the BGE-M3 projection without exposing stored vectors."""

    return _search_guide_chunks(
        session,
        scope,
        query_vector,
        statement=build_bge_m3_search_statement(),
        expected_dimension=1024,
        dense_weight=dense_weight,
        lexical_weight=lexical_weight,
        candidate_multiplier=candidate_multiplier,
        candidate_limit=candidate_limit,
    )
