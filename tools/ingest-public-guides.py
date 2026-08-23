"""승인된 공공기관 보완 가이드의 32/1,024차원 검색 세대를 적재합니다."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

import psycopg
from psycopg.rows import dict_row

from security_audit.application.model_search import BgeM3Client, ModelSearchSettings
from security_audit.common.secret_files import read_required_secret
from security_audit.guides.contracts import load_json_strict
from security_audit.guides.ingestion import scan_pdf_with_clamav
from security_audit.guides.public_guides import (
    extract_public_guide_pages,
    load_public_guide_manifest,
    public_guide_page_map_path,
    verify_public_guide_sources,
)
from security_audit.guides.retrieval import (
    ApprovedLocalKoreanEmbedder,
    GuideChunk,
    GuideIngestGateInput,
    build_guide_chunks,
    vector_literal,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
BGE_MODEL_ID = "BAAI/bge-m3@5617a9f61b028005a4858fdac845db406aefb181"
BGE_DIMENSION = 1024
EMBEDDING_BATCH_SIZE = 16


@dataclass(frozen=True, slots=True)
class PreparedGuide:
    document: dict[str, Any]
    chunks: tuple[GuideChunk, ...]
    legacy_vectors: tuple[list[float], ...]
    bge_vectors: tuple[list[float], ...]
    clamav_engine: str


def _required(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if not value:
        raise RuntimeError(f"Required setting is missing: {name}")
    return value


def _connect() -> psycopg.Connection[dict[str, Any]]:
    return psycopg.connect(
        host=_required("SECAI_POSTGRES_HOST", "postgres"),
        port=int(_required("SECAI_POSTGRES_PORT", "5432")),
        dbname=_required("SECAI_POSTGRES_DB", "secai"),
        user=_required("SECAI_POSTGRES_USER", "secai_app"),
        password=read_required_secret(
            _required("SECAI_POSTGRES_PASSWORD_FILE", "/run/secrets/postgres_password")
        ),
        row_factory=dict_row,
    )


def _executemany(
    connection: psycopg.Connection[dict[str, Any]],
    query: str,
    params_seq: list[tuple[object, ...]],
) -> None:
    with connection.cursor() as cursor:
        cursor.executemany(query, params_seq)


def _prepare(document: dict[str, Any], bge: BgeM3Client) -> PreparedGuide:
    if document.get("status") != "APPROVED":
        raise RuntimeError(f"PUBLIC_GUIDE_NOT_APPROVED:{document.get('guide_id')}")
    source_path = PROJECT_ROOT / str(document["relative_path"])
    scan = scan_pdf_with_clamav(
        source_path,
        host=_required("SECAI_CLAMAV_HOST", "clamav"),
        port=int(_required("SECAI_CLAMAV_PORT", "3310")),
    )
    if not scan.accepted or scan.source_sha256 != document["source_sha256"]:
        raise RuntimeError(f"PUBLIC_GUIDE_MALWARE_GATE_FAILED:{document['guide_id']}")
    page_map = load_json_strict(public_guide_page_map_path(PROJECT_ROOT, document))
    pages = extract_public_guide_pages(PROJECT_ROOT, document, page_map)
    gate = GuideIngestGateInput(
        guide_status="APPROVED",
        license_status="APPROVED",
        derivative_text_storage_allowed=True,
        source_hash_verified=True,
        page_map_verified=True,
        malware_scan_passed=True,
        extraction_quality_approved=True,
        query_scope_enabled=True,
        synthetic_test_only=False,
    )
    chunks = build_guide_chunks(
        organization_id=ORGANIZATION_ID,
        guide_id=str(document["guide_id"]),
        guide_version=str(document["version"]),
        source_sha256=str(document["source_sha256"]),
        scope_id=str(document["scope_id"]),
        pages=pages,
        gate=gate,
    )
    legacy = ApprovedLocalKoreanEmbedder()
    legacy_vectors = tuple(legacy.embed(chunk.text) for chunk in chunks)
    bge_vectors: list[list[float]] = []
    for start in range(0, len(chunks), EMBEDDING_BATCH_SIZE):
        batch = tuple(
            chunk.text for chunk in chunks[start : start + EMBEDDING_BATCH_SIZE]
        )
        bge_vectors.extend(bge.embed_documents(batch))
    if len(bge_vectors) != len(chunks):
        raise RuntimeError(f"PUBLIC_GUIDE_BGE_COVERAGE_MISMATCH:{document['guide_id']}")
    return PreparedGuide(
        document=document,
        chunks=chunks,
        legacy_vectors=legacy_vectors,
        bge_vectors=tuple(bge_vectors),
        clamav_engine=scan.engine,
    )


def _activate_guide(
    connection: psycopg.Connection[dict[str, Any]],
    prepared: PreparedGuide,
) -> dict[str, object]:
    document = prepared.document
    guide_id = str(document["guide_id"])
    guide_version = str(document["version"])
    source_sha256 = str(document["source_sha256"])
    scope_id = str(document["scope_id"])
    document_id = uuid5(
        NAMESPACE_URL,
        f"secai-guide-document:{ORGANIZATION_ID}|{guide_id}|{guide_version}|{scope_id}",
    )
    legacy = ApprovedLocalKoreanEmbedder()
    legacy_generation_id = uuid5(
        NAMESPACE_URL,
        f"secai-guide-generation:{document_id}|{legacy.model_id}",
    )
    bge_generation_id = uuid5(
        NAMESPACE_URL,
        f"secai-guide-generation:{document_id}|{BGE_MODEL_ID}",
    )

    existing = connection.execute(
        """
        SELECT id, source_sha256
        FROM guide_content.guide_documents
        WHERE organization_id = %s AND guide_id = %s
          AND guide_version = %s AND scope_id = %s
        """,
        (ORGANIZATION_ID, guide_id, guide_version, scope_id),
    ).fetchone()
    if existing is not None and (
        existing["id"] != document_id or existing["source_sha256"] != source_sha256
    ):
        raise RuntimeError(f"PUBLIC_GUIDE_VERSION_ROLLOVER_REQUIRED:{guide_id}")

    connection.execute(
        """
        INSERT INTO guide_content.guide_documents (
            id, organization_id, guide_id, guide_version, source_sha256,
            scope_id, status, license_status,
            derivative_text_storage_allowed, malware_scan_status,
            extraction_quality_status, classification,
            retrieval_role, decision_authority
        ) VALUES (
            %s, %s, %s, %s, %s, %s, 'APPROVED', 'APPROVED',
            true, 'CLEAN', 'APPROVED', 'PUBLIC_SOURCE_INTERNAL_APPROVED',
            'SUPPLEMENTAL_EXPLANATION', false
        )
        ON CONFLICT (organization_id, guide_id, guide_version, scope_id)
        DO UPDATE SET
            retrieval_role = 'SUPPLEMENTAL_EXPLANATION',
            decision_authority = false
        """,
        (
            document_id,
            ORGANIZATION_ID,
            guide_id,
            guide_version,
            source_sha256,
            scope_id,
        ),
    )
    _executemany(
        connection,
        """
        INSERT INTO guide_content.guide_chunks (
            chunk_id, document_id, organization_id, guide_id,
            guide_version, source_sha256, scope_id, pdf_page_number,
            control_id, ordinal, content_text, text_sha256,
            chunker_version, status
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            'public-page-text-v1', 'READY'
        )
        ON CONFLICT (chunk_id) DO NOTHING
        """,
        [
            (
                chunk.chunk_id,
                document_id,
                ORGANIZATION_ID,
                guide_id,
                guide_version,
                source_sha256,
                scope_id,
                chunk.pdf_page_number,
                chunk.control_id,
                chunk.ordinal,
                chunk.text,
                chunk.text_sha256,
            )
            for chunk in prepared.chunks
        ],
    )
    connection.execute(
        """
        INSERT INTO vector_store.guide_vector_generations (
            id, organization_id, document_id, embedding_model_id,
            embedding_dimension, metric_type, status, activated_at
        ) VALUES (%s, %s, %s, %s, 32, 'COSINE', 'ACTIVE', now())
        ON CONFLICT (organization_id, document_id, embedding_model_id)
        DO UPDATE SET status = 'ACTIVE', activated_at = now()
        """,
        (legacy_generation_id, ORGANIZATION_ID, document_id, legacy.model_id),
    )
    _executemany(
        connection,
        """
        INSERT INTO vector_store.guide_embeddings (
            vector_generation_id, chunk_id, organization_id,
            content_fingerprint, status, embedding
        ) VALUES (%s, %s, %s, %s, 'READY', CAST(%s AS vector))
        ON CONFLICT (vector_generation_id, chunk_id) DO UPDATE SET
            content_fingerprint = EXCLUDED.content_fingerprint,
            status = 'READY', embedding = EXCLUDED.embedding
        """,
        [
            (
                legacy_generation_id,
                chunk.chunk_id,
                ORGANIZATION_ID,
                chunk.text_sha256,
                vector_literal(vector),
            )
            for chunk, vector in zip(
                prepared.chunks,
                prepared.legacy_vectors,
                strict=True,
            )
        ],
    )
    connection.execute(
        """
        INSERT INTO vector_store.guide_vector_generations (
            id, organization_id, document_id, embedding_model_id,
            embedding_dimension, metric_type, status, activated_at
        ) VALUES (%s, %s, %s, %s, 1024, 'COSINE', 'ACTIVE', now())
        ON CONFLICT (organization_id, document_id, embedding_model_id)
        DO UPDATE SET status = 'ACTIVE', activated_at = now()
        """,
        (bge_generation_id, ORGANIZATION_ID, document_id, BGE_MODEL_ID),
    )
    _executemany(
        connection,
        """
        INSERT INTO vector_store.guide_embeddings_bge_m3 (
            vector_generation_id, chunk_id, organization_id,
            content_fingerprint, status, embedding
        ) VALUES (%s, %s, %s, %s, 'READY', CAST(%s AS vector))
        ON CONFLICT (vector_generation_id, chunk_id) DO UPDATE SET
            content_fingerprint = EXCLUDED.content_fingerprint,
            status = 'READY', embedding = EXCLUDED.embedding
        """,
        [
            (
                bge_generation_id,
                chunk.chunk_id,
                ORGANIZATION_ID,
                chunk.text_sha256,
                vector_literal(vector, expected_dimension=BGE_DIMENSION),
            )
            for chunk, vector in zip(
                prepared.chunks,
                prepared.bge_vectors,
                strict=True,
            )
        ],
    )
    connection.execute(
        """
        INSERT INTO vector_store.guide_active_generations (
            organization_id, guide_id, guide_version, scope_id,
            vector_generation_id, activated_at
        ) VALUES (%s, %s, %s, %s, %s, now())
        ON CONFLICT (organization_id, guide_id, guide_version, scope_id)
        DO UPDATE SET vector_generation_id = EXCLUDED.vector_generation_id,
                      activated_at = EXCLUDED.activated_at
        """,
        (
            ORGANIZATION_ID,
            guide_id,
            guide_version,
            scope_id,
            legacy_generation_id,
        ),
    )
    for dimension, generation_id in (
        (32, legacy_generation_id),
        (1024, bge_generation_id),
    ):
        connection.execute(
            """
            INSERT INTO vector_store.guide_active_generations_by_dimension (
                organization_id, guide_id, guide_version, scope_id,
                embedding_dimension, vector_generation_id, activated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, now())
            ON CONFLICT (
                organization_id, guide_id, guide_version, scope_id,
                embedding_dimension
            ) DO UPDATE SET vector_generation_id = EXCLUDED.vector_generation_id,
                            activated_at = EXCLUDED.activated_at
            """,
            (
                ORGANIZATION_ID,
                guide_id,
                guide_version,
                scope_id,
                dimension,
                generation_id,
            ),
        )

    counts = connection.execute(
        """
        SELECT
          (SELECT count(*) FROM guide_content.guide_chunks
           WHERE document_id = %s AND status = 'READY') AS chunks,
          (SELECT count(*) FROM vector_store.guide_embeddings
           WHERE vector_generation_id = %s AND status = 'READY') AS legacy_embeddings,
          (SELECT count(*) FROM vector_store.guide_embeddings_bge_m3
           WHERE vector_generation_id = %s AND status = 'READY') AS bge_embeddings
        """,
        (document_id, legacy_generation_id, bge_generation_id),
    ).fetchone()
    expected = len(prepared.chunks)
    if counts is None or any(
        counts[key] != expected
        for key in ("chunks", "legacy_embeddings", "bge_embeddings")
    ):
        raise RuntimeError(f"PUBLIC_GUIDE_DATABASE_COVERAGE_MISMATCH:{guide_id}")
    return {
        "guide_id": guide_id,
        "version": guide_version,
        "scope_id": scope_id,
        "chunks": expected,
        "legacy_embeddings": expected,
        "bge_embeddings": expected,
        "decision_authority": False,
        "retrieval_role": "SUPPLEMENTAL_EXPLANATION",
        "clamav_engine": prepared.clamav_engine,
    }


def main() -> int:
    manifest = load_public_guide_manifest(PROJECT_ROOT)
    source_report = verify_public_guide_sources(PROJECT_ROOT, manifest)
    if not source_report.accepted:
        raise RuntimeError("PUBLIC_GUIDE_SOURCE_GATE_FAILED:" + ",".join(source_report.errors))
    documents = manifest["documents"]
    if not isinstance(documents, list) or not all(
        isinstance(document, dict) for document in documents
    ):
        raise RuntimeError("PUBLIC_GUIDE_DOCUMENTS_INVALID")
    settings = ModelSearchSettings.from_environment()
    bge = BgeM3Client(settings)
    prepared = tuple(_prepare(document, bge) for document in documents)

    summaries: list[dict[str, object]] = []
    with _connect() as connection, connection.transaction():
        connection.execute(
            "SELECT set_config('secai.organization_id', %s, false)",
            (str(ORGANIZATION_ID),),
        )
        summaries.extend(_activate_guide(connection, item) for item in prepared)
    chunk_count = 0
    for item in summaries:
        value = item["chunks"]
        if not isinstance(value, int):
            raise RuntimeError("PUBLIC_GUIDE_CHUNK_COUNT_INVALID")
        chunk_count += value
    print(
        json.dumps(
            {
                "status": "INGESTED",
                "documents": summaries,
                "document_count": len(summaries),
                "chunk_count": chunk_count,
                "embedding_dimensions": [32, 1024],
                "official_finding_write_allowed": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
