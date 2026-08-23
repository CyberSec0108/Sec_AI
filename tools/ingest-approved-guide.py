"""승인된 KISA 2026 상세가이드의 전체 분류 페이지를 검증·적재한다."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, cast
from uuid import NAMESPACE_URL, UUID, uuid5

import psycopg
from psycopg.rows import dict_row

from security_audit.common.secret_files import read_required_secret
from security_audit.guides.ingestion import inspect_guide_pdf, scan_pdf_with_clamav
from security_audit.guides.retrieval import (
    ApprovedLocalKoreanEmbedder,
    GuideIngestGateInput,
    build_guide_chunks,
    vector_literal,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = PROJECT_ROOT / "guides" / "catalog.json"
PAGE_MAP_PATH = PROJECT_ROOT / "guides" / "page_maps" / "kisa_2026_all_pages.json"
ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")


def _load_json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"Expected an object in {path.name}.")
    return cast(dict[str, Any], loaded)


def _required(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if not value:
        raise RuntimeError(f"Required setting is missing: {name}.")
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


def main() -> int:
    catalog = _load_json(CATALOG_PATH)
    page_map = _load_json(PAGE_MAP_PATH)
    guide = cast(dict[str, Any], catalog["guides"][0])
    source = cast(dict[str, Any], guide["source"])
    scopes = cast(list[dict[str, Any]], guide["query_scopes"])
    scope = next(item for item in scopes if item["scope_id"] == "kisa-2026-all")
    gates = cast(dict[str, Any], guide["gates"])
    license_policy = cast(dict[str, Any], guide["license_policy"])
    source_path = PROJECT_ROOT / cast(str, source["relative_path"])

    quality = inspect_guide_pdf(source_path, page_map)
    if not quality.accepted:
        raise RuntimeError("Guide extraction quality gate failed: " + ",".join(quality.errors))
    malware = scan_pdf_with_clamav(
        source_path,
        host=_required("SECAI_CLAMAV_HOST", "clamav"),
        port=int(_required("SECAI_CLAMAV_PORT", "3310")),
    )
    if not malware.accepted:
        raise RuntimeError("Guide malware gate failed.")

    gate = GuideIngestGateInput(
        guide_status=cast(str, guide["status"]),
        license_status=cast(str, license_policy["status"]),
        derivative_text_storage_allowed=cast(
            bool, license_policy["derivative_text_storage_allowed"]
        ),
        source_hash_verified=cast(bool, gates["source_hash_verified"]),
        page_map_verified=cast(bool, gates["page_map_verified"]),
        malware_scan_passed=malware.accepted,
        extraction_quality_approved=quality.accepted,
        query_scope_enabled=cast(bool, scope["default_enabled"]),
        synthetic_test_only=False,
    )
    guide_id = cast(str, guide["guide_id"])
    guide_version = cast(str, guide["version"])
    source_sha256 = cast(str, source["source_sha256"])
    scope_id = cast(str, scope["scope_id"])
    chunks = build_guide_chunks(
        organization_id=ORGANIZATION_ID,
        guide_id=guide_id,
        guide_version=guide_version,
        source_sha256=source_sha256,
        scope_id=scope_id,
        pages=quality.pages,
        gate=gate,
    )
    embedder = ApprovedLocalKoreanEmbedder()
    document_id = uuid5(
        NAMESPACE_URL,
        f"secai-guide-document:{ORGANIZATION_ID}|{guide_id}|{guide_version}|{scope_id}",
    )
    generation_id = uuid5(
        NAMESPACE_URL,
        f"secai-guide-generation:{document_id}|{embedder.model_id}",
    )

    with _connect() as connection, connection.transaction():
        connection.execute(
            "SELECT set_config('secai.organization_id', %s, false)",
            (str(ORGANIZATION_ID),),
        )
        existing_document = connection.execute(
            """
            SELECT id, source_sha256
            FROM guide_content.guide_documents
            WHERE organization_id = %s
              AND guide_id = %s
              AND guide_version = %s
              AND scope_id = %s
            """,
            (ORGANIZATION_ID, guide_id, guide_version, scope_id),
        ).fetchone()
        if existing_document is not None and (
            existing_document["id"] != document_id
            or existing_document["source_sha256"] != source_sha256
        ):
            raise RuntimeError("Existing guide identity differs; version rollover is required.")
        connection.execute(
            """
            INSERT INTO guide_content.guide_documents (
                id, organization_id, guide_id, guide_version, source_sha256,
                scope_id, status, license_status,
                derivative_text_storage_allowed, malware_scan_status,
                extraction_quality_status, classification
            ) VALUES (
                %s, %s, %s, %s, %s, %s, 'APPROVED', 'APPROVED',
                true, 'CLEAN', 'APPROVED', 'PUBLIC_SOURCE_INTERNAL_APPROVED'
            )
            ON CONFLICT (organization_id, guide_id, guide_version, scope_id)
            DO NOTHING
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
        for chunk in chunks:
            connection.execute(
                """
                INSERT INTO guide_content.guide_chunks (
                    chunk_id, document_id, organization_id, guide_id,
                    guide_version, source_sha256, scope_id, pdf_page_number,
                    control_id, ordinal, content_text, text_sha256,
                    chunker_version, status
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    'page-text-v1', 'READY'
                )
                ON CONFLICT (chunk_id) DO NOTHING
                """,
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
                ),
            )
        connection.execute(
            """
            INSERT INTO vector_store.guide_vector_generations (
                id, organization_id, document_id, embedding_model_id,
                embedding_dimension, metric_type, status, activated_at
            ) VALUES (%s, %s, %s, %s, %s, 'COSINE', 'ACTIVE', now())
            ON CONFLICT (organization_id, document_id, embedding_model_id)
            DO UPDATE SET status = 'ACTIVE', activated_at = now()
            """,
            (
                generation_id,
                ORGANIZATION_ID,
                document_id,
                embedder.model_id,
                embedder.dimension,
            ),
        )
        for chunk in chunks:
            connection.execute(
                """
                INSERT INTO vector_store.guide_embeddings (
                    vector_generation_id, chunk_id, organization_id,
                    content_fingerprint, status, embedding
                ) VALUES (%s, %s, %s, %s, 'READY', CAST(%s AS vector))
                ON CONFLICT (vector_generation_id, chunk_id)
                DO UPDATE SET
                    content_fingerprint = EXCLUDED.content_fingerprint,
                    status = EXCLUDED.status,
                    embedding = EXCLUDED.embedding
                """,
                (
                    generation_id,
                    chunk.chunk_id,
                    ORGANIZATION_ID,
                    chunk.text_sha256,
                    vector_literal(embedder.embed(chunk.text)),
                ),
            )
        connection.execute(
            """
            INSERT INTO vector_store.guide_active_generations (
                organization_id, guide_id, guide_version, scope_id,
                vector_generation_id, activated_at
            ) VALUES (%s, %s, %s, %s, %s, now())
            ON CONFLICT (organization_id, guide_id, guide_version, scope_id)
            DO UPDATE SET
                vector_generation_id = EXCLUDED.vector_generation_id,
                activated_at = EXCLUDED.activated_at
            """,
            (ORGANIZATION_ID, guide_id, guide_version, scope_id, generation_id),
        )
        connection.execute(
            """
            INSERT INTO vector_store.guide_active_generations_by_dimension (
                organization_id, guide_id, guide_version, scope_id,
                embedding_dimension, vector_generation_id, activated_at
            ) VALUES (%s, %s, %s, %s, 32, %s, now())
            ON CONFLICT (
                organization_id, guide_id, guide_version, scope_id,
                embedding_dimension
            ) DO UPDATE SET
                vector_generation_id = EXCLUDED.vector_generation_id,
                activated_at = EXCLUDED.activated_at
            """,
            (ORGANIZATION_ID, guide_id, guide_version, scope_id, generation_id),
        )
        counts = connection.execute(
            """
            SELECT
                (SELECT count(*) FROM guide_content.guide_chunks
                 WHERE document_id = %s AND status = 'READY') AS chunks,
                (SELECT count(*) FROM vector_store.guide_embeddings
                 WHERE vector_generation_id = %s AND status = 'READY') AS embeddings
            """,
            (document_id, generation_id),
        ).fetchone()
        expected_count = len(chunks)
        if (
            counts is None
            or counts["chunks"] != expected_count
            or counts["embeddings"] != expected_count
        ):
            raise RuntimeError("승인된 전체 분류 페이지의 정확한 적재 개수에 도달하지 못했습니다.")

    print(
        json.dumps(
            {
                "status": "INGESTED",
                "source_sha256": source_sha256,
                "malware_status": malware.status,
                "extraction_mode": quality.extraction_mode,
                "ocr_required_pages": quality.ocr_required_pages,
                "page_count": len(chunks),
                "embedding_count": len(chunks),
                "embedding_model_id": embedder.model_id,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
