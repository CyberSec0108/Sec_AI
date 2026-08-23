"""Build, validate, and atomically activate the pinned BGE-M3 generation."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from uuid import NAMESPACE_URL, UUID, uuid5

import psycopg
from psycopg.rows import dict_row

from security_audit.common.secret_files import read_required_secret
from security_audit.guides.retrieval import ApprovedLocalKoreanEmbedder, vector_literal

ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
MODEL_ID = "BAAI/bge-m3@5617a9f61b028005a4858fdac845db406aefb181"
MODEL_REVISION = "5617a9f61b028005a4858fdac845db406aefb181"
MODEL_WEIGHT_SHA256 = "b5e0ce3470abf5ef3831aa1bd5553b486803e83251590ab7ff35a117cf6aad38"
DIMENSION = 1024


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--embedding-url", default=os.getenv("SECAI_EMBEDDING_URL", "http://embedding-service:80")
    )
    parser.add_argument("--activate", action="store_true")
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--restore-bge", action="store_true")
    return parser.parse_args()


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


def _embed(endpoint: str, text: str) -> list[float]:
    request = Request(  # noqa: S310 - 내부 고정 모델 서비스 URL만 허용
        endpoint.rstrip("/") + "/embed",
        data=json.dumps({"inputs": [text], "normalize": True, "truncate": True}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=120) as response:  # noqa: S310 - 내부 고정 모델 서비스
        value = json.loads(response.read(8 * 1024 * 1024))
    if not isinstance(value, list) or len(value) != 1 or len(value[0]) != DIMENSION:
        raise RuntimeError("BGE-M3 embedding dimension mismatch")
    return [float(item) for item in value[0]]


def _quality_queries(root: Path) -> list[tuple[str, str]]:
    mapping = json.loads(
        (root / "guides/mappings/kisa_2026_pc_control_sources.json").read_text(encoding="utf-8")
    )
    return [
        (str(item["control_id"]), f"{item['control_id']} {item['section_label']}")
        for item in mapping["mappings"]
    ]


def _search(
    connection: psycopg.Connection[dict[str, Any]],
    function: str,
    vector: list[float],
    *,
    guide_id: str,
    guide_version: str,
    scope_id: str,
) -> list[str]:
    rows = connection.execute(
        f"""
        SELECT chunk.control_id
        FROM vector_store.{function}(%s, %s, %s, %s, CAST(%s AS vector), 5) AS hit
        JOIN guide_content.guide_chunks AS chunk ON chunk.chunk_id = hit.chunk_id
        ORDER BY hit.dense_score DESC
        """,  # noqa: S608 - function은 이 파일의 상수만 전달
        (
            ORGANIZATION_ID,
            guide_id,
            guide_version,
            scope_id,
            vector_literal(vector, expected_dimension=len(vector)),
        ),
    ).fetchall()
    return [str(row["control_id"]) for row in rows]


def main() -> int:
    args = _args()
    root = Path(__file__).resolve().parents[1]
    with _connect() as connection:
        connection.execute(
            "SELECT set_config('secai.organization_id', %s, false)", (str(ORGANIZATION_ID),)
        )
        document = connection.execute(
            """
            SELECT id, guide_id, guide_version, scope_id
            FROM guide_content.guide_documents
            WHERE organization_id = %s AND status = 'APPROVED'
            ORDER BY created_at DESC LIMIT 1
            """,
            (ORGANIZATION_ID,),
        ).fetchone()
        if document is None:
            raise RuntimeError("Approved guide document not found")
        if sum((args.activate, args.rollback, args.restore_bge)) > 1:
            raise RuntimeError("Choose only one activation action")
        if args.rollback:
            with connection.transaction():
                legacy = connection.execute(
                    """
                    SELECT id FROM vector_store.guide_vector_generations
                    WHERE organization_id = %s AND document_id = %s
                      AND embedding_dimension = 32 AND status = 'ACTIVE'
                    ORDER BY activated_at DESC LIMIT 1
                    """,
                    (ORGANIZATION_ID, document["id"]),
                ).fetchone()
                if legacy is None:
                    raise RuntimeError("Legacy 32-dimensional generation not found")
                connection.execute(
                    """
                    INSERT INTO vector_store.guide_active_generations_by_dimension
                      (organization_id, guide_id, guide_version, scope_id,
                       embedding_dimension, vector_generation_id, activated_at)
                    VALUES (%s, %s, %s, %s, 32, %s, now())
                    ON CONFLICT (
                        organization_id, guide_id, guide_version,
                        scope_id, embedding_dimension
                    )
                    DO UPDATE SET vector_generation_id = EXCLUDED.vector_generation_id,
                                  activated_at = EXCLUDED.activated_at
                    """,
                    (
                        ORGANIZATION_ID,
                        document["guide_id"],
                        document["guide_version"],
                        document["scope_id"],
                        legacy["id"],
                    ),
                )
            print(json.dumps({"status": "ROLLED_BACK", "search_mode": "LEGACY_LOCAL"}))
            return 0
        if args.restore_bge:
            with connection.transaction():
                bge = connection.execute(
                    """
                    SELECT id FROM vector_store.guide_vector_generations
                    WHERE organization_id = %s AND document_id = %s
                      AND embedding_dimension = 1024 AND status IN ('READY', 'ACTIVE')
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (ORGANIZATION_ID, document["id"]),
                ).fetchone()
                if bge is None:
                    raise RuntimeError("Validated 1024-dimensional generation not found")
                connection.execute(
                    """
                    UPDATE vector_store.guide_vector_generations
                    SET status = 'ACTIVE', activated_at = now()
                    WHERE id = %s
                    """,
                    (bge["id"],),
                )
                connection.execute(
                    """
                    INSERT INTO vector_store.guide_active_generations_by_dimension
                      (organization_id, guide_id, guide_version, scope_id,
                       embedding_dimension, vector_generation_id, activated_at)
                    VALUES (%s, %s, %s, %s, 1024, %s, now())
                    ON CONFLICT (
                        organization_id, guide_id, guide_version,
                        scope_id, embedding_dimension
                    )
                    DO UPDATE SET vector_generation_id = EXCLUDED.vector_generation_id,
                                  activated_at = EXCLUDED.activated_at
                    """,
                    (
                        ORGANIZATION_ID,
                        document["guide_id"],
                        document["guide_version"],
                        document["scope_id"],
                        bge["id"],
                    ),
                )
            print(
                json.dumps(
                    {
                        "status": "BGE_RESTORED",
                        "search_mode": "BGE_M3_WITH_LEGACY_FALLBACK",
                        "generation_id": str(bge["id"]),
                    }
                )
            )
            return 0

        generation_id = uuid5(NAMESPACE_URL, f"secai-guide-generation:{document['id']}|{MODEL_ID}")
        chunks = connection.execute(
            """
            SELECT chunk_id, content_text, text_sha256
            FROM guide_content.guide_chunks
            WHERE document_id = %s AND status = 'READY'
            ORDER BY ordinal
            """,
            (document["id"],),
        ).fetchall()
        with connection.transaction():
            connection.execute(
                """
                INSERT INTO vector_store.guide_vector_generations
                  (id, organization_id, document_id, embedding_model_id,
                   embedding_dimension, metric_type, status)
                VALUES (%s, %s, %s, %s, 1024, 'COSINE', 'BUILDING')
                ON CONFLICT (organization_id, document_id, embedding_model_id)
                DO UPDATE SET status = 'BUILDING', activated_at = NULL
                """,
                (generation_id, ORGANIZATION_ID, document["id"], MODEL_ID),
            )
        started = time.perf_counter()
        for chunk in chunks:
            embedding = _embed(args.embedding_url, str(chunk["content_text"]))
            with connection.transaction():
                connection.execute(
                    """
                    INSERT INTO vector_store.guide_embeddings_bge_m3
                      (vector_generation_id, chunk_id, organization_id,
                       content_fingerprint, status, embedding)
                    VALUES (%s, %s, %s, %s, 'READY', CAST(%s AS vector))
                    ON CONFLICT (vector_generation_id, chunk_id) DO UPDATE SET
                      content_fingerprint = EXCLUDED.content_fingerprint,
                      status = 'READY', embedding = EXCLUDED.embedding
                    """,
                    (
                        generation_id,
                        chunk["chunk_id"],
                        ORGANIZATION_ID,
                        chunk["text_sha256"],
                        vector_literal(embedding, expected_dimension=DIMENSION),
                    ),
                )
        with connection.transaction():
            count_row = connection.execute(
                "SELECT count(*) AS value "
                "FROM vector_store.guide_embeddings_bge_m3 "
                "WHERE vector_generation_id = %s AND status = 'READY'",
                (generation_id,),
            ).fetchone()
            if count_row is None:
                raise RuntimeError("BGE-M3 generation count could not be read")
            count = count_row["value"]
            if count != len(chunks):
                raise RuntimeError("BGE-M3 generation coverage mismatch")
            # 품질 비교 함수는 ACTIVE 세대만 조회합니다. 애플리케이션 모드는 아직
            # LEGACY_LOCAL이므로 검증 중 1024 세대가 사용자 검색에 노출되지는 않습니다.
            connection.execute(
                "UPDATE vector_store.guide_vector_generations SET status = 'ACTIVE' WHERE id = %s",
                (generation_id,),
            )
            connection.execute(
                """
                INSERT INTO vector_store.guide_active_generations_by_dimension
                  (organization_id, guide_id, guide_version, scope_id,
                   embedding_dimension, vector_generation_id, activated_at)
                VALUES (%s, %s, %s, %s, 1024, %s, now())
                ON CONFLICT (
                    organization_id, guide_id, guide_version,
                    scope_id, embedding_dimension
                )
                DO UPDATE SET vector_generation_id = EXCLUDED.vector_generation_id,
                              activated_at = EXCLUDED.activated_at
                """,
                (
                    ORGANIZATION_ID,
                    document["guide_id"],
                    document["guide_version"],
                    document["scope_id"],
                    generation_id,
                ),
            )

        legacy_embedder = ApprovedLocalKoreanEmbedder()
        bge_hits = legacy_hits = 0
        bge_ms = legacy_ms = 0.0
        for expected, query in _quality_queries(root):
            began = time.perf_counter()
            bge_result = _search(
                connection,
                "search_guide_chunks_bge_m3",
                _embed(args.embedding_url, query),
                guide_id=document["guide_id"],
                guide_version=document["guide_version"],
                scope_id=document["scope_id"],
            )
            bge_ms += (time.perf_counter() - began) * 1000
            began = time.perf_counter()
            legacy_result = _search(
                connection,
                "search_guide_chunks",
                legacy_embedder.embed(query),
                guide_id=document["guide_id"],
                guide_version=document["guide_version"],
                scope_id=document["scope_id"],
            )
            legacy_ms += (time.perf_counter() - began) * 1000
            bge_hits += expected in bge_result
            legacy_hits += expected in legacy_result
        query_count = len(_quality_queries(root))
        passed = bge_hits >= legacy_hits and bge_hits / query_count >= 0.9
        with connection.transaction():
            connection.execute(
                "UPDATE vector_store.guide_vector_generations SET status = %s, "
                "activated_at = CASE WHEN %s THEN now() ELSE NULL END "
                "WHERE id = %s",
                (
                    "ACTIVE" if args.activate and passed else "READY",
                    args.activate and passed,
                    generation_id,
                ),
            )
        output = {
            "status": "ACTIVE" if args.activate and passed else "VALIDATED",
            "generation_id": str(generation_id),
            "model_id": MODEL_ID,
            "revision": MODEL_REVISION,
            "weight_sha256": MODEL_WEIGHT_SHA256,
            "dimension": DIMENSION,
            "chunks": len(chunks),
            "build_seconds": round(time.perf_counter() - started, 3),
            "quality": {
                "queries": query_count,
                "bge_recall_at_5": bge_hits / query_count,
                "legacy_recall_at_5": legacy_hits / query_count,
                "bge_average_ms": bge_ms / query_count,
                "legacy_average_ms": legacy_ms / query_count,
                "passed": passed,
            },
        }
        print(json.dumps(output, ensure_ascii=False, sort_keys=True))
        return 0 if passed else 3


if __name__ == "__main__":
    raise SystemExit(main())
