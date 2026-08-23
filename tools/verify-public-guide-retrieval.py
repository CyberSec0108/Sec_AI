"""공공 가이드 7종의 실제 BGE-M3 검색과 판정 격리를 검증합니다."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

from security_audit.application.model_search import BgeM3Client, ModelSearchSettings
from security_audit.common.secret_files import read_required_secret
from security_audit.guides.public_guides import load_public_guide_manifest
from security_audit.guides.retrieval import vector_literal

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
REPRESENTATIVE_QUERIES = {
    "ncsc-n2sf-security-guideline": "국가 망 보안체계 보안등급 데이터 분류",
    "ncsc-n2sf-security-controls-commentary": "접근통제 인증 권한 관리 보안통제",
    "kisa-zero-trust-guideline": "제로트러스트 지속적 검증 최소 권한",
    "kisa-sw-supply-chain-guideline": "소프트웨어 공급망 SBOM 무결성",
    "kisa-ai-security-guide": "AI 시스템 보안 위협과 보호",
    "kisa-ai-threat-response-manual": "AI 보안 위협 사고 대응 절차",
    "kisa-ai-red-teaming-guide": "AI 레드티밍 공격 테스트",
}


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


def main() -> int:
    manifest = load_public_guide_manifest(PROJECT_ROOT)
    documents_value = manifest.get("documents")
    if not isinstance(documents_value, list) or not all(
        isinstance(document, dict) for document in documents_value
    ):
        raise RuntimeError("PUBLIC_GUIDE_DOCUMENTS_INVALID")
    documents: list[dict[str, Any]] = documents_value
    settings = ModelSearchSettings.from_environment()
    client = BgeM3Client(settings)
    queries = tuple(REPRESENTATIVE_QUERIES[str(item["guide_id"])] for item in documents)
    query_vectors = client.embed_documents(queries)

    results: list[dict[str, object]] = []
    with _connect() as connection, connection.transaction():
        connection.execute(
            "SELECT set_config('secai.organization_id', %s, false)",
            (str(ORGANIZATION_ID),),
        )
        for document, query, query_vector in zip(
            documents,
            queries,
            query_vectors,
            strict=True,
        ):
            guide_id = str(document["guide_id"])
            guide_version = str(document["version"])
            scope_id = str(document["scope_id"])
            inventory = connection.execute(
                """
                SELECT d.id, d.retrieval_role, d.decision_authority,
                       count(DISTINCT c.chunk_id) AS chunks,
                       (SELECT count(*)
                        FROM vector_store.guide_embeddings e
                        JOIN vector_store.guide_vector_generations g
                          ON g.id = e.vector_generation_id
                        WHERE g.document_id = d.id AND e.status = 'READY')
                           AS legacy_embeddings,
                       (SELECT count(*)
                        FROM vector_store.guide_embeddings_bge_m3 e
                        JOIN vector_store.guide_vector_generations g
                          ON g.id = e.vector_generation_id
                        WHERE g.document_id = d.id AND e.status = 'READY')
                           AS bge_embeddings
                FROM guide_content.guide_documents d
                JOIN guide_content.guide_chunks c ON c.document_id = d.id
                WHERE d.organization_id = %s AND d.guide_id = %s
                  AND d.guide_version = %s AND d.scope_id = %s
                  AND c.status = 'READY'
                GROUP BY d.id, d.retrieval_role, d.decision_authority
                """,
                (ORGANIZATION_ID, guide_id, guide_version, scope_id),
            ).fetchone()
            expected = sum(
                1
                for page in json.loads(
                    (
                        PROJECT_ROOT / str(document["page_map_relative_path"])
                    ).read_text(encoding="utf-8")
                )["pages"]
                if page["indexable"]
            )
            if (
                inventory is None
                or inventory["retrieval_role"] != "SUPPLEMENTAL_EXPLANATION"
                or inventory["decision_authority"] is not False
                or inventory["chunks"] != expected
                or inventory["legacy_embeddings"] != expected
                or inventory["bge_embeddings"] != expected
            ):
                raise RuntimeError(f"PUBLIC_GUIDE_INVENTORY_INVALID:{guide_id}")
            hits = connection.execute(
                """
                SELECT found.chunk_id, found.dense_score,
                       chunk.pdf_page_number, chunk.guide_id,
                       chunk.guide_version, chunk.scope_id,
                       chunk.source_sha256, chunk.text_sha256
                FROM vector_store.search_guide_chunks_bge_m3(
                    %s, %s, %s, %s, CAST(%s AS vector), 5
                ) AS found
                JOIN guide_content.guide_chunks AS chunk
                  ON chunk.chunk_id = found.chunk_id
                ORDER BY found.dense_score DESC, chunk.pdf_page_number
                LIMIT 1
                """,
                (
                    ORGANIZATION_ID,
                    guide_id,
                    guide_version,
                    scope_id,
                    vector_literal(query_vector, expected_dimension=1024),
                ),
            ).fetchone()
            if (
                hits is None
                or hits["guide_id"] != guide_id
                or hits["guide_version"] != guide_version
                or hits["scope_id"] != scope_id
                or hits["source_sha256"] != document["source_sha256"]
            ):
                raise RuntimeError(f"PUBLIC_GUIDE_SEARCH_LINEAGE_INVALID:{guide_id}")
            results.append(
                {
                    "guide_id": guide_id,
                    "query": query,
                    "chunks": expected,
                    "top_page": int(hits["pdf_page_number"]),
                    "top_dense_score": round(float(hits["dense_score"]), 6),
                    "retrieval_role": inventory["retrieval_role"],
                    "decision_authority": inventory["decision_authority"],
                }
            )
        official = connection.execute(
            """
            SELECT count(*) AS documents,
                   bool_and(retrieval_role = 'OFFICIAL_CHECK_REFERENCE') AS role_ok,
                   bool_and(decision_authority = false) AS authority_ok
            FROM guide_content.guide_documents
            WHERE organization_id = %s
              AND guide_id = 'kisa-major-infrastructure-detailed-guide'
            """,
            (ORGANIZATION_ID,),
        ).fetchone()
        if (
            official is None
            or int(official["documents"]) < 1
            or official["role_ok"] is not True
            or official["authority_ok"] is not True
        ):
            raise RuntimeError("OFFICIAL_KISA_RETRIEVAL_ROLE_INVALID")

    chunk_count = 0
    for item in results:
        count = item["chunks"]
        if not isinstance(count, int):
            raise RuntimeError("PUBLIC_GUIDE_CHUNK_COUNT_INVALID")
        chunk_count += count

    print(
        json.dumps(
            {
                "status": "VERIFIED",
                "documents": results,
                "document_count": len(results),
                "chunk_count": chunk_count,
                "embedding_dimension": 1024,
                "official_decision_source": "KISA_AUDIT_PACK_ONLY",
                "supplemental_guides_change_findings": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
