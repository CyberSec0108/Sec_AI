from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy.dialects import postgresql

from security_audit.guides.retrieval import (
    DeterministicTestEmbedder,
    GuideIngestGateInput,
    GuidePageText,
    GuideSearchCandidate,
    GuideSearchScope,
    build_guide_chunks,
    evaluate_ingest_gate,
    filter_and_rerank,
    vector_literal,
)
from security_audit.persistence.database.guide_repository import (
    build_pgvector_search_statement,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ORGANIZATION_ID = UUID("48000000-0000-4000-8000-000000000001")
OTHER_ORGANIZATION_ID = UUID("48000000-0000-4000-8000-000000000002")


def _approved_synthetic_gate() -> GuideIngestGateInput:
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


def _scope() -> GuideSearchScope:
    return GuideSearchScope(
        organization_id=ORGANIZATION_ID,
        guide_id="synthetic-kisa-pc-guide",
        guide_version="test-1",
        scope_id="pc-pages",
        query="비밀번호 변경 주기",
        top_k=3,
        allow_synthetic_test_data=True,
    )


def test_unapproved_real_kisa_source_remains_blocked_from_ingest() -> None:
    result = evaluate_ingest_gate(
        GuideIngestGateInput(
            guide_status="DRAFT",
            license_status="REVIEW_REQUIRED",
            derivative_text_storage_allowed=False,
            source_hash_verified=True,
            page_map_verified=True,
            malware_scan_passed=False,
            extraction_quality_approved=False,
            query_scope_enabled=False,
            synthetic_test_only=False,
        )
    )

    assert not result.accepted
    assert set(result.errors) == {
        "DERIVATIVE_TEXT_STORAGE_NOT_ALLOWED",
        "EXTRACTION_QUALITY_NOT_APPROVED",
        "GUIDE_NOT_APPROVED",
        "LICENSE_NOT_APPROVED",
        "MALWARE_SCAN_REQUIRED",
        "QUERY_SCOPE_DISABLED",
    }


def test_synthetic_test_gate_cannot_bypass_a_real_draft_guide() -> None:
    changed = _approved_synthetic_gate()
    changed = GuideIngestGateInput(
        guide_status="DRAFT",
        license_status=changed.license_status,
        derivative_text_storage_allowed=changed.derivative_text_storage_allowed,
        source_hash_verified=changed.source_hash_verified,
        page_map_verified=changed.page_map_verified,
        malware_scan_passed=changed.malware_scan_passed,
        extraction_quality_approved=changed.extraction_quality_approved,
        query_scope_enabled=changed.query_scope_enabled,
        synthetic_test_only=True,
    )

    result = evaluate_ingest_gate(changed)

    assert not result.accepted
    assert result.errors == ("SYNTHETIC_GATE_IDENTITY_INVALID",)


def test_approved_synthetic_pages_build_deterministic_page_lineage() -> None:
    pages = (
        GuidePageText(555, "PC-01", "비밀번호는 정해진 주기에 따라 변경합니다."),
        GuidePageText(557, "PC-02", "비밀번호 길이와 복잡성 기준을 확인합니다."),
    )

    first = build_guide_chunks(
        organization_id=ORGANIZATION_ID,
        guide_id="synthetic-kisa-pc-guide",
        guide_version="test-1",
        source_sha256="a" * 64,
        scope_id="pc-pages",
        pages=pages,
        gate=_approved_synthetic_gate(),
    )
    repeated = build_guide_chunks(
        organization_id=ORGANIZATION_ID,
        guide_id="synthetic-kisa-pc-guide",
        guide_version="test-1",
        source_sha256="a" * 64,
        scope_id="pc-pages",
        pages=tuple(reversed(tuple(reversed(pages)))),
        gate=_approved_synthetic_gate(),
    )

    assert first == repeated
    assert [chunk.pdf_page_number for chunk in first] == [555, 557]
    assert [chunk.control_id for chunk in first] == ["PC-01", "PC-02"]
    assert len({chunk.chunk_id for chunk in first}) == 2
    assert all(len(chunk.text_sha256) == 64 for chunk in first)


def test_chunk_build_rejects_unapproved_gate_and_duplicate_pages() -> None:
    with pytest.raises(ValueError, match="GUIDE_INGEST_BLOCKED"):
        build_guide_chunks(
            organization_id=ORGANIZATION_ID,
            guide_id="kisa-real",
            guide_version="2026",
            source_sha256="a" * 64,
            scope_id="pc-pages",
            pages=(GuidePageText(555, "PC-01", "원문"),),
            gate=GuideIngestGateInput(
                guide_status="DRAFT",
                license_status="REVIEW_REQUIRED",
                derivative_text_storage_allowed=False,
                source_hash_verified=True,
                page_map_verified=True,
                malware_scan_passed=False,
                extraction_quality_approved=False,
                query_scope_enabled=False,
                synthetic_test_only=False,
            ),
        )

    with pytest.raises(ValueError, match="PAGE_ORDER_OR_DUPLICATE_INVALID"):
        build_guide_chunks(
            organization_id=ORGANIZATION_ID,
            guide_id="synthetic-kisa-pc-guide",
            guide_version="test-1",
            source_sha256="a" * 64,
            scope_id="pc-pages",
            pages=(
                GuidePageText(555, "PC-01", "첫 문장"),
                GuidePageText(555, "PC-01", "중복 문장"),
            ),
            gate=_approved_synthetic_gate(),
        )


def test_test_embedder_is_normalized_and_deterministic_across_100_runs() -> None:
    embedder = DeterministicTestEmbedder()

    vectors = {
        tuple(embedder.embed("비밀번호 변경 주기와 안전한 계정 설정"))
        for _ in range(100)
    }

    assert embedder.dimension == 32
    assert embedder.model_id == "secai-hash-ko-test-v1"
    assert len(vectors) == 1
    vector = next(iter(vectors))
    assert len(vector) == 32
    assert sum(value * value for value in vector) == pytest.approx(1.0)
    assert vector_literal(vector).startswith("[")
    assert vector_literal(vector).endswith("]")


def test_scope_filter_and_reranker_exclude_other_organization_and_scope() -> None:
    scope = _scope()
    candidates = (
        GuideSearchCandidate(
            chunk_id=UUID("48000000-0000-4000-8000-000000000011"),
            organization_id=ORGANIZATION_ID,
            guide_id=scope.guide_id,
            guide_version=scope.guide_version,
            scope_id=scope.scope_id,
            pdf_page_number=555,
            control_id="PC-01",
            text="비밀번호 변경 주기를 확인합니다.",
            dense_score=0.70,
        ),
        GuideSearchCandidate(
            chunk_id=UUID("48000000-0000-4000-8000-000000000012"),
            organization_id=ORGANIZATION_ID,
            guide_id=scope.guide_id,
            guide_version=scope.guide_version,
            scope_id=scope.scope_id,
            pdf_page_number=557,
            control_id="PC-02",
            text="비밀번호 복잡성과 길이를 확인합니다.",
            dense_score=0.82,
        ),
        GuideSearchCandidate(
            chunk_id=UUID("48000000-0000-4000-8000-000000000013"),
            organization_id=OTHER_ORGANIZATION_ID,
            guide_id=scope.guide_id,
            guide_version=scope.guide_version,
            scope_id=scope.scope_id,
            pdf_page_number=555,
            control_id="PC-01",
            text="비밀번호 변경 주기",
            dense_score=1.0,
        ),
        GuideSearchCandidate(
            chunk_id=UUID("48000000-0000-4000-8000-000000000014"),
            organization_id=ORGANIZATION_ID,
            guide_id=scope.guide_id,
            guide_version=scope.guide_version,
            scope_id="server-pages",
            pdf_page_number=10,
            control_id="SV-01",
            text="비밀번호 변경 주기",
            dense_score=1.0,
        ),
    )

    hits = filter_and_rerank(scope, candidates)

    assert [hit.chunk_id for hit in hits] == [
        UUID("48000000-0000-4000-8000-000000000011"),
        UUID("48000000-0000-4000-8000-000000000012"),
    ]
    assert all(hit.organization_id == ORGANIZATION_ID for hit in hits)
    assert all(hit.scope_id == "pc-pages" for hit in hits)
    assert hits[0].rerank_score > hits[1].rerank_score


def test_scope_filter_applies_control_before_top_k() -> None:
    scope = GuideSearchScope(
        organization_id=ORGANIZATION_ID,
        guide_id="kisa-major-infrastructure-detailed-guide",
        guide_version="2026",
        scope_id="pc-pages",
        query="PC-07 파일 시스템을 NTFS 형식으로 설정",
        top_k=1,
        control_id="PC-07",
    )
    candidates = (
        GuideSearchCandidate(
            chunk_id=UUID("48000000-0000-4000-8000-000000000021"),
            organization_id=ORGANIZATION_ID,
            guide_id=scope.guide_id,
            guide_version=scope.guide_version,
            scope_id=scope.scope_id,
            pdf_page_number=555,
            control_id="PC-01",
            text="파일 시스템과 비밀번호 변경 주기를 확인합니다.",
            dense_score=1.0,
        ),
        GuideSearchCandidate(
            chunk_id=UUID("48000000-0000-4000-8000-000000000022"),
            organization_id=ORGANIZATION_ID,
            guide_id=scope.guide_id,
            guide_version=scope.guide_version,
            scope_id=scope.scope_id,
            pdf_page_number=571,
            control_id="PC-07",
            text="운영체제와 고정 저장 장치의 파일 시스템은 NTFS로 설정합니다.",
            dense_score=0.1,
        ),
    )

    hits = filter_and_rerank(scope, candidates)

    assert [hit.control_id for hit in hits] == ["PC-07"]


def test_pgvector_search_statement_exposes_ids_and_scores_not_raw_vectors() -> None:
    statement = build_pgvector_search_statement()
    compiled = str(
        statement.compile(
            dialect=postgresql.dialect(),  # type: ignore[no-untyped-call]
            compile_kwargs={"literal_binds": False},
        )
    )

    assert "vector_store.search_guide_chunks" in compiled
    assert "organization_id" in compiled
    assert "guide_id" in compiled
    assert "guide_version" in compiled
    assert "scope_id" in compiled
    assert "embedding" not in compiled


def test_imp048_migration_has_pgvector_generation_rls_and_no_milvus() -> None:
    migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0006_imp048_pgvector_guide_retrieval.py"
    ).read_text(encoding="utf-8")
    compose = (PROJECT_ROOT / "deploy" / "compose" / "compose.yml").read_text(
        encoding="utf-8"
    )

    assert "CREATE EXTENSION IF NOT EXISTS vector" in migration
    assert "guide_content" in migration
    assert "vector_store" in migration
    assert "vector(32)" in migration
    assert "ENABLE ROW LEVEL SECURITY" in migration
    assert "FORCE ROW LEVEL SECURITY" in migration
    assert "SECURITY DEFINER" in migration
    assert "raw embedding" in migration
    assert "milvus" not in compose.casefold()
