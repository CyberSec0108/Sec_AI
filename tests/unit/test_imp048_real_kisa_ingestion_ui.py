from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from apps.api import guide_store as guide_store_api
from apps.api.main import app
from fastapi.testclient import TestClient

from security_audit.guides import (
    ApprovedLocalKoreanEmbedder,
    GuideIngestGateInput,
    evaluate_ingest_gate,
)
from security_audit.guides.ingestion import inspect_guide_pdf
from security_audit.persistence.database.guide_repository import (
    GuideStoreChunk,
    GuideStoreSnapshot,
    build_guide_store_inventory_statement,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PDF_PATH = (
    PROJECT_ROOT
    / "data"
    / "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf"
)
CATALOG_PATH = PROJECT_ROOT / "guides" / "catalog.json"
PAGE_MAP_PATH = (
    PROJECT_ROOT / "guides" / "page_maps" / "kisa_2026_pc_pages.json"
)
ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")


def _catalog_guide() -> dict[str, Any]:
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    return cast(dict[str, Any], catalog["guides"][0])


def test_real_kisa_catalog_records_user_approval_without_enabling_pack() -> None:
    guide = _catalog_guide()

    assert guide["status"] == "APPROVED"
    assert guide["license_policy"]["status"] == "APPROVED"
    assert guide["license_policy"]["derivative_text_storage_allowed"] is True
    assert guide["license_policy"]["redistribution_allowed"] is False
    assert guide["query_scopes"][0]["default_enabled"] is True
    assert guide["gates"]["malware_scan_passed"] is True
    assert guide["gates"]["ocr_quality_approved"] is True
    assert guide["gates"]["license_review_approved"] is True
    assert guide["gates"]["retrieval_quality_approved"] is True
    assert guide["audit_pack_activation_allowed"] is False

    gate = evaluate_ingest_gate(
        GuideIngestGateInput(
            guide_status=guide["status"],
            license_status=guide["license_policy"]["status"],
            derivative_text_storage_allowed=guide["license_policy"][
                "derivative_text_storage_allowed"
            ],
            source_hash_verified=guide["gates"]["source_hash_verified"],
            page_map_verified=guide["gates"]["page_map_verified"],
            malware_scan_passed=guide["gates"]["malware_scan_passed"],
            extraction_quality_approved=guide["gates"]["ocr_quality_approved"],
            query_scope_enabled=guide["query_scopes"][0]["default_enabled"],
            synthetic_test_only=False,
        )
    )
    assert gate.accepted


def test_real_kisa_41_pages_match_exact_map_without_ocr() -> None:
    page_map = json.loads(PAGE_MAP_PATH.read_text(encoding="utf-8"))

    report = inspect_guide_pdf(PDF_PATH, page_map)

    assert report.accepted
    assert report.errors == ()
    assert report.source_sha256 == (
        "44fe393981b244147be6af7423d99dc15633c089fad0bcb296cbe2371dde812d"
    )
    assert report.page_count == 41
    assert report.pdf_page_start == 552
    assert report.pdf_page_end == 592
    assert report.extraction_mode == "TEXT_LAYER"
    assert report.ocr_required_pages == 0
    assert len(report.pages) == 41
    assert [page.pdf_page_number for page in report.pages] == list(range(552, 593))
    assert [page.control_id for page in report.pages[:3]] == [
        "PC-INTRO",
        "PC-INTRO",
        "PC-INTRO",
    ]
    assert {page.control_id for page in report.pages[3:]} == {
        f"PC-{number:02d}" for number in range(1, 19)
    }


def test_approved_local_embedder_is_deterministic_and_prefers_related_text() -> None:
    embedder = ApprovedLocalKoreanEmbedder()
    query = embedder.embed("비밀번호 변경 주기는 어떻게 확인하나요")
    repeated = {tuple(embedder.embed("비밀번호 변경 주기는 어떻게 확인하나요")) for _ in range(100)}
    related = embedder.embed("비밀번호는 정해진 주기에 따라 변경해야 합니다")
    unrelated = embedder.embed("이동식 저장매체 사용을 제한합니다")

    def cosine(left: list[float], right: list[float]) -> float:
        return sum(a * b for a, b in zip(left, right, strict=True))

    assert embedder.dimension == 32
    assert embedder.model_id == "secai-ko-lexical-hash-v1"
    assert len(repeated) == 1
    assert cosine(query, related) > cosine(query, unrelated)


def test_inventory_contract_returns_counts_without_raw_embeddings() -> None:
    statement = str(build_guide_store_inventory_statement())

    assert "vector_store.guide_store_inventory" in statement
    assert "embedding_count" in statement
    assert "embedding " not in statement.casefold()

    migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0007_imp048_real_guide_and_inventory.py"
    ).read_text(encoding="utf-8")
    assert "PC-INTRO" in migration
    assert "SECURITY DEFINER" in migration
    assert "guide_store_inventory" in migration
    assert "RETURNS TABLE" in migration


def test_authenticated_product_ui_shows_safe_pgvector_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = GuideStoreSnapshot(
        organization_id=ORGANIZATION_ID,
        postgresql_version="18.4",
        pgvector_version="0.8.2",
        document_count=1,
        chunk_count=41,
        embedding_count=41,
        active_generation_count=1,
        generation_status="ACTIVE",
        embedding_model_id="secai-ko-lexical-hash-v1",
        embedding_dimension=32,
        metric_type="COSINE",
        guide_id="kisa-major-infrastructure-detailed-guide",
        guide_version="2026",
        scope_id="kisa-2026-pc",
        chunks=(
            GuideStoreChunk(
                pdf_page_number=555,
                control_id="PC-01",
                text="비밀번호의 주기적 변경 여부를 확인합니다.",
                text_sha256="a" * 64,
            ),
        ),
    )
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setattr(guide_store_api, "_load_snapshot", lambda _: snapshot)

    with TestClient(app) as client:
        html = client.get("/ui/guide-store")
        api = client.get("/api/v1/guide-store")

    assert html.status_code == 200
    for phrase in (
        "가이드 검색 저장소",
        "PostgreSQL 18.4",
        "pgvector 0.8.2",
        "문서 1건",
        "검색 문단 41건",
        "검색 벡터 41건",
        "PC-01",
        "555쪽",
        "원시 벡터는 표시하지 않습니다",
    ):
        assert phrase in html.text
    assert api.status_code == 200
    body = api.json()
    assert body["embedding_count"] == 41
    assert body["raw_embeddings_included"] is False
    assert "database_url" not in body
    assert "password" not in body
