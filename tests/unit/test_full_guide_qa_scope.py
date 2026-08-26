from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from security_audit.guides.retrieval import (
    GuideIngestGateInput,
    GuidePageText,
    build_guide_chunks,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_catalog_exposes_every_kisa_classification_and_full_search_scope() -> None:
    catalog = json.loads(
        (PROJECT_ROOT / "guides" / "catalog.json").read_text(encoding="utf-8")
    )
    scopes = {
        item["scope_id"]: item
        for item in catalog["guides"][0]["query_scopes"]
    }

    assert scopes["kisa-2026-all"]["pdf_page_start"] == 7
    assert scopes["kisa-2026-all"]["pdf_page_end"] == 873
    assert {
        item["section_label"]
        for item in scopes.values()
        if item["scope_id"] != "kisa-2026-all"
    } >= {
        "01. Unix 서버",
        "02. Windows 서버",
        "03. 웹 서비스",
        "04. 보안 장비",
        "05. 네트워크 장비",
        "06. 제어시스템",
        "07. PC",
        "08. DBMS",
        "09. 이동통신",
        "10. Web Application(웹)",
        "11. 가상화 장비",
        "12. 클라우드",
    }


def test_full_page_map_and_control_sources_cover_the_search_scope() -> None:
    page_map = json.loads(
        (
            PROJECT_ROOT
            / "guides"
            / "page_maps"
            / "kisa_2026_all_pages.json"
        ).read_text(encoding="utf-8")
    )
    mapping = json.loads(
        (
            PROJECT_ROOT
            / "guides"
            / "mappings"
            / "kisa_2026_all_control_sources.json"
        ).read_text(encoding="utf-8")
    )

    assert page_map["scope_id"] == "kisa-2026-all"
    assert [page["pdf_page_number"] for page in page_map["pages"]] == list(
        range(7, 874)
    )
    mapped_controls = {
        control_id
        for page in page_map["pages"]
        for control_id in page["control_ids"]
    }
    source_controls = {item["control_id"] for item in mapping["mappings"]}
    assert mapped_controls == source_controls
    assert {
        "U-01",
        "W-01",
        "WEB-01",
        "N-01",
        "PC-01",
        "D-01",
        "M-01",
        "CI",
        "HV-01",
        "CA-01",
    } <= mapped_controls


def test_guide_chat_uses_full_scope_and_pdf_page_links() -> None:
    script = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "guide-chat.js"
    ).read_text(encoding="utf-8")
    api = (PROJECT_ROOT / "apps" / "api" / "guide_store.py").read_text(
        encoding="utf-8"
    )

    assert 'scope_id: "kisa-2026-all"' in script
    assert (
        "/source.pdf?requested_page=${pageNumber}"
        "#page=${pageNumber}&zoom=page-width"
    ) in script
    assert "@router.get(\"/api/v1/guides/{guide_id}/{guide_version}/source.pdf\")" in api
    assert "@router.get(\"/api/v1/guides/{guide_id}/{guide_version}/source-page\")" in api
    assert "requested_page: int | None = None" in api
    assert "?requested_page={pdf_page_number}" in api
    assert "#page={pdf_page_number}&zoom=page-width" in api
    assert '"X-SecAI-Source-PDF-Page"' in api


def test_ingest_contract_accepts_representative_codes_from_every_classification() -> None:
    control_ids = (
        "U-01",
        "W-01",
        "WEB-01",
        "S-01",
        "N-01",
        "C-01",
        "PC-01",
        "D-01",
        "M-01",
        "CI",
        "HV-01",
        "CA-01",
    )
    chunks = build_guide_chunks(
        organization_id=UUID("46000000-0000-4000-8000-000000000001"),
        guide_id="kisa-major-infrastructure-detailed-guide",
        guide_version="2026",
        source_sha256="a" * 64,
        scope_id="kisa-2026-all",
        pages=tuple(
            GuidePageText(
                pdf_page_number=index + 1,
                control_id=control_id,
                text=f"{control_id} 승인된 원문 본문",
            )
            for index, control_id in enumerate(control_ids)
        ),
        gate=GuideIngestGateInput(
            guide_status="APPROVED",
            license_status="APPROVED",
            derivative_text_storage_allowed=True,
            source_hash_verified=True,
            page_map_verified=True,
            malware_scan_passed=True,
            extraction_quality_approved=True,
            query_scope_enabled=True,
            synthetic_test_only=False,
        ),
    )

    assert tuple(chunk.control_id for chunk in chunks) == control_ids


def test_database_constraint_accepts_full_guide_control_namespaces() -> None:
    migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0019_full_guide_classifications.py"
    ).read_text(encoding="utf-8")

    assert "0019_full_guide" in migration
    assert "U|W|WEB|S|N|C|D|M|HV|CA" in migration
    assert "UNIX|WINDOWS|WEB-SERVICE" in migration
    assert "CI|SI|DI|EP" in migration

    length_migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0020_full_guide_control_id_length.py"
    ).read_text(encoding="utf-8")
    assert "ALTER COLUMN control_id TYPE varchar(64)" in length_migration
