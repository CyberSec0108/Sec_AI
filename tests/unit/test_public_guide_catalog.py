from __future__ import annotations

import copy
from pathlib import Path
from uuid import UUID

from security_audit.guides.public_guides import (
    build_public_guide_page_map,
    extract_public_guide_pages,
    load_public_guide_manifest,
    public_guide_page_map_path,
    select_supplemental_guides,
    verify_public_guide_sources,
)
from security_audit.guides.retrieval import GuideIngestGateInput, build_guide_chunks

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")


def _manifest() -> dict[str, object]:
    return load_public_guide_manifest(PROJECT_ROOT)


def test_downloaded_public_guides_have_exact_lineage_and_no_decision_authority() -> None:
    manifest = _manifest()

    report = verify_public_guide_sources(PROJECT_ROOT, manifest)

    assert report.accepted
    assert report.errors == ()
    assert report.document_count == 7
    assert report.page_count == 997
    assert report.size_bytes == 56815470
    documents = manifest["documents"]
    assert isinstance(documents, list)
    assert all(item["retrieval_role"] == "SUPPLEMENTAL_EXPLANATION" for item in documents)
    assert all(item["decision_authority"] is False for item in documents)
    assert manifest["decision_authority"] is False
    assert manifest["audit_pack_activation_allowed"] is False
    assert manifest["redistribution_allowed"] is False
    assert all(
        public_guide_page_map_path(PROJECT_ROOT, item).suffix == ".json"
        for item in documents
    )


def test_manifest_rejects_unsafe_path_and_any_decision_authority() -> None:
    manifest = _manifest()
    changed = copy.deepcopy(manifest)
    documents = changed["documents"]
    assert isinstance(documents, list)
    documents[0]["relative_path"] = "../outside.pdf"
    documents[1]["decision_authority"] = True

    report = verify_public_guide_sources(PROJECT_ROOT, changed)

    assert not report.accepted
    assert "PUBLIC_GUIDE_SOURCE_PATH_UNSAFE" in report.errors
    assert "PUBLIC_GUIDE_DECISION_AUTHORITY_FORBIDDEN" in report.errors


def test_page_map_preserves_empty_pages_but_only_indexes_real_text() -> None:
    manifest = _manifest()
    documents = manifest["documents"]
    assert isinstance(documents, list)
    supply_chain = next(
        item
        for item in documents
        if item["guide_id"] == "kisa-sw-supply-chain-guideline"
    )

    first = build_public_guide_page_map(PROJECT_ROOT, supply_chain)
    second = build_public_guide_page_map(PROJECT_ROOT, supply_chain)
    pages = first["pages"]

    assert first == second
    assert first["source_page_count"] == 22
    assert len(pages) == 22
    assert pages[19]["pdf_page_number"] == 20
    assert pages[19]["indexable"] is False
    assert pages[19]["normalized_text_chars"] == 0
    assert sum(item["indexable"] for item in pages) == 21

    extracted = extract_public_guide_pages(
        PROJECT_ROOT,
        supply_chain,
        first,
    )
    assert len(extracted) == 21
    assert {page.pdf_page_number for page in extracted}.isdisjoint({20})
    assert {page.control_id for page in extracted} == {"GUIDE-PAGE"}

    n2sf = next(
        item
        for item in documents
        if item["guide_id"] == "ncsc-n2sf-security-guideline"
    )
    n2sf_map = build_public_guide_page_map(PROJECT_ROOT, n2sf)
    assert n2sf_map["pages"][1]["indexable"] is False
    assert n2sf_map["pages"][1]["skip_reason"] == "NO_SEARCHABLE_TOKEN"


def test_supplemental_routing_keeps_device_and_ai_topics_separate() -> None:
    manifest = _manifest()

    linux = select_supplemental_guides(
        manifest,
        platform="LINUX",
        topics=("ACCESS_CONTROL",),
    )
    supply_chain = select_supplemental_guides(
        manifest,
        platform="PRODUCT",
        topics=("SOFTWARE_SUPPLY_CHAIN",),
    )
    ai = select_supplemental_guides(
        manifest,
        platform="AI_SYSTEM",
        topics=("AI_SYSTEM_SECURITY",),
    )

    assert {item["guide_id"] for item in linux} == {
        "ncsc-n2sf-security-guideline",
        "ncsc-n2sf-security-controls-commentary",
        "kisa-zero-trust-guideline",
    }
    assert [item["guide_id"] for item in supply_chain] == [
        "kisa-sw-supply-chain-guideline"
    ]
    assert {item["guide_id"] for item in ai} == {
        "kisa-ai-security-guide",
        "kisa-ai-threat-response-manual",
        "kisa-ai-red-teaming-guide",
    }
    assert not {item["guide_id"] for item in linux}.intersection(
        {item["guide_id"] for item in ai}
    )


def test_supplemental_pages_build_deterministic_non_decision_chunks() -> None:
    manifest = _manifest()
    documents = manifest["documents"]
    assert isinstance(documents, list)
    red_team = next(
        item for item in documents if item["guide_id"] == "kisa-ai-red-teaming-guide"
    )
    page_map = build_public_guide_page_map(PROJECT_ROOT, red_team)
    pages = extract_public_guide_pages(PROJECT_ROOT, red_team, page_map)
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
        guide_id=str(red_team["guide_id"]),
        guide_version=str(red_team["version"]),
        source_sha256=str(red_team["source_sha256"]),
        scope_id=str(red_team["scope_id"]),
        pages=pages,
        gate=gate,
    )

    assert len(chunks) == 65
    assert {chunk.control_id for chunk in chunks} == {"GUIDE-PAGE"}
    assert len({chunk.chunk_id for chunk in chunks}) == len(chunks)
    assert all(chunk.guide_id == "kisa-ai-red-teaming-guide" for chunk in chunks)


def test_new_migration_allows_generic_guide_pages_and_blocks_document_authority() -> None:
    migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0028_public_guide_retrieval_roles.py"
    ).read_text(encoding="utf-8")

    assert "GUIDE-PAGE" in migration
    assert "SUPPLEMENTAL_EXPLANATION" in migration
    assert "OFFICIAL_CHECK_REFERENCE" in migration
    assert "decision_authority = false" in migration
    assert 'down_revision: str | None = "0027_switch_n01_n38_ai_keys"' in migration

    ingest = (PROJECT_ROOT / "tools" / "ingest-public-guides.py").read_text(
        encoding="utf-8"
    )
    assert "SUPPLEMENTAL_EXPLANATION" in ingest
    assert "official_finding_write_allowed" in ingest
    assert "decision_authority = false" in ingest
    assert "BGE_DIMENSION = 1024" in ingest
