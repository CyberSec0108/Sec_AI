from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from security_audit.guides import (
    PdfInspection,
    PdfPageInspection,
    load_json_strict,
    normalize_page_text,
    verify_guide_lineage,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = PROJECT_ROOT / "guides" / "catalog.json"
PAGE_MAP_PATH = (
    PROJECT_ROOT / "guides" / "page_maps" / "kisa_2026_pc_pages.json"
)
MAPPING_PATH = (
    PROJECT_ROOT
    / "guides"
    / "mappings"
    / "kisa_2026_pc_control_sources.json"
)
PACK_PATH = (
    PROJECT_ROOT
    / "audit_packs"
    / "kisa_2026_pc"
    / "src"
    / "pack-0.6.0.json"
)


def _artifacts() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    PdfInspection,
]:
    catalog = load_json_strict(CATALOG_PATH)
    page_map = load_json_strict(PAGE_MAP_PATH)
    mapping = load_json_strict(MAPPING_PATH)
    audit_pack = load_json_strict(PACK_PATH)
    guide = catalog["guides"][0]
    source = guide["source"]
    pages = tuple(
        PdfPageInspection(
            pdf_page_number=page["pdf_page_number"],
            text_sha256=page["text_sha256"],
            normalized_text_chars=page["normalized_text_chars"],
        )
        for page in page_map["pages"]
    )
    inspection = PdfInspection(
        source_sha256=source["source_sha256"],
        size_bytes=source["size_bytes"],
        page_count=source["page_count"],
        pdf_version=source["pdf_version"],
        encrypted=source["encrypted"],
        pages=pages,
    )
    return catalog, page_map, mapping, audit_pack, inspection


def test_whitespace_and_unicode_normalization_is_deterministic() -> None:
    composed = "가이드\t문장\n다음"
    decomposed = "\u1100\u1161\u110b\u1175\u1103\u1173  문장\r\n다음"

    assert normalize_page_text(composed) == normalize_page_text(decomposed)
    assert normalize_page_text(composed) == "가이드 문장 다음"


def test_strict_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    duplicate_json = tmp_path / "duplicate.json"
    duplicate_json.write_text('{"guide_id":"first","guide_id":"second"}', encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_json_strict(duplicate_json)


def test_registered_pc_source_lineage_is_approved_for_search_but_pack_is_not_activated() -> None:
    catalog, page_map, mapping, audit_pack, inspection = _artifacts()

    result = verify_guide_lineage(
        catalog,
        page_map,
        mapping,
        audit_pack,
        inspection,
    )

    assert result.accepted
    assert result.errors == ()
    assert set(result.warnings) == {
        "PC-04_DRAFT_PACK_SECTION_LABEL_DRIFT",
        "PC-06_DRAFT_PACK_SECTION_LABEL_DRIFT",
        "PC-08_DRAFT_PACK_SECTION_LABEL_DRIFT",
        "PC-09_DRAFT_PACK_SECTION_LABEL_DRIFT",
    }
    assert result.source_page_count == 873
    assert result.mapped_page_count == 41
    assert result.mapped_control_count == 18
    assert catalog["guides"][0]["status"] == "APPROVED"
    assert catalog["guides"][0]["query_scopes"][0]["default_enabled"] is True
    assert mapping["runtime_activation_allowed"] is False


def test_changed_pdf_hash_is_rejected() -> None:
    catalog, page_map, mapping, audit_pack, inspection = _artifacts()
    changed_inspection = PdfInspection(
        source_sha256="0" * 64,
        size_bytes=inspection.size_bytes,
        page_count=inspection.page_count,
        pdf_version=inspection.pdf_version,
        encrypted=inspection.encrypted,
        pages=inspection.pages,
    )

    result = verify_guide_lineage(
        catalog,
        page_map,
        mapping,
        audit_pack,
        changed_inspection,
    )

    assert not result.accepted
    assert "SOURCE_SHA256_MISMATCH" in result.errors
    assert "PAGE_MAP_SOURCE_SHA256_MISMATCH" in result.errors


def test_changed_page_text_fingerprint_is_rejected() -> None:
    catalog, page_map, mapping, audit_pack, inspection = _artifacts()
    changed_pages = list(inspection.pages)
    original = changed_pages[3]
    changed_pages[3] = PdfPageInspection(
        pdf_page_number=original.pdf_page_number,
        text_sha256="f" * 64,
        normalized_text_chars=original.normalized_text_chars,
    )
    changed_inspection = PdfInspection(
        source_sha256=inspection.source_sha256,
        size_bytes=inspection.size_bytes,
        page_count=inspection.page_count,
        pdf_version=inspection.pdf_version,
        encrypted=inspection.encrypted,
        pages=tuple(changed_pages),
    )

    result = verify_guide_lineage(
        catalog,
        page_map,
        mapping,
        audit_pack,
        changed_inspection,
    )

    assert not result.accepted
    assert "PAGE_TEXT_SHA256_MISMATCH" in result.errors


def test_control_citation_drift_from_audit_pack_is_rejected() -> None:
    catalog, page_map, mapping, audit_pack, inspection = _artifacts()
    changed_mapping = copy.deepcopy(mapping)
    changed_mapping["mappings"][15]["page_end"] = 589

    result = verify_guide_lineage(
        catalog,
        page_map,
        changed_mapping,
        audit_pack,
        inspection,
    )

    assert not result.accepted
    assert "PC-16_CITATION_MISMATCH" in result.errors
    assert "PC-16_PAGE_MAP_RANGE_MISMATCH" in result.errors


def test_approved_query_disable_or_rule_activation_is_rejected() -> None:
    catalog, page_map, mapping, audit_pack, inspection = _artifacts()
    changed_catalog = copy.deepcopy(catalog)
    changed_mapping = copy.deepcopy(mapping)
    changed_catalog["guides"][0]["query_scopes"][0]["default_enabled"] = False
    changed_catalog["guides"][0]["audit_pack_activation_allowed"] = True
    changed_mapping["runtime_activation_allowed"] = True

    result = verify_guide_lineage(
        changed_catalog,
        page_map,
        changed_mapping,
        audit_pack,
        inspection,
    )

    assert not result.accepted
    assert "APPROVED_QUERY_SCOPE_DISABLED" in result.errors
    assert "GUIDE_CANNOT_ACTIVATE_AUDIT_PACK" in result.errors
    assert "CONTROL_MAPPING_NOT_FAIL_CLOSED" in result.errors


def test_internal_approval_cannot_be_changed_to_redistribution() -> None:
    catalog, page_map, mapping, audit_pack, inspection = _artifacts()
    changed_catalog = copy.deepcopy(catalog)
    changed_catalog["guides"][0]["license_policy"]["redistribution_allowed"] = True

    result = verify_guide_lineage(
        changed_catalog,
        page_map,
        mapping,
        audit_pack,
        inspection,
    )

    assert not result.accepted
    assert "LICENSE_GATE_INVALID" in result.errors
