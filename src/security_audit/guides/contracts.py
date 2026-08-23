"""Fail-closed lineage checks for Guide Catalog and Control source mappings."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


@dataclass(frozen=True, slots=True)
class PdfPageInspection:
    pdf_page_number: int
    text_sha256: str
    normalized_text_chars: int


@dataclass(frozen=True, slots=True)
class PdfInspection:
    source_sha256: str
    size_bytes: int
    page_count: int
    pdf_version: str
    encrypted: bool
    pages: tuple[PdfPageInspection, ...]


@dataclass(frozen=True, slots=True)
class GuideVerificationResult:
    errors: tuple[str, ...]
    source_page_count: int
    mapped_page_count: int
    mapped_control_count: int
    warnings: tuple[str, ...] = ()

    @property
    def accepted(self) -> bool:
        return not self.errors


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_strict(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
    )
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path.name}")
    return value


def normalize_page_text(text: str) -> str:
    """Normalize extracted PDF text for a stable, non-content page fingerprint."""
    return re.sub(r"\s+", " ", unicodedata.normalize("NFC", text)).strip()


def text_sha256(text: str) -> str:
    return hashlib.sha256(normalize_page_text(text).encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _append_if(errors: list[str], condition: bool, code: str) -> None:
    if condition:
        errors.append(code)


def _catalog_guide(
    catalog: Mapping[str, Any],
    guide_id: str,
    version: str,
) -> Mapping[str, Any] | None:
    guides = catalog.get("guides")
    if not isinstance(guides, list):
        return None
    matches = [
        guide
        for guide in guides
        if isinstance(guide, dict)
        and guide.get("guide_id") == guide_id
        and guide.get("version") == version
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _safe_relative_pdf(value: object) -> bool:
    if not isinstance(value, str):
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and path.parts[:1] == ("data",)
        and path.suffix.casefold() == ".pdf"
    )


def verify_guide_lineage(
    catalog: Mapping[str, Any],
    page_map: Mapping[str, Any],
    control_mapping: Mapping[str, Any],
    audit_pack: Mapping[str, Any],
    inspection: PdfInspection,
) -> GuideVerificationResult:
    """Verify exact source identity and the independently controlled search gates."""
    errors: list[str] = []
    warnings: list[str] = []
    guide_id = page_map.get("guide_id")
    guide_version = page_map.get("guide_version")
    if not isinstance(guide_id, str) or not isinstance(guide_version, str):
        return GuideVerificationResult(("GUIDE_IDENTITY_INVALID",), 0, 0, 0)
    guide = _catalog_guide(catalog, guide_id, guide_version)
    if guide is None:
        return GuideVerificationResult(("GUIDE_CATALOG_ENTRY_NOT_UNIQUE",), 0, 0, 0)

    source = guide.get("source")
    if not isinstance(source, dict):
        return GuideVerificationResult(("GUIDE_SOURCE_INVALID",), 0, 0, 0)
    _append_if(
        errors,
        not _safe_relative_pdf(source.get("relative_path")),
        "GUIDE_SOURCE_PATH_UNSAFE",
    )
    _append_if(
        errors,
        source.get("source_sha256") != inspection.source_sha256,
        "SOURCE_SHA256_MISMATCH",
    )
    _append_if(
        errors,
        source.get("size_bytes") != inspection.size_bytes,
        "SOURCE_SIZE_MISMATCH",
    )
    _append_if(
        errors,
        source.get("page_count") != inspection.page_count,
        "SOURCE_PAGE_COUNT_MISMATCH",
    )
    _append_if(
        errors,
        source.get("pdf_version") != inspection.pdf_version,
        "SOURCE_PDF_VERSION_MISMATCH",
    )
    _append_if(
        errors,
        source.get("encrypted") != inspection.encrypted,
        "SOURCE_ENCRYPTION_MISMATCH",
    )
    _append_if(
        errors,
        page_map.get("source_sha256") != inspection.source_sha256,
        "PAGE_MAP_SOURCE_SHA256_MISMATCH",
    )
    _append_if(
        errors,
        page_map.get("source_page_count") != inspection.page_count,
        "PAGE_MAP_SOURCE_PAGE_COUNT_MISMATCH",
    )

    license_policy = guide.get("license_policy")
    gates = guide.get("gates")
    query_scopes = guide.get("query_scopes")
    _append_if(errors, guide.get("status") != "APPROVED", "GUIDE_NOT_APPROVED")
    _append_if(
        errors,
        not isinstance(license_policy, dict)
        or license_policy.get("status") != "APPROVED"
        or license_policy.get("allowed_use")
        != "APPROVED_INTERNAL_GUIDE_QA"
        or license_policy.get("redistribution_allowed") is not False
        or license_policy.get("derivative_text_storage_allowed") is not True,
        "LICENSE_GATE_INVALID",
    )
    _append_if(
        errors,
        not isinstance(gates, dict)
        or gates.get("source_hash_verified") is not True
        or gates.get("page_map_verified") is not True
        or gates.get("visual_anchor_verified") is not True
        or gates.get("malware_scan_passed") is not True
        or gates.get("ocr_quality_approved") is not True
        or gates.get("license_review_approved") is not True
        or gates.get("retrieval_quality_approved") is not True,
        "GUIDE_GATE_STATE_INVALID",
    )
    _append_if(
        errors,
        guide.get("audit_pack_activation_allowed") is not False,
        "GUIDE_CANNOT_ACTIVATE_AUDIT_PACK",
    )

    scope_id = page_map.get("scope_id")
    matching_scopes = (
        [
            scope
            for scope in query_scopes
            if isinstance(scope, dict) and scope.get("scope_id") == scope_id
        ]
        if isinstance(query_scopes, list)
        else []
    )
    _append_if(errors, len(matching_scopes) != 1, "QUERY_SCOPE_NOT_UNIQUE")
    if len(matching_scopes) == 1:
        scope = matching_scopes[0]
        _append_if(
            errors,
            scope.get("pdf_page_start") != page_map.get("pdf_page_start")
            or scope.get("pdf_page_end") != page_map.get("pdf_page_end"),
            "QUERY_SCOPE_PAGE_RANGE_MISMATCH",
        )
        _append_if(
            errors,
            scope.get("default_enabled") is not True,
            "APPROVED_QUERY_SCOPE_DISABLED",
        )

    mapped_pages = page_map.get("pages")
    inspection_pages = {
        page.pdf_page_number: page for page in inspection.pages
    }
    if not isinstance(mapped_pages, list):
        errors.append("PAGE_MAP_INVALID")
        mapped_pages = []
    start = page_map.get("pdf_page_start")
    end = page_map.get("pdf_page_end")
    expected_numbers = (
        list(range(start, end + 1))
        if isinstance(start, int) and isinstance(end, int) and start <= end
        else []
    )
    page_numbers = [
        page.get("pdf_page_number")
        for page in mapped_pages
        if isinstance(page, dict)
    ]
    _append_if(
        errors,
        page_numbers != expected_numbers,
        "PAGE_MAP_NOT_CONTIGUOUS",
    )
    for page in mapped_pages:
        if not isinstance(page, dict):
            errors.append("PAGE_MAP_ENTRY_INVALID")
            continue
        number = page.get("pdf_page_number")
        if not isinstance(number, int):
            errors.append("PAGE_INSPECTION_MISSING")
            continue
        inspected = inspection_pages.get(number)
        _append_if(errors, inspected is None, "PAGE_INSPECTION_MISSING")
        if inspected is None:
            continue
        _append_if(
            errors,
            page.get("pdf_page_index") != number - 1
            or page.get("printed_page_number") != number,
            "PAGE_NUMBER_MAPPING_INVALID",
        )
        _append_if(
            errors,
            page.get("text_sha256") != inspected.text_sha256,
            "PAGE_TEXT_SHA256_MISMATCH",
        )
        _append_if(
            errors,
            page.get("normalized_text_chars") != inspected.normalized_text_chars,
            "PAGE_TEXT_LENGTH_MISMATCH",
        )

    mapping_guide = control_mapping.get("guide")
    mapping_pack = control_mapping.get("audit_pack")
    mappings = control_mapping.get("mappings")
    _append_if(
        errors,
        control_mapping.get("status") != "DRAFT"
        or control_mapping.get("runtime_activation_allowed") is not False,
        "CONTROL_MAPPING_NOT_FAIL_CLOSED",
    )
    _append_if(
        errors,
        not isinstance(mapping_guide, dict)
        or mapping_guide.get("guide_id") != guide_id
        or mapping_guide.get("version") != guide_version
        or mapping_guide.get("source_sha256") != inspection.source_sha256
        or mapping_guide.get("required_catalog_status") != "APPROVED",
        "CONTROL_MAPPING_GUIDE_MISMATCH",
    )
    _append_if(
        errors,
        not isinstance(mapping_pack, dict)
        or mapping_pack.get("pack_profile") != audit_pack.get("pack_profile")
        or mapping_pack.get("version") != audit_pack.get("version")
        or mapping_pack.get("content_sha256") != audit_pack.get("content_sha256")
        or mapping_pack.get("current_status")
        != (
            audit_pack.get("approval", {}).get("status")
            if isinstance(audit_pack.get("approval"), dict)
            else None
        ),
        "CONTROL_MAPPING_PACK_MISMATCH",
    )
    pack_guide = audit_pack.get("guide")
    _append_if(
        errors,
        not isinstance(pack_guide, dict)
        or pack_guide.get("document_sha256") != inspection.source_sha256,
        "AUDIT_PACK_GUIDE_HASH_MISMATCH",
    )

    expected_controls = {f"PC-{number:02d}" for number in range(1, 19)}
    mapping_by_control = (
        {
            item.get("control_id"): item
            for item in mappings
            if isinstance(item, dict) and isinstance(item.get("control_id"), str)
        }
        if isinstance(mappings, list)
        else {}
    )
    _append_if(
        errors,
        set(mapping_by_control) != expected_controls
        or not isinstance(mappings, list)
        or len(mappings) != len(mapping_by_control),
        "CONTROL_MAPPING_COVERAGE_INVALID",
    )
    pack_controls = audit_pack.get("controls")
    pack_by_control = (
        {
            item.get("control_id"): item
            for item in pack_controls
            if isinstance(item, dict) and isinstance(item.get("control_id"), str)
        }
        if isinstance(pack_controls, list)
        else {}
    )
    _append_if(
        errors,
        set(pack_by_control) != expected_controls,
        "AUDIT_PACK_CONTROL_COVERAGE_INVALID",
    )
    page_map_controls = {
        control_id
        for page in mapped_pages
        if isinstance(page, dict)
        for control_id in page.get("control_ids", [])
        if isinstance(control_id, str)
    }
    _append_if(
        errors,
        page_map_controls != expected_controls,
        "PAGE_MAP_CONTROL_COVERAGE_INVALID",
    )

    for control_id in sorted(expected_controls):
        mapped = mapping_by_control.get(control_id)
        packed = pack_by_control.get(control_id)
        if mapped is None or packed is None:
            continue
        citations = packed.get("citations")
        citation = citations[0] if isinstance(citations, list) and len(citations) == 1 else None
        citation_identity_mismatch = (
            not isinstance(citation, dict)
            or mapped.get("source_document_code") != citation.get("document")
            or mapped.get("page_start") != citation.get("page_start")
            or mapped.get("page_end") != citation.get("page_end")
        )
        _append_if(
            errors,
            citation_identity_mismatch,
            f"{control_id}_CITATION_MISMATCH",
        )
        if (
            not citation_identity_mismatch
            and isinstance(citation, dict)
            and mapped.get("section_label") != citation.get("section_label")
        ):
            warnings.append(f"{control_id}_DRAFT_PACK_SECTION_LABEL_DRIFT")
        if isinstance(mapped.get("page_start"), int) and isinstance(
            mapped.get("page_end"), int
        ):
            mapped_range = set(
                range(mapped["page_start"], mapped["page_end"] + 1)
            )
            pages_for_control = {
                page["pdf_page_number"]
                for page in mapped_pages
                if isinstance(page, dict)
                and control_id in page.get("control_ids", [])
                and isinstance(page.get("pdf_page_number"), int)
            }
            _append_if(
                errors,
                pages_for_control != mapped_range,
                f"{control_id}_PAGE_MAP_RANGE_MISMATCH",
            )

    return GuideVerificationResult(
        tuple(sorted(set(errors))),
        inspection.page_count,
        len(mapped_pages),
        len(mapping_by_control),
        tuple(sorted(set(warnings))),
    )
