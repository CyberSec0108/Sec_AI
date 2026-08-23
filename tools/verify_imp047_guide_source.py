from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import fitz
from jsonschema import Draft202012Validator, FormatChecker

from security_audit.guides import (
    PdfInspection,
    PdfPageInspection,
    file_sha256,
    load_json_strict,
    normalize_page_text,
    text_sha256,
    verify_guide_lineage,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
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
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"


def _validate(instance: dict[str, Any], schema_name: str) -> None:
    schema = load_json_strict(SCHEMA_ROOT / schema_name)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if errors:
        raise ValueError(f"{schema_name}: {errors[0].message}")


def _guide_entry(catalog: dict[str, Any]) -> dict[str, Any]:
    guides = catalog.get("guides")
    if not isinstance(guides, list) or len(guides) != 1:
        raise ValueError("IMP-047 requires exactly one registered development guide.")
    guide = guides[0]
    if not isinstance(guide, dict):
        raise ValueError("The Guide Catalog entry must be an object.")
    return guide


def _source_path(guide: dict[str, Any]) -> Path:
    source = guide.get("source")
    if not isinstance(source, dict):
        raise ValueError("The Guide Catalog source must be an object.")
    relative_path = source.get("relative_path")
    if not isinstance(relative_path, str):
        raise ValueError("The guide source relative_path is missing.")
    resolved = (PROJECT_ROOT / Path(relative_path)).resolve()
    data_root = (PROJECT_ROOT / "data").resolve()
    if not resolved.is_relative_to(data_root):
        raise ValueError("The guide source escaped the project data directory.")
    if not resolved.is_file():
        raise FileNotFoundError("The registered guide source PDF is unavailable.")
    return resolved


def _inspect_pdf(
    source_path: Path,
    page_map: dict[str, Any],
) -> PdfInspection:
    mapped_pages = page_map.get("pages")
    if not isinstance(mapped_pages, list):
        raise ValueError("The page map pages value must be an array.")
    page_numbers = [
        page["pdf_page_number"]
        for page in mapped_pages
        if isinstance(page, dict) and isinstance(page.get("pdf_page_number"), int)
    ]
    with fitz.open(source_path) as document:
        pages: list[PdfPageInspection] = []
        for page_number in page_numbers:
            text = document[page_number - 1].get_text("text")
            normalized = normalize_page_text(text)
            pages.append(
                PdfPageInspection(
                    pdf_page_number=page_number,
                    text_sha256=text_sha256(text),
                    normalized_text_chars=len(normalized),
                )
            )
        return PdfInspection(
            source_sha256=file_sha256(source_path),
            size_bytes=source_path.stat().st_size,
            page_count=document.page_count,
            pdf_version=document.metadata.get("format", ""),
            encrypted=document.is_encrypted,
            pages=tuple(pages),
        )


def main() -> int:
    catalog = load_json_strict(CATALOG_PATH)
    page_map = load_json_strict(PAGE_MAP_PATH)
    mapping = load_json_strict(MAPPING_PATH)
    audit_pack = load_json_strict(PACK_PATH)
    _validate(catalog, "guide_catalog.schema.json")
    _validate(page_map, "guide_page_map.schema.json")
    _validate(mapping, "control_source_mapping.schema.json")
    guide = _guide_entry(catalog)
    inspection = _inspect_pdf(_source_path(guide), page_map)
    result = verify_guide_lineage(
        catalog,
        page_map,
        mapping,
        audit_pack,
        inspection,
    )
    license_policy = guide["license_policy"]
    summary = {
        "imp": "IMP-047",
        "accepted": result.accepted,
        "source_sha256_verified": result.accepted,
        "source_page_count": result.source_page_count,
        "mapped_pc_page_count": result.mapped_page_count,
        "mapped_control_count": result.mapped_control_count,
        "catalog_status": guide["status"],
        "license_status": license_policy["status"],
        "query_default_enabled": guide["query_scopes"][0]["default_enabled"],
        "runtime_activation_allowed": mapping["runtime_activation_allowed"],
        "full_text_persisted": False,
        "errors": list(result.errors),
        "warnings": list(result.warnings),
    }
    print(json.dumps(summary, ensure_ascii=False, separators=(",", ":")))
    return 0 if result.accepted else 1


if __name__ == "__main__":
    sys.exit(main())
