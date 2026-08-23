"""공공기관 PDF의 ClamAV·Page Map·추출 품질 Gate를 검증합니다."""

from __future__ import annotations

import json
import os
from pathlib import Path

from security_audit.guides.contracts import load_json_strict
from security_audit.guides.ingestion import scan_pdf_with_clamav
from security_audit.guides.public_guides import (
    extract_public_guide_pages,
    load_public_guide_manifest,
    public_guide_page_map_path,
    verify_public_guide_sources,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    manifest = load_public_guide_manifest(PROJECT_ROOT)
    source_report = verify_public_guide_sources(PROJECT_ROOT, manifest)
    if not source_report.accepted:
        raise RuntimeError("PUBLIC_GUIDE_SOURCE_GATE_FAILED:" + ",".join(source_report.errors))
    host = os.getenv("SECAI_CLAMAV_HOST", "clamav")
    port = int(os.getenv("SECAI_CLAMAV_PORT", "3310"))
    documents = manifest["documents"]
    if not isinstance(documents, list):
        raise RuntimeError("PUBLIC_GUIDE_DOCUMENTS_INVALID")

    summaries: list[dict[str, object]] = []
    for document in documents:
        if not isinstance(document, dict):
            raise RuntimeError("PUBLIC_GUIDE_DOCUMENT_INVALID")
        source_path = PROJECT_ROOT / str(document["relative_path"])
        scan = scan_pdf_with_clamav(source_path, host=host, port=port)
        if not scan.accepted or scan.source_sha256 != document["source_sha256"]:
            raise RuntimeError(f"PUBLIC_GUIDE_MALWARE_GATE_FAILED:{document['guide_id']}")
        page_map = load_json_strict(public_guide_page_map_path(PROJECT_ROOT, document))
        pages = extract_public_guide_pages(PROJECT_ROOT, document, page_map)
        summaries.append(
            {
                "guide_id": document["guide_id"],
                "source_sha256": scan.source_sha256,
                "malware_status": scan.status,
                "clamav_engine": scan.engine,
                "source_pages": document["page_count"],
                "indexable_pages": len(pages),
            }
        )
    print(json.dumps({"status": "APPROVED_FOR_INGEST", "documents": summaries}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

