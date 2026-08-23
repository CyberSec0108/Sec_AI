"""고정된 공공기관 PDF에서 결정론적 페이지 계보 파일을 생성합니다."""

from __future__ import annotations

import json
from pathlib import Path

from security_audit.guides.public_guides import (
    build_public_guide_page_map,
    load_public_guide_manifest,
    public_guide_page_map_path,
    verify_public_guide_sources,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    manifest = load_public_guide_manifest(PROJECT_ROOT)
    report = verify_public_guide_sources(PROJECT_ROOT, manifest)
    if not report.accepted:
        raise RuntimeError("PUBLIC_GUIDE_SOURCE_GATE_FAILED:" + ",".join(report.errors))

    documents = manifest["documents"]
    if not isinstance(documents, list):
        raise RuntimeError("PUBLIC_GUIDE_DOCUMENTS_INVALID")
    summaries: list[dict[str, object]] = []
    for document in documents:
        if not isinstance(document, dict):
            raise RuntimeError("PUBLIC_GUIDE_DOCUMENT_INVALID")
        page_map = build_public_guide_page_map(PROJECT_ROOT, document)
        target = public_guide_page_map_path(PROJECT_ROOT, document)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(page_map, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        pages = page_map["pages"]
        if not isinstance(pages, list):
            raise RuntimeError("PUBLIC_GUIDE_PAGE_MAP_INVALID")
        summaries.append(
            {
                "guide_id": document["guide_id"],
                "page_map": target.relative_to(PROJECT_ROOT).as_posix(),
                "source_pages": len(pages),
                "indexable_pages": sum(
                    item.get("indexable") is True
                    for item in pages
                    if isinstance(item, dict)
                ),
            }
        )
    print(json.dumps({"status": "BUILT", "documents": summaries}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

