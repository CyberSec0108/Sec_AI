"""승인된 KISA 2026 PDF의 전체 분류 검색용 페이지·출처 맵을 생성한다."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import fitz  # type: ignore[import-untyped]

from security_audit.guides.contracts import normalize_page_text, text_sha256


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf"
)
PAGE_MAP_PATH = (
    PROJECT_ROOT / "guides" / "page_maps" / "kisa_2026_all_pages.json"
)
CONTROL_MAP_PATH = (
    PROJECT_ROOT
    / "guides"
    / "mappings"
    / "kisa_2026_all_control_sources.json"
)
SOURCE_SHA256 = "44fe393981b244147be6af7423d99dc15633c089fad0bcb296cbe2371dde812d"


@dataclass(frozen=True, slots=True)
class Category:
    number: int
    label: str
    page_start: int
    page_end: int
    first_control_page: int
    intro_control_id: str


CATEGORIES = (
    Category(1, "Unix 서버", 7, 171, 12, "UNIX-INTRO"),
    Category(2, "Windows 서버", 172, 270, 177, "WINDOWS-INTRO"),
    Category(3, "웹 서비스", 271, 352, 274, "WEB-SERVICE-INTRO"),
    Category(4, "보안 장비", 353, 386, 356, "SECURITY-EQUIPMENT-INTRO"),
    Category(5, "네트워크 장비", 387, 466, 391, "NETWORK-EQUIPMENT-INTRO"),
    Category(6, "제어시스템", 467, 551, 472, "CONTROL-SYSTEM-INTRO"),
    Category(7, "PC", 552, 592, 555, "PC-INTRO"),
    Category(8, "DBMS", 593, 669, 596, "DBMS-INTRO"),
    Category(9, "이동통신", 670, 675, 672, "MOBILE-INTRO"),
    Category(10, "Web Application(웹)", 676, 786, 679, "WEB-APP-INTRO"),
    Category(11, "가상화 장비", 787, 850, 790, "VIRTUALIZATION-INTRO"),
    Category(12, "클라우드", 851, 873, 854, "CLOUD-INTRO"),
)

_CONTROL_PATTERN = re.compile(
    r"^(?:U|W|WEB|S|N|C|PC|D|M|HV|CA)-\d{2}$"
    r"|^(?:CI|SI|DI|EP|IL|XS|CF|SF|BF|IA|IN|PR|PV|FU|FD|IS|SN|CC|AE|AU|WM)$",
    re.MULTILINE,
)
_IMPORTANCE_PATTERN = re.compile(r"^\([상중하]\)$")


def _category_for(page_number: int) -> Category:
    for category in CATEGORIES:
        if category.page_start <= page_number <= category.page_end:
            return category
    raise ValueError(f"분류되지 않은 PDF 페이지입니다: {page_number}")


def _control_at_page_start(text: str, category: Category, page_number: int) -> str | None:
    if page_number < category.first_control_page:
        return None
    match = _CONTROL_PATTERN.search(text[:700])
    return match.group(0) if match is not None else None


def _control_title(text: str, control_id: str, category: Category) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    try:
        index = lines.index(control_id)
    except ValueError:
        return ""
    for line in lines[index + 1 : index + 8]:
        if _IMPORTANCE_PATTERN.fullmatch(line):
            continue
        if line == category.label or ">" in line:
            continue
        if line.startswith("2026 ") or line.startswith("Chapter "):
            continue
        if line.isdigit() or line in {"| 한국인터넷진흥원 |", "한국인터넷진흥원"}:
            continue
        return line
    return ""


def main() -> int:
    pages: list[dict[str, object]] = []
    control_rows: dict[str, dict[str, object]] = {}
    current_control_by_category = {
        category.number: category.intro_control_id for category in CATEGORIES
    }

    with fitz.open(SOURCE_PATH) as document:
        if document.page_count != 873:
            raise RuntimeError("KISA PDF 페이지 수가 승인된 원본과 다릅니다.")
        for page_number in range(7, 874):
            category = _category_for(page_number)
            text = document[page_number - 1].get_text("text")
            normalized = normalize_page_text(text)
            found_control = _control_at_page_start(text, category, page_number)
            if found_control:
                current_control_by_category[category.number] = found_control
            control_id = current_control_by_category[category.number]
            title = (
                _control_title(text, control_id, category)
                if found_control == control_id
                else ""
            )
            pages.append(
                {
                    "pdf_page_number": page_number,
                    "pdf_page_index": page_number - 1,
                    "printed_page_number": page_number,
                    "control_ids": [control_id],
                    "text_sha256": text_sha256(text),
                    "normalized_text_chars": len(normalized),
                }
            )
            row = control_rows.get(control_id)
            if row is None:
                label = f"{category.number:02d}. {category.label}"
                detail = (
                    f"{control_id} {title}".strip()
                    if control_id != category.intro_control_id
                    else "분류 안내"
                )
                control_rows[control_id] = {
                    "control_id": control_id,
                    "control_title": title or detail,
                    "source_document_code": "KISA-2026-FULL",
                    "page_start": page_number,
                    "page_end": page_number,
                    "section_label": f"{label} · {detail}",
                    "mapping_status": "APPROVED_SOURCE",
                }
            else:
                row["page_end"] = page_number

    page_map = {
        "schema_version": "1.0.0",
        "map_id": "kisa-2026-all-pages",
        "guide_id": "kisa-major-infrastructure-detailed-guide",
        "guide_version": "2026",
        "source_sha256": SOURCE_SHA256,
        "source_page_count": 873,
        "scope_id": "kisa-2026-all",
        "pdf_page_start": 7,
        "pdf_page_end": 873,
        "pages": pages,
    }
    control_map = {
        "schema_version": "1.0.0",
        "mapping_id": "kisa-2026-all-control-sources",
        "version": "1.0.0",
        "status": "APPROVED_SOURCE",
        "guide": {
            "guide_id": "kisa-major-infrastructure-detailed-guide",
            "version": "2026",
            "source_sha256": SOURCE_SHA256,
            "required_catalog_status": "APPROVED",
        },
        "runtime_activation_allowed": True,
        "mappings": list(control_rows.values()),
    }
    PAGE_MAP_PATH.write_text(
        json.dumps(page_map, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    CONTROL_MAP_PATH.write_text(
        json.dumps(control_map, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "pages": len(pages),
                "controls": len(control_rows),
                "page_map": str(PAGE_MAP_PATH),
                "control_map": str(CONTROL_MAP_PATH),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
