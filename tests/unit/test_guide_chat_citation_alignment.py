from __future__ import annotations

from pathlib import Path
from uuid import UUID

from apps.api import chat_conversation

from security_audit.chat.contracts import ChatCitation
from security_audit.persistence.database.chat_repository import _indexed_citations

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _payloads() -> list[dict[str, object]]:
    return [
        {"ordinal": ordinal, "section_label": f"검색 후보 {ordinal}"}
        for ordinal in range(1, 6)
    ]


def _chat_citations() -> tuple[ChatCitation, ...]:
    return tuple(
        ChatCitation(
            guide_id="kisa-major-infrastructure-detailed-guide",
            guide_version="2026",
            scope_id="kisa-2026-all",
            chunk_id=UUID(f"48000000-0000-4000-8000-{ordinal:012d}"),
            pdf_page_number=100 + ordinal,
            section_label=f"검색 후보 {ordinal}",
            paragraph_ordinal=ordinal,
            paragraph_sha256=f"{ordinal:x}" * 64,
            text_start=0,
            text_end=20,
        )
        for ordinal in range(1, 6)
    )


def test_parenthesized_outline_numbers_are_not_mistaken_for_citations() -> None:
    content = "(1) 일반 사용자 점검\n(2) 관리자 점검\n설정값(3)을 비교합니다."

    assert chat_conversation._referenced_citation_payloads(
        content,
        _payloads(),
    ) == []

    visible = chat_conversation._referenced_citation_payloads(
        "승인된 원문에서 확인했습니다.（3）",
        _payloads(),
    )
    assert [item["ordinal"] for item in visible] == [3]
    assert chat_conversation._referenced_citation_payloads(
        "앞에 0을 붙인 [01]은 동일한 인라인 번호가 아닙니다.",
        _payloads(),
    ) == []


def test_generation_keeps_only_referenced_citations_with_original_ordinals() -> None:
    selector = getattr(
        chat_conversation,
        "_referenced_chat_citations",
        None,
    )
    assert selector is not None

    selected = selector(
        "첫 번째 근거입니다.[1] 세 번째 근거입니다.【3】",
        _chat_citations(),
    )

    assert [citation.ordinal for citation in selected] == [1, 3]
    assert [citation.pdf_page_number for citation in selected] == [101, 103]
    assert [ordinal for ordinal, _citation in _indexed_citations(selected)] == [
        1,
        3,
    ]


def test_guide_chat_filters_citations_before_rendering_and_opening_sources() -> None:
    script = (
        PROJECT_ROOT / "apps/web/static/app/guide-chat.js"
    ).read_text(encoding="utf-8")

    assert "function referencedCitations(content, citations)" in script
    assert "const messageCitations = referencedCitations(" in script
    assert "showSources(messageCitations)" in script
    assert "Array.from({length: 20}" not in script
    assert "} else {\n    showSources([]);" in script
