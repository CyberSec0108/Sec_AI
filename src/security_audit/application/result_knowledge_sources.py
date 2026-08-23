"""점검 결과 AI 설명의 출처 등급·표시·평가 계약."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Final, cast

from security_audit.common.canonical_json import JsonValue

KNOWLEDGE_CONTRACT_VERSION: Final = "secai.result-knowledge.v2"
KISA_DOCUMENT_TITLE_KO: Final = "KISA PC 보안 가이드 2026"

SOURCE_GRADES: Final[tuple[dict[str, JsonValue], ...]] = (
    {
        "source_type": "OBSERVED_VALUE",
        "grade_code": "E1",
        "grade_label": "내 PC 확인 증적",
        "decision_role": "RULE_INPUT",
        "official_decision_allowed": False,
    },
    {
        "source_type": "RULE_ENGINE",
        "grade_code": "R1",
        "grade_label": "공식 판정 규칙",
        "decision_role": "OFFICIAL_DECISION",
        "official_decision_allowed": True,
    },
    {
        "source_type": "KISA_PRIMARY",
        "grade_code": "G1",
        "grade_label": "KISA 공식 근거",
        "decision_role": "CONTROL_BASIS",
        "official_decision_allowed": False,
    },
    {
        "source_type": "VENDOR_PRIMARY",
        "grade_code": "G2",
        "grade_label": "제조사 공식 문서",
        "decision_role": "SUPPLEMENTAL_BASIS",
        "official_decision_allowed": False,
    },
    {
        "source_type": "APPROVED_PUBLIC",
        "grade_code": "G3",
        "grade_label": "승인된 공공 보안 자료",
        "decision_role": "SUPPLEMENTAL_BASIS",
        "official_decision_allowed": False,
    },
    {
        "source_type": "MODEL_GENERAL_KNOWLEDGE",
        "grade_code": "A1",
        "grade_label": "AI 일반 보안지식",
        "decision_role": "EXPLANATION_ONLY",
        "official_decision_allowed": False,
    },
)

_GRADE_BY_TYPE = {
    cast(str, item["source_type"]): item for item in SOURCE_GRADES
}
_CITATION_PATTERN = re.compile(r"\[(\d{1,2})\]")
_PRECISE_CLAIM_PATTERN = re.compile(
    r"(?<!\d)(?:19|20)\d{2}(?!\d)|\b\d+(?:\.\d+)?%|"
    r"CVE-\d{4}-\d+|\b\d+(?:\.\d+){1,3}\b",
    re.IGNORECASE,
)
_REFUSAL_PATTERNS = (
    "답변할 수 없",
    "설명할 수 없",
    "정보가 없어 답변",
    "근거가 없어 답변",
)


def source_grade_catalog() -> tuple[dict[str, JsonValue], ...]:
    """외부 DTO에 노출 가능한 출처 등급 사본을 반환한다."""

    return tuple(dict(item) for item in SOURCE_GRADES)


def _grade(source_type: str) -> dict[str, JsonValue]:
    return dict(_GRADE_BY_TYPE[source_type])


def _page_locator(citation: Mapping[str, JsonValue], control_id: str) -> str:
    page = citation.get("pdf_page_number")
    section = citation.get("section_label")
    if not isinstance(page, int):
        return f"{control_id} 근거 위치 확인 필요"
    section_label = section.strip() if isinstance(section, str) else control_id
    return f"{page}쪽 · {section_label}"


def _source(
    citation_id: str,
    source_type: str,
    title_ko: str,
    locator_label: str,
    *,
    availability: str,
    freshness_status: str,
    limitation: str,
    technical_lineage: Mapping[str, JsonValue] | None = None,
) -> dict[str, JsonValue]:
    grade = _grade(source_type)
    return {
        "citation_id": citation_id,
        "source_type": source_type,
        "grade_code": grade["grade_code"],
        "grade_label": grade["grade_label"],
        "decision_role": grade["decision_role"],
        "official_decision_allowed": grade["official_decision_allowed"],
        "title_ko": title_ko,
        "locator_label": locator_label,
        "display_label": f"{title_ko} · {locator_label}",
        "availability": availability,
        "freshness_status": freshness_status,
        "limitation": limitation,
        "technical_lineage": dict(technical_lineage or {}),
    }


def build_control_knowledge_sources(
    *,
    control_id: str,
    control_title: str,
    citation: Mapping[str, JsonValue],
    evidence_status: str,
) -> tuple[dict[str, JsonValue], ...]:
    """AI 설명에 직접 사용한 세 종류의 출처만 구성한다."""

    kisa_available = evidence_status == "FOUND" and isinstance(
        citation.get("pdf_page_number"), int
    )
    kisa_locator = _page_locator(citation, control_id)
    lineage = {
        key: citation.get(key)
        for key in (
            "guide_id",
            "guide_version",
            "pdf_page_number",
            "section_label",
            "paragraph_ordinal",
        )
        if citation.get(key) is not None
    }
    return (
        _source(
            "[1]",
            "OBSERVED_VALUE",
            "내 PC 점검 결과",
            f"{control_id} 실제 확인값",
            availability="AVAILABLE",
            freshness_status="COLLECTED_AT_SCAN",
            limitation="점검 시점에 읽은 값이며 이후 설정 변경은 반영하지 않습니다.",
        ),
        _source(
            "[2]",
            "KISA_PRIMARY",
            KISA_DOCUMENT_TITLE_KO,
            kisa_locator,
            availability="AVAILABLE" if kisa_available else "UNAVAILABLE",
            freshness_status=(
                "PINNED_GUIDE_VERSION" if kisa_available else "REVIEW_REQUIRED"
            ),
            limitation=(
                "승인된 원문의 해당 쪽과 절을 사용합니다."
                if kisa_available
                else "원문 위치를 확인하지 못해 KISA 근거 설명을 보류합니다."
            ),
            technical_lineage=lineage,
        ),
        _source(
            "[3]",
            "MODEL_GENERAL_KNOWLEDGE",
            "AI 일반 보안지식",
            f"{control_id} 이해를 돕는 참고 설명",
            availability="AVAILABLE",
            freshness_status="CURRENTNESS_NOT_GUARANTEED",
            limitation=(
                "이해를 돕는 보충 설명이며 공식 판정·최신 사실의 근거로 사용하지 않습니다."
            ),
        ),
    )


def evaluate_control_knowledge_output(
    output_text: str,
    sources: Sequence[Mapping[str, JsonValue]],
    *,
    grounding_text: str,
    evidence_status: str,
) -> dict[str, JsonValue]:
    """출력은 차단하지 않고 인용·충돌·환각 신호·최신성·보류를 평가한다."""

    allowed = {
        cast(str, source.get("citation_id"))
        for source in sources
        if isinstance(source.get("citation_id"), str)
    }
    used = tuple(dict.fromkeys(f"[{match}]" for match in _CITATION_PATTERN.findall(output_text)))
    unknown = tuple(item for item in used if item not in allowed)
    required = {"[1]", "[3]"}
    if evidence_status == "FOUND":
        required.add("[2]")
    missing = tuple(sorted(required.difference(used)))

    grounded_precise = set(_PRECISE_CLAIM_PATTERN.findall(grounding_text))
    unsupported_precise = tuple(
        dict.fromkeys(
            claim
            for claim in _PRECISE_CLAIM_PATTERN.findall(output_text)
            if claim not in grounded_precise
        )
    )
    refused = any(pattern in output_text for pattern in _REFUSAL_PATTERNS)
    conflict = evidence_status == "DOCUMENT_CONFLICT"
    missing_kisa = evidence_status != "FOUND"

    limitations: list[str] = []
    if conflict:
        limitations.append("KISA 근거가 서로 충돌해 원문 확인 전까지 관련 설명을 보류합니다.")
    elif missing_kisa:
        limitations.append("KISA 원문 위치를 확인하지 못해 관련 설명을 보류합니다.")
    if unknown:
        limitations.append("출처 목록에 없는 인용 번호가 포함되어 확인이 필요합니다.")
    if missing:
        limitations.append("설명에 필요한 출처 번호가 빠져 있어 확인이 필요합니다.")
    if unsupported_precise:
        limitations.append("제공된 근거에 없는 날짜·비율·버전 등 정밀 주장을 확인해야 합니다.")
    limitations.append("AI 일반 보안지식은 최신성을 보장하지 않으며 공식 판정을 바꾸지 않습니다.")

    if refused:
        status = "REFUSED"
    elif conflict or missing_kisa:
        status = "DEFERRED"
    elif unknown or missing or unsupported_precise:
        status = "REVIEW"
    else:
        status = "SUPPORTED"

    return {
        "contract_version": KNOWLEDGE_CONTRACT_VERSION,
        "status": status,
        "used_citation_ids": list(used),
        "unknown_citation_ids": list(unknown),
        "missing_citation_ids": list(missing),
        "unsupported_precise_claims": list(unsupported_precise),
        "source_conflict": conflict,
        "refused": refused,
        "freshness_reviewed": True,
        "limitations": cast(list[JsonValue], limitations),
        "official_decision_authority": "RULE_ENGINE",
        "rule_status_unchanged": True,
    }
