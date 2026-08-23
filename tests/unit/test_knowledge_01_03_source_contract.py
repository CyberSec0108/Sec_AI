from __future__ import annotations

from typing import cast

from security_audit.application.result_knowledge_sources import (
    build_control_knowledge_sources,
    evaluate_control_knowledge_output,
    source_grade_catalog,
)
from security_audit.common.canonical_json import JsonValue


def _citation() -> dict[str, JsonValue]:
    return {
        "guide_id": "kisa-major-infrastructure-detailed-guide",
        "guide_version": "2026",
        "pdf_page_number": 555,
        "section_label": "PC-01 비밀번호의 주기적 변경",
        "paragraph_ordinal": 2,
    }


def _sources(
    *, evidence_status: str = "FOUND"
) -> tuple[dict[str, JsonValue], ...]:
    return build_control_knowledge_sources(
        control_id="PC-01",
        control_title="비밀번호의 주기적 변경",
        citation=_citation(),
        evidence_status=evidence_status,
    )


def test_source_grades_keep_rule_decision_separate_from_ai_knowledge() -> None:
    catalog = {str(item["source_type"]): item for item in source_grade_catalog()}

    assert catalog["RULE_ENGINE"]["official_decision_allowed"] is True
    assert catalog["MODEL_GENERAL_KNOWLEDGE"]["official_decision_allowed"] is False
    assert catalog["MODEL_GENERAL_KNOWLEDGE"]["decision_role"] == "EXPLANATION_ONLY"
    assert catalog["KISA_PRIMARY"]["grade_label"] == "KISA 공식 근거"
    assert "VENDOR_PRIMARY" in catalog


def test_sources_use_inline_numbers_and_short_korean_document_locations() -> None:
    sources = _sources()
    kisa = sources[1]

    assert [source["citation_id"] for source in sources] == ["[1]", "[2]", "[3]"]
    assert all(source["source_type"] != "RULE_ENGINE" for source in sources)
    assert kisa["title_ko"] == "KISA PC 보안 가이드 2026"
    assert kisa["locator_label"] == "555쪽 · PC-01 비밀번호의 주기적 변경"
    assert kisa["display_label"] == (
        "KISA PC 보안 가이드 2026 · 555쪽 · PC-01 비밀번호의 주기적 변경"
    )
    assert "kisa-major-infrastructure" not in str(kisa["display_label"])
    lineage = cast(dict[str, JsonValue], kisa["technical_lineage"])
    assert lineage["guide_id"] == "kisa-major-infrastructure-detailed-guide"


def test_output_evaluation_reports_bad_citation_hallucination_and_freshness() -> None:
    result = evaluate_control_knowledge_output(
        "현재값은 기준과 비교되었습니다.[1][2] 일반 설명입니다.[3] "
        "2029년에는 77%입니다.[9]",
        _sources(),
        grounding_text="점검 기준은 1~90일이며 KISA 2026 가이드를 사용합니다.",
        evidence_status="FOUND",
    )

    assert result["status"] == "REVIEW"
    assert result["unknown_citation_ids"] == ["[9]"]
    assert result["unsupported_precise_claims"] == ["2029", "77%"]
    assert result["freshness_reviewed"] is True
    assert result["rule_status_unchanged"] is True


def test_output_evaluation_defers_conflicting_source_without_changing_rule() -> None:
    result = evaluate_control_knowledge_output(
        "확인된 값과 KISA 근거만 안내합니다.[1][3]",
        _sources(evidence_status="DOCUMENT_CONFLICT"),
        grounding_text="확인된 값과 규칙 결과",
        evidence_status="DOCUMENT_CONFLICT",
    )

    assert result["status"] == "DEFERRED"
    assert result["source_conflict"] is True
    assert result["official_decision_authority"] == "RULE_ENGINE"
    assert result["rule_status_unchanged"] is True


def test_output_evaluation_records_model_refusal() -> None:
    result = evaluate_control_knowledge_output(
        "근거가 없어 답변할 수 없습니다.[1][2][3]",
        _sources(),
        grounding_text="근거",
        evidence_status="FOUND",
    )

    assert result["status"] == "REFUSED"
    assert result["refused"] is True
