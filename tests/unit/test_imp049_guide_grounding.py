from __future__ import annotations

import json
from dataclasses import replace
from datetime import date
from pathlib import Path
from uuid import UUID

from security_audit.guides.grounding import (
    ControlCitationSource,
    GuideSourceEvidence,
    build_grounding_result,
    citation_matches_terms,
    resolve_guide_conflict,
)
from security_audit.guides.retrieval import (
    GuideSearchHit,
    GuideSearchScope,
    lexical_relevance_score,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
CHUNK_ID = UUID("49000000-0000-4000-8000-000000000001")
SOURCE_SHA256 = "a" * 64
TEXT_SHA256 = "b" * 64


def _scope(query: str = "저장 장치의 파일 시스템은 어떤 형식이어야 하나요?") -> GuideSearchScope:
    return GuideSearchScope(
        organization_id=ORGANIZATION_ID,
        guide_id="kisa-major-infrastructure-detailed-guide",
        guide_version="2026",
        scope_id="kisa-2026-pc",
        query=query,
        top_k=5,
    )


def _source() -> ControlCitationSource:
    return ControlCitationSource(
        control_id="PC-07",
        document_code="KISA-2026-07-PC",
        page_start=571,
        page_end=572,
        section_label="PC-07 파일 시스템이 NTFS 포맷으로 설정",
    )


def _hit(
    *,
    page: int = 571,
    text: str = (
        "PC-07 파일 시스템이 NTFS 포맷으로 설정. "
        "점검 대상 저장 장치의 파일 시스템이 모두 NTFS인지 확인합니다."
    ),
    lexical_score: float = 0.8,
    rerank_score: float = 0.85,
) -> GuideSearchHit:
    return GuideSearchHit(
        chunk_id=CHUNK_ID,
        organization_id=ORGANIZATION_ID,
        guide_id="kisa-major-infrastructure-detailed-guide",
        guide_version="2026",
        source_sha256=SOURCE_SHA256,
        scope_id="kisa-2026-pc",
        pdf_page_number=page,
        control_id="PC-07",
        text=text,
        text_sha256=TEXT_SHA256,
        dense_score=0.9,
        lexical_score=lexical_score,
        rerank_score=rerank_score,
    )


def test_relevant_hit_builds_exact_page_section_and_paragraph_citation() -> None:
    result = build_grounding_result(
        _scope(),
        (_hit(),),
        {"PC-07": _source()},
    )

    assert result.status == "FOUND"
    assert result.reason_code is None
    assert len(result.citations) == 1
    citation = result.citations[0]
    assert citation.chunk_id == CHUNK_ID
    assert citation.document_code == "KISA-2026-07-PC"
    assert citation.pdf_page_number == 571
    assert citation.section_label == "PC-07 파일 시스템이 NTFS 포맷으로 설정"
    assert citation.paragraph_ordinal == 2
    assert len(citation.paragraph_sha256) == 64
    assert citation.source_sha256 == SOURCE_SHA256
    assert citation.text_sha256 == TEXT_SHA256
    assert citation_matches_terms(
        citation,
        _hit().text,
        ("저장 장치", "NTFS"),
    )
    assert not citation_matches_terms(citation, _hit().text, ("SSH",))


def test_low_relevance_returns_no_evidence_without_a_citation() -> None:
    result = build_grounding_result(
        _scope("클라우드 객체 저장소 버킷 공개 차단 기준은 무엇인가요?"),
        (_hit(lexical_score=0.05, rerank_score=0.18),),
        {"PC-07": _source()},
    )

    assert result.status == "NO_EVIDENCE"
    assert result.reason_code == "NO_MATCH_IN_APPROVED_SCOPE"
    assert result.citations == ()


def test_next_exact_hit_is_used_when_the_dense_first_hit_is_not_sufficient() -> None:
    weak = _hit(
        page=572,
        lexical_score=0.30,
        rerank_score=0.34,
    )
    strong = replace(
        _hit(page=571),
        chunk_id=UUID("49000000-0000-4000-8000-000000000002"),
    )

    result = build_grounding_result(
        _scope(),
        (weak, strong),
        {"PC-07": _source()},
    )

    assert result.status == "FOUND"
    assert result.citations[0].chunk_id == strong.chunk_id


def test_clear_non_pc_platform_terms_are_rejected_by_the_pc_scope() -> None:
    result = build_grounding_result(
        _scope("리눅스 SSH root 로그인을 차단하는 기준은 무엇인가요?"),
        (_hit(),),
        {"PC-07": _source()},
    )

    assert result.status == "NO_EVIDENCE"
    assert result.reason_code == "NO_MATCH_IN_APPROVED_SCOPE"


def test_korean_phrase_score_prefers_the_exact_control_topic() -> None:
    question = "복구 콘솔의 자동 관리자 로그온은 어떻게 설정해야 하나요?"

    expected = lexical_relevance_score(
        question,
        "PC-03 복구 콘솔에서 자동 로그온을 금지하도록 설정",
    )
    nearby = lexical_relevance_score(
        question,
        "PC-12 Windows 자동 로그인 점검",
    )
    unrelated = lexical_relevance_score(
        question,
        "클라우드 객체 저장소 버킷 공개 차단",
    )

    assert expected > nearby > unrelated


def test_korean_question_aliases_match_kisa_control_wording() -> None:
    periodic_change_question = "비밀번호는 얼마마다 변경해야 하나요?"
    software_question = "필요하지 않은 소프트웨어는 어떻게 관리하나요?"

    assert lexical_relevance_score(
        periodic_change_question,
        "PC-01 비밀번호의 주기적 변경",
    ) > lexical_relevance_score(
        periodic_change_question,
        "PC-09 불필요한 IE 보안 영역 설정",
    )
    assert lexical_relevance_score(
        software_question,
        "PC-06 불필요한 소프트웨어 제거",
    ) > lexical_relevance_score(
        software_question,
        "PC-13 바이러스 백신 프로그램 설치",
    )


def test_page_or_control_mapping_mismatch_fails_closed() -> None:
    result = build_grounding_result(
        _scope(),
        (_hit(page=580),),
        {"PC-07": _source()},
    )

    assert result.status == "NO_EVIDENCE"
    assert result.reason_code == "CITATION_LINEAGE_INVALID"
    assert result.citations == ()


def test_conflicting_approved_guides_are_not_silently_merged() -> None:
    conflict = resolve_guide_conflict(
        (
            GuideSourceEvidence(
                guide_id="kisa-pc",
                version="2025",
                status="APPROVED",
                effective_from=date(2025, 1, 1),
                source_sha256="1" * 64,
                statement_sha256="a" * 64,
                supersedes_version=None,
            ),
            GuideSourceEvidence(
                guide_id="organization-pc",
                version="2025",
                status="APPROVED",
                effective_from=date(2025, 1, 1),
                source_sha256="2" * 64,
                statement_sha256="b" * 64,
                supersedes_version=None,
            ),
        )
    )

    assert conflict.status == "CONFLICT"
    assert conflict.reason_code == "APPROVED_GUIDES_CONFLICT"
    assert conflict.selected is None


def test_explicit_newer_superseding_guide_resolves_version_difference() -> None:
    older = GuideSourceEvidence(
        guide_id="kisa-pc",
        version="2025",
        status="APPROVED",
        effective_from=date(2025, 1, 1),
        source_sha256="1" * 64,
        statement_sha256="a" * 64,
        supersedes_version=None,
    )
    newer = GuideSourceEvidence(
        guide_id="kisa-pc",
        version="2026",
        status="APPROVED",
        effective_from=date(2026, 1, 1),
        source_sha256="2" * 64,
        statement_sha256="b" * 64,
        supersedes_version="2025",
    )

    resolved = resolve_guide_conflict((older, newer))

    assert resolved.status == "FOUND"
    assert resolved.reason_code == "SUPERSEDING_GUIDE_SELECTED"
    assert resolved.selected == newer


def test_evaluation_fixture_covers_all_pc_controls_and_negative_questions() -> None:
    fixture = json.loads(
        (
            PROJECT_ROOT
            / "guides"
            / "evaluations"
            / "kisa_2026_pc_questions.json"
        ).read_text(encoding="utf-8")
    )
    supported = [
        case for case in fixture["cases"] if case["expected_status"] == "FOUND"
    ]
    unsupported = [
        case
        for case in fixture["cases"]
        if case["expected_status"] == "NO_EVIDENCE"
    ]

    assert {case["expected_control_id"] for case in supported} == {
        f"PC-{number:02d}" for number in range(1, 19)
    }
    assert len(supported) >= 18
    assert len(unsupported) >= 4
    assert all(case["expected_evidence_terms"] for case in supported)
    assert all(case["expected_control_id"] is None for case in unsupported)


def test_api_image_contains_only_derived_guide_contracts_not_the_source_pdf() -> None:
    dockerfile = (
        PROJECT_ROOT / "deploy" / "docker" / "api.Dockerfile"
    ).read_text(encoding="utf-8")

    assert "COPY --chown=10001:10001 guides /app/guides" in dockerfile
    assert "COPY data" not in dockerfile
