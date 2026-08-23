"""여러 승인 가이드를 한 번에 검색하는 로컬·읽기 전용 질문 서비스."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sqlalchemy.orm import Session

from security_audit.application.grounded_ai import (
    CompletionModel,
    GroundedAIRequest,
    GroundedAIResult,
    GroundedAIService,
    ModelExecutionPolicy,
    contains_executable_output,
    contains_prompt_injection,
)
from security_audit.application.model_search import (
    BgeM3Client,
    ModelSearchError,
    ModelSearchSettings,
)
from security_audit.common.canonical_json import JsonValue, canonical_sha256
from security_audit.guides.grounding import (
    ControlCitationSource,
    GuideCitation,
    build_grounding_result,
)
from security_audit.guides.retrieval import (
    ApprovedLocalKoreanEmbedder,
    GuideSearchHit,
    GuideSearchScope,
)
from security_audit.persistence.database.guide_repository import (
    search_guide_chunks,
    search_guide_chunks_bge_m3,
)

_PARAGRAPH_BOUNDARY = re.compile(r"(?<=[.!?])\s+")
_MODEL_ID = "secai-local-integrated-guide-summary-v1"
_PROMPT_TEMPLATE_ID = "secai-integrated-guide-summary"
_PROMPT_TEMPLATE_VERSION = "1.0.0"
INTEGRATED_GUIDE_ID = "secai-integrated-security-guides"
INTEGRATED_GUIDE_VERSION = "2026-08-06"
INTEGRATED_SCOPE_ID = "integrated-all"


@dataclass(frozen=True, slots=True)
class IntegratedGuideTarget:
    guide_id: str
    guide_version: str
    scope_id: str
    citation_sources: dict[str, ControlCitationSource]

    def __post_init__(self) -> None:
        if (
            not self.guide_id
            or not self.guide_version
            or not self.scope_id
            or not self.citation_sources
        ):
            raise ValueError("INTEGRATED_GUIDE_TARGET_INVALID")


def _json_hash(value: JsonValue) -> str:
    return canonical_sha256(value)


def _paragraph(value: str, ordinal: int) -> str:
    normalized = re.sub(r"\s+", " ", unicodedata.normalize("NFC", value)).strip()
    paragraphs = tuple(
        part.strip()
        for part in _PARAGRAPH_BOUNDARY.split(normalized)
        if part.strip()
    ) or ((normalized,) if normalized else ())
    if not paragraphs:
        return ""
    position = min(max(ordinal, 1), len(paragraphs)) - 1
    return paragraphs[position][:900]


def _scopes(
    organization_id: UUID,
    question: str,
    top_k: int,
    targets: tuple[IntegratedGuideTarget, ...],
) -> tuple[tuple[IntegratedGuideTarget, GuideSearchScope], ...]:
    if (
        not question.strip()
        or len(question) > 500
        or not 1 <= top_k <= 10
        or not 1 <= len(targets) <= 16
        or len({(item.guide_id, item.guide_version, item.scope_id) for item in targets})
        != len(targets)
    ):
        raise ValueError("INTEGRATED_GUIDE_QUERY_INVALID")
    return tuple(
        (
            target,
            GuideSearchScope(
                organization_id=organization_id,
                guide_id=target.guide_id,
                guide_version=target.guide_version,
                scope_id=target.scope_id,
                query=question,
                top_k=top_k,
            ),
        )
        for target in targets
    )


def _search_all(
    session: Session,
    scopes: tuple[tuple[IntegratedGuideTarget, GuideSearchScope], ...],
    settings: ModelSearchSettings,
) -> tuple[tuple[IntegratedGuideTarget, GuideSearchScope, tuple[GuideSearchHit, ...]], ...]:
    question = scopes[0][1].query
    if settings.mode in {"BGE_M3_RERANKER", "BGE_M3_WITH_LEGACY_FALLBACK"}:
        try:
            query_vector = BgeM3Client(settings).embed(question)
            return tuple(
                (
                    target,
                    scope,
                    search_guide_chunks_bge_m3(
                        session,
                        scope,
                        query_vector,
                        dense_weight=settings.dense_weight,
                        lexical_weight=settings.lexical_weight,
                        candidate_multiplier=settings.db_candidate_multiplier,
                        candidate_limit=settings.db_candidate_limit,
                    ),
                )
                for target, scope in scopes
            )
        except ModelSearchError:
            if settings.mode != "BGE_M3_WITH_LEGACY_FALLBACK":
                raise
    legacy_vector = ApprovedLocalKoreanEmbedder().embed(question)
    return tuple(
        (target, scope, search_guide_chunks(session, scope, legacy_vector))
        for target, scope in scopes
    )


def generate_integrated_guide_answer(
    session: Session,
    *,
    organization_id: UUID,
    question: str,
    profile: Literal["FAST", "PRECISE"],
    targets: tuple[IntegratedGuideTarget, ...],
    settings: ModelSearchSettings | None = None,
    model: CompletionModel | None = None,
    policy: ModelExecutionPolicy | None = None,
    on_token: Callable[[str], None] | None = None,
) -> GroundedAIResult:
    """모든 승인 문서를 검색하고 관련도가 높은 서로 다른 문서를 종합합니다."""

    if contains_prompt_injection(question):
        return GroundedAIResult(
            mode="GUIDE_QA",
            status="SECURITY_BLOCKED",
            reason_code="PROMPT_INJECTION_DETECTED",
            answer=None,
            citations=(),
        )
    top_k = 3 if profile == "FAST" else 5
    scopes = _scopes(organization_id, question, top_k, targets)
    active = settings or ModelSearchSettings.from_environment()
    candidates: list[tuple[GuideCitation, GuideSearchHit]] = []
    for target, scope, hits in _search_all(session, scopes, active):
        grounding = build_grounding_result(
            scope,
            hits,
            target.citation_sources,
            minimum_rerank_score=active.minimum_rerank_score,
            minimum_lexical_score=active.minimum_lexical_score,
        )
        if grounding.status != "FOUND":
            continue
        hits_by_id = {hit.chunk_id: hit for hit in hits}
        candidates.extend(
            (citation, hits_by_id[citation.chunk_id])
            for citation in grounding.citations
            if citation.chunk_id in hits_by_id
        )
    candidates.sort(
        key=lambda item: (
            -item[0].rerank_score,
            -item[0].lexical_score,
            item[0].guide_id,
            item[0].pdf_page_number,
        )
    )
    selected: list[tuple[GuideCitation, GuideSearchHit]] = []
    selected_guides: set[str] = set()
    unsafe_evidence_count = 0
    for candidate in candidates:
        if candidate[0].guide_id in selected_guides:
            continue
        if contains_prompt_injection(candidate[1].text):
            unsafe_evidence_count += 1
            continue
        selected.append(candidate)
        selected_guides.add(candidate[0].guide_id)
        if len(selected) >= top_k:
            break
    if not selected:
        return GroundedAIResult(
            mode="GUIDE_QA",
            status=("SECURITY_BLOCKED" if unsafe_evidence_count else "NO_EVIDENCE"),
            reason_code=(
                "UNTRUSTED_GUIDE_INSTRUCTION_DETECTED"
                if unsafe_evidence_count
                else "NO_MATCH_IN_APPROVED_SCOPE"
            ),
            answer=None,
            citations=(),
        )

    if model is not None:
        if policy is None:
            raise ValueError("INTEGRATED_GUIDE_MODEL_POLICY_REQUIRED")
        request = GroundedAIRequest(
            mode="GUIDE_QA",
            scope=GuideSearchScope(
                organization_id=organization_id,
                guide_id=INTEGRATED_GUIDE_ID,
                guide_version=INTEGRATED_GUIDE_VERSION,
                scope_id=INTEGRATED_SCOPE_ID,
                query=question,
                top_k=top_k,
            ),
            profile=profile,
        )
        return GroundedAIService(model).generate(
            request,
            hits=(),
            citation_sources={},
            policy=policy,
            on_token=on_token,
            verified_cited_hits=tuple(selected),
        )
    if policy is not None or on_token is not None:
        raise ValueError("INTEGRATED_GUIDE_MODEL_REQUIRED")

    evidence_lines: list[str] = []
    used_citations: list[GuideCitation] = []
    evidence_payload: list[JsonValue] = []
    for citation, hit in selected:
        evidence = _paragraph(hit.text, citation.paragraph_ordinal)
        if not evidence:
            continue
        ordinal = len(used_citations) + 1
        evidence_lines.append(f"- {evidence}[{ordinal}]")
        used_citations.append(citation)
        evidence_payload.append(
            {
                "guide_id": citation.guide_id,
                "guide_version": citation.guide_version,
                "chunk_id": str(citation.chunk_id),
                "page": citation.pdf_page_number,
                "text_sha256": citation.text_sha256,
            }
        )
    if not used_citations:
        return GroundedAIResult(
            mode="GUIDE_QA",
            status="NO_EVIDENCE",
            reason_code="NO_MATCH_IN_APPROVED_SCOPE",
            answer=None,
            citations=(),
        )
    answer = "\n\n".join(
        (
            "핵심 답변\n질문과 관련된 승인 가이드를 통합 검색한 결과입니다.",
            "통합 근거\n" + "\n".join(evidence_lines),
            (
                "알아두세요\n- 실제 사용된 문서명과 쪽수는 출처 패널에 표시됩니다. "
                "보완 가이드는 설명에만 사용하며 KISA 점검 판정이나 공식 점검 "
                "결과를 변경하지 않습니다."
            ),
        )
    )
    if contains_executable_output(answer):
        return GroundedAIResult(
            mode="GUIDE_QA",
            status="SECURITY_BLOCKED",
            reason_code="UNSAFE_MODEL_OUTPUT",
            answer=None,
            citations=(),
        )
    prompt_sha256 = _json_hash(
        {
            "template_id": _PROMPT_TEMPLATE_ID,
            "template_version": _PROMPT_TEMPLATE_VERSION,
            "external_data_transfer": False,
        }
    )
    input_sha256 = _json_hash(
        {
            "question": question,
            "profile": profile,
            "evidence": evidence_payload,
        }
    )
    return GroundedAIResult(
        mode="GUIDE_QA",
        status="GENERATED",
        reason_code=None,
        answer=answer,
        citations=tuple(used_citations),
        model_id=_MODEL_ID,
        prompt_template_id=_PROMPT_TEMPLATE_ID,
        prompt_template_version=_PROMPT_TEMPLATE_VERSION,
        prompt_sha256=prompt_sha256,
        input_sha256=input_sha256,
        output_sha256=_json_hash({"model_id": _MODEL_ID, "answer": answer}),
    )
