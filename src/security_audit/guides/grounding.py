"""Fail-closed KISA guide grounding and exact citation contracts for IMP-049."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from datetime import date
from uuid import UUID

from security_audit.guides.retrieval import (
    GuideSearchHit,
    GuideSearchScope,
    lexical_relevance_score,
)

_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_PARAGRAPH_BOUNDARY = re.compile(r"(?<=[.!?])\s+")
_SCOPE_EXCLUSION_TERMS = {
    "kisa-2026-pc": (
        "리눅스",
        "linux",
        "ssh",
        "root",
        "클라우드",
        "버킷",
        "스마트폰",
        "생체인증",
        "데이터베이스",
    )
}


@dataclass(frozen=True, slots=True)
class ControlCitationSource:
    control_id: str
    document_code: str
    page_start: int
    page_end: int
    section_label: str


@dataclass(frozen=True, slots=True)
class GuideCitation:
    chunk_id: UUID
    guide_id: str
    guide_version: str
    document_code: str
    source_sha256: str
    scope_id: str
    pdf_page_number: int
    control_id: str
    section_label: str
    paragraph_ordinal: int
    paragraph_sha256: str
    text_sha256: str
    dense_score: float
    lexical_score: float
    rerank_score: float


@dataclass(frozen=True, slots=True)
class GuideGroundingResult:
    status: str
    reason_code: str | None
    citations: tuple[GuideCitation, ...]


@dataclass(frozen=True, slots=True)
class GuideSourceEvidence:
    guide_id: str
    version: str
    status: str
    effective_from: date
    source_sha256: str
    statement_sha256: str
    supersedes_version: str | None


@dataclass(frozen=True, slots=True)
class GuideConflictResolution:
    status: str
    reason_code: str
    selected: GuideSourceEvidence | None


def _normalized_text(value: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFC", value)).strip()


def _paragraphs(value: str) -> tuple[str, ...]:
    normalized = _normalized_text(value)
    paragraphs = tuple(
        part.strip()
        for part in _PARAGRAPH_BOUNDARY.split(normalized)
        if part.strip()
    )
    return paragraphs or ((normalized,) if normalized else ())


def _best_paragraph(query: str, text: str) -> tuple[int, str] | None:
    paragraphs = _paragraphs(text)
    if not paragraphs:
        return None
    ranked = sorted(
        enumerate(paragraphs, start=1),
        key=lambda item: (
            -lexical_relevance_score(query, item[1]),
            item[0],
        ),
    )
    ordinal, paragraph = ranked[0]
    if lexical_relevance_score(query, paragraph) < 0.20:
        return None
    return ordinal, hashlib.sha256(paragraph.encode("utf-8")).hexdigest()


def _valid_lineage(hit: GuideSearchHit, source: ControlCitationSource | None) -> bool:
    return (
        source is not None
        and source.control_id == hit.control_id
        and source.page_start <= hit.pdf_page_number <= source.page_end
        and bool(source.document_code)
        and bool(source.section_label)
        and _SHA256_PATTERN.fullmatch(hit.source_sha256) is not None
        and _SHA256_PATTERN.fullmatch(hit.text_sha256) is not None
    )


def build_grounding_result(
    scope: GuideSearchScope,
    hits: tuple[GuideSearchHit, ...],
    citation_sources: dict[str, ControlCitationSource],
    *,
    minimum_rerank_score: float = 0.30,
    minimum_lexical_score: float = 0.35,
) -> GuideGroundingResult:
    """Return ranked exact citations or a fail-closed no-evidence state."""

    normalized_query = unicodedata.normalize("NFC", scope.query).casefold()
    exclusions = _SCOPE_EXCLUSION_TERMS.get(scope.scope_id, ())
    if any(term.casefold() in normalized_query for term in exclusions):
        return GuideGroundingResult(
            status="NO_EVIDENCE",
            reason_code="NO_MATCH_IN_APPROVED_SCOPE",
            citations=(),
        )
    if not hits:
        return GuideGroundingResult(
            status="NO_EVIDENCE",
            reason_code="NO_MATCH_IN_APPROVED_SCOPE",
            citations=(),
        )
    scoped_hits = tuple(
        hit
        for hit in hits
        if hit.organization_id == scope.organization_id
        and hit.guide_id == scope.guide_id
        and hit.guide_version == scope.guide_version
        and hit.scope_id == scope.scope_id
    )
    if not scoped_hits:
        return GuideGroundingResult(
            status="NO_EVIDENCE",
            reason_code="CITATION_LINEAGE_INVALID",
            citations=(),
        )
    qualified_hits = tuple(
        hit
        for hit in scoped_hits
        if hit.rerank_score >= minimum_rerank_score
        and hit.lexical_score >= minimum_lexical_score
    )
    if not qualified_hits:
        return GuideGroundingResult(
            status="NO_EVIDENCE",
            reason_code="INSUFFICIENT_RELEVANCE",
            citations=(),
        )

    citations: list[GuideCitation] = []
    for hit in qualified_hits:
        source = citation_sources.get(hit.control_id)
        if not _valid_lineage(hit, source):
            return GuideGroundingResult(
                status="NO_EVIDENCE",
                reason_code="CITATION_LINEAGE_INVALID",
                citations=(),
            )
        paragraph = _best_paragraph(scope.query, hit.text)
        if paragraph is None or source is None:
            continue
        paragraph_ordinal, paragraph_sha256 = paragraph
        citations.append(
            GuideCitation(
                chunk_id=hit.chunk_id,
                guide_id=hit.guide_id,
                guide_version=hit.guide_version,
                document_code=source.document_code,
                source_sha256=hit.source_sha256,
                scope_id=hit.scope_id,
                pdf_page_number=hit.pdf_page_number,
                control_id=hit.control_id,
                section_label=source.section_label,
                paragraph_ordinal=paragraph_ordinal,
                paragraph_sha256=paragraph_sha256,
                text_sha256=hit.text_sha256,
                dense_score=hit.dense_score,
                lexical_score=hit.lexical_score,
                rerank_score=hit.rerank_score,
            )
        )

    if not citations:
        return GuideGroundingResult(
            status="NO_EVIDENCE",
            reason_code="INSUFFICIENT_RELEVANCE",
            citations=(),
        )
    return GuideGroundingResult(
        status="FOUND",
        reason_code=None,
        citations=tuple(citations),
    )


def citation_matches_terms(
    citation: GuideCitation,
    chunk_text: str,
    expected_terms: tuple[str, ...],
) -> bool:
    """Verify the cited paragraph hash and expected gold terms without exposing it."""

    paragraphs = _paragraphs(chunk_text)
    index = citation.paragraph_ordinal - 1
    if index < 0 or index >= len(paragraphs) or not expected_terms:
        return False
    paragraph = paragraphs[index]
    if hashlib.sha256(paragraph.encode("utf-8")).hexdigest() != citation.paragraph_sha256:
        return False
    normalized = unicodedata.normalize("NFC", paragraph).casefold()
    compact = re.sub(r"\s+", "", normalized)
    return all(
        re.sub(
            r"\s+",
            "",
            unicodedata.normalize("NFC", term).casefold(),
        )
        in compact
        for term in expected_terms
    )


def resolve_guide_conflict(
    evidence: tuple[GuideSourceEvidence, ...],
) -> GuideConflictResolution:
    """Resolve only explicit succession or identical approved statements."""

    approved = tuple(item for item in evidence if item.status == "APPROVED")
    if not approved:
        return GuideConflictResolution("NO_EVIDENCE", "NO_APPROVED_GUIDE", None)
    newest = max(
        approved,
        key=lambda item: (item.effective_from, item.guide_id, item.version),
    )
    if len({item.statement_sha256 for item in approved}) == 1:
        return GuideConflictResolution("FOUND", "CONSISTENT_GUIDES", newest)

    same_guide = all(item.guide_id == newest.guide_id for item in approved)
    older_versions = {item.version for item in approved if item != newest}
    if (
        same_guide
        and len(older_versions) == 1
        and newest.supersedes_version in older_versions
        and all(newest.effective_from > item.effective_from for item in approved if item != newest)
    ):
        return GuideConflictResolution(
            "FOUND",
            "SUPERSEDING_GUIDE_SELECTED",
            newest,
        )
    return GuideConflictResolution(
        "CONFLICT",
        "APPROVED_GUIDES_CONFLICT",
        None,
    )
