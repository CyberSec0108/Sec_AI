"""PRODUCT-AI-02 점검 결과별 KISA 근거 검색 application service."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from uuid import UUID

from sqlalchemy.orm import Session

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.application.model_search import (
    ModelSearchError,
    ModelSearchSettings,
    search_with_bge_m3,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)
from security_audit.guides.grounding import (
    ControlCitationSource,
    GuideCitation,
    GuideConflictResolution,
    build_grounding_result,
)
from security_audit.guides.retrieval import (
    ApprovedLocalKoreanEmbedder,
    GuideSearchHit,
    GuideSearchScope,
)
from security_audit.persistence.database.guide_repository import search_guide_chunks

_CONTROL_PATTERN = re.compile(r"^PC-(0[1-9]|1[0-8])$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_PARAGRAPH_BOUNDARY = re.compile(r"(?<=[.!?])\s+")
_RULE_STATUSES = frozenset({"PASS", "FAIL", "ERROR", "REVIEW", "N/A"})
_GUIDE_SCOPE_ID = "kisa-2026-pc"

GuideSearch = Callable[
    [object, GuideSearchScope, list[float] | tuple[float, ...]],
    tuple[GuideSearchHit, ...],
]


class ResultGuideRetrievalError(ValueError):
    """검색 전에 거부하는 안전한 PRODUCT-AI-02 계약 오류."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ResultGuideEvidenceSegment:
    chunk_id: UUID
    paragraph_ordinal: int
    paragraph_text: str
    paragraph_sha256: str

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "chunk_id": str(self.chunk_id),
            "paragraph_ordinal": self.paragraph_ordinal,
            "paragraph_text": self.paragraph_text,
            "paragraph_sha256": self.paragraph_sha256,
        }


@dataclass(frozen=True, slots=True)
class ResultGuideRetrievalResult:
    status: str
    reason_code: str | None
    control_id: str
    rule_status: str
    explanation_input_sha256: str
    search_query_sha256: str
    citations: tuple[GuideCitation, ...]
    evidence_segments: tuple[ResultGuideEvidenceSegment, ...]
    official_finding_write_allowed: bool
    output_sha256: str

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "schema_version": "1.0.0",
            "status": self.status,
            "reason_code": self.reason_code,
            "control_id": self.control_id,
            "rule_status": self.rule_status,
            "status_authority": "RULE_ENGINE",
            "explanation_input_sha256": self.explanation_input_sha256,
            "search_query_sha256": self.search_query_sha256,
            "citations": [_citation_json(item) for item in self.citations],
            "evidence_segments": [
                item.to_json() for item in self.evidence_segments
            ],
            "official_finding_write_allowed": self.official_finding_write_allowed,
            "output_sha256": self.output_sha256,
        }


def _postgres_search(
    session: object,
    scope: GuideSearchScope,
    vector: list[float] | tuple[float, ...],
) -> tuple[GuideSearchHit, ...]:
    settings = ModelSearchSettings.from_environment()
    if settings.mode in {"BGE_M3_RERANKER", "BGE_M3_WITH_LEGACY_FALLBACK"}:
        try:
            return search_with_bge_m3(cast(Session, session), scope, settings)
        except ModelSearchError:
            if settings.mode != "BGE_M3_WITH_LEGACY_FALLBACK":
                raise
    return search_guide_chunks(cast(Session, session), scope, vector)


def _object(value: JsonValue, code: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ResultGuideRetrievalError(code)
    return value


def _text(value: JsonValue | None, code: str, *, maximum: int = 4_000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ResultGuideRetrievalError(code)
    return value.strip()


def _load_object(path: Path, code: str) -> dict[str, JsonValue]:
    value = load_strict_json(path.read_bytes())
    if not isinstance(value, dict):
        raise ResultGuideRetrievalError(code)
    return value


def _mapping_source(
    project_root: Path,
    control_id: str,
) -> tuple[dict[str, JsonValue], str]:
    catalog = _load_object(
        project_root / "guides" / "catalog.json",
        "GUIDE_CATALOG_INVALID",
    )
    mapping = _load_object(
        project_root
        / "guides"
        / "mappings"
        / "kisa_2026_pc_control_sources.json",
        "SOURCE_MAPPING_INVALID",
    )
    guide = _object(mapping.get("guide"), "SOURCE_MAPPING_INVALID")
    guide_id = _text(guide.get("guide_id"), "SOURCE_MAPPING_INVALID")
    guide_version = _text(guide.get("version"), "SOURCE_MAPPING_INVALID")
    source_sha256 = _text(guide.get("source_sha256"), "SOURCE_MAPPING_INVALID")

    guides = catalog.get("guides")
    if not isinstance(guides, list):
        raise ResultGuideRetrievalError("GUIDE_CATALOG_INVALID")
    approved = [
        _object(item, "GUIDE_CATALOG_INVALID")
        for item in guides
        if isinstance(item, dict)
        and item.get("guide_id") == guide_id
        and item.get("version") == guide_version
        and item.get("status") == "APPROVED"
    ]
    if len(approved) != 1:
        raise ResultGuideRetrievalError("GUIDE_NOT_APPROVED")
    catalog_guide = approved[0]
    source = _object(catalog_guide.get("source"), "GUIDE_CATALOG_INVALID")
    if (
        source.get("source_sha256") != source_sha256
        or _SHA256_PATTERN.fullmatch(source_sha256) is None
    ):
        raise ResultGuideRetrievalError("GUIDE_SOURCE_HASH_MISMATCH")
    query_scopes = catalog_guide.get("query_scopes")
    if not isinstance(query_scopes, list) or not any(
        isinstance(item, dict)
        and item.get("scope_id") == _GUIDE_SCOPE_ID
        and item.get("default_enabled") is True
        for item in query_scopes
    ):
        raise ResultGuideRetrievalError("GUIDE_SCOPE_NOT_APPROVED")

    mappings = mapping.get("mappings")
    if not isinstance(mappings, list):
        raise ResultGuideRetrievalError("SOURCE_MAPPING_INVALID")
    matches = [
        _object(item, "SOURCE_MAPPING_INVALID")
        for item in mappings
        if isinstance(item, dict) and item.get("control_id") == control_id
    ]
    if len(matches) != 1:
        raise ResultGuideRetrievalError("SOURCE_MAPPING_INVALID")
    item = matches[0]
    return (
        {
            "guide_id": guide_id,
            "guide_version": guide_version,
            "source_sha256": source_sha256,
            "document_code": item.get("source_document_code"),
            "page_start": item.get("page_start"),
            "page_end": item.get("page_end"),
            "section_label": item.get("section_label"),
            "mapping_status": item.get("mapping_status"),
        },
        source_sha256,
    )


def _validated_input(
    value: Mapping[str, JsonValue],
    *,
    project_root: Path,
) -> tuple[str, str, str, dict[str, JsonValue]]:
    supplied_hash = _text(
        value.get("explanation_input_sha256"),
        "EXPLANATION_INPUT_INVALID",
    )
    calculated = canonical_sha256_without_fields(
        dict(value),
        {"explanation_input_sha256"},
    )
    if supplied_hash != calculated:
        raise ResultGuideRetrievalError("INPUT_HASH_MISMATCH")
    control_id = _text(value.get("control_id"), "EXPLANATION_INPUT_INVALID")
    if _CONTROL_PATTERN.fullmatch(control_id) is None:
        raise ResultGuideRetrievalError("EXPLANATION_INPUT_INVALID")
    rule_status = _text(value.get("rule_status"), "EXPLANATION_INPUT_INVALID")
    if (
        rule_status not in _RULE_STATUSES
        or value.get("status_authority") != "RULE_ENGINE"
        or value.get("official_finding_write_allowed") is not False
    ):
        raise ResultGuideRetrievalError("RULE_STATUS_AUTHORITY_INVALID")

    expected_source, _ = _mapping_source(project_root, control_id)
    citations = value.get("kisa_citations")
    if (
        not isinstance(citations, list)
        or len(citations) != 1
        or citations[0] != expected_source
    ):
        raise ResultGuideRetrievalError("SOURCE_MAPPING_MISMATCH")
    return supplied_hash, control_id, rule_status, expected_source


def _search_query(
    value: Mapping[str, JsonValue],
    _source: Mapping[str, JsonValue],
) -> str:
    fields = (
        value.get("control_id"),
        value.get("what_was_checked"),
    )
    query = re.sub(
        r"\s+",
        " ",
        " ".join(item.strip() for item in fields if isinstance(item, str)),
    ).strip()
    if not query:
        raise ResultGuideRetrievalError("RESULT_SEARCH_QUERY_INVALID")
    return query[:500]


def _citation_source(
    control_id: str,
    source: Mapping[str, JsonValue],
) -> ControlCitationSource:
    page_start = source.get("page_start")
    page_end = source.get("page_end")
    if not isinstance(page_start, int) or not isinstance(page_end, int):
        raise ResultGuideRetrievalError("SOURCE_MAPPING_INVALID")
    return ControlCitationSource(
        control_id=control_id,
        document_code=_text(source.get("document_code"), "SOURCE_MAPPING_INVALID"),
        page_start=page_start,
        page_end=page_end,
        section_label=_text(source.get("section_label"), "SOURCE_MAPPING_INVALID"),
    )


def _citation_json(citation: GuideCitation) -> dict[str, JsonValue]:
    return {
        "chunk_id": str(citation.chunk_id),
        "guide_id": citation.guide_id,
        "guide_version": citation.guide_version,
        "document_code": citation.document_code,
        "source_sha256": citation.source_sha256,
        "scope_id": citation.scope_id,
        "pdf_page_number": citation.pdf_page_number,
        "control_id": citation.control_id,
        "section_label": citation.section_label,
        "paragraph_ordinal": citation.paragraph_ordinal,
        "paragraph_sha256": citation.paragraph_sha256,
        "text_sha256": citation.text_sha256,
        "dense_score": citation.dense_score,
        "lexical_score": citation.lexical_score,
        "rerank_score": citation.rerank_score,
    }


def _paragraph_segment(
    citation: GuideCitation,
    hit: GuideSearchHit,
) -> ResultGuideEvidenceSegment:
    normalized = re.sub(
        r"\s+",
        " ",
        unicodedata.normalize("NFC", hit.text),
    ).strip()
    paragraphs = tuple(
        part.strip()
        for part in _PARAGRAPH_BOUNDARY.split(normalized)
        if part.strip()
    )
    index = citation.paragraph_ordinal - 1
    if index < 0 or index >= len(paragraphs):
        raise ResultGuideRetrievalError("CITATION_PARAGRAPH_INVALID")
    paragraph = paragraphs[index]
    paragraph_sha256 = hashlib.sha256(paragraph.encode("utf-8")).hexdigest()
    if paragraph_sha256 != citation.paragraph_sha256:
        raise ResultGuideRetrievalError("CITATION_PARAGRAPH_HASH_MISMATCH")
    return ResultGuideEvidenceSegment(
        chunk_id=citation.chunk_id,
        paragraph_ordinal=citation.paragraph_ordinal,
        paragraph_text=paragraph,
        paragraph_sha256=paragraph_sha256,
    )


def _result(
    *,
    status: str,
    reason_code: str | None,
    control_id: str,
    rule_status: str,
    explanation_input_sha256: str,
    search_query_sha256: str,
    citations: tuple[GuideCitation, ...] = (),
    evidence_segments: tuple[ResultGuideEvidenceSegment, ...] = (),
) -> ResultGuideRetrievalResult:
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "status": status,
        "reason_code": reason_code,
        "control_id": control_id,
        "rule_status": rule_status,
        "status_authority": "RULE_ENGINE",
        "explanation_input_sha256": explanation_input_sha256,
        "search_query_sha256": search_query_sha256,
        "citations": [_citation_json(item) for item in citations],
        "evidence_segments": [item.to_json() for item in evidence_segments],
        "official_finding_write_allowed": False,
    }
    output_sha256 = canonical_sha256_without_fields(payload, {"output_sha256"})
    return ResultGuideRetrievalResult(
        status=status,
        reason_code=reason_code,
        control_id=control_id,
        rule_status=rule_status,
        explanation_input_sha256=explanation_input_sha256,
        search_query_sha256=search_query_sha256,
        citations=citations,
        evidence_segments=evidence_segments,
        official_finding_write_allowed=False,
        output_sha256=output_sha256,
    )


class ResultGuideRetrievalService:
    """불변 규칙 결과를 승인된 KISA 근거와 연결하고 추정 인용을 거부한다."""

    def __init__(
        self,
        project_root: Path,
        *,
        search: GuideSearch = _postgres_search,
    ) -> None:
        self._project_root = project_root
        self._search = search

    def retrieve(
        self,
        session: object,
        explanation_input: Mapping[str, JsonValue],
        *,
        organization_id: UUID,
        conflict: GuideConflictResolution | None = None,
    ) -> ResultGuideRetrievalResult:
        input_hash, control_id, rule_status, source = _validated_input(
            explanation_input,
            project_root=self._project_root,
        )
        query = _search_query(explanation_input, source)
        query_sha256 = hashlib.sha256(query.encode("utf-8")).hexdigest()
        if conflict is not None and conflict.status == "CONFLICT":
            return _result(
                status="CONFLICT",
                reason_code=conflict.reason_code,
                control_id=control_id,
                rule_status=rule_status,
                explanation_input_sha256=input_hash,
                search_query_sha256=query_sha256,
            )

        search_settings = ModelSearchSettings.from_environment()
        scope = GuideSearchScope(
            organization_id=organization_id,
            guide_id=_text(source.get("guide_id"), "SOURCE_MAPPING_INVALID"),
            guide_version=_text(
                source.get("guide_version"),
                "SOURCE_MAPPING_INVALID",
            ),
            scope_id=_GUIDE_SCOPE_ID,
            query=query,
            top_k=search_settings.result_top_k,
            control_id=control_id,
        )
        hits = self._search(
            session,
            scope,
            ApprovedLocalKoreanEmbedder().embed(query),
        )
        if any(
            hit.organization_id != organization_id
            or hit.guide_id != scope.guide_id
            or hit.guide_version != scope.guide_version
            or hit.scope_id != scope.scope_id
            for hit in hits
        ):
            return _result(
                status="INSUFFICIENT_EVIDENCE",
                reason_code="CITATION_SCOPE_MISMATCH",
                control_id=control_id,
                rule_status=rule_status,
                explanation_input_sha256=input_hash,
                search_query_sha256=query_sha256,
            )
        matching_hits = tuple(hit for hit in hits if hit.control_id == control_id)
        if not matching_hits:
            return _result(
                status="INSUFFICIENT_EVIDENCE",
                reason_code="NO_MATCH_FOR_RESULT_CONTROL",
                control_id=control_id,
                rule_status=rule_status,
                explanation_input_sha256=input_hash,
                search_query_sha256=query_sha256,
            )
        grounding_settings = ModelSearchSettings.from_environment()
        grounding = build_grounding_result(
            scope,
            matching_hits,
            {control_id: _citation_source(control_id, source)},
            minimum_rerank_score=grounding_settings.minimum_rerank_score,
            minimum_lexical_score=grounding_settings.minimum_lexical_score,
        )
        if grounding.status != "FOUND" or not grounding.citations:
            return _result(
                status="INSUFFICIENT_EVIDENCE",
                reason_code=grounding.reason_code or "INSUFFICIENT_RELEVANCE",
                control_id=control_id,
                rule_status=rule_status,
                explanation_input_sha256=input_hash,
                search_query_sha256=query_sha256,
            )
        citation = grounding.citations[0]
        hit = next(item for item in matching_hits if item.chunk_id == citation.chunk_id)
        segment = _paragraph_segment(citation, hit)
        return _result(
            status="FOUND",
            reason_code=None,
            control_id=control_id,
            rule_status=rule_status,
            explanation_input_sha256=input_hash,
            search_query_sha256=query_sha256,
            citations=(citation,),
            evidence_segments=(segment,),
        )
