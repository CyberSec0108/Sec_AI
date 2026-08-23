"""Fail-closed IMP-048 guide ingest and deterministic test retrieval contracts."""

from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from dataclasses import dataclass
from uuid import NAMESPACE_URL, UUID, uuid5

_TOKEN_PATTERN = re.compile(r"[0-9A-Za-z가-힣]+")
_CONTROL_PATTERN = re.compile(
    r"^(?:"
    r"PC-(?:0[1-9]|1[0-8])"
    r"|(?:U|W|WEB|S|N|C|D|M|HV|CA)-\d{2}"
    r"|(?:UNIX|WINDOWS|WEB-SERVICE|SECURITY-EQUIPMENT|NETWORK-EQUIPMENT|CONTROL-SYSTEM|PC|DBMS|MOBILE|WEB-APP|VIRTUALIZATION|CLOUD)-INTRO"
    r"|(?:CI|SI|DI|EP|IL|XS|CF|SF|BF|IA|IN|PR|PV|FU|FD|IS|SN|CC|AE|AU|WM)"
    r"|GUIDE-PAGE"
    r")$"
)
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_KOREAN_SECURITY_TERM_GROUPS = (
    ("비밀번호", "패스워드", "암호"),
    ("변경", "교체"),
    ("주기", "기간"),
    ("복잡성", "길이", "문자"),
    ("계정", "사용자", "관리자"),
    ("자동 로그인", "자동로그인", "복구 콘솔"),
    ("공유", "권한"),
    ("서비스", "불필요"),
    ("메신저",),
    ("저장 장치", "저장장치", "파일 시스템", "NTFS", "FAT32"),
    ("운영체제", "멀티부팅"),
    ("인터넷 익스플로러", "임시 파일", "브라우저"),
    ("보안 패치", "업데이트"),
    ("지원 종료", "제품 수명"),
    ("백신", "악성코드"),
    ("실시간 감시",),
    ("방화벽",),
    ("화면보호기", "화면 잠금"),
    ("자동실행", "이동식 미디어"),
    ("원격 지원", "Remote Assistance"),
    ("수집", "정보"),
    ("양호", "취약"),
    ("설정", "정책"),
    ("확인", "점검"),
)
_KOREAN_RETRIEVAL_CONCEPT_GROUPS = (
    _KOREAN_SECURITY_TERM_GROUPS[:9]
    + (
        ("저장 장치", "저장장치"),
        ("파일 시스템", "NTFS", "FAT32"),
    )
    + _KOREAN_SECURITY_TERM_GROUPS[10:]
    + (
    ("소프트웨어", "응용 프로그램", "프로그램 제거"),
    ("로그온", "로그인"),
    ("침입차단", "Windows 방화벽"),
    )
)
_KOREAN_QUERY_ALIASES = (
    ("얼마마다", "주기"),
    ("필요하지 않은", "불필요한"),
    ("제조사", "벤더"),
    ("켜야", "활성화"),
    ("다시 시작", "재시작"),
)


@dataclass(frozen=True, slots=True)
class GuideIngestGateInput:
    guide_status: str
    license_status: str
    derivative_text_storage_allowed: bool
    source_hash_verified: bool
    page_map_verified: bool
    malware_scan_passed: bool
    extraction_quality_approved: bool
    query_scope_enabled: bool
    synthetic_test_only: bool


@dataclass(frozen=True, slots=True)
class GuideIngestGateResult:
    errors: tuple[str, ...]

    @property
    def accepted(self) -> bool:
        return not self.errors


@dataclass(frozen=True, slots=True)
class GuidePageText:
    pdf_page_number: int
    control_id: str
    text: str


@dataclass(frozen=True, slots=True)
class GuideChunk:
    chunk_id: UUID
    organization_id: UUID
    guide_id: str
    guide_version: str
    source_sha256: str
    scope_id: str
    pdf_page_number: int
    control_id: str
    ordinal: int
    text: str
    text_sha256: str


@dataclass(frozen=True, slots=True)
class GuideSearchScope:
    organization_id: UUID
    guide_id: str
    guide_version: str
    scope_id: str
    query: str
    top_k: int = 5
    allow_synthetic_test_data: bool = False
    control_id: str | None = None

    def __post_init__(self) -> None:
        if not self.guide_id or not self.guide_version or not self.scope_id:
            raise ValueError("GUIDE_SCOPE_INVALID")
        if not self.query.strip() or len(self.query) > 500:
            raise ValueError("GUIDE_QUERY_INVALID")
        if not 1 <= self.top_k <= 20:
            raise ValueError("GUIDE_TOP_K_INVALID")
        if (
            self.control_id is not None
            and _CONTROL_PATTERN.fullmatch(self.control_id) is None
        ):
            raise ValueError("GUIDE_CONTROL_ID_INVALID")


@dataclass(frozen=True, slots=True)
class GuideSearchCandidate:
    chunk_id: UUID
    organization_id: UUID
    guide_id: str
    guide_version: str
    scope_id: str
    pdf_page_number: int
    control_id: str
    text: str
    dense_score: float
    source_sha256: str = ""
    text_sha256: str = ""


@dataclass(frozen=True, slots=True)
class GuideSearchHit:
    chunk_id: UUID
    organization_id: UUID
    guide_id: str
    guide_version: str
    scope_id: str
    pdf_page_number: int
    control_id: str
    text: str
    dense_score: float
    lexical_score: float
    rerank_score: float
    source_sha256: str = ""
    text_sha256: str = ""


def evaluate_ingest_gate(gate: GuideIngestGateInput) -> GuideIngestGateResult:
    """Require every real-source gate, with a distinct synthetic-only identity."""

    if gate.synthetic_test_only and (
        gate.guide_status != "SYNTHETIC_TEST_ONLY"
        or gate.license_status != "SYNTHETIC_TEST_ONLY"
    ):
        return GuideIngestGateResult(("SYNTHETIC_GATE_IDENTITY_INVALID",))

    errors: list[str] = []
    if not gate.synthetic_test_only and gate.guide_status != "APPROVED":
        errors.append("GUIDE_NOT_APPROVED")
    if not gate.synthetic_test_only and gate.license_status != "APPROVED":
        errors.append("LICENSE_NOT_APPROVED")
    if not gate.derivative_text_storage_allowed:
        errors.append("DERIVATIVE_TEXT_STORAGE_NOT_ALLOWED")
    if not gate.source_hash_verified:
        errors.append("SOURCE_HASH_NOT_VERIFIED")
    if not gate.page_map_verified:
        errors.append("PAGE_MAP_NOT_VERIFIED")
    if not gate.malware_scan_passed:
        errors.append("MALWARE_SCAN_REQUIRED")
    if not gate.extraction_quality_approved:
        errors.append("EXTRACTION_QUALITY_NOT_APPROVED")
    if not gate.query_scope_enabled:
        errors.append("QUERY_SCOPE_DISABLED")
    return GuideIngestGateResult(tuple(sorted(errors)))


def _normalized_text(value: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFC", value)).strip()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_guide_chunks(
    *,
    organization_id: UUID,
    guide_id: str,
    guide_version: str,
    source_sha256: str,
    scope_id: str,
    pages: tuple[GuidePageText, ...],
    gate: GuideIngestGateInput,
) -> tuple[GuideChunk, ...]:
    """Build immutable page chunks only after the explicit ingest gate passes."""

    gate_result = evaluate_ingest_gate(gate)
    if not gate_result.accepted:
        raise ValueError(f"GUIDE_INGEST_BLOCKED:{','.join(gate_result.errors)}")
    if (
        not guide_id
        or not guide_version
        or not scope_id
        or _SHA256_PATTERN.fullmatch(source_sha256) is None
    ):
        raise ValueError("GUIDE_IDENTITY_INVALID")

    page_numbers = [page.pdf_page_number for page in pages]
    if not pages or page_numbers != sorted(set(page_numbers)):
        raise ValueError("PAGE_ORDER_OR_DUPLICATE_INVALID")

    chunks: list[GuideChunk] = []
    for ordinal, page in enumerate(pages):
        text = _normalized_text(page.text)
        if (
            page.pdf_page_number <= 0
            or _CONTROL_PATTERN.fullmatch(page.control_id) is None
            or not text
        ):
            raise ValueError("GUIDE_PAGE_INVALID")
        text_hash = _text_sha256(text)
        identity = "|".join(
            (
                str(organization_id),
                guide_id,
                guide_version,
                source_sha256,
                scope_id,
                str(page.pdf_page_number),
                page.control_id,
                str(ordinal),
                text_hash,
            )
        )
        chunks.append(
            GuideChunk(
                chunk_id=uuid5(NAMESPACE_URL, f"secai-guide-chunk:{identity}"),
                organization_id=organization_id,
                guide_id=guide_id,
                guide_version=guide_version,
                source_sha256=source_sha256,
                scope_id=scope_id,
                pdf_page_number=page.pdf_page_number,
                control_id=page.control_id,
                ordinal=ordinal,
                text=text,
                text_sha256=text_hash,
            )
        )
    return tuple(chunks)


def _tokens(value: str) -> tuple[str, ...]:
    return tuple(
        token.casefold()
        for token in _TOKEN_PATTERN.findall(unicodedata.normalize("NFC", value))
    )


class DeterministicTestEmbedder:
    """Dependency-free test vectorizer; it is never an approved production model."""

    dimension = 32
    model_id = "secai-hash-ko-test-v1"

    def embed(self, text: str) -> list[float]:
        tokens = _tokens(text)
        if not tokens:
            raise ValueError("EMBEDDING_TEXT_EMPTY")
        values = [0.0] * self.dimension
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimension
            sign = 1.0 if digest[4] & 1 else -1.0
            values[index] += sign
        norm = math.sqrt(sum(value * value for value in values))
        if norm == 0:
            raise ValueError("EMBEDDING_NORM_ZERO")
        return [value / norm for value in values]


class ApprovedLocalKoreanEmbedder:
    """Local KISA-domain lexical projection without external data transfer."""

    dimension = 32
    model_id = "secai-ko-lexical-hash-v1"

    def embed(self, text: str) -> list[float]:
        normalized = unicodedata.normalize("NFC", text)
        tokens = _tokens(normalized)
        if not tokens:
            raise ValueError("EMBEDDING_TEXT_EMPTY")
        values = [0.0] * self.dimension
        for index, terms in enumerate(_KOREAN_SECURITY_TERM_GROUPS):
            if any(term.casefold() in normalized.casefold() for term in terms):
                values[index] = 3.0
        fallback_offset = len(_KOREAN_SECURITY_TERM_GROUPS)
        fallback_dimensions = self.dimension - fallback_offset
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = fallback_offset + int.from_bytes(digest[:4], "big") % fallback_dimensions
            values[index] += 0.25
        norm = math.sqrt(sum(value * value for value in values))
        if norm == 0:
            raise ValueError("EMBEDDING_NORM_ZERO")
        return [value / norm for value in values]


def vector_literal(
    values: list[float] | tuple[float, ...],
    *,
    expected_dimension: int = DeterministicTestEmbedder.dimension,
) -> str:
    if len(values) != expected_dimension or any(
        not math.isfinite(value) for value in values
    ):
        raise ValueError("EMBEDDING_VECTOR_INVALID")
    return "[" + ",".join(format(value, ".12g") for value in values) + "]"


def lexical_relevance_score(query: str, text: str) -> float:
    """Measure exact-token or KISA-domain concept coverage without an LLM."""

    normalized_query_value = unicodedata.normalize("NFC", query)
    for source, canonical in _KOREAN_QUERY_ALIASES:
        normalized_query_value = normalized_query_value.replace(source, canonical)
    query_tokens = set(_tokens(normalized_query_value))
    if not query_tokens:
        return 0.0
    exact_score = len(query_tokens.intersection(_tokens(text))) / len(query_tokens)
    normalized_query = normalized_query_value.casefold()
    normalized_text = unicodedata.normalize("NFC", text).casefold()
    query_concepts = {
        index
        for index, terms in enumerate(_KOREAN_RETRIEVAL_CONCEPT_GROUPS)
        if any(term.casefold() in normalized_query for term in terms)
    }
    text_concepts = {
        index
        for index, terms in enumerate(_KOREAN_RETRIEVAL_CONCEPT_GROUPS)
        if any(term.casefold() in normalized_text for term in terms)
    }
    concept_score = (
        len(query_concepts.intersection(text_concepts)) / len(query_concepts)
        if query_concepts
        else 0.0
    )

    def _ngrams(value: str, size: int) -> set[str]:
        compact = "".join(_TOKEN_PATTERN.findall(value.casefold()))
        if len(compact) < size:
            return {compact} if compact else set()
        return {
            compact[index : index + size]
            for index in range(len(compact) - size + 1)
        }

    normalized_query = normalized_query_value
    normalized_text = unicodedata.normalize("NFC", text)
    character_scores: list[float] = []
    for size in (2, 3):
        query_ngrams = _ngrams(normalized_query, size)
        text_ngrams = _ngrams(normalized_text, size)
        if query_ngrams:
            character_scores.append(
                len(query_ngrams.intersection(text_ngrams)) / len(query_ngrams)
            )
    character_score = max(character_scores, default=0.0)
    return min(
        1.0,
        (exact_score * 0.10)
        + (concept_score * 0.25)
        + (character_score * 0.65),
    )


def filter_and_rerank(
    scope: GuideSearchScope,
    candidates: tuple[GuideSearchCandidate, ...],
    *,
    dense_weight: float = 0.15,
    lexical_weight: float = 0.85,
) -> tuple[GuideSearchHit, ...]:
    """Apply exact authorization scope before deterministic lexical reranking."""

    if (
        not 0.0 <= dense_weight <= 1.0
        or not 0.0 <= lexical_weight <= 1.0
        or not math.isclose(dense_weight + lexical_weight, 1.0, abs_tol=1e-9)
    ):
        raise ValueError("GUIDE_SEARCH_WEIGHT_INVALID")

    hits: list[GuideSearchHit] = []
    for candidate in candidates:
        if (
            candidate.organization_id != scope.organization_id
            or candidate.guide_id != scope.guide_id
            or candidate.guide_version != scope.guide_version
            or candidate.scope_id != scope.scope_id
            or candidate.control_id == "PC-INTRO"
            or (
                scope.control_id is not None
                and candidate.control_id != scope.control_id
            )
        ):
            continue
        dense = min(1.0, max(0.0, candidate.dense_score))
        lexical = lexical_relevance_score(scope.query, candidate.text)
        hits.append(
            GuideSearchHit(
                chunk_id=candidate.chunk_id,
                organization_id=candidate.organization_id,
                guide_id=candidate.guide_id,
                guide_version=candidate.guide_version,
                scope_id=candidate.scope_id,
                pdf_page_number=candidate.pdf_page_number,
                control_id=candidate.control_id,
                text=candidate.text,
                dense_score=dense,
                lexical_score=lexical,
                rerank_score=(dense * dense_weight) + (lexical * lexical_weight),
                source_sha256=candidate.source_sha256,
                text_sha256=candidate.text_sha256,
            )
        )
    hits.sort(
        key=lambda hit: (
            -hit.rerank_score,
            hit.pdf_page_number,
            str(hit.chunk_id),
        )
    )
    return tuple(hits[: scope.top_k])
