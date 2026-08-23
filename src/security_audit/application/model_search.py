"""BGE-M3와 Reranker를 명시적으로 선택하는 내부 검색 경계."""

from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass, replace
from typing import Literal, cast
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from sqlalchemy.orm import Session

from security_audit.guides.retrieval import GuideSearchHit, GuideSearchScope
from security_audit.persistence.database.guide_repository import (
    search_guide_chunks_bge_m3,
)


class ModelSearchError(RuntimeError):
    """모델 검색 계약 위반 또는 내부 서비스 실패입니다."""


def _environment_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ModelSearchError(f"GUIDE_SEARCH_SETTING_INVALID:{name}") from exc
    if not minimum <= value <= maximum:
        raise ModelSearchError(f"GUIDE_SEARCH_SETTING_INVALID:{name}")
    return value


def _environment_float(
    name: str,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ModelSearchError(f"GUIDE_SEARCH_SETTING_INVALID:{name}") from exc
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise ModelSearchError(f"GUIDE_SEARCH_SETTING_INVALID:{name}")
    return value


_CATEGORY_HINTS: tuple[
    tuple[str, str, tuple[str, ...], tuple[str, ...]], ...
] = (
    (
        "UNIX",
        "Unix 서버",
        ("리눅스", "linux", "unix", "ubuntu", "rocky"),
        ("U-", "UNIX-"),
    ),
    (
        "WINDOWS",
        "Windows 서버",
        ("윈도우", "windows"),
        ("W-", "WINDOWS-"),
    ),
    (
        "WEB_SERVICE",
        "웹 서비스",
        ("웹 서비스", "web service"),
        ("WEB-", "WEB-SERVICE-"),
    ),
    (
        "SECURITY_DEVICE",
        "보안 장비",
        ("보안 장비", "보안장비", "security appliance"),
        ("S-", "SECURITY-EQUIPMENT-"),
    ),
    (
        "NETWORK_DEVICE",
        "네트워크 장비",
        (
            "네트워크 장비",
            "네트워크 스위치",
            "network device",
            "switch",
            "스위치",
            "cisco",
            "aruba",
        ),
        ("N-", "NETWORK-EQUIPMENT-"),
    ),
    (
        "CONTROL_SYSTEM",
        "제어시스템",
        ("제어시스템", "제어 시스템", "scada", "ics"),
        ("C-", "CONTROL-SYSTEM-"),
    ),
    (
        "PC",
        "PC",
        ("pc 보안", "pc 점검", "개인용 컴퓨터", "워크스테이션"),
        ("PC-",),
    ),
    (
        "DBMS",
        "DBMS",
        ("dbms", "데이터베이스", "database"),
        ("D-", "DBMS-"),
    ),
    (
        "MOBILE",
        "이동통신",
        ("이동통신", "모바일 네트워크", "mobile network"),
        ("M-", "MOBILE-"),
    ),
    (
        "WEB_APPLICATION",
        "Web Application",
        ("웹 애플리케이션", "웹 어플리케이션", "web application", "코드 인젝션"),
        ("CI", "SI", "DI", "EP", "WEB-APPLICATION-"),
    ),
    (
        "VIRTUALIZATION",
        "가상화 장비",
        ("가상화", "하이퍼바이저", "hypervisor", "vmware"),
        ("HV-", "VIRTUALIZATION-"),
    ),
    (
        "CLOUD",
        "클라우드",
        ("클라우드", "cloud"),
        ("CA-", "CLOUD-"),
    ),
)

_COMPOUND_SEPARATOR = re.compile(
    r"\s+(?:그리고|및|또는)\s+|[,;/]|(?<=[가-힣A-Za-z0-9])(?:과|와)\s+",
    re.IGNORECASE,
)


def _normalized_query(query: str) -> str:
    return " ".join(query.strip().split())


def _explicit_category_keys(query: str) -> tuple[str, ...]:
    folded = query.casefold()
    return tuple(
        key
        for key, _label, aliases, _prefixes in _CATEGORY_HINTS
        if any(alias.casefold() in folded for alias in aliases)
    )


def expand_guide_search_queries(query: str, *, limit: int = 6) -> tuple[str, ...]:
    """비교·복합·모호 질문을 제한된 다중 검색 질의로 확장합니다."""

    normalized = _normalized_query(query)
    if not normalized or not 1 <= limit <= 12:
        raise ModelSearchError("EMBEDDING_TEXT_INVALID")
    category_keys = set(_explicit_category_keys(normalized))
    queries = [normalized]

    for key, label, _aliases, _prefixes in _CATEGORY_HINTS:
        if key in category_keys:
            queries.append(f"{label} KISA 보안 점검 기준 {normalized}")

    parts = [
        _normalized_query(part)
        for part in _COMPOUND_SEPARATOR.split(normalized)
        if len(_normalized_query(part)) >= 3
    ]
    if len(parts) > 1:
        queries.extend(
            f"KISA 주요정보통신기반시설 보안 점검 기준 {part}"
            for part in parts
        )
    elif not category_keys:
        queries.append(
            f"KISA 주요정보통신기반시설 기술적 취약점 점검 기준 {normalized}"
        )

    deduplicated: list[str] = []
    for item in queries:
        if item not in deduplicated:
            deduplicated.append(item)
    return tuple(deduplicated[:limit])


def _hit_category_key(hit: GuideSearchHit) -> str | None:
    control_id = hit.control_id.upper()
    for key, _label, _aliases, prefixes in _CATEGORY_HINTS:
        if any(control_id.startswith(prefix) for prefix in prefixes):
            return key
    return None


def _with_category_coverage(
    hits: tuple[GuideSearchHit, ...],
    category_keys: tuple[str, ...],
    limit: int,
) -> tuple[GuideSearchHit, ...]:
    """명시된 장비 분류별 최상위 근거를 결과 제한 안에 보존합니다."""

    required_ids: set[object] = set()
    for category_key in category_keys:
        match = next(
            (hit for hit in hits if _hit_category_key(hit) == category_key),
            None,
        )
        if match is not None:
            required_ids.add(match.chunk_id)

    selected_ids = set(required_ids)
    for hit in hits:
        if len(selected_ids) >= limit:
            break
        selected_ids.add(hit.chunk_id)
    return tuple(hit for hit in hits if hit.chunk_id in selected_ids)[:limit]


@dataclass(frozen=True, slots=True)
class ModelSearchSettings:
    mode: Literal[
        "LEGACY_LOCAL",
        "BGE_M3_RERANKER",
        "BGE_M3_WITH_LEGACY_FALLBACK",
    ]
    embedding_url: str
    reranker_url: str
    timeout_seconds: float
    fast_top_k: int = 5
    precise_top_k: int = 10
    result_top_k: int = 5
    query_expansion_limit: int = 6
    candidate_multiplier: int = 4
    candidate_limit: int = 20
    db_candidate_multiplier: int = 4
    db_candidate_limit: int = 100
    rrf_k: int = 60
    dense_weight: float = 0.15
    lexical_weight: float = 0.85
    base_weight: float = 0.60
    reranker_weight: float = 0.40
    minimum_rerank_score: float = 0.30
    minimum_lexical_score: float = 0.35

    @classmethod
    def from_environment(cls) -> ModelSearchSettings:
        mode = os.getenv("SECAI_GUIDE_SEARCH_MODE", "LEGACY_LOCAL").strip().upper()
        if mode not in {
            "LEGACY_LOCAL",
            "BGE_M3_RERANKER",
            "BGE_M3_WITH_LEGACY_FALLBACK",
        }:
            raise ModelSearchError("GUIDE_SEARCH_MODE_INVALID")
        timeout_seconds = _environment_float(
            "SECAI_SEARCH_MODEL_TIMEOUT_SECONDS", 30.0, 1.0, 120.0
        )
        settings = cls(
            mode=cast(
                Literal[
                    "LEGACY_LOCAL",
                    "BGE_M3_RERANKER",
                    "BGE_M3_WITH_LEGACY_FALLBACK",
                ],
                mode,
            ),
            embedding_url=os.getenv(
                "SECAI_EMBEDDING_URL", "http://embedding-service:80"
            ).rstrip("/"),
            reranker_url=os.getenv(
                "SECAI_RERANKER_URL", "http://reranker-service:80"
            ).rstrip("/"),
            timeout_seconds=timeout_seconds,
            fast_top_k=_environment_int(
                "SECAI_GUIDE_SEARCH_FAST_TOP_K", 5, 1, 20
            ),
            precise_top_k=_environment_int(
                "SECAI_GUIDE_SEARCH_PRECISE_TOP_K", 10, 1, 20
            ),
            result_top_k=_environment_int(
                "SECAI_GUIDE_SEARCH_RESULT_TOP_K", 5, 1, 20
            ),
            query_expansion_limit=_environment_int(
                "SECAI_GUIDE_SEARCH_QUERY_EXPANSION_LIMIT", 6, 1, 12
            ),
            candidate_multiplier=_environment_int(
                "SECAI_GUIDE_SEARCH_CANDIDATE_MULTIPLIER", 4, 1, 10
            ),
            candidate_limit=_environment_int(
                "SECAI_GUIDE_SEARCH_CANDIDATE_LIMIT", 20, 1, 20
            ),
            db_candidate_multiplier=_environment_int(
                "SECAI_GUIDE_SEARCH_DB_CANDIDATE_MULTIPLIER", 4, 1, 10
            ),
            db_candidate_limit=_environment_int(
                "SECAI_GUIDE_SEARCH_DB_CANDIDATE_LIMIT", 100, 1, 100
            ),
            rrf_k=_environment_int("SECAI_GUIDE_SEARCH_RRF_K", 60, 1, 200),
            dense_weight=_environment_float(
                "SECAI_GUIDE_SEARCH_DENSE_WEIGHT", 0.15, 0.0, 1.0
            ),
            lexical_weight=_environment_float(
                "SECAI_GUIDE_SEARCH_LEXICAL_WEIGHT", 0.85, 0.0, 1.0
            ),
            base_weight=_environment_float(
                "SECAI_GUIDE_SEARCH_BASE_WEIGHT", 0.60, 0.0, 1.0
            ),
            reranker_weight=_environment_float(
                "SECAI_GUIDE_SEARCH_RERANKER_WEIGHT", 0.40, 0.0, 1.0
            ),
            minimum_rerank_score=_environment_float(
                "SECAI_GUIDE_SEARCH_MIN_RERANK_SCORE", 0.30, 0.0, 1.0
            ),
            minimum_lexical_score=_environment_float(
                "SECAI_GUIDE_SEARCH_MIN_LEXICAL_SCORE", 0.35, 0.0, 1.0
            ),
        )
        if settings.precise_top_k < settings.fast_top_k:
            raise ModelSearchError("GUIDE_SEARCH_TOP_K_INVALID")
        if settings.candidate_limit < max(
            settings.fast_top_k,
            settings.precise_top_k,
            settings.result_top_k,
        ):
            raise ModelSearchError("GUIDE_SEARCH_CANDIDATE_LIMIT_INVALID")
        if settings.db_candidate_limit < settings.candidate_limit:
            raise ModelSearchError("GUIDE_SEARCH_DB_CANDIDATE_LIMIT_INVALID")
        if not math.isclose(
            settings.dense_weight + settings.lexical_weight,
            1.0,
            abs_tol=1e-9,
        ) or not math.isclose(
            settings.base_weight + settings.reranker_weight,
            1.0,
            abs_tol=1e-9,
        ):
            raise ModelSearchError("GUIDE_SEARCH_WEIGHT_INVALID")
        for endpoint in (settings.embedding_url, settings.reranker_url):
            parsed = urlparse(endpoint)
            if parsed.scheme != "http" or not parsed.hostname or parsed.username:
                raise ModelSearchError("SEARCH_MODEL_ENDPOINT_INVALID")
        return settings


def guide_search_top_k(
    profile: str,
    settings: ModelSearchSettings | None = None,
) -> int:
    """답변 프로필에 대응하는 최종 근거 수를 반환합니다."""

    active = settings or ModelSearchSettings.from_environment()
    if profile == "FAST":
        return active.fast_top_k
    if profile == "PRECISE":
        return active.precise_top_k
    raise ModelSearchError("GUIDE_SEARCH_PROFILE_INVALID")


def _post_json(url: str, payload: dict[str, object], timeout: float) -> object:
    parsed = urlparse(url)
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ModelSearchError("SEARCH_MODEL_ENDPOINT_INVALID")
    request = Request(  # noqa: S310 -- 관리자 설정의 내부 HTTP 서비스만 허용합니다.
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310
            if response.status != 200:
                raise ModelSearchError("SEARCH_MODEL_HTTP_ERROR")
            body = response.read(4 * 1024 * 1024 + 1)
    except ModelSearchError:
        raise
    except OSError as exc:
        raise ModelSearchError("SEARCH_MODEL_UNAVAILABLE") from exc
    if len(body) > 4 * 1024 * 1024:
        raise ModelSearchError("SEARCH_MODEL_RESPONSE_TOO_LARGE")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelSearchError("SEARCH_MODEL_RESPONSE_INVALID") from exc


class BgeM3Client:
    dimension = 1024
    model_id = "BAAI/bge-m3"

    def __init__(self, settings: ModelSearchSettings) -> None:
        self._settings = settings

    def embed(self, text: str) -> list[float]:
        normalized = " ".join(text.strip().split())
        if not normalized or len(normalized) > 4_000:
            raise ModelSearchError("EMBEDDING_TEXT_INVALID")
        return self._embed_normalized((normalized,))[0]

    def embed_documents(
        self,
        texts: tuple[str, ...],
    ) -> tuple[list[float], ...]:
        """색인 문서를 제한된 묶음으로 보내고 입력 순서를 그대로 보존합니다."""

        if not 1 <= len(texts) <= 32:
            raise ModelSearchError("EMBEDDING_BATCH_INVALID")
        normalized = tuple(" ".join(text.strip().split()) for text in texts)
        if any(not text or len(text) > 50_000 for text in normalized):
            raise ModelSearchError("EMBEDDING_TEXT_INVALID")
        return self._embed_normalized(normalized)

    def _embed_normalized(
        self,
        texts: tuple[str, ...],
    ) -> tuple[list[float], ...]:
        value = _post_json(
            f"{self._settings.embedding_url}/embed",
            {"inputs": list(texts), "normalize": True, "truncate": True},
            self._settings.timeout_seconds,
        )
        if (
            not isinstance(value, list)
            or len(value) != len(texts)
            or any(not isinstance(vector, list) for vector in value)
        ):
            raise ModelSearchError("EMBEDDING_RESPONSE_INVALID")
        vectors: list[list[float]] = []
        for vector in value:
            if not isinstance(vector, list):
                raise ModelSearchError("EMBEDDING_RESPONSE_INVALID")
            if len(vector) != self.dimension or any(
                not isinstance(item, (int, float)) or not math.isfinite(float(item))
                for item in vector
            ):
                raise ModelSearchError("EMBEDDING_DIMENSION_INVALID")
            vectors.append([float(item) for item in vector])
        return tuple(vectors)

    def rerank(
        self,
        query: str,
        hits: tuple[GuideSearchHit, ...],
    ) -> tuple[GuideSearchHit, ...]:
        if not hits:
            return ()
        value = _post_json(
            f"{self._settings.reranker_url}/rerank",
            {
                "query": query,
                "texts": [hit.text for hit in hits],
                "truncate": True,
                "raw_scores": False,
            },
            self._settings.timeout_seconds,
        )
        if not isinstance(value, list) or len(value) != len(hits):
            raise ModelSearchError("RERANK_RESPONSE_INVALID")
        external_scores: list[tuple[int, float]] = []
        used: set[int] = set()
        for item in value:
            if not isinstance(item, dict):
                raise ModelSearchError("RERANK_RESPONSE_INVALID")
            index = item.get("index")
            score = item.get("score")
            if (
                not isinstance(index, int)
                or index < 0
                or index >= len(hits)
                or index in used
                or not isinstance(score, (int, float))
                or not math.isfinite(float(score))
            ):
                raise ModelSearchError("RERANK_RESPONSE_INVALID")
            used.add(index)
            external_scores.append((index, min(1.0, max(0.0, float(score)))))

        # TEI의 bge-reranker-v2-m3 점수는 문서 집합과 질의에 따라 매우
        # 작은 확률값으로 반환될 수 있습니다. 이 값을 절대 점수로 덮어쓰면
        # 이미 통과한 BGE-M3·어휘 하이브리드 근거가 모두 탈락합니다.
        # 외부 점수는 후보 집합 안의 상대 점수로만 사용하고, 검증된 기존
        # 관련도와 결합해 근거 채택 임계값의 의미를 유지합니다.
        maximum_external = max((score for _index, score in external_scores), default=0.0)
        scored = [
            replace(
                hits[index],
                rerank_score=min(
                    1.0,
                    max(
                        0.0,
                        (hits[index].rerank_score * self._settings.base_weight)
                        + (
                            (score / maximum_external)
                            * self._settings.reranker_weight
                            if maximum_external > 0.0
                            else 0.0
                        ),
                    ),
                ),
            )
            for index, score in external_scores
        ]
        scored.sort(key=lambda hit: (-hit.rerank_score, str(hit.chunk_id)))
        return tuple(scored)


def search_with_bge_m3(
    session: Session,
    scope: GuideSearchScope,
    settings: ModelSearchSettings | None = None,
) -> tuple[GuideSearchHit, ...]:
    active = settings or ModelSearchSettings.from_environment()
    if active.mode not in {
        "BGE_M3_RERANKER",
        "BGE_M3_WITH_LEGACY_FALLBACK",
    }:
        raise ModelSearchError("BGE_M3_SEARCH_NOT_ENABLED")
    client = BgeM3Client(active)
    expanded_queries = expand_guide_search_queries(
        scope.query,
        limit=active.query_expansion_limit,
    )
    category_keys = _explicit_category_keys(scope.query)
    hits_by_id: dict[object, GuideSearchHit] = {}
    reciprocal_rank: dict[object, float] = {}
    for expanded_query in expanded_queries:
        candidate_scope = replace(
            scope,
            query=expanded_query,
            top_k=min(
                active.candidate_limit,
                max(scope.top_k * active.candidate_multiplier, scope.top_k),
            ),
        )
        query_hits = search_guide_chunks_bge_m3(
            session,
            candidate_scope,
            client.embed(expanded_query),
            dense_weight=active.dense_weight,
            lexical_weight=active.lexical_weight,
            candidate_multiplier=active.db_candidate_multiplier,
            candidate_limit=active.db_candidate_limit,
        )
        for rank, hit in enumerate(query_hits, start=1):
            hits_by_id.setdefault(hit.chunk_id, hit)
            reciprocal_rank[hit.chunk_id] = (
                reciprocal_rank.get(hit.chunk_id, 0.0)
                + (1.0 / (active.rrf_k + rank))
            )
    fused_hits = tuple(
        sorted(
            hits_by_id.values(),
            key=lambda hit: (
                -reciprocal_rank[hit.chunk_id],
                -hit.rerank_score,
                hit.pdf_page_number,
                str(hit.chunk_id),
            ),
        )
    )
    candidate_hits = _with_category_coverage(
        fused_hits,
        category_keys,
        active.candidate_limit,
    )
    try:
        ranked_hits = client.rerank(scope.query, candidate_hits)
    except ModelSearchError:
        if active.mode != "BGE_M3_WITH_LEGACY_FALLBACK":
            raise
        # RTX 3060 6GB에서는 임베딩·재정렬·vLLM을 동시에 상주시킬 수
        # 없습니다. 선택적 재정렬이 중단되어도 검증된 1024차원 BGE 검색
        # 결과를 유지하고, 임베딩 또는 DB 검색 실패만 상위 계층의 기존
        # 32차원 검색 폴백으로 전달합니다.
        ranked_hits = candidate_hits
    return _with_category_coverage(ranked_hits, category_keys, scope.top_k)
