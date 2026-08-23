from __future__ import annotations

from pathlib import Path
from typing import Literal, cast
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from security_audit.application import model_search
from security_audit.application.model_search import (
    BgeM3Client,
    ModelSearchError,
    ModelSearchSettings,
    expand_guide_search_queries,
    guide_search_top_k,
)
from security_audit.guides.retrieval import (
    GuideSearchCandidate,
    GuideSearchHit,
    GuideSearchScope,
    filter_and_rerank,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _settings(
    mode: Literal[
        "LEGACY_LOCAL",
        "BGE_M3_RERANKER",
        "BGE_M3_WITH_LEGACY_FALLBACK",
    ] = "BGE_M3_RERANKER",
) -> ModelSearchSettings:
    return ModelSearchSettings(
        mode=mode,
        embedding_url="http://embedding-service:80",
        reranker_url="http://reranker-service:80",
        timeout_seconds=30,
    )


def test_bge_m3_client_requires_exact_1024_dimension(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(model_search, "_post_json", lambda *_args: [[0.0] * 1024])

    assert len(BgeM3Client(_settings()).embed("비밀번호 기준")) == 1024

    monkeypatch.setattr(model_search, "_post_json", lambda *_args: [[0.0] * 32])
    with pytest.raises(ModelSearchError, match="EMBEDDING_DIMENSION_INVALID"):
        BgeM3Client(_settings()).embed("비밀번호 기준")


def test_bge_m3_client_batches_document_embeddings_without_external_text_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[dict[str, object]] = []

    def fake_post(_url: str, payload: dict[str, object], _timeout: float) -> object:
        captured.append(payload)
        inputs = payload["inputs"]
        assert isinstance(inputs, list)
        return [[float(index)] * 1024 for index, _text in enumerate(inputs)]

    monkeypatch.setattr(model_search, "_post_json", fake_post)
    client = BgeM3Client(_settings())

    vectors = client.embed_documents(("  첫 문서  ", "둘째   문서"))

    assert len(vectors) == 2
    assert all(len(vector) == 1024 for vector in vectors)
    assert captured == [
        {
            "inputs": ["첫 문서", "둘째 문서"],
            "normalize": True,
            "truncate": True,
        }
    ]


def test_bge_m3_document_batch_rejects_empty_oversized_or_too_many_inputs() -> None:
    client = BgeM3Client(_settings())

    with pytest.raises(ModelSearchError, match="EMBEDDING_BATCH_INVALID"):
        client.embed_documents(())
    with pytest.raises(ModelSearchError, match="EMBEDDING_TEXT_INVALID"):
        client.embed_documents(("",))
    with pytest.raises(ModelSearchError, match="EMBEDDING_TEXT_INVALID"):
        client.embed_documents(("가" * 50_001,))
    with pytest.raises(ModelSearchError, match="EMBEDDING_BATCH_INVALID"):
        client.embed_documents(tuple("문서" for _ in range(33)))


def test_search_tuning_settings_are_loaded_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "SECAI_GUIDE_SEARCH_FAST_TOP_K": "6",
        "SECAI_GUIDE_SEARCH_PRECISE_TOP_K": "12",
        "SECAI_GUIDE_SEARCH_RESULT_TOP_K": "7",
        "SECAI_GUIDE_SEARCH_QUERY_EXPANSION_LIMIT": "5",
        "SECAI_GUIDE_SEARCH_CANDIDATE_MULTIPLIER": "3",
        "SECAI_GUIDE_SEARCH_CANDIDATE_LIMIT": "18",
        "SECAI_GUIDE_SEARCH_DB_CANDIDATE_MULTIPLIER": "3",
        "SECAI_GUIDE_SEARCH_DB_CANDIDATE_LIMIT": "72",
        "SECAI_GUIDE_SEARCH_RRF_K": "50",
        "SECAI_GUIDE_SEARCH_DENSE_WEIGHT": "0.25",
        "SECAI_GUIDE_SEARCH_LEXICAL_WEIGHT": "0.75",
        "SECAI_GUIDE_SEARCH_BASE_WEIGHT": "0.55",
        "SECAI_GUIDE_SEARCH_RERANKER_WEIGHT": "0.45",
        "SECAI_GUIDE_SEARCH_MIN_RERANK_SCORE": "0.32",
        "SECAI_GUIDE_SEARCH_MIN_LEXICAL_SCORE": "0.28",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)

    settings = ModelSearchSettings.from_environment()

    assert guide_search_top_k("FAST", settings) == 6
    assert guide_search_top_k("PRECISE", settings) == 12
    assert settings.result_top_k == 7
    assert settings.query_expansion_limit == 5
    assert settings.candidate_multiplier == 3
    assert settings.candidate_limit == 18
    assert settings.db_candidate_multiplier == 3
    assert settings.db_candidate_limit == 72
    assert settings.rrf_k == 50
    assert settings.dense_weight == pytest.approx(0.25)
    assert settings.lexical_weight == pytest.approx(0.75)
    assert settings.base_weight == pytest.approx(0.55)
    assert settings.reranker_weight == pytest.approx(0.45)
    assert settings.minimum_rerank_score == pytest.approx(0.32)
    assert settings.minimum_lexical_score == pytest.approx(0.28)


def test_search_tuning_rejects_invalid_weight_sum(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECAI_GUIDE_SEARCH_DENSE_WEIGHT", "0.60")
    monkeypatch.setenv("SECAI_GUIDE_SEARCH_LEXICAL_WEIGHT", "0.60")

    with pytest.raises(ModelSearchError, match="GUIDE_SEARCH_WEIGHT_INVALID"):
        ModelSearchSettings.from_environment()


def test_hybrid_candidate_weights_are_configurable() -> None:
    organization_id = uuid4()
    scope = GuideSearchScope(
        organization_id=organization_id,
        guide_id="KISA-FULL",
        guide_version="2026",
        scope_id="kisa-2026-all",
        query="비밀번호 기준",
        top_k=1,
    )
    candidate = GuideSearchCandidate(
        chunk_id=uuid4(),
        organization_id=organization_id,
        guide_id="KISA-FULL",
        guide_version="2026",
        scope_id="kisa-2026-all",
        pdf_page_number=15,
        control_id="U-02",
        text="비밀번호 기준과 주기를 확인합니다.",
        dense_score=0.80,
    )

    result = filter_and_rerank(
        scope,
        (candidate,),
        dense_weight=0.25,
        lexical_weight=0.75,
    )

    expected = (result[0].dense_score * 0.25) + (result[0].lexical_score * 0.75)
    assert result[0].rerank_score == pytest.approx(expected)


def test_reranker_keeps_verified_hybrid_relevance_when_raw_scores_are_small(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = uuid4()

    def hit(control_id: str, page: int, hybrid_score: float) -> GuideSearchHit:
        return GuideSearchHit(
            chunk_id=uuid4(),
            organization_id=organization_id,
            guide_id="KISA-FULL",
            guide_version="2026",
            scope_id="kisa-2026-all",
            pdf_page_number=page,
            control_id=control_id,
            text=f"{control_id} 비밀번호 관리정책 설정",
            dense_score=0.60,
            lexical_score=0.45,
            rerank_score=hybrid_score,
        )

    unix_hit = hit("U-02", 15, 0.50)
    windows_hit = hit("W-09", 187, 0.45)
    monkeypatch.setattr(
        model_search,
        "_post_json",
        lambda *_args: [
            {"index": 0, "score": 0.04},
            {"index": 1, "score": 0.0065},
        ],
    )

    result = BgeM3Client(_settings()).rerank(
        "윈도우와 리눅스 비밀번호 설정의 차이는 무엇인가요?",
        (unix_hit, windows_hit),
    )

    assert result[0].control_id == "U-02"
    assert result[0].rerank_score == pytest.approx(0.70)
    assert result[1].control_id == "W-09"
    assert result[1].rerank_score == pytest.approx(0.335)


def test_optional_reranker_failure_keeps_bge_m3_dense_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = uuid4()
    scope = GuideSearchScope(
        organization_id=organization_id,
        guide_id="KISA-PC",
        guide_version="2026",
        scope_id="PC",
        query="비밀번호 기준",
        top_k=1,
    )
    hit = GuideSearchHit(
        chunk_id=uuid4(),
        organization_id=organization_id,
        guide_id="KISA-PC",
        guide_version="2026",
        scope_id="PC",
        pdf_page_number=555,
        control_id="PC-01",
        text="비밀번호 최대 사용 기간을 확인합니다.",
        dense_score=0.91,
        lexical_score=0.0,
        rerank_score=0.0,
    )

    def fake_post(url: str, *_args: object) -> object:
        if url.endswith("/embed"):
            return [[0.0] * 1024]
        raise ModelSearchError("SEARCH_MODEL_UNAVAILABLE")

    monkeypatch.setattr(model_search, "_post_json", fake_post)
    monkeypatch.setattr(
        model_search,
        "search_guide_chunks_bge_m3",
        lambda *_args, **_kwargs: (hit,),
    )

    result = model_search.search_with_bge_m3(
        cast(Session, object()),
        scope,
        _settings("BGE_M3_WITH_LEGACY_FALLBACK"),
    )

    assert result == (hit,)


def test_strict_bge_m3_mode_rejects_reranker_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = uuid4()
    scope = GuideSearchScope(
        organization_id=organization_id,
        guide_id="KISA-PC",
        guide_version="2026",
        scope_id="PC",
        query="비밀번호 기준",
    )

    monkeypatch.setattr(
        model_search,
        "_post_json",
        lambda url, *_args: (
            [[0.0] * 1024]
            if url.endswith("/embed")
            else (_ for _ in ()).throw(ModelSearchError("SEARCH_MODEL_UNAVAILABLE"))
        ),
    )
    monkeypatch.setattr(
        model_search,
        "search_guide_chunks_bge_m3",
        lambda *_args, **_kwargs: (
            GuideSearchHit(
                chunk_id=uuid4(),
                organization_id=organization_id,
                guide_id="KISA-PC",
                guide_version="2026",
                scope_id="PC",
                pdf_page_number=555,
                control_id="PC-01",
                text="비밀번호 최대 사용 기간을 확인합니다.",
                dense_score=0.91,
                lexical_score=0.0,
                rerank_score=0.0,
            ),
        ),
    )

    with pytest.raises(ModelSearchError, match="SEARCH_MODEL_UNAVAILABLE"):
        model_search.search_with_bge_m3(
            cast(Session, object()),
            scope,
            _settings(),
        )


def test_model_services_use_separate_persistent_gpu_caches() -> None:
    compose = (
        PROJECT_ROOT / "deploy/compose/compose.search-models.yml"
    ).read_text(encoding="utf-8")

    assert "BAAI/bge-m3" in compose
    assert "BAAI/bge-reranker-v2-m3" in compose
    assert "sec-ai-mvp-bge-m3-model-cache" in compose
    assert "sec-ai-mvp-reranker-model-cache" in compose
    assert compose.count("gpus: all") == 2
    assert "ports:" not in compose

    base_compose = (PROJECT_ROOT / "deploy/compose/compose.yml").read_text(
        encoding="utf-8"
    )
    example = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")
    for key in (
        "SECAI_GUIDE_SEARCH_FAST_TOP_K",
        "SECAI_GUIDE_SEARCH_PRECISE_TOP_K",
        "SECAI_GUIDE_SEARCH_RESULT_TOP_K",
        "SECAI_GUIDE_SEARCH_CANDIDATE_LIMIT",
        "SECAI_GUIDE_SEARCH_RERANKER_WEIGHT",
        "SECAI_GUIDE_SEARCH_MIN_RERANK_SCORE",
    ):
        assert key in base_compose
        assert key in example


def test_comparison_query_expands_each_named_platform() -> None:
    queries = expand_guide_search_queries(
        "윈도우와 리눅스 비밀번호 설정의 차이는 무엇인가요?"
    )

    assert queries[0] == "윈도우와 리눅스 비밀번호 설정의 차이는 무엇인가요?"
    assert any("Windows 서버" in query for query in queries)
    assert any("Unix 서버" in query for query in queries)


def test_compound_and_ambiguous_queries_gain_retrieval_context() -> None:
    compound = expand_guide_search_queries(
        "비밀번호 정책과 방화벽 설정을 함께 설명해 주세요"
    )
    ambiguous = expand_guide_search_queries("계정 설정은 어떻게 하나요?")

    assert any("비밀번호 정책" in query for query in compound[1:])
    assert any("방화벽 설정" in query for query in compound[1:])
    assert any("KISA 주요정보통신기반시설" in query for query in ambiguous[1:])


def test_comparison_search_preserves_windows_and_unix_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = uuid4()
    scope = GuideSearchScope(
        organization_id=organization_id,
        guide_id="KISA-FULL",
        guide_version="2026",
        scope_id="kisa-2026-all",
        query="윈도우와 리눅스 비밀번호 설정의 차이는 무엇인가요?",
        top_k=3,
    )

    def hit(control_id: str, page: int, score: float) -> GuideSearchHit:
        return GuideSearchHit(
            chunk_id=uuid4(),
            organization_id=organization_id,
            guide_id="KISA-FULL",
            guide_version="2026",
            scope_id="kisa-2026-all",
            pdf_page_number=page,
            control_id=control_id,
            text=f"{control_id} 비밀번호 관리정책 설정",
            dense_score=score,
            lexical_score=score,
            rerank_score=score,
        )

    unix_hit = hit("U-02", 15, 0.9)
    windows_hit = hit("W-09", 187, 0.5)
    unrelated_hit = hit("PC-02", 557, 0.8)

    monkeypatch.setattr(
        model_search.BgeM3Client,
        "embed",
        lambda _self, _query: [0.0] * 1024,
    )
    monkeypatch.setattr(
        model_search.BgeM3Client,
        "rerank",
        lambda _self, _query, hits: tuple(
            sorted(hits, key=lambda item: -item.rerank_score)
        ),
    )

    def fake_search(
        _session: Session,
        query_scope: GuideSearchScope,
        _vector: list[float],
        **_kwargs: object,
    ) -> tuple[GuideSearchHit, ...]:
        if "Windows 서버" in query_scope.query:
            return (windows_hit, unrelated_hit)
        if "Unix 서버" in query_scope.query:
            return (unix_hit, unrelated_hit)
        return (unix_hit, unrelated_hit, windows_hit)

    monkeypatch.setattr(
        model_search,
        "search_guide_chunks_bge_m3",
        fake_search,
    )

    result = model_search.search_with_bge_m3(
        cast(Session, object()),
        scope,
        _settings(),
    )

    assert {item.control_id for item in result} >= {"U-02", "W-09"}
