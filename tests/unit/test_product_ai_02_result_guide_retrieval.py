from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import cast
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from security_audit.application.result_guide_retrieval import (
    ResultGuideRetrievalError,
    ResultGuideRetrievalService,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)
from security_audit.guides.grounding import GuideConflictResolution
from security_audit.guides.retrieval import GuideSearchHit, GuideSearchScope

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
OTHER_ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000099")
SOURCE_SHA256 = "44fe393981b244147be6af7423d99dc15633c089fad0bcb296cbe2371dde812d"


def _mapping() -> dict[str, dict[str, object]]:
    document = json.loads(
        (
            PROJECT_ROOT
            / "guides"
            / "mappings"
            / "kisa_2026_pc_control_sources.json"
        ).read_text(encoding="utf-8")
    )
    guide = document["guide"]
    return {
        item["control_id"]: {
            "guide_id": guide["guide_id"],
            "guide_version": guide["version"],
            "source_sha256": guide["source_sha256"],
            "document_code": item["source_document_code"],
            "page_start": item["page_start"],
            "page_end": item["page_end"],
            "section_label": item["section_label"],
            "mapping_status": item["mapping_status"],
        }
        for item in document["mappings"]
    }


def _explanation(control_id: str, *, status: str = "FAIL") -> dict[str, JsonValue]:
    source = _mapping()[control_id]
    value: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "control_id": control_id,
        "title": str(source["section_label"]),
        "importance": "HIGH",
        "what_was_checked": f"{source['section_label']}을 확인했습니다.",
        "observed_summary": f"{control_id}에서 확인한 현재 설정값입니다.",
        "normalized_facts": {"actual_summary": "비식별 실제 확인값"},
        "collection_methods": [
            {
                "probe_id": f"win.test.{control_id.casefold()}",
                "method_code": "WINDOWS_API",
                "method_summary": "승인된 Windows 읽기 전용 방법으로 확인",
                "collection_status": "COLLECTED",
            }
        ],
        "execution_tools": [
            {
                "probe_id": f"win.test.{control_id.casefold()}",
                "probe_version": "1.0.0",
                "tool_name": "SecAI Windows Collector",
                "collector_name": "SecAI Windows Collector",
                "collector_version": "0.1.0",
                "adapter_id": "secai.test",
                "adapter_version": "1.0.0",
            }
        ],
        "source_locations": [
            {
                "probe_id": f"win.test.{control_id.casefold()}",
                "user_label": "Windows 보안 설정",
                "technical_locator": "approved-read-only-source",
            }
        ],
        "rule_status": status,
        "status_authority": "RULE_ENGINE",
        "result_code": f"{control_id.replace('-', '')}_TEST_REASON",
        "result_code_visibility": "TECHNICAL_ONLY",
        "expected_summary": f"{source['section_label']}의 KISA 안전 기준",
        "judgement_explanation": "규칙 결과와 KISA 기준을 비교한 설명입니다.",
        "collection_limitations": [],
        "importance_source": "상",
        "kisa_citations": [cast(JsonValue, source)],
        "allowed_actions": ["결과를 확인하고 필요한 경우 담당자에게 문의하세요."],
        "assessment_kind": "DEVELOPMENT_DRAFT",
        "source_rule_result_sha256": "a" * 64,
        "official_finding_write_allowed": False,
        "safety": {
            "raw_evidence_included": False,
            "sensitive_identifiers_included": False,
            "rule_status_unchanged": True,
            "internal_reason_code_user_visible": False,
        },
    }
    value["explanation_input_sha256"] = canonical_sha256_without_fields(
        value,
        {"explanation_input_sha256"},
    )
    return value


def _hit(
    scope: GuideSearchScope,
    *,
    control_id: str,
    organization_id: UUID | None = None,
) -> GuideSearchHit:
    source = _mapping()[control_id]
    text = (
        f"{source['section_label']}. "
        f"{control_id} 점검 항목의 KISA 기준과 확인 방법을 설명합니다."
    )
    return GuideSearchHit(
        chunk_id=uuid5(NAMESPACE_URL, f"product-ai-02:{control_id}"),
        organization_id=organization_id or scope.organization_id,
        guide_id=scope.guide_id,
        guide_version=scope.guide_version,
        source_sha256=SOURCE_SHA256,
        scope_id=scope.scope_id,
        pdf_page_number=cast(int, source["page_start"]),
        control_id=control_id,
        text=text,
        text_sha256=__import__("hashlib").sha256(text.encode("utf-8")).hexdigest(),
        dense_score=0.95,
        lexical_score=0.95,
        rerank_score=0.95,
    )


class SearchStub:
    def __init__(self, *, wrong_control: bool = False, wrong_organization: bool = False) -> None:
        self.wrong_control = wrong_control
        self.wrong_organization = wrong_organization
        self.scopes: list[GuideSearchScope] = []

    def __call__(
        self,
        _session: object,
        scope: GuideSearchScope,
        _vector: list[float] | tuple[float, ...],
    ) -> tuple[GuideSearchHit, ...]:
        self.scopes.append(scope)
        match = next(
            control_id
            for control_id in _mapping()
            if control_id in scope.query
        )
        control_id = "PC-18" if self.wrong_control and match != "PC-18" else match
        return (
            _hit(
                scope,
                control_id=control_id,
                organization_id=(
                    OTHER_ORGANIZATION_ID
                    if self.wrong_organization
                    else scope.organization_id
                ),
            ),
        )


def test_product_ai_02_finds_exact_kisa_page_section_paragraph_for_pc01_to_pc18() -> None:
    search = SearchStub()
    service = ResultGuideRetrievalService(PROJECT_ROOT, search=search)

    results = [
        service.retrieve(
            object(),
            _explanation(f"PC-{number:02d}"),
            organization_id=ORGANIZATION_ID,
        )
        for number in range(1, 19)
    ]

    assert [result.control_id for result in results] == [
        f"PC-{number:02d}" for number in range(1, 19)
    ]
    assert all(result.status == "FOUND" for result in results)
    assert all(len(result.citations) == 1 for result in results)
    assert all(result.citations[0].control_id == result.control_id for result in results)
    assert all(result.citations[0].paragraph_ordinal >= 1 for result in results)
    assert all(result.evidence_segments[0].paragraph_text for result in results)
    assert all(result.rule_status == "FAIL" for result in results)
    assert all(result.official_finding_write_allowed is False for result in results)
    assert [scope.control_id for scope in search.scopes] == [
        f"PC-{number:02d}" for number in range(1, 19)
    ]
    schema = json.loads(
        (
            PROJECT_ROOT
            / "database"
            / "schemas"
            / "finding_guide_evidence.schema.json"
        ).read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    assert [
        error.message
        for result in results
        for error in validator.iter_errors(result.to_json())
    ] == []
    assert all(
        result.output_sha256
        == canonical_sha256_without_fields(
            result.to_json(),
            {"output_sha256"},
        )
        for result in results
    )
    assert len(search.scopes) == 18


def test_product_ai_02_returns_insufficient_evidence_without_cross_control_fallback() -> None:
    result = ResultGuideRetrievalService(
        PROJECT_ROOT,
        search=SearchStub(wrong_control=True),
    ).retrieve(
        object(),
        _explanation("PC-01"),
        organization_id=ORGANIZATION_ID,
    )

    assert result.status == "INSUFFICIENT_EVIDENCE"
    assert result.reason_code == "NO_MATCH_FOR_RESULT_CONTROL"
    assert result.citations == ()
    assert result.evidence_segments == ()


def test_product_ai_02_blocks_organization_scope_leak() -> None:
    result = ResultGuideRetrievalService(
        PROJECT_ROOT,
        search=SearchStub(wrong_organization=True),
    ).retrieve(
        object(),
        _explanation("PC-07"),
        organization_id=ORGANIZATION_ID,
    )

    assert result.status == "INSUFFICIENT_EVIDENCE"
    assert result.reason_code == "CITATION_SCOPE_MISMATCH"
    assert str(OTHER_ORGANIZATION_ID) not in json.dumps(
        result.to_json(),
        ensure_ascii=False,
    )


def test_product_ai_02_conflict_is_distinct_and_does_not_search() -> None:
    search = SearchStub()
    result = ResultGuideRetrievalService(PROJECT_ROOT, search=search).retrieve(
        object(),
        _explanation("PC-07"),
        organization_id=ORGANIZATION_ID,
        conflict=GuideConflictResolution(
            status="CONFLICT",
            reason_code="APPROVED_GUIDES_CONFLICT",
            selected=None,
        ),
    )

    assert result.status == "CONFLICT"
    assert result.reason_code == "APPROVED_GUIDES_CONFLICT"
    assert result.citations == ()
    assert search.scopes == []


def test_product_ai_02_rejects_tampered_explanation_hash_and_source_mapping() -> None:
    service = ResultGuideRetrievalService(PROJECT_ROOT, search=SearchStub())
    tampered = _explanation("PC-07")
    tampered["observed_summary"] = "변조된 실제값"

    with pytest.raises(ResultGuideRetrievalError, match="INPUT_HASH_MISMATCH"):
        service.retrieve(
            object(),
            tampered,
            organization_id=ORGANIZATION_ID,
        )

    wrong_source = deepcopy(_explanation("PC-07"))
    citation = cast(list[dict[str, JsonValue]], wrong_source["kisa_citations"])[0]
    citation["page_start"] = 580
    wrong_source["explanation_input_sha256"] = canonical_sha256_without_fields(
        wrong_source,
        {"explanation_input_sha256"},
    )
    with pytest.raises(ResultGuideRetrievalError, match="SOURCE_MAPPING_MISMATCH"):
        service.retrieve(
            object(),
            wrong_source,
            organization_id=ORGANIZATION_ID,
        )


def test_product_ai_02_is_deterministic_for_one_hundred_retrievals() -> None:
    service = ResultGuideRetrievalService(PROJECT_ROOT, search=SearchStub())
    hashes = {
        service.retrieve(
            object(),
            _explanation("PC-07"),
            organization_id=ORGANIZATION_ID,
        ).output_sha256
        for _ in range(100)
    }

    assert len(hashes) == 1
