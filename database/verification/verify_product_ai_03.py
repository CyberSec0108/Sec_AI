"""PRODUCT-AI-03 실제 model-gateway 구조화 설명 호환성 Gate."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, cast
from uuid import NAMESPACE_URL, uuid5

from security_audit.application.result_ai_explanation import (
    ResultAIExecutionPolicy,
    ResultAIExplanationService,
)
from security_audit.application.result_explanation_input import (
    build_explanation_inputs,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)
from security_audit.llm import InternalModelGatewayClient

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _probe_results() -> list[dict[str, object]]:
    allowlist = _load_json(
        PROJECT_ROOT
        / "collectors"
        / "one_shot"
        / "contracts"
        / "imp031_probe_allowlist.json"
    )
    return [
        {
            "probe_id": probe["probe_id"],
            "probe_version": probe["probe_version"],
            "control_ids": probe["control_ids"],
            "collection_status": "COLLECTED",
            "error_code": "NONE",
        }
        for probe in cast(list[dict[str, object]], allowlist["probes"])
    ]


def _control_results() -> list[dict[str, object]]:
    evaluation = _load_json(
        PROJECT_ROOT
        / "guides"
        / "evaluations"
        / "kisa_2026_pc_questions.json"
    )
    supported = {
        str(item["expected_control_id"]): item
        for item in cast(list[dict[str, Any]], evaluation["cases"])
        if item["expected_status"] == "FOUND"
    }
    statuses = {"PC-01": "FAIL", "PC-02": "REVIEW"}
    return [
        {
            "control_id": control_id,
            "title": str(case["expected_section_label"]),
            "importance": "상",
            "checked_summary": f"{control_id} 합성 설정 상태를 확인했습니다.",
            "evidence_summary": f"{control_id} 합성·비식별 시험값",
            "action_guidance": "조직의 승인된 보안 기준을 확인하세요.",
            "assessment_status": statuses.get(control_id, "PASS"),
            "actual": f"{control_id} 합성·비식별 현재값",
            "expected": str(case["expected_section_label"]),
            "result_code": f"{control_id.replace('-', '')}_SYNTHETIC_TEST_REASON",
            "assessment_kind": "DEVELOPMENT_DRAFT",
        }
        for control_id, case in sorted(supported.items())
    ]


def _guide_evidence(
    explanation: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    control_id = cast(str, explanation["control_id"])
    sources = cast(list[dict[str, JsonValue]], explanation["kisa_citations"])
    source = sources[0]
    paragraph = (
        f"{control_id} 합성 호환성 시험 근거입니다. 실제 PC 자료나 개인정보를 "
        "포함하지 않으며 승인된 기준과 현재 상태의 차이를 설명합니다."
    )
    paragraph_sha256 = hashlib.sha256(paragraph.encode("utf-8")).hexdigest()
    chunk_id = str(uuid5(NAMESPACE_URL, f"product-ai-03-runtime:{control_id}"))
    citation: dict[str, JsonValue] = {
        "chunk_id": chunk_id,
        "guide_id": source["guide_id"],
        "guide_version": source["guide_version"],
        "document_code": source["document_code"],
        "source_sha256": source["source_sha256"],
        "scope_id": "product-ai-03-synthetic-runtime",
        "pdf_page_number": source["page_start"],
        "control_id": control_id,
        "section_label": source["section_label"],
        "paragraph_ordinal": 1,
        "paragraph_sha256": paragraph_sha256,
        "text_sha256": paragraph_sha256,
        "dense_score": 1.0,
        "lexical_score": 1.0,
        "rerank_score": 1.0,
    }
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "status": "FOUND",
        "reason_code": None,
        "control_id": control_id,
        "rule_status": explanation["rule_status"],
        "status_authority": "RULE_ENGINE",
        "explanation_input_sha256": explanation["explanation_input_sha256"],
        "search_query_sha256": "b" * 64,
        "citations": [citation],
        "evidence_segments": [
            {
                "chunk_id": chunk_id,
                "paragraph_ordinal": 1,
                "paragraph_text": paragraph,
                "paragraph_sha256": paragraph_sha256,
            }
        ],
        "official_finding_write_allowed": False,
    }
    payload["output_sha256"] = canonical_sha256_without_fields(
        payload,
        {"output_sha256"},
    )
    return payload


def _policy(
    capability: dict[str, object],
) -> ResultAIExecutionPolicy:
    provider_kind = capability.get("provider_kind")
    external_data_transfer = capability.get("external_data_transfer")
    if not isinstance(external_data_transfer, bool):
        raise RuntimeError("model-gateway external_data_transfer is invalid.")
    if provider_kind == "OPENROUTER":
        if (
            os.getenv("SECAI_RESULT_AI_REMOTE_TEST_APPROVED", "false").casefold()
            != "true"
        ):
            raise RuntimeError("OpenRouter synthetic test transfer is not approved.")
        return ResultAIExecutionPolicy(
            runtime_profile="VLLM_COMPATIBILITY_TEST_DOUBLE",
            external_data_transfer=True,
            approved_deidentified_test_transfer=True,
            test_data_only=True,
        )
    if provider_kind == "VLLM" and external_data_transfer is False:
        return ResultAIExecutionPolicy(
            runtime_profile="LOCAL_VLLM_FULL_CONTEXT",
            external_data_transfer=False,
            approved_deidentified_test_transfer=False,
            test_data_only=True,
        )
    raise RuntimeError("Unapproved model-gateway runtime profile.")


def main() -> None:
    all_explanations = build_explanation_inputs(
        PROJECT_ROOT,
        controls=_control_results(),
        probe_results=_probe_results(),
    )
    explanations = [
        item
        for item in all_explanations
        if item["control_id"] in {"PC-01", "PC-02"}
    ]
    evidence = [_guide_evidence(item) for item in explanations]
    client = InternalModelGatewayClient.from_environment()
    capability = client.capabilities()
    result = ResultAIExplanationService(client).generate(
        explanations,
        evidence,
        policy=_policy(capability),
        profile="FAST",
    )
    body = result.to_json()
    official_results = [
        (item["control_id"], item["rule_status"])
        for item in cast(list[dict[str, JsonValue]], body["official_results"])
    ]
    item_results = [
        (item["control_id"], item["rule_status"])
        for item in cast(list[dict[str, JsonValue]], body["items"])
    ]
    summary = {
        "product_work": "PRODUCT-AI-03",
        "provider_kind": capability.get("provider_kind"),
        "runtime_profile": result.runtime_profile,
        "external_data_transfer": result.external_data_transfer,
        "test_data_only": result.test_data_only,
        "status": result.status,
        "reason_code": result.reason_code,
        "model_id": result.model_id,
        "official_results": official_results,
        "explained_results": item_results,
        "citations": len(result.citations),
        "input_sha256": result.input_sha256,
        "model_output_sha256": result.model_output_sha256,
        "output_sha256": result.output_sha256,
        "official_finding_writes": 0,
        "audit_pack_writes": 0,
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    if (
        result.status != "GENERATED"
        or official_results != [("PC-01", "FAIL"), ("PC-02", "REVIEW")]
        or item_results != official_results
        or len(result.citations) != 2
        or not result.input_sha256
        or not result.model_output_sha256
    ):
        raise RuntimeError("PRODUCT-AI-03 model-gateway compatibility gate failed.")


if __name__ == "__main__":
    main()
