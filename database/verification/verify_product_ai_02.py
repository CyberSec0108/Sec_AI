"""PRODUCT-AI-02 actual PostgreSQL result-specific KISA retrieval gate."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from security_audit.application.result_explanation_input import (
    build_explanation_inputs,
)
from security_audit.application.result_guide_retrieval import (
    ResultGuideRetrievalService,
)
from security_audit.common.service_settings import ServiceSettings
from security_audit.guides.grounding import GuideConflictResolution

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
OTHER_ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000002")


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


def _control_results() -> tuple[list[dict[str, object]], dict[str, dict[str, Any]]]:
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
    controls = [
        {
            "control_id": control_id,
            "title": str(case["expected_section_label"]),
            "importance": "상",
            "checked_summary": str(case["question"]),
            "evidence_summary": f"{control_id} 비식별 확인 자료",
            "action_guidance": "결과를 확인하고 필요한 경우 담당자에게 문의하세요.",
            "assessment_status": "FAIL",
            "actual": f"{control_id}에서 확인한 비식별 현재 설정값",
            "expected": str(case["expected_section_label"]),
            "result_code": f"{control_id.replace('-', '')}_VERIFY_REASON",
            "assessment_kind": "DEVELOPMENT_DRAFT",
        }
        for control_id, case in sorted(supported.items())
    ]
    return controls, supported


def main() -> None:
    controls, expected = _control_results()
    explanation_inputs = build_explanation_inputs(
        PROJECT_ROOT,
        controls=controls,
        probe_results=_probe_results(),
    )
    engine = create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )
    service = ResultGuideRetrievalService(PROJECT_ROOT)
    failures: list[dict[str, object]] = []
    found = 0
    page_section_pass = 0
    paragraph_pass = 0

    with Session(engine) as session, session.begin():
        for explanation_input in explanation_inputs:
            control_id = str(explanation_input["control_id"])
            result = service.retrieve(
                session,
                explanation_input,
                organization_id=ORGANIZATION_ID,
            )
            case = expected[control_id]
            found += int(result.status == "FOUND")
            if result.status != "FOUND" or not result.citations:
                failures.append(
                    {
                        "control_id": control_id,
                        "status": result.status,
                        "reason_code": result.reason_code,
                    }
                )
                continue
            citation = result.citations[0]
            page_ok = (
                int(case["expected_page_start"])
                <= citation.pdf_page_number
                <= int(case["expected_page_end"])
                and citation.section_label == str(case["expected_section_label"])
                and citation.control_id == control_id
            )
            segment = result.evidence_segments[0]
            normalized_paragraph = "".join(segment.paragraph_text.split()).casefold()
            terms_ok = all(
                "".join(str(term).split()).casefold() in normalized_paragraph
                for term in cast(list[object], case["expected_evidence_terms"])
            )
            page_section_pass += int(page_ok)
            paragraph_pass += int(terms_ok)
            if not page_ok or not terms_ok:
                failures.append(
                    {
                        "control_id": control_id,
                        "page": citation.pdf_page_number,
                        "page_section_ok": page_ok,
                        "paragraph_terms_ok": terms_ok,
                    }
                )

        scope_leak = service.retrieve(
            session,
            explanation_inputs[0],
            organization_id=OTHER_ORGANIZATION_ID,
        )
        conflict = service.retrieve(
            session,
            explanation_inputs[0],
            organization_id=ORGANIZATION_ID,
            conflict=GuideConflictResolution(
                status="CONFLICT",
                reason_code="APPROVED_GUIDES_CONFLICT",
                selected=None,
            ),
        )

    summary = {
        "product_work": "PRODUCT-AI-02",
        "controls": len(explanation_inputs),
        "found": found,
        "page_section_pass": page_section_pass,
        "paragraph_pass": paragraph_pass,
        "other_organization_status": scope_leak.status,
        "other_organization_citations": len(scope_leak.citations),
        "conflict_status": conflict.status,
        "conflict_citations": len(conflict.citations),
        "official_finding_writes": 0,
        "failures": failures,
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    engine.dispose()
    if (
        failures
        or found != 18
        or page_section_pass != 18
        or paragraph_pass != 18
        or scope_leak.status != "INSUFFICIENT_EVIDENCE"
        or scope_leak.citations
        or conflict.status != "CONFLICT"
        or conflict.citations
    ):
        raise RuntimeError("PRODUCT-AI-02 actual PostgreSQL gate failed.")


if __name__ == "__main__":
    main()
