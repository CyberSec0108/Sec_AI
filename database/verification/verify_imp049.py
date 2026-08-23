"""Evaluate actual KISA PC retrieval, citations, no-evidence and conflicts."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from security_audit.common.service_settings import ServiceSettings
from security_audit.guides.grounding import (
    ControlCitationSource,
    GuideSourceEvidence,
    build_grounding_result,
    citation_matches_terms,
    resolve_guide_conflict,
)
from security_audit.guides.retrieval import (
    ApprovedLocalKoreanEmbedder,
    GuideSearchScope,
)
from security_audit.persistence.database.guide_repository import search_guide_chunks

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVALUATION_PATH = (
    PROJECT_ROOT / "guides" / "evaluations" / "kisa_2026_pc_questions.json"
)
MAPPING_PATH = (
    PROJECT_ROOT
    / "guides"
    / "mappings"
    / "kisa_2026_pc_control_sources.json"
)
ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
OTHER_ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000002")


def _load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _citation_sources() -> dict[str, ControlCitationSource]:
    mapping = _load_json(MAPPING_PATH)
    return {
        str(item["control_id"]): ControlCitationSource(
            control_id=str(item["control_id"]),
            document_code=str(item["source_document_code"]),
            page_start=int(item["page_start"]),
            page_end=int(item["page_end"]),
            section_label=str(item["section_label"]),
        )
        for item in cast(list[dict[str, Any]], mapping["mappings"])
    }


def _conflict_checks() -> tuple[int, int]:
    first = GuideSourceEvidence(
        guide_id="kisa-pc",
        version="2025",
        status="APPROVED",
        effective_from=date(2025, 1, 1),
        source_sha256="1" * 64,
        statement_sha256="a" * 64,
        supersedes_version=None,
    )
    same = GuideSourceEvidence(
        guide_id="organization-pc",
        version="2025",
        status="APPROVED",
        effective_from=date(2025, 2, 1),
        source_sha256="2" * 64,
        statement_sha256="a" * 64,
        supersedes_version=None,
    )
    newer = GuideSourceEvidence(
        guide_id="kisa-pc",
        version="2026",
        status="APPROVED",
        effective_from=date(2026, 1, 1),
        source_sha256="3" * 64,
        statement_sha256="b" * 64,
        supersedes_version="2025",
    )
    conflict = GuideSourceEvidence(
        guide_id="organization-pc",
        version="2025",
        status="APPROVED",
        effective_from=date(2025, 1, 1),
        source_sha256="4" * 64,
        statement_sha256="c" * 64,
        supersedes_version=None,
    )
    checks = (
        resolve_guide_conflict((first, same)).status == "FOUND",
        resolve_guide_conflict((first, newer)).reason_code
        == "SUPERSEDING_GUIDE_SELECTED",
        resolve_guide_conflict((first, conflict)).status == "CONFLICT",
    )
    return sum(checks), len(checks)


def main() -> None:
    evaluation = _load_json(EVALUATION_PATH)
    guide = cast(dict[str, Any], evaluation["guide"])
    cases = cast(list[dict[str, Any]], evaluation["cases"])
    sources = _citation_sources()
    embedder = ApprovedLocalKoreanEmbedder()
    engine = create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )

    supported_total = 0
    supported_control_pass = 0
    citation_page_pass = 0
    paragraph_pass = 0
    unsupported_total = 0
    no_evidence_pass = 0
    failures: list[dict[str, object]] = []

    with Session(engine) as session, session.begin():
        for case in cases:
            question = str(case["question"])
            scope = GuideSearchScope(
                organization_id=ORGANIZATION_ID,
                guide_id=str(guide["guide_id"]),
                guide_version=str(guide["version"]),
                scope_id=str(guide["scope_id"]),
                query=question,
                top_k=5,
            )
            hits = search_guide_chunks(session, scope, embedder.embed(question))
            result = build_grounding_result(scope, hits, sources)
            expected_status = str(case["expected_status"])
            if expected_status == "NO_EVIDENCE":
                unsupported_total += 1
                if result.status == "NO_EVIDENCE":
                    no_evidence_pass += 1
                else:
                    failures.append(
                        {
                            "case_id": case["case_id"],
                            "expected": expected_status,
                            "actual": result.status,
                            "actual_control": (
                                result.citations[0].control_id
                                if result.citations
                                else None
                            ),
                        }
                    )
                continue

            supported_total += 1
            expected_control = str(case["expected_control_id"])
            if result.status != "FOUND" or not result.citations:
                failures.append(
                    {
                        "case_id": case["case_id"],
                        "expected": expected_control,
                        "actual": result.status,
                        "reason": result.reason_code,
                        "top_control": hits[0].control_id if hits else None,
                        "top_page": hits[0].pdf_page_number if hits else None,
                        "top_lexical": round(hits[0].lexical_score, 4) if hits else None,
                        "top_rerank": round(hits[0].rerank_score, 4) if hits else None,
                        "top_hits": [
                            {
                                "control": hit.control_id,
                                "page": hit.pdf_page_number,
                                "dense": round(hit.dense_score, 4),
                                "lexical": round(hit.lexical_score, 4),
                                "rerank": round(hit.rerank_score, 4),
                            }
                            for hit in hits
                        ],
                    }
                )
                continue
            citation = result.citations[0]
            control_ok = citation.control_id == expected_control
            page_ok = (
                int(case["expected_page_start"])
                <= citation.pdf_page_number
                <= int(case["expected_page_end"])
                and citation.section_label == str(case["expected_section_label"])
                and citation.source_sha256 == str(guide["source_sha256"])
            )
            terms = tuple(
                str(term)
                for term in cast(list[object], case["expected_evidence_terms"])
            )
            hit = next(
                (item for item in hits if item.chunk_id == citation.chunk_id),
                None,
            )
            paragraph_ok = (
                hit is not None
                and citation_matches_terms(citation, hit.text, terms)
            )
            supported_control_pass += int(control_ok)
            citation_page_pass += int(page_ok)
            paragraph_pass += int(paragraph_ok)
            if not (control_ok and page_ok and paragraph_ok):
                failures.append(
                    {
                        "case_id": case["case_id"],
                        "expected_control": expected_control,
                        "actual_control": citation.control_id,
                        "actual_page": citation.pdf_page_number,
                        "control_ok": control_ok,
                        "page_ok": page_ok,
                        "paragraph_ok": paragraph_ok,
                        "top_hits": [
                            {
                                "control": hit.control_id,
                                "page": hit.pdf_page_number,
                                "dense": round(hit.dense_score, 4),
                                "lexical": round(hit.lexical_score, 4),
                                "rerank": round(hit.rerank_score, 4),
                            }
                            for hit in hits
                        ],
                    }
                )

        probe_question = str(cases[0]["question"])
        cross_scope = GuideSearchScope(
            organization_id=OTHER_ORGANIZATION_ID,
            guide_id=str(guide["guide_id"]),
            guide_version=str(guide["version"]),
            scope_id=str(guide["scope_id"]),
            query=probe_question,
            top_k=5,
        )
        wrong_scope = GuideSearchScope(
            organization_id=ORGANIZATION_ID,
            guide_id=str(guide["guide_id"]),
            guide_version=str(guide["version"]),
            scope_id="kisa-2026-server",
            query=probe_question,
            top_k=5,
        )
        scope_leaks = len(
            search_guide_chunks(
                session,
                cross_scope,
                embedder.embed(probe_question),
            )
        ) + len(
            search_guide_chunks(
                session,
                wrong_scope,
                embedder.embed(probe_question),
            )
        )

    conflict_pass, conflict_total = _conflict_checks()
    summary = {
        "imp": "IMP-049",
        "evaluation_id": evaluation["evaluation_id"],
        "supported_questions": supported_total,
        "top1_control_pass": supported_control_pass,
        "citation_page_pass": citation_page_pass,
        "paragraph_evidence_pass": paragraph_pass,
        "no_evidence_questions": unsupported_total,
        "no_evidence_pass": no_evidence_pass,
        "conflict_pass": conflict_pass,
        "conflict_total": conflict_total,
        "scope_leaks": scope_leaks,
        "failures": failures,
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    engine.dispose()
    if (
        failures
        or supported_control_pass != supported_total
        or citation_page_pass != supported_total
        or paragraph_pass != supported_total
        or no_evidence_pass != unsupported_total
        or conflict_pass != conflict_total
        or scope_leaks != 0
    ):
        raise RuntimeError("IMP-049 evaluation gate failed.")


if __name__ == "__main__":
    main()
