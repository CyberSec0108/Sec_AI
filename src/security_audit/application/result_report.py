"""Immutable PRODUCT-AI-08 report contracts and dependency-free PDF rendering."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from typing import NoReturn, cast

from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256,
    canonical_sha256_without_fields,
)

_RESULT_ID = re.compile(r"^[a-f0-9]{16}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_CONTROL_IDS = tuple(f"PC-{index:02d}" for index in range(1, 19))
_RULE_STATUSES = frozenset({"PASS", "FAIL", "ERROR", "REVIEW", "NOT_EVALUATED"})


class ReportKind(StrEnum):
    USER = "USER"
    TECHNICAL = "TECHNICAL"


class ReportContractError(ValueError):
    """Raised when browser-supplied report material violates the safe contract."""


@dataclass(frozen=True, slots=True)
class ValidatedReportSnapshot:
    result_id: str
    result_version: int
    observed_at_utc: str
    explanation_inputs: tuple[dict[str, JsonValue], ...]
    ai_explanation: dict[str, JsonValue] | None
    test_environment_result: bool
    snapshot_payload: dict[str, JsonValue]
    snapshot_sha256: str


@dataclass(frozen=True, slots=True)
class ReportDocument:
    title: str
    lines: tuple[str, ...]
    content_sha256: str
    report_kind: ReportKind = ReportKind.USER


def _fail(code: str) -> NoReturn:
    raise ReportContractError(code)


def _as_object(value: object, code: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _fail(code)
    return cast(dict[str, JsonValue], value)


def _as_text(value: JsonValue | object, code: str, maximum: int = 4000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        _fail(code)
    return value.strip()


def _validate_explanation(value: object) -> dict[str, JsonValue]:
    item = _as_object(value, "EXPLANATION_INPUT_INVALID")
    control_id = _as_text(item.get("control_id"), "CONTROL_ID_INVALID", 5)
    if control_id not in _CONTROL_IDS:
        _fail("CONTROL_ID_INVALID")
    if item.get("status_authority") != "RULE_ENGINE":
        _fail("STATUS_AUTHORITY_INVALID")
    if item.get("rule_status") not in _RULE_STATUSES:
        _fail("RULE_STATUS_INVALID")
    if item.get("result_code_visibility") != "TECHNICAL_ONLY":
        _fail("RESULT_CODE_VISIBILITY_INVALID")
    if item.get("official_finding_write_allowed") is not False:
        _fail("OFFICIAL_FINDING_WRITE_NOT_ALLOWED")
    safety = _as_object(item.get("safety"), "EXPLANATION_SAFETY_INVALID")
    expected_safety: dict[str, JsonValue] = {
        "raw_evidence_included": False,
        "sensitive_identifiers_included": False,
        "rule_status_unchanged": True,
        "internal_reason_code_user_visible": False,
    }
    if safety != expected_safety:
        _fail("EXPLANATION_SAFETY_INVALID")
    digest = item.get("explanation_input_sha256")
    if (
        not isinstance(digest, str)
        or not _SHA256.fullmatch(digest)
        or digest
        != canonical_sha256_without_fields(item, {"explanation_input_sha256"})
    ):
        _fail("EXPLANATION_INPUT_HASH_MISMATCH")
    for field in (
        "title",
        "what_was_checked",
        "observed_summary",
        "expected_summary",
        "judgement_explanation",
        "result_code",
    ):
        _as_text(item.get(field), f"{field.upper()}_INVALID")
    for field in (
        "collection_methods",
        "execution_tools",
        "source_locations",
        "kisa_citations",
        "allowed_actions",
    ):
        if not isinstance(item.get(field), list) or not item[field]:
            _fail(f"{field.upper()}_INVALID")
    return item


def _validate_ai_explanation(
    value: object,
    explanation_inputs: tuple[dict[str, JsonValue], ...],
) -> dict[str, JsonValue] | None:
    if value is None:
        return None
    ai = _as_object(value, "AI_EXPLANATION_INVALID")
    if ai.get("status") != "GENERATED":
        return ai
    safety = _as_object(ai.get("safety"), "AI_SAFETY_INVALID")
    if (
        safety.get("official_finding_write_allowed") is not False
        or safety.get("audit_pack_write_allowed") is not False
        or safety.get("rule_status_unchanged") is not True
    ):
        _fail("AI_SAFETY_INVALID")
    expected = {
        str(item["control_id"]): str(item["rule_status"])
        for item in explanation_inputs
    }
    official = ai.get("official_results")
    if not isinstance(official, list) or len(official) != len(expected):
        _fail("AI_OFFICIAL_RESULTS_MISMATCH")
    actual: dict[str, str] = {}
    for result in official:
        result_object = _as_object(result, "AI_OFFICIAL_RESULTS_MISMATCH")
        if result_object.get("status_authority") != "RULE_ENGINE":
            _fail("AI_OFFICIAL_RESULTS_MISMATCH")
        actual[str(result_object.get("control_id"))] = str(
            result_object.get("rule_status")
        )
    if actual != expected:
        _fail("AI_OFFICIAL_RESULTS_MISMATCH")
    input_hashes = ai.get("explanation_input_sha256s")
    expected_hashes = [str(item["explanation_input_sha256"]) for item in explanation_inputs]
    if input_hashes != expected_hashes:
        _fail("AI_INPUT_LINEAGE_MISMATCH")
    for field in ("input_sha256", "model_output_sha256", "output_sha256"):
        digest = ai.get(field)
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            _fail("AI_HASH_INVALID")
    if ai["output_sha256"] != canonical_sha256_without_fields(
        ai, {"output_sha256"}
    ):
        _fail("AI_OUTPUT_HASH_MISMATCH")
    return ai


def validate_report_snapshot(value: object) -> ValidatedReportSnapshot:
    payload = _as_object(value, "REPORT_SNAPSHOT_INVALID")
    result_id = _as_text(payload.get("result_id"), "RESULT_ID_INVALID", 16)
    if not _RESULT_ID.fullmatch(result_id):
        _fail("RESULT_ID_INVALID")
    result_version = payload.get("result_version")
    if not isinstance(result_version, int) or isinstance(result_version, bool):
        _fail("RESULT_VERSION_INVALID")
    if result_version < 1:
        _fail("RESULT_VERSION_INVALID")
    observed_at = _as_text(
        payload.get("observed_at_utc"), "OBSERVED_AT_INVALID", maximum=64
    )
    values = payload.get("explanation_inputs")
    if not isinstance(values, list) or len(values) != 18:
        _fail("CONTROL_COVERAGE_INVALID")
    explanations = tuple(_validate_explanation(item) for item in values)
    if tuple(str(item["control_id"]) for item in explanations) != _CONTROL_IDS:
        _fail("CONTROL_COVERAGE_INVALID")
    ai = _validate_ai_explanation(payload.get("ai_explanation"), explanations)
    if payload.get("test_environment_result") is not True:
        _fail("TEST_ENVIRONMENT_MARKER_REQUIRED")
    snapshot_payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "result_id": result_id,
        "result_version": result_version,
        "observed_at_utc": observed_at,
        "explanation_inputs": [dict(item) for item in explanations],
        "ai_explanation": None if ai is None else dict(ai),
        "test_environment_result": True,
    }
    return ValidatedReportSnapshot(
        result_id=result_id,
        result_version=result_version,
        observed_at_utc=observed_at,
        explanation_inputs=explanations,
        ai_explanation=ai,
        test_environment_result=True,
        snapshot_payload=snapshot_payload,
        snapshot_sha256=canonical_sha256(snapshot_payload),
    )


def build_model_manifest(
    capability: dict[str, object],
    ai_explanation: dict[str, JsonValue] | None,
) -> dict[str, JsonValue]:
    provider_kind = str(capability.get("provider_kind") or "UNKNOWN")
    deployment_mode = str(capability.get("deployment_mode") or "UNKNOWN")
    default_runtime_profile = (
        "VLLM_COMPATIBILITY_TEST_DOUBLE"
        if provider_kind == "OPENROUTER"
        else (
            "LOCAL_VLLM_FULL_CONTEXT"
            if provider_kind == "VLLM" and deployment_mode == "LOCAL_VLLM"
            else "UNAVAILABLE"
        )
    )
    runtime_profile = str(
        (ai_explanation or {}).get("runtime_profile")
        or capability.get("runtime_profile")
        or default_runtime_profile
    )
    model_id = str(
        (ai_explanation or {}).get("model_id")
        or capability.get("resolved_model_id")
        or capability.get("model_id")
        or "설정 확인 필요"
    )
    external_transfer = bool(
        (ai_explanation or {}).get(
            "external_data_transfer",
            capability.get("external_data_transfer", True),
        )
    )
    local_vllm = (
        provider_kind == "VLLM"
        and deployment_mode == "LOCAL_VLLM"
    )
    preparation_value = capability.get("local_vllm_preparation")
    preparation = (
        cast(dict[str, object], preparation_value)
        if isinstance(preparation_value, dict)
        else {}
    )
    preparation_status = str(
        preparation.get("status") or "NOT_PREPARED"
    )
    preparation_image = (
        str(preparation["image"])
        if isinstance(preparation.get("image"), str)
        else None
    )
    preparation_image_digest = (
        str(preparation["image_digest"])
        if isinstance(preparation.get("image_digest"), str)
        else None
    )
    preparation_base_digest = (
        str(preparation["base_image_digest"])
        if isinstance(preparation.get("base_image_digest"), str)
        else None
    )
    preparation_runtime_gate = (
        str(preparation["runtime_gate"])
        if isinstance(preparation.get("runtime_gate"), str)
        else None
    )
    manifest: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "usage_type": "LOCAL_INFERENCE" if local_vllm else "COMPATIBILITY_TEST",
        "runtime_profile": runtime_profile,
        "provider_kind": provider_kind,
        "deployment_mode": deployment_mode,
        "model_id": model_id,
        "base_model_id": model_id,
        "served_model_id": model_id,
        "model_revision": str(
            capability.get("resolved_model_id")
            or capability.get("model_revision")
            or "NOT_DISCLOSED"
        ),
        "model_license": str(
            capability.get("model_license") or "REVIEW_REQUIRED"
        ),
        "model_repository_url": None,
        "external_data_transfer": external_transfer,
        "ai_roles": [
            "실제 확인값과 보안 의미를 쉬운 말로 설명",
            "위험과 우선순위 및 다음 행동 정리",
            "KISA 근거를 사용한 후속 질문 답변",
        ],
        "ai_non_roles": [
            "규칙 엔진 판정 변경",
            "공식 Finding 또는 Audit Pack 작성",
            "PC 설정 자동 변경",
        ],
        "input_policy": {
            "raw_evidence_allowed": False,
            "sensitive_identifiers_allowed": False,
            "test_data_only": True,
        },
        "lineage": {
            "prompt_sha256": (
                cast(dict[str, JsonValue], (ai_explanation or {}).get("prompt"))[
                    "template_sha256"
                ]
                if isinstance((ai_explanation or {}).get("prompt"), dict)
                and "template_sha256"
                in cast(dict[str, JsonValue], (ai_explanation or {}).get("prompt"))
                else None
            ),
            "input_sha256": (ai_explanation or {}).get("input_sha256"),
            "model_output_sha256": (ai_explanation or {}).get(
                "model_output_sha256"
            ),
            "output_sha256": (ai_explanation or {}).get("output_sha256"),
        },
        "local_vllm": {
            "image": preparation_image,
            "image_digest": preparation_image_digest,
            "base_image_digest": preparation_base_digest,
            "runtime_gate": preparation_runtime_gate,
            "sbom_sha256": None,
            "weight_sha256": None,
            "weight_source": None,
            "malware_scan_status": (
                "PENDING_RUNTIME_GATE"
                if preparation_status == "PREPARED_NOT_ACTIVE"
                else ("PENDING" if local_vllm else "NOT_PRESENT")
            ),
            "verification_status": (
                "ACTIVE_VALIDATED"
                if local_vllm
                and preparation_status == "ACTIVE_VALIDATED"
                else preparation_status
            ),
        },
        "fine_tuning": {
            "performed": False,
            "dataset": None,
            "preprocessing": None,
            "derived_weights": None,
        },
        "coding_assistant_disclosure": (
            "개발 보조 도구 사용 여부는 제품 런타임 AI와 별도입니다."
        ),
    }
    manifest["manifest_sha256"] = canonical_sha256_without_fields(
        manifest, {"manifest_sha256"}
    )
    return manifest


def _list_values(value: JsonValue | None) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _citation_text(item: dict[str, JsonValue]) -> str:
    citations = item.get("kisa_citations")
    if not isinstance(citations, list) or not citations:
        return "KISA 근거 확인 필요"
    citation = _as_object(citations[0], "CITATION_INVALID")
    start = citation.get("page_start")
    end = citation.get("page_end")
    pages = str(start) if start == end else f"{start}~{end}"
    return (
        f"KISA PC 보안 가이드 2026 · {pages}쪽 · "
        f"{citation.get('section_label')}"
    )


def _evidence_value_text(value: JsonValue) -> str:
    if value is None:
        return "없음"
    if value is True:
        return "예"
    if value is False:
        return "아니요"
    if isinstance(value, (str, int, float)):
        return str(value)
    if isinstance(value, list):
        return ", ".join(_evidence_value_text(item) for item in value)
    if isinstance(value, dict):
        return ", ".join(
            f"{key}={_evidence_value_text(child)}"
            for key, child in sorted(value.items())
        )
    return str(value)


def build_report_document(
    snapshot: ValidatedReportSnapshot,
    report_kind: ReportKind,
    *,
    report_version: int,
    generated_at: datetime,
    model_manifest: dict[str, JsonValue],
) -> ReportDocument:
    title = (
        "Sec_AI 내 PC 보안 점검 결과 보고서"
        if report_kind is ReportKind.USER
        else "Sec_AI 기술 검증용 점검 결과 보고서"
    )
    lines = [
        title,
        f"결과 번호: {snapshot.result_id} / 결과 버전: {snapshot.result_version}",
        f"보고서 버전: {report_version} / 생성 시각: {generated_at.isoformat()}",
        f"점검 시각: {snapshot.observed_at_utc}",
        "판정 성격: 개발 환경 읽기 전용 점검 · 공식 Finding 아님",
        "",
    ]
    statuses = {status: 0 for status in _RULE_STATUSES}
    for item in snapshot.explanation_inputs:
        statuses[str(item["rule_status"])] += 1
    lines.extend(
        [
            "1. 점검 요약",
            (
                f"전체 18건 · 양호 {statuses['PASS']} · 취약 {statuses['FAIL']} · "
                f"확인 필요 {statuses['ERROR']} · 기준 확인 {statuses['REVIEW']}"
            ),
            "",
            "2. AI 종합 설명",
        ]
    )
    ai = snapshot.ai_explanation
    if ai is not None and ai.get("status") == "GENERATED":
        summary = _as_object(ai.get("summary"), "AI_SUMMARY_INVALID")
        lines.append(
            "AI 종합 판단: "
            + str(summary.get("overall_state") or "AI 종합 설명 없음")
        )
        for risk in _list_values(summary.get("related_risks")):
            lines.append(f"- 관련 위험: {risk}")
        for summary_action in _list_values(summary.get("user_actions")):
            lines.append(f"- 사용자 다음 행동: {summary_action}")
        for summary_action in _list_values(summary.get("administrator_actions")):
            lines.append(f"- 관리자 다음 행동: {summary_action}")
        lines.append(
            "AI는 실제 확인값·KISA 근거·일반 보안지식을 구분해 의미와 행동을 설명했습니다."
        )
    else:
        lines.append(
            "AI 설명 상태: AI 설명을 생성하지 못했지만 공식 점검 결과와 "
            "KISA 근거는 그대로 제공합니다."
        )
    lines.extend(["", "3. 항목별 점검 결과"])
    ai_items_by_control: dict[str, dict[str, JsonValue]] = {}
    if ai is not None and ai.get("status") == "GENERATED":
        raw_ai_items = ai.get("items")
        if isinstance(raw_ai_items, list):
            for raw_item in raw_ai_items:
                if not isinstance(raw_item, dict):
                    continue
                control_id = raw_item.get("control_id")
                if isinstance(control_id, str):
                    ai_items_by_control[control_id] = raw_item
    for item in snapshot.explanation_inputs:
        control_id = str(item["control_id"])
        ai_item = ai_items_by_control.get(control_id)
        lines.extend(
            [
                "",
                f"[{control_id}] {item['title']}",
                f"공식 판정 (규칙 엔진): {item['rule_status']}",
                f"무엇을 확인했나요: {item['what_was_checked']}[1]",
                f"내 PC에서 확인한 값: {item['observed_summary']}[1]",
                f"KISA 권고 기준: {item['expected_summary']}[2]",
                f"판정 이유: {item['judgement_explanation']}[1][2]",
            ]
        )
        if ai_item is not None:
            ai_risk = ai_item.get("risk_explanation")
            if isinstance(ai_risk, str) and ai_risk.strip():
                lines.append(f"AI 보충 설명: {ai_risk.strip()}[3]")
            for limitation in _list_values(ai_item.get("limitations")):
                lines.append(f"AI 설명 한계: {limitation}")
        actions = item.get("allowed_actions")
        if isinstance(actions, list):
            for item_action in actions:
                lines.append(f"다음 행동: {item_action}")
        lines.extend(
            [
                "출처",
                f"[1] 내 PC 점검 결과 · {control_id} 실제 확인값 "
                "(내 PC 확인 증적)",
                f"[2] {_citation_text(item)} (KISA 공식 근거)",
            ]
        )
        if ai is not None and ai.get("status") == "GENERATED":
            lines.append(
                f"[3] AI 일반 보안지식 · {control_id} 이해를 돕는 참고 설명 "
                "(공식 판정 근거 아님·최신성 보장 안 됨)"
            )
        if report_kind is ReportKind.TECHNICAL:
            normalized_facts = item.get("normalized_facts")
            if isinstance(normalized_facts, dict):
                for fact_name, fact_value in sorted(normalized_facts.items()):
                    lines.append(
                        f"정규화 증적: {fact_name} = "
                        f"{_evidence_value_text(fact_value)}"
                    )
            lines.append(
                "원본 증적 포함: 아니요 · 비식별 실제값과 정규화 증적 hash를 제공합니다."
            )
            lines.extend(
                [
                    f"내부 판정 이유 코드: {item['result_code']}",
                    f"설명 입력 SHA-256: {item['explanation_input_sha256']}",
                    f"규칙 결과 SHA-256: {item['source_rule_result_sha256']}",
                ]
            )
            for method in cast(list[dict[str, JsonValue]], item["collection_methods"]):
                lines.append(
                    f"확인 방법: {method.get('method_code')} · "
                    f"{method.get('method_summary')} · {method.get('collection_status')}"
                )
            for tool in cast(list[dict[str, JsonValue]], item["execution_tools"]):
                lines.append(
                    f"실행 도구: {tool.get('collector_name')} "
                    f"{tool.get('collector_version')} · Probe "
                    f"{tool.get('probe_id')} {tool.get('probe_version')} · "
                    f"Adapter {tool.get('adapter_id')} {tool.get('adapter_version')}"
                )
            for source in cast(list[dict[str, JsonValue]], item["source_locations"]):
                lines.append(
                    f"확인 위치: {source.get('user_label')} · "
                    f"{source.get('technical_locator')}"
                )
            evidence_trace = item.get("evidence_trace")
            if isinstance(evidence_trace, list):
                for raw_trace in evidence_trace:
                    if not isinstance(raw_trace, dict):
                        continue
                    trace = raw_trace
                    labels = _evidence_value_text(trace.get("source_labels"))
                    lines.append(
                        "실제 증적 추적: "
                        f"{trace.get('probe_id')} · {trace.get('collection_status')} · "
                        f"수집 {trace.get('collected_at_utc') or '시각 없음'} · "
                        f"출처 {labels or '없음'} · 정규화 SHA-256 "
                        f"{trace.get('normalized_records_sha256') or '생성되지 않음'}"
                    )
            limitations = item.get("collection_limitations")
            if isinstance(limitations, list):
                for limitation_value in limitations:
                    if isinstance(limitation_value, str) and limitation_value.strip():
                        lines.append(f"수집 제약: {limitation_value.strip()}")
            citations = item.get("kisa_citations")
            if isinstance(citations, list):
                for raw_citation in citations:
                    if not isinstance(raw_citation, dict):
                        continue
                    citation = raw_citation
                    lines.append(
                        "KISA 증적 계보: "
                        f"{citation.get('document_code')} · source SHA-256 "
                        f"{citation.get('source_sha256')} · mapping "
                        f"{citation.get('mapping_status')}"
                    )
    if report_kind is ReportKind.TECHNICAL:
        local = cast(dict[str, JsonValue], model_manifest["local_vllm"])
        lines.extend(
            [
                "",
                "4. AI 모델 활용 및 라이선스 기술 명세",
                f"활용 유형: {model_manifest['usage_type']}",
                f"실행 프로필: {model_manifest['runtime_profile']}",
                (
                    f"제공 방식: {model_manifest['provider_kind']} / "
                    f"{model_manifest['deployment_mode']}"
                ),
                (
                    f"모델: {model_manifest['model_id']} / "
                    f"리비전: {model_manifest['model_revision']}"
                ),
                f"라이선스: {model_manifest['model_license']}",
                f"외부 전송: {'예' if model_manifest['external_data_transfer'] else '아니요'}",
                (
                    "로컬 vLLM 공급망 검증: PRODUCT-AI-09에서 검증 예정"
                    if local["verification_status"] == "DEFERRED_PRODUCT_AI_09"
                    else f"로컬 vLLM 공급망 검증: {local['verification_status']}"
                ),
                f"모델 명세 SHA-256: {model_manifest['manifest_sha256']}",
                "",
                "5. 무결성 및 추적 정보",
                f"결과 snapshot SHA-256: {snapshot.snapshot_sha256}",
            ]
        )
        lineage = cast(dict[str, JsonValue], model_manifest["lineage"])
        for label, key in (
            ("Prompt", "prompt_sha256"),
            ("AI 입력", "input_sha256"),
            ("모델 출력", "model_output_sha256"),
            ("AI 설명", "output_sha256"),
        ):
            lines.append(f"{label} SHA-256: {lineage.get(key) or '생성되지 않음'}")
    content_payload: dict[str, JsonValue] = {
        "title": title,
        "lines": cast(list[JsonValue], lines),
        "report_kind": report_kind.value,
        "report_version": report_version,
        "snapshot_sha256": snapshot.snapshot_sha256,
    }
    content_hash = canonical_sha256(content_payload)
    lines.extend(["", f"보고서 내용 SHA-256: {content_hash}"])
    return ReportDocument(
        title=title,
        lines=tuple(lines),
        content_sha256=content_hash,
        report_kind=report_kind,
    )


def _pdf_text(value: str) -> str:
    safe_value = value.replace("•", "·")
    return safe_value.encode("cp949", errors="replace").hex().upper()


_NAVY = (0.063, 0.165, 0.263)
_BLUE = (0.047, 0.353, 0.651)
_TEXT = (0.071, 0.129, 0.188)
_MUTED = (0.350, 0.420, 0.490)
_LINE = (0.820, 0.855, 0.890)
_SURFACE = (0.965, 0.975, 0.985)
_PASS = (0.030, 0.460, 0.340)
_FAIL = (0.700, 0.140, 0.210)
_ERROR = (0.600, 0.350, 0.000)


def _color(value: tuple[float, float, float]) -> str:
    return " ".join(f"{item:.3f}" for item in value)


def _text_units(value: str) -> float:
    return sum(
        0.35 if char == " " else (0.55 if char.isascii() else 1.0)
        for char in value
    )


def _wrap_pdf_text(value: str, width: float, font_size: float) -> list[str]:
    limit = max(width / font_size, 1.0)
    result: list[str] = []
    current = ""
    for character in value.replace("\t", " "):
        candidate = current + character
        if current and _text_units(candidate) > limit:
            split = current.rfind(" ")
            if split > 0:
                result.append(current[:split].rstrip())
                current = current[split + 1 :] + character
            else:
                result.append(current.rstrip())
                current = character.lstrip()
        else:
            current = candidate
    if current or not result:
        result.append(current.rstrip())
    return result


def _pdf_tj(value: str) -> str:
    parts: list[str] = []
    for character in value:
        parts.append(f"<{_pdf_text(character)}>")
        if not character.isascii():
            continue
        if character == " ":
            advance = 0.35
        elif character in "ilI.,:;!'|`":
            advance = 0.28
        elif character in "mwMW@%&":
            advance = 0.85
        elif character in "fjt[](){}":
            advance = 0.40
        elif character.isupper():
            advance = 0.62
        elif character.isdigit():
            advance = 0.55
        else:
            advance = 0.52
        parts.append(str(round((1.0 - advance) * 1000)))
    return "[" + " ".join(parts) + "] TJ"


class _PdfLayout:
    def __init__(self, document: ReportDocument) -> None:
        self.document = document
        self.pages: list[list[str]] = []
        self.y = 0.0
        self.new_page()

    @property
    def commands(self) -> list[str]:
        return self.pages[-1]

    def text(
        self,
        x: float,
        y: float,
        value: str,
        *,
        size: float = 9.0,
        color: tuple[float, float, float] = _TEXT,
    ) -> None:
        self.commands.append(
            f"BT /F1 {size:.2f} Tf {_color(color)} rg "
            f"1 0 0 1 {x:.2f} {y:.2f} Tm {_pdf_tj(value)} ET"
        )

    def rect(
        self,
        x: float,
        top: float,
        width: float,
        height: float,
        *,
        fill: tuple[float, float, float] | None = None,
        stroke: tuple[float, float, float] | None = None,
        line_width: float = 0.8,
    ) -> None:
        bottom = top - height
        if fill is not None:
            self.commands.append(
                f"{_color(fill)} rg {x:.2f} {bottom:.2f} "
                f"{width:.2f} {height:.2f} re f"
            )
        if stroke is not None:
            self.commands.append(
                f"{_color(stroke)} RG {line_width:.2f} w {x:.2f} {bottom:.2f} "
                f"{width:.2f} {height:.2f} re S"
            )

    def line(
        self,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        *,
        color: tuple[float, float, float] = _LINE,
        width: float = 0.8,
    ) -> None:
        self.commands.append(
            f"{_color(color)} RG {width:.2f} w "
            f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S"
        )

    def new_page(self) -> None:
        self.pages.append([])
        self.rect(0, 842, 595, 72, fill=_NAVY)
        title_size = 15 if self.document.report_kind is ReportKind.TECHNICAL else 17
        self.text(
            40,
            808,
            self.document.title,
            size=title_size,
            color=(1.0, 1.0, 1.0),
        )
        subtitle = (
            "승인된 보안 검증 담당자용 · 실제 증적 및 무결성 계보"
            if self.document.report_kind is ReportKind.TECHNICAL
            else "내 PC 점검 결과 · 실제 확인값과 안전한 조치 안내"
        )
        self.text(40, 786, subtitle, size=8.5, color=(0.850, 0.910, 0.970))
        kind = "기술 검증용" if self.document.report_kind is ReportKind.TECHNICAL else "사용자용"
        self.rect(487, 816, 68, 24, fill=_BLUE)
        self.text(496, 800, kind, size=8, color=(1.0, 1.0, 1.0))
        self.y = 752

    def ensure(self, height: float) -> bool:
        if self.y - height >= 48:
            return False
        self.new_page()
        return True

    def paragraph(
        self,
        value: str,
        *,
        size: float = 9.0,
        color: tuple[float, float, float] = _TEXT,
        indent: float = 0.0,
        gap: float = 5.0,
    ) -> None:
        lines = _wrap_pdf_text(value, 515 - indent, size)
        height = len(lines) * (size + 3) + gap
        self.ensure(height)
        for line in lines:
            self.text(40 + indent, self.y, line, size=size, color=color)
            self.y -= size + 3
        self.y -= gap

    def section(self, value: str) -> None:
        self.ensure(66)
        self.y -= 20
        match = re.fullmatch(r"(\d+)\.\s+(.+)", value)
        if match is None:
            self.text(40, self.y, value, size=13, color=_NAVY)
        else:
            number, title = match.groups()
            self.rect(40, self.y + 8, 24, 24, fill=_BLUE)
            self.text(48, self.y - 7, number, size=9, color=(1.0, 1.0, 1.0))
            self.text(74, self.y, title, size=13, color=_NAVY)
        self.y -= 13
        self.line(40, self.y, 555, self.y, color=_BLUE, width=1.5)
        self.y -= 22

    def notice(self, value: str) -> None:
        lines = _wrap_pdf_text(value, 475, 9)
        height = len(lines) * 12 + 18
        self.ensure(height + 8)
        top = self.y
        self.rect(40, top, 515, height, fill=(1.000, 0.973, 0.890), stroke=(0.850, 0.650, 0.180))
        self.rect(40, top, 4, height, fill=(0.720, 0.430, 0.000))
        y = top - 15
        for line in lines:
            self.text(52, y, line, size=9, color=(0.390, 0.290, 0.100))
            y -= 12
        self.y -= height + 12

    def metadata(self, values: list[str]) -> None:
        height = len(values) * 15 + 14
        self.ensure(height)
        top = self.y
        self.rect(40, top, 515, height, fill=_SURFACE, stroke=_LINE)
        y = top - 17
        for value in values:
            self.text(52, y, value, size=8.5, color=_MUTED)
            y -= 15
        self.y -= height + 14

    def info_panel(self, label: str, value: str) -> None:
        value_lines = _wrap_pdf_text(value, 485, 9)
        height = 31 + len(value_lines) * 12
        self.ensure(height + 10)
        top = self.y
        self.rect(40, top, 515, height, fill=(0.965, 0.980, 1.000), stroke=_LINE)
        self.rect(40, top, 4, height, fill=_BLUE)
        self.text(52, top - 17, label, size=8, color=_BLUE)
        y = top - 34
        for line in value_lines:
            self.text(52, y, line, size=9, color=_TEXT)
            y -= 12
        self.y -= height + 12

    def summary_table(self, value: str) -> bool:
        match = re.fullmatch(
            r"전체 (\d+)건 · 양호 (\d+) · 취약 (\d+) · 확인 필요 (\d+) · 기준 확인 (\d+)",
            value,
        )
        if match is None:
            return False
        self.ensure(68)
        labels = ("전체", "양호", "취약", "수집 오류", "기준 확인")
        colors = (_NAVY, _PASS, _FAIL, _ERROR, _BLUE)
        width = 103.0
        summary_values = zip(labels, match.groups(), colors, strict=True)
        for index, (label, count, color) in enumerate(summary_values):
            x = 40 + index * width
            self.rect(x, self.y, width, 54, fill=(1.0, 1.0, 1.0), stroke=_LINE)
            self.rect(x, self.y, width, 4, fill=color)
            self.text(x + 10, self.y - 19, label, size=8, color=_MUTED)
            self.text(x + 10, self.y - 41, count, size=15, color=color)
        self.y -= 68
        return True

    def control_header(self, title: str, status_value: str, *, continued: bool) -> None:
        status_colors = {
            "PASS": _PASS,
            "FAIL": _FAIL,
            "ERROR": _ERROR,
            "REVIEW": _BLUE,
            "NOT_EVALUATED": _MUTED,
        }
        color = status_colors.get(status_value, _MUTED)
        label = {
            "PASS": "양호",
            "FAIL": "취약",
            "ERROR": "수집 오류",
            "REVIEW": "기준 확인",
        }.get(status_value, status_value)
        self.rect(40, self.y, 515, 38, fill=(1.0, 1.0, 1.0), stroke=_LINE)
        self.rect(40, self.y, 4, 38, fill=color)
        suffix = " (계속)" if continued else ""
        self.text(52, self.y - 24, title + suffix, size=10.5, color=_NAVY)
        self.rect(478, self.y - 7, 65, 23, fill=(0.950, 0.970, 0.980), stroke=color)
        self.text(489, self.y - 23, label, size=8, color=color)
        self.y -= 38

    def control_row(self, label: str, value: str, *, technical: bool) -> None:
        label_width = 108.0
        size = 7.8 if technical else 8.5
        value_lines = _wrap_pdf_text(value, 383, size)
        label_lines = _wrap_pdf_text(label, label_width - 16, size)
        height = max(len(value_lines), len(label_lines)) * (size + 3) + 12
        top = self.y
        value_fill = (0.970, 0.980, 0.992) if technical else (1.0, 1.0, 1.0)
        label_fill = (0.925, 0.950, 0.975) if technical else _SURFACE
        if label == "다음 행동":
            value_fill = (0.965, 0.985, 0.975)
            label_fill = (0.900, 0.960, 0.930)
        self.rect(40, top, 515, height, fill=value_fill, stroke=_LINE)
        self.rect(40, top, label_width, height, fill=label_fill)
        self.line(40 + label_width, top, 40 + label_width, top - height, color=_LINE)
        y = top - 15
        for line in label_lines:
            self.text(50, y, line, size=size, color=_NAVY)
            y -= size + 3
        y = top - 15
        for line in value_lines:
            self.text(40 + label_width + 10, y, line, size=size, color=_TEXT)
            y -= size + 3
        self.y -= height

    def source_heading(self) -> None:
        self.line(52, self.y, 543, self.y, color=_LINE, width=0.6)
        self.y -= 15
        self.text(52, self.y, "[출처]", size=6.5, color=_MUTED)
        self.y -= 13

    def source_line(self, marker: str, value: str) -> None:
        size = 6.5
        value_lines = _wrap_pdf_text(value, 462, size)
        y = self.y
        self.text(52, y, marker, size=size, color=_MUTED)
        for line in value_lines:
            self.text(78, y, line, size=size, color=_MUTED)
            y -= size + 2.5
        self.y -= len(value_lines) * (size + 2.5) + 5


def _line_label_value(value: str) -> tuple[str, str]:
    if value == "출처":
        return "출처", "항목별 근거"
    if value.startswith("[") and "] " in value:
        marker, _, text = value.partition("] ")
        return marker + "]", text
    label, separator, text = value.partition(": ")
    return (label, text) if separator else ("설명", value)


def _technical_row(label: str) -> bool:
    return any(
        marker in label
        for marker in (
            "내부", "SHA-256", "정규화 증적", "원본 증적", "확인 방법",
            "실행 도구", "확인 위치", "실제 증적", "수집 제약", "KISA 증적",
        )
    )


def _control_row_height(label: str, text: str, *, technical: bool) -> float:
    size = 7.8 if technical else 8.5
    return max(
        len(_wrap_pdf_text(label, 92, size)),
        len(_wrap_pdf_text(text, 383, size)),
    ) * (size + 3) + 12


def _source_line_height(value: str) -> float:
    size = 6.5
    return len(_wrap_pdf_text(value, 462, size)) * (size + 2.5) + 5


def _draw_control(layout: _PdfLayout, values: list[str]) -> None:
    title = values[0]
    status_line = next(
        (value for value in values if value.startswith("공식 판정 (규칙 엔진): ")),
        "공식 판정 (규칙 엔진): REVIEW",
    )
    status_value = status_line.rsplit(": ", 1)[-1]
    core_height = 38.0
    core_row_count = 0
    for value in values[1:]:
        if not value or value == status_line or value == "출처":
            continue
        label, text = _line_label_value(value)
        core_height += _control_row_height(
            label,
            text,
            technical=_technical_row(label),
        )
        core_row_count += 1
        if core_row_count == 4:
            break
    layout.ensure(min(core_height + 10, 690))
    layout.control_header(title, status_value, continued=False)
    for position, value in enumerate(values[1:], start=1):
        if not value or value == status_line:
            continue
        label, text = _line_label_value(value)
        if label == "출처":
            first_source_height = 0.0
            if position + 1 < len(values):
                _, next_text = _line_label_value(values[position + 1])
                first_source_height = _source_line_height(next_text)
            if layout.y - 28 - first_source_height < 48:
                layout.new_page()
                layout.control_header(title, status_value, continued=True)
            layout.source_heading()
            continue
        if re.fullmatch(r"\[\d+\]", label):
            if layout.y - _source_line_height(text) < 48:
                layout.new_page()
                layout.control_header(title, status_value, continued=True)
                layout.source_heading()
            layout.source_line(label, text)
            continue
        technical = _technical_row(label)
        height = _control_row_height(label, text, technical=technical)
        if layout.y - height < 48:
            layout.new_page()
            layout.control_header(title, status_value, continued=True)
        layout.control_row(label, text, technical=technical)
    layout.y -= 14


def _styled_pages(document: ReportDocument) -> list[list[str]]:
    layout = _PdfLayout(document)
    lines = list(document.lines)
    index = 1
    if len(lines) > 1 and lines[1].startswith("현재 결과는 승인 전 시험 판정"):
        layout.notice(lines[1])
        index = 2
    metadata: list[str] = []
    while index < len(lines) and lines[index]:
        metadata.append(lines[index])
        index += 1
    if metadata:
        layout.metadata(metadata)
    while index < len(lines):
        value = lines[index]
        if not value:
            index += 1
            continue
        if re.match(r"^\d+\. ", value):
            layout.section(value)
            index += 1
            continue
        if value.startswith("[PC-"):
            end = index + 1
            while end < len(lines):
                next_value = lines[end]
                if next_value.startswith("[PC-") or re.match(r"^\d+\. ", next_value):
                    break
                end += 1
            _draw_control(layout, lines[index:end])
            index = end
            continue
        if layout.summary_table(value):
            index += 1
            continue
        if value.startswith("AI 종합 판단: ") or value.startswith("AI 설명 상태: "):
            label, _, text = value.partition(": ")
            layout.info_panel(label, text)
        elif value.startswith("보고서 내용 SHA-256: "):
            layout.notice(value)
        elif value.startswith("- "):
            layout.paragraph("• " + value[2:], indent=8)
        else:
            layout.paragraph(value)
        index += 1
    total = len(layout.pages)
    for page_number, commands in enumerate(layout.pages, start=1):
        commands.append(f"{_color(_LINE)} RG 0.80 w 40 35 m 555 35 l S")
        commands.append(
            "BT /F1 7.50 Tf " + _color(_MUTED) + " rg 1 0 0 1 40 20 Tm "
            + _pdf_tj("Sec_AI · 승인 전 시험 판정") + " ET"
        )
        commands.append(
            "BT /F1 7.50 Tf " + _color(_MUTED) + " rg 1 0 0 1 505 20 Tm "
            + _pdf_tj(f"{page_number} / {total}") + " ET"
        )
    return layout.pages


def render_pdf(document: ReportDocument) -> bytes:
    """Render deterministic styled A4 PDF using a standard Korean Gothic font."""

    pages = _styled_pages(document)
    page_object_numbers = [7 + index * 2 for index in range(len(pages))]
    kids = " ".join(f"{number} 0 R" for number in page_object_numbers)
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        (f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>").encode(),
        (
            b"<< /Type /Font /Subtype /Type0 /BaseFont /HYGoThic-Medium "
            b"/Encoding /KSCms-UHC-H /DescendantFonts [4 0 R] >>"
        ),
        (
            b"<< /Type /Font /Subtype /CIDFontType0 /BaseFont /HYGoThic-Medium "
            b"/CIDSystemInfo << /Registry (Adobe) /Ordering (Korea1) "
            b"/Supplement 2 >> /FontDescriptor 5 0 R /DW 1000 >>"
        ),
        (
            b"<< /Type /FontDescriptor /FontName /HYGoThic-Medium /Flags 6 "
            b"/FontBBox [-6 -145 1003 880] /ItalicAngle 0 /Ascent 880 "
            b"/Descent -120 /CapHeight 880 /StemV 93 >>"
        ),
        (
            f"<< /Title <{_pdf_text(document.title)}> "
            f"/Producer (Sec_AI PRODUCT-AI-08) >>"
        ).encode(),
    ]
    for object_number, page_commands in zip(page_object_numbers, pages, strict=True):
        stream = "\n".join(page_commands).encode("ascii")
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                f"/Resources << /Font << /F1 3 0 R >> >> "
                f"/Contents {object_number + 1} 0 R >>"
            ).encode()
        )
        objects.append(
            f"<< /Length {len(stream)} >>\nstream\n".encode()
            + stream
            + b"\nendstream"
        )
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode())
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info 6 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n"
        ).encode()
    )
    return bytes(output)


def pdf_sha256(value: bytes) -> str:
    return sha256(value).hexdigest()
