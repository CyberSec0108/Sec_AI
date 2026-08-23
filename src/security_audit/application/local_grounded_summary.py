"""외부 전송 없이 승인된 Guide 문단을 쉽게 표시하는 로컬 요약 모델."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from security_audit.llm import ChatCompletionInput, ChatCompletionResult

_PREFIX = "<untrusted_payload>"
_SUFFIX = "</untrusted_payload>"
_PARAGRAPH_BOUNDARY = re.compile(r"(?<=[.!?])\s+")
_CONTROL_ID = re.compile(r"^(?:PC-(0[1-9]|1[0-8])|GUIDE-PAGE)$")


def _payload(request: ChatCompletionInput) -> Mapping[str, Any]:
    wrapped = request.messages[-1].content
    if not wrapped.startswith(_PREFIX) or not wrapped.endswith(_SUFFIX):
        raise ValueError("LOCAL_GROUNDED_PAYLOAD_INVALID")
    try:
        value = json.loads(wrapped[len(_PREFIX) : -len(_SUFFIX)])
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("LOCAL_GROUNDED_PAYLOAD_INVALID") from exc
    if not isinstance(value, dict):
        raise ValueError("LOCAL_GROUNDED_PAYLOAD_INVALID")
    return value


def _plain_text(value: object, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError("LOCAL_GROUNDED_PAYLOAD_INVALID")
    normalized = re.sub(r"\s+", " ", value).strip()
    if not normalized or len(normalized) > maximum:
        raise ValueError("LOCAL_GROUNDED_PAYLOAD_INVALID")
    return normalized


class LocalGroundedSummaryModel:
    """Completion 계약을 따르는 명시적 로컬·결정론적 요약 모드."""

    model_id = "secai-local-grounded-summary-v1"

    def complete(self, request: ChatCompletionInput) -> ChatCompletionResult:
        payload = _payload(request)
        citation = payload.get("citation")
        if not isinstance(citation, dict):
            raise ValueError("LOCAL_GROUNDED_PAYLOAD_INVALID")
        control_id = _plain_text(citation.get("control_id"), maximum=16)
        if _CONTROL_ID.fullmatch(control_id) is None:
            raise ValueError("LOCAL_GROUNDED_PAYLOAD_INVALID")
        section = _plain_text(citation.get("section_label"), maximum=256)
        guide_version = _plain_text(
            citation.get("guide_version"),
            maximum=64,
        )
        document_code_value = citation.get("document_code")
        document_code = (
            _plain_text(document_code_value, maximum=256)
            if isinstance(document_code_value, str)
            else f"KISA {guide_version}"
        )
        page = citation.get("pdf_page_number")
        if isinstance(page, bool) or not isinstance(page, int) or page <= 0:
            raise ValueError("LOCAL_GROUNDED_PAYLOAD_INVALID")
        excerpt = _plain_text(payload.get("guide_excerpt"), maximum=24_000)
        paragraphs = tuple(
            part.strip()
            for part in _PARAGRAPH_BOUNDARY.split(excerpt)
            if part.strip()
        )
        ordinal = citation.get("paragraph_ordinal", 2)
        if (
            isinstance(ordinal, bool)
            or not isinstance(ordinal, int)
            or ordinal <= 0
            or ordinal > len(paragraphs)
        ):
            ordinal = min(2, len(paragraphs))
        evidence = paragraphs[ordinal - 1][:900]
        mode = payload.get("mode")
        if mode == "FINDING_EXPLAIN":
            finding = payload.get("finding")
            if not isinstance(finding, dict):
                raise ValueError("LOCAL_GROUNDED_PAYLOAD_INVALID")
            status = _plain_text(
                finding.get("official_status"),
                maximum=16,
            )
            content = "\n\n".join(
                (
                    f"핵심 답변\n{control_id}의 공식 점검 상태는 {status}입니다.",
                    f"확인 기준\n- {section}\n- {evidence}[1]",
                    f"출처\n- KISA {guide_version} {page}쪽",
                    (
                        "알아두세요\n- 이 설명은 승인된 KISA 근거를 쉽게 "
                        "정리한 것이며 공식 점검 결과를 변경하지 않습니다."
                    ),
                )
            )
        elif mode == "GUIDE_QA":
            if control_id == "GUIDE-PAGE":
                content = "\n\n".join(
                    (
                        f"핵심 답변\n{section}의 승인된 원문에서 확인한 내용입니다.",
                        f"확인 기준\n- {evidence}[1]",
                        f"출처\n- {document_code} {page}쪽",
                        (
                            "알아두세요\n- 이 문서는 추가 설명에만 사용하며 "
                            "KISA 점검 판정이나 공식 점검 결과를 변경하지 않습니다."
                        ),
                    )
                )
            else:
                content = "\n\n".join(
                    (
                        f"핵심 답변\n{control_id}은(는) {section} 항목입니다.",
                        f"확인 기준\n- {evidence}[1]",
                        f"출처\n- KISA {guide_version} {page}쪽",
                        (
                            "알아두세요\n- 이 답변은 승인된 KISA 근거를 쉽게 "
                            "정리한 것이며 PC 설정이나 공식 점검 결과를 "
                            "변경하지 않습니다."
                        ),
                    )
                )
        else:
            raise ValueError("LOCAL_GROUNDED_PAYLOAD_INVALID")
        return ChatCompletionResult(
            model_id=self.model_id,
            content=content,
            finish_reason="stop",
            prompt_tokens=None,
            completion_tokens=None,
            total_tokens=None,
        )
