"""Windows 점검 결과 DTO를 한 곳에서 조립합니다.

로컬 Launcher와 원격 제출이 같은 문서를 만들도록 모아둔 것입니다. 안전 표시
필드는 호출자가 바꿀 수 없게 여기서 고정합니다.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from security_audit.application.result_explanation_input import (
    build_scan_explanation_inputs,
)
from security_audit.application.result_explanation_presentation import (
    build_result_explanation_presentations,
)
from security_audit.application.scan_result_guidance import (
    summarize_control_results,
    summarize_draft_assessments,
)

_RESULT_ID = re.compile(r"^[a-f0-9]{16}$")


class WindowsResultDocumentError(ValueError):
    """결과 문서를 만들 수 없는 입력일 때 발생합니다."""


def build_windows_result_document(
    project_root: Path,
    *,
    receipt: Mapping[str, Any],
    controls: Sequence[Mapping[str, Any]],
    result_id: str,
    sequence: int,
    attempt: int,
    comparison: Mapping[str, Any] | None = None,
    changed_control_count: int = 0,
) -> dict[str, Any]:
    """규칙 판정이 모두 있을 때만 설명 입력을 만들고, 아니면 비워 둡니다."""

    if _RESULT_ID.fullmatch(result_id) is None:
        raise WindowsResultDocumentError("RESULT_ID_INVALID")
    if sequence < 1 or attempt < 1:
        raise WindowsResultDocumentError("RESULT_VERSION_INVALID")

    has_complete_rule_results = all(
        control.get("assessment_status") is not None for control in controls
    )
    explanations = (
        build_result_explanation_presentations(project_root, controls=controls)
        if has_complete_rule_results and controls
        else []
    )
    ai_explanation_inputs = (
        build_scan_explanation_inputs(
            project_root,
            controls=controls,
            collected_probe_results=cast(
                Sequence[Mapping[str, object]],
                receipt.get("results", []),
            ),
        )
        if has_complete_rule_results and controls
        else []
    )
    observed_at = receipt.get("observed_at_utc")
    inventory = receipt.get("vulnerability_inventory")
    return {
        "result_id": result_id,
        "sequence": sequence,
        "attempt": attempt,
        "observed_at_utc": observed_at if isinstance(observed_at, str) else "UNKNOWN",
        "vulnerability_inventory": (
            dict(inventory) if isinstance(inventory, Mapping) else None
        ),
        "counts": summarize_control_results(controls),
        "assessment_counts": summarize_draft_assessments(controls),
        "changed_control_count": changed_control_count,
        "comparison": dict(comparison) if comparison is not None else None,
        "controls": list(controls),
        "explanations": explanations,
        "ai_explanation_inputs": ai_explanation_inputs,
        # 아래 네 값은 호출자가 바꿀 수 없는 안전 경계입니다.
        "ai_input_contains_raw_evidence": False,
        "raw_values_persisted": False,
        "settings_modified": False,
        "official_finding_created": False,
        "result_kind": (
            "LIVE_DRAFT_ASSESSMENT"
            if has_complete_rule_results and controls
            else "COLLECTION_GUIDANCE"
        ),
    }
