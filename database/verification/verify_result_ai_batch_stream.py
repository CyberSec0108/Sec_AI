"""18개 비식별 점검 결과의 검증 묶음 생성·병합 실환경 Gate."""

from __future__ import annotations

import json
from typing import cast

from apps.api.result_ai_explanation import _merge_generated_batches
from database.verification.verify_product_ai_03 import (
    PROJECT_ROOT,
    _control_results,
    _guide_evidence,
    _policy,
    _probe_results,
)

from security_audit.application.result_ai_explanation import (
    ResultAIExplanationService,
)
from security_audit.application.result_explanation_input import (
    build_explanation_inputs,
)
from security_audit.common.canonical_json import JsonValue
from security_audit.llm import InternalModelGatewayClient

_BATCH_SIZE = 6


def main() -> None:
    explanations = build_explanation_inputs(
        PROJECT_ROOT,
        controls=_control_results(),
        probe_results=_probe_results(),
    )
    evidence = [_guide_evidence(item) for item in explanations]
    client = InternalModelGatewayClient.from_environment()
    capability = client.capabilities()
    policy = _policy(capability)
    service = ResultAIExplanationService(client)
    batch_results: list[dict[str, JsonValue]] = []
    for start in range(0, len(explanations), _BATCH_SIZE):
        result = service.generate(
            explanations[start : start + _BATCH_SIZE],
            evidence[start : start + _BATCH_SIZE],
            policy=policy,
            profile="FAST",
        ).to_json()
        batch_results.append(result)
        if result["status"] != "GENERATED":
            raise RuntimeError(
                "AI explanation batch failed: "
                f"{result['status']}:{result['reason_code']}"
            )

    merged = _merge_generated_batches(batch_results)
    items = cast(list[dict[str, JsonValue]], merged["items"])
    official_results = cast(
        list[dict[str, JsonValue]],
        merged["official_results"],
    )
    citations = cast(list[dict[str, JsonValue]], merged["citations"])
    control_ids = [cast(str, item["control_id"]) for item in items]
    summary = {
        "status": merged["status"],
        "provider_kind": capability.get("provider_kind"),
        "model_id": merged["model_id"],
        "batch_count": len(batch_results),
        "batch_size": _BATCH_SIZE,
        "controls": len(control_ids),
        "official_results": len(official_results),
        "citations": len(citations),
        "output_sha256": merged["output_sha256"],
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    if (
        merged["status"] != "GENERATED"
        or len(batch_results) != 3
        or control_ids != [f"PC-{number:02d}" for number in range(1, 19)]
        or len(official_results) != 18
        or len(citations) != 18
    ):
        raise RuntimeError("18-control batch streaming compatibility gate failed.")


if __name__ == "__main__":
    main()
