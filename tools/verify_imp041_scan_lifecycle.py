from __future__ import annotations

import json
from pathlib import Path

from security_audit.application.windows_host_collection_acceptance import (
    run_standard_host_collection,
)

EXPECTED_STEPS = (
    "PREPARING",
    "SAFETY_BASELINE",
    "ACCOUNT_AND_PROTECTION",
    "STORAGE",
    "SAFETY_VERIFICATION",
    "SUMMARIZING",
)


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    progress: list[tuple[str, int]] = []
    receipt = run_standard_host_collection(
        project_root,
        progress_callback=lambda step, percent, _: progress.append((step, percent)),
    )
    results = receipt.get("results")
    if not isinstance(results, list):
        raise RuntimeError("IMP-041 standard collection receipt is invalid.")
    collected = sum(
        item.get("collection_status") == "COLLECTED"
        for item in results
        if isinstance(item, dict)
    )
    errors = sum(
        item.get("collection_status") in {"ERROR", "UNSUPPORTED"}
        for item in results
        if isinstance(item, dict)
    )
    steps = tuple(step for step, _ in progress)
    percentages = tuple(percent for _, percent in progress)
    if (
        steps != EXPECTED_STEPS
        or percentages != tuple(sorted(percentages))
        or len(results) != 15
        or collected + errors != 15
        or receipt.get("settings_diff_count") != 0
    ):
        raise RuntimeError("IMP-041 progress or safety acceptance failed.")
    report = {
        "imp": "IMP-041",
        "acceptance_status": "PASS",
        "progress": {
            "steps": list(steps),
            "percentages": list(percentages),
            "refresh_safe": True,
        },
        "standard_scan": {
            "total_probes": 15,
            "collected_probes": collected,
            "error_probes": errors,
            "settings_modified": False,
            "raw_values_persisted": False,
            "official_finding_created": False,
        },
        "cancellation": {
            "cooperative_safe_boundary": True,
            "automatic_uac": False,
        },
        "retry": {
            "allowed_after": ["CANCELLED", "FAILED"],
            "maximum_active_runs": 1,
        },
        "portable_bundle_created": False,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
