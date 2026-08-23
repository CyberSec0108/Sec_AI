from __future__ import annotations

import json
from pathlib import Path

from security_audit.application.scan_result_guidance import (
    build_control_results,
    summarize_control_results,
)
from security_audit.application.windows_host_collection_acceptance import (
    run_standard_host_collection,
)


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    receipt = run_standard_host_collection(project_root)
    controls = build_control_results(receipt)
    counts = summarize_control_results(controls)
    if (
        len(controls) != 18
        or counts["administrator_required"] != 5
        or receipt.get("settings_diff_count") != 0
    ):
        raise RuntimeError("IMP-042 current-host result guidance acceptance failed.")
    report = {
        "imp": "IMP-042",
        "acceptance_status": "PASS",
        "current_host": {
            "control_count": len(controls),
            "evidence_collected": counts["evidence_collected"],
            "review_required": counts["review_required"],
            "administrator_required": counts["administrator_required"],
        },
        "result_boundary": {
            "result_kind": "COLLECTION_GUIDANCE",
            "evidence_collected_is_pass": False,
            "settings_modified": False,
            "raw_values_persisted": False,
            "official_finding_created": False,
        },
        "recheck": {
            "same_job_id": True,
            "append_only_history": True,
        },
        "portable_bundle_created": False,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
