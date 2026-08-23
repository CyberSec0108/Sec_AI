from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path

from security_audit.application.administrator_scan import (
    CONSENT_VERSION,
    build_administrator_results,
    validate_administrator_consent_request,
)
from security_audit.collector.expanded import ADMINISTRATOR_PROBES


def _is_administrator() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    policy = json.loads(
        (
            project_root
            / "collectors"
            / "one_shot"
            / "contracts"
            / "imp043_administrator_consent_policy.json"
        ).read_text(encoding="utf-8")
    )
    selected = validate_administrator_consent_request(
        {
            "consent": True,
            "consent_version": CONSENT_VERSION,
            "probe_ids": list(ADMINISTRATOR_PROBES),
        }
    )
    receipt = {
        "observed_at_utc": "VERIFICATION",
        "explicit_consent": True,
        "selected_probe_ids": list(selected),
        "settings_diff_count": 0,
        "results": [
            {
                "probe_id": probe_id,
                "control_ids": ["VERIFICATION"],
                "privilege": "ADMINISTRATOR",
                "collection_status": "COLLECTED",
                "error_code": "NONE",
                "record_count": 1,
            }
            for probe_id in selected
        ],
    }
    result = build_administrator_results(receipt)
    if (
        policy["consent"]["automatic_elevation"] is not False
        or policy["selection"]["maximum_probe_count"] != len(selected)
        or result["collected_probe_count"] != len(selected)
        or result["settings_modified"] is not False
        or result["raw_values_persisted"] is not False
        or result["official_finding_created"] is not False
    ):
        raise RuntimeError("IMP-043 administrator consent acceptance failed.")
    report = {
        "imp": "IMP-043",
        "acceptance_status": "PASS",
        "current_process_is_administrator": _is_administrator(),
        "actual_uac_requested_by_verifier": False,
        "consent": {
            "version": CONSENT_VERSION,
            "probe_count": len(selected),
            "explicit_consent_required": True,
            "selected_only": True,
        },
        "safety": {
            "automatic_elevation": False,
            "settings_modified": False,
            "raw_values_persisted": False,
            "official_finding_created": False,
        },
        "portable_bundle_created": False,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
