from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from security_audit.application.product_launcher_acceptance import (
    run_product_launcher_acceptance,
)


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    report = run_product_launcher_acceptance(project_root)
    standard_scan = cast(dict[str, Any], report["standard_scan"])
    preview_boundary = cast(dict[str, Any], report["preview_boundary"])
    if (
        report["acceptance_status"] != "PASS"
        or standard_scan["total_probes"] != 15
        or standard_scan["settings_modified"] is not False
        or standard_scan["official_finding_created"] is not False
        or any(
            not (
                value is False
                or (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value == 0
                )
            )
            for value in preview_boundary.values()
        )
        or report["hidden_feature_exposed"] is not False
        or report["administrator_direct_url_status"] != 423
    ):
        raise RuntimeError("IMP-040 product or Launcher boundary failed.")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
