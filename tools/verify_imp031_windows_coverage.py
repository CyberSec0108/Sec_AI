from __future__ import annotations

import json
from pathlib import Path

from security_audit.application.windows_coverage_acceptance import (
    run_windows_coverage_acceptance,
)


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    report = run_windows_coverage_acceptance(project_root)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["acceptance_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
