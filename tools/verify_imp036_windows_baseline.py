from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast

from security_audit.application.windows_baseline_acceptance import (
    run_windows_baseline_acceptance,
)


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    if len(sys.argv) != 2:
        raise RuntimeError("The de-identified Docker status file is required.")
    docker_status_path = Path(sys.argv[1]).resolve()
    runtime_root = (project_root / "runtime").resolve()
    if runtime_root not in docker_status_path.parents:
        raise RuntimeError("Docker status file must be inside the project runtime.")
    docker_services = cast(
        list[dict[str, Any]],
        json.loads(docker_status_path.read_text(encoding="utf-8")),
    )
    report = run_windows_baseline_acceptance(
        project_root,
        docker_services=docker_services,
    )
    destination = (
        project_root / "apps" / "web" / "data" / "imp036_baseline.json"
    )
    destination.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["acceptance_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
