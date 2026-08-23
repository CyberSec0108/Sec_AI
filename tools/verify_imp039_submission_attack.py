from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast

from security_audit.application.submission_attack_acceptance import (
    run_submission_attack_acceptance,
)


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    report = run_submission_attack_acceptance(project_root)
    serialized = json.dumps(
        report,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    lowered = serialized.casefold()
    summary = cast(dict[str, Any], report["summary"])
    boundary = cast(dict[str, Any], report["downstream_boundary"])
    forbidden = (
        "secai_job_v1.",
        "begin private key",
        "leaf_certificate_der_base64url",
        "redacted-device-summary",
        "\\appdata\\",
        f"{Path('/').as_posix()}tmp/",
    )
    if (
        report["acceptance_status"] != "PASS"
        or summary["escaped_count"] != 0
        or any(value != 0 for value in boundary.values())
        or any(value in lowered for value in forbidden)
    ):
        raise RuntimeError("IMP-039 attack, downstream, or privacy invariant failed.")

    static_report = (
        project_root / "apps" / "web" / "data" / "imp039_submission_attack.json"
    )
    if len(sys.argv) == 1:
        stored = json.loads(static_report.read_text(encoding="utf-8"))
        if stored != report:
            raise RuntimeError("IMP-039 static UI report differs from the attack run.")
    elif len(sys.argv) == 2 and sys.argv[1] != "-":
        destination = Path(sys.argv[1]).resolve()
        destination.write_text(serialized + "\n", encoding="utf-8", newline="\n")
    elif len(sys.argv) > 2:
        raise RuntimeError("Expected no argument, '-', or one output path.")
    print(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
