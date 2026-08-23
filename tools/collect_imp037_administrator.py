from __future__ import annotations

import json
import sys
from pathlib import Path

from security_audit.application.windows_host_collection_acceptance import (
    run_administrator_host_collection,
)


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    if len(sys.argv) != 2:
        raise RuntimeError("The administrator evidence path is required.")
    destination = Path(sys.argv[1]).resolve()
    runtime_root = (project_root / "runtime").resolve()
    if runtime_root not in destination.parents:
        raise RuntimeError("Administrator evidence must remain inside project runtime.")

    report = run_administrator_host_collection(
        project_root,
        explicit_consent=True,
    )
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(destination)
    print(
        json.dumps(
            {
                "probe_count": len(report["results"]),  # type: ignore[arg-type]
                "settings_diff_count": report["settings_diff_count"],
                "raw_values_persisted": False,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
