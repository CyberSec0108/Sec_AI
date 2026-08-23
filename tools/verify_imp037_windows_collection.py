from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from security_audit.application.windows_host_collection_acceptance import (
    build_host_collection_receipt,
    run_standard_host_collection,
)


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    if len(sys.argv) != 2:
        raise RuntimeError("The administrator evidence path is required.")
    administrator_path = Path(sys.argv[1]).resolve()
    runtime_root = (project_root / "runtime").resolve()
    if runtime_root not in administrator_path.parents:
        raise RuntimeError("Administrator evidence must be inside project runtime.")

    administrator = cast(
        Mapping[str, object],
        json.loads(administrator_path.read_text(encoding="utf-8")),
    )
    standard = run_standard_host_collection(project_root)
    standard_results = standard.get("results")
    administrator_results = administrator.get("results")
    if (
        not isinstance(standard_results, Sequence)
        or isinstance(standard_results, (str, bytes, bytearray))
        or not isinstance(administrator_results, Sequence)
        or isinstance(administrator_results, (str, bytes, bytearray))
    ):
        raise RuntimeError("IMP-037 evidence results are invalid.")

    receipt = build_host_collection_receipt(
        observed_at_utc=datetime.now(UTC).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        standard_results=cast(Sequence[Mapping[str, object]], standard_results),
        administrator_results=cast(
            Sequence[Mapping[str, object]], administrator_results
        ),
        administrator_consent=administrator.get("explicit_consent") is True,
        automatic_uac=False,
        standard_settings_diff_count=cast(
            int, standard.get("settings_diff_count")
        ),
        administrator_settings_diff_count=cast(
            int, administrator.get("settings_diff_count")
        ),
    )
    destination = (
        project_root / "apps" / "web" / "data" / "imp037_collection.json"
    )
    destination.write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(receipt, ensure_ascii=False, indent=2))
    return 0 if receipt["acceptance_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
