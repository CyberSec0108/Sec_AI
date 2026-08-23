from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_audit.supply_chain.collector_release import finalize_imp035_release


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    arguments = parser.parse_args()
    acceptance = finalize_imp035_release(
        arguments.project_root,
        arguments.output_directory,
    )
    print(json.dumps(acceptance, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
