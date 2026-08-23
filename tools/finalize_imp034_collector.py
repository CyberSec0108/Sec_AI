from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_audit.supply_chain import finalize_imp034_build


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_directory", type=Path)
    arguments = parser.parse_args()
    project_root = Path(__file__).resolve().parents[1]
    report = finalize_imp034_build(project_root, arguments.output_directory)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
