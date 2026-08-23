"""지원 Linux 서버에서 KISA U-01~U-67 읽기 전용 점검을 실행합니다."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from security_audit.platforms import (
    SshReadOnlyTarget,
    collect_plan_over_ssh,
    detect_linux_distribution,
    evaluate_kisa_unix,
    linux_adapter_for,
)
from security_audit.platforms.readonly_plan import ReadOnlyCommand, ReadOnlyCommandPlan


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ubuntu 24.04 또는 Rocky 9 KISA UNIX 67개 항목을 점검합니다."
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--port", type=int, default=22)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    target = SshReadOnlyTarget(
        host=args.host,
        username=args.username,
        private_key=args.private_key,
        known_hosts=args.known_hosts,
        port=args.port,
    )
    detection = ReadOnlyCommandPlan(
        platform="LINUX",
        commands=(
            ReadOnlyCommand(
                "linux.os-release",
                ("/usr/bin/cat", "/etc/os-release"),
                "STANDARD_USER",
                10,
                8_192,
            ),
        ),
    )
    preflight = collect_plan_over_ssh(detection, target)
    os_release = preflight.outputs.get("linux.os-release")
    if os_release is None:
        print(
            json.dumps(
                {"status": "ERROR", "message": "배포판을 확인하지 못했습니다."},
                ensure_ascii=False,
            )
        )
        return 2
    distribution = detect_linux_distribution(os_release)
    adapter = linux_adapter_for(distribution)
    batch = collect_plan_over_ssh(adapter.plan, target)
    results = evaluate_kisa_unix(
        batch.outputs,
        captured_at=datetime.now(UTC),
        distribution=distribution,
    )
    counts = Counter(item.status for item in results)
    print(
        json.dumps(
            {
                "status": "COMPLETED",
                "distribution": distribution.value,
                "adapter": adapter.display_name,
                "controls": len(results),
                "summary": {
                    "PASS": counts["PASS"],
                    "FAIL": counts["FAIL"],
                    "ERROR": counts["ERROR"],
                    "REVIEW": counts["REVIEW"],
                    "N/A": counts["N/A"],
                },
                "collection_failures": batch.failures,
                "results": [
                    {
                        "control_id": item.control_id,
                        "title": item.title,
                        "status": item.status,
                        "result_code": item.result_code,
                        "expected_summary": item.expected_summary,
                        "observed_summary": item.observed_summary,
                        "action_guidance": item.action_guidance,
                        "evidence": [trace.to_json() for trace in item.evidence],
                    }
                    for item in results
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
