"""Redacted IMP-030 privilege and Probe safety acceptance runner."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from security_audit.application.windows_collector_acceptance import (
    build_local_acceptance_plan,
)
from security_audit.collector import (
    CollectorSafetyPolicy,
    SafeWindowsCollectionCoordinator,
    WindowsReadOnlyCollector,
    WindowsSafetySnapshotter,
    split_execution_plan,
)


def run_windows_safety_acceptance(project_root: Path) -> dict[str, Any]:
    """Run standard PC-07 collection between two digest-only snapshots."""

    contracts = project_root / "collectors" / "one_shot" / "contracts"
    scripts = (
        project_root
        / "collectors"
        / "one_shot"
        / "probes"
        / "windows"
        / "powershell"
    )
    policy = CollectorSafetyPolicy.from_file(
        contracts / "imp030_safety_policy.json"
    )
    plan = build_local_acceptance_plan(project_root)
    plans = split_execution_plan(plan, policy)
    coordinator = SafeWindowsCollectionCoordinator(
        policy,
        WindowsReadOnlyCollector(scripts / "pc07_storage_context.ps1"),
        WindowsSafetySnapshotter(
            scripts / "imp030_safety_snapshot.ps1",
            policy,
        ),
    )
    verified = coordinator.collect_standard(plan)
    collection = verified.collection
    probe_summaries = []
    for result in collection.results:
        payload = cast(list[object], result.payload)
        probe_summaries.append(
            {
                "probe_id": result.probe_id,
                "required_privilege": "STANDARD_USER",
                "collection_status": result.collection_status,
                "record_count": len(payload),
            }
        )
    notice = plans.elevation_notice
    checks = [
        {
            "id": "IMP030-C01",
            "title": "PC-07 Probe 일반 사용자 process 분리",
            "passed": (
                plans.standard is not None
                and len(plans.standard.probes) == 3
                and plans.elevated is None
            ),
        },
        {
            "id": "IMP030-C02",
            "title": "자동 UAC 상승 없음",
            "passed": verified.auto_elevation is False,
        },
        {
            "id": "IMP030-C03",
            "title": "관리자 Probe 사전 안내 계약",
            "passed": (
                notice.auto_start is False
                and notice.explicit_user_consent_required is True
            ),
        },
        {
            "id": "IMP030-C04",
            "title": "실행 중 timeout 상한 적용",
            "passed": policy.process_limits.max_timeout_seconds == 30,
        },
        {
            "id": "IMP030-C05",
            "title": "실행 중 stdout·stderr byte 상한 적용",
            "passed": policy.process_limits.max_output_bytes == 65536,
        },
        {
            "id": "IMP030-C06",
            "title": "timeout·초과 시 process tree 종료",
            "passed": policy.process_limits.terminate_process_tree is True,
        },
        {
            "id": "IMP030-C07",
            "title": "실행 전후 설정 snapshot 일치",
            "passed": (
                verified.settings_before_after_equal
                and verified.settings_diff_count == 0
            ),
        },
        {
            "id": "IMP030-C08",
            "title": "설정 변경과 공식 Finding 없음",
            "passed": (
                collection.settings_modified is False
                and not hasattr(collection, "finding")
                and not hasattr(collection, "finding_status")
            ),
        },
    ]
    return {
        "imp": "IMP-030",
        "acceptance_status": "PASS" if all(item["passed"] for item in checks) else "FAIL",
        "scope": "Privilege separation and Probe safety",
        "current_context": collection.context.redacted(),
        "privilege_plan": {
            "standard_probe_count": len(collection.results),
            "elevated_probe_count": verified.elevated_probe_count,
            "elevation_required_now": notice.required,
            "auto_elevation": verified.auto_elevation,
            "explicit_user_consent_required": notice.explicit_user_consent_required,
            "elevated_process_started": False,
            "message": notice.message,
        },
        "limits": {
            "timeout_seconds": policy.process_limits.max_timeout_seconds,
            "max_output_bytes": policy.process_limits.max_output_bytes,
            "terminate_process_tree": policy.process_limits.terminate_process_tree,
        },
        "settings_safety": {
            "snapshot_surfaces": list(policy.settings_snapshot.surfaces),
            "before_after_equal": verified.settings_before_after_equal,
            "settings_diff_count": verified.settings_diff_count,
            "snapshot_hashes_disclosed": False,
        },
        "probes": probe_summaries,
        "checks": checks,
        "actual_host_data_persisted": False,
        "official_finding_created": False,
        "next_imp": "IMP-031",
    }
