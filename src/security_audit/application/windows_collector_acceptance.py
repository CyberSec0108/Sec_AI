"""Safe IMP-029 host acceptance runner and redacted report."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from security_audit.collector import (
    ProbeAllowlist,
    VerifiedExecutionPlan,
    VerifiedProbeRequest,
    WindowsReadOnlyCollector,
)


def build_local_acceptance_plan(project_root: Path) -> VerifiedExecutionPlan:
    """Build a local-only plan from the exact IMP-029 release catalog.

    Online authorization and signature submission remain IMP-032 scope. This
    plan cannot be uploaded and is used only to prove the host Probe itself.
    """

    allowlist = ProbeAllowlist.from_file(
        project_root
        / "collectors"
        / "one_shot"
        / "contracts"
        / "imp029_probe_allowlist.json"
    )
    if allowlist.execution_mode != "WINDOWS_READ_ONLY" or not allowlist.real_os_access:
        raise ValueError("IMP-029 allowlist is not bound to Windows read-only access.")
    probes = tuple(
        VerifiedProbeRequest(
            probe_id=contract.probe_id,
            probe_version=contract.probe_version,
            control_ids=tuple(sorted(contract.control_ids)),
            required_privilege=contract.required_privilege,
            timeout_seconds=contract.max_timeout_seconds,
            max_output_bytes=contract.max_output_bytes,
            parameters=MappingProxyType(dict(contract.parameters)),
        )
        for probe_id in allowlist.probe_ids
        if (contract := allowlist.get(probe_id)) is not None
    )
    return VerifiedExecutionPlan(
        manifest_id="29000000-0000-4000-8000-000000000001",
        manifest_sha256="0" * 64,
        job_id="29000000-0000-4000-8000-000000000002",
        asset_id="29000000-0000-4000-8000-000000000003",
        nonce="SU1QLTAyOS1sb2NhbC1hY2NlcHRhbmNl",
        verified_at=datetime.now(UTC),
        probes=probes,
    )


def run_windows_collector_acceptance(project_root: Path) -> dict[str, Any]:
    """Run the current Windows host Probe and return only a redacted summary."""

    script_path = (
        project_root
        / "collectors"
        / "one_shot"
        / "probes"
        / "windows"
        / "powershell"
        / "pc07_storage_context.ps1"
    )
    run = WindowsReadOnlyCollector(script_path).execute(
        build_local_acceptance_plan(project_root)
    )
    probe_summaries = []
    for result in run.results:
        payload = cast(list[object], result.payload)
        probe_summaries.append(
            {
                "probe_id": result.probe_id,
                "probe_version": result.probe_version,
                "collection_status": result.collection_status,
                "synthetic": result.synthetic,
                "record_count": len(payload),
            }
        )
    checks = [
        {
            "id": "IMP029-C01",
            "title": "Windows 10/11 x64 context 확인",
            "passed": (
                run.context.os_family == "WINDOWS"
                and run.context.os_version in {"10", "11"}
                and run.context.architecture == "x86_64"
            ),
        },
        {
            "id": "IMP029-C02",
            "title": "실행 SID 형식 확인 후 값 비공개",
            "passed": run.context.redacted()["sid_format_valid"] is True,
        },
        {
            "id": "IMP029-C03",
            "title": "PC-07 세 Probe 실제 읽기",
            "passed": (
                len(run.results) == 3
                and all(result.collection_status == "COLLECTED" for result in run.results)
                and all(result.synthetic is False for result in run.results)
            ),
        },
        {
            "id": "IMP029-C04",
            "title": "권한 상승 요청 없음",
            "passed": run.elevation_requested is False,
        },
        {
            "id": "IMP029-C05",
            "title": "설정 변경 없음",
            "passed": run.settings_modified is False,
        },
        {
            "id": "IMP029-C06",
            "title": "공식 Finding 생성 없음",
            "passed": not hasattr(run, "finding") and not hasattr(run, "finding_status"),
        },
    ]
    return {
        "imp": "IMP-029",
        "acceptance_status": "PASS" if all(check["passed"] for check in checks) else "FAIL",
        "scope": "Current Windows context and PC-07 read-only Probe",
        "execution_mode": run.execution_mode,
        "real_os_access": run.real_os_access,
        "context": run.context.redacted(),
        "probes": probe_summaries,
        "checks": checks,
        "actual_host_data_persisted": False,
        "official_finding_created": False,
        "next_imp": "IMP-030",
    }
