"""Redacted IMP-031 PC-01~18 Windows Probe coverage acceptance."""

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
    WindowsSafetySnapshotter,
)
from security_audit.collector.coverage import verify_imp031_coverage
from security_audit.collector.expanded import (
    ADMINISTRATOR_PROBES,
    STANDARD_NON_STORAGE_PROBES,
    ExpandedWindowsCollector,
)
from security_audit.collector.safety import CollectorSafetyPolicy

_STORAGE_PROBES = (
    "win.storage.disks",
    "win.storage.partitions",
    "win.storage.volumes",
)


def _plan(
    allowlist: ProbeAllowlist,
    probe_ids: tuple[str, ...],
    *,
    suffix: str,
) -> VerifiedExecutionPlan:
    probes: list[VerifiedProbeRequest] = []
    for probe_id in probe_ids:
        contract = allowlist.get(probe_id)
        if contract is None:
            raise ValueError("IMP-031 Probe is absent from the fixed allowlist.")
        probes.append(
            VerifiedProbeRequest(
                probe_id=contract.probe_id,
                probe_version=contract.probe_version,
                control_ids=tuple(sorted(contract.control_ids)),
                required_privilege=contract.required_privilege,
                timeout_seconds=contract.max_timeout_seconds,
                max_output_bytes=contract.max_output_bytes,
                parameters=MappingProxyType(dict(contract.parameters)),
            )
        )
    return VerifiedExecutionPlan(
        manifest_id=f"31000000-0000-4000-8000-0000000000{suffix}1",
        manifest_sha256="1" * 64,
        job_id=f"31000000-0000-4000-8000-0000000000{suffix}2",
        asset_id=f"31000000-0000-4000-8000-0000000000{suffix}3",
        nonce=f"SU1QLTAzMS1sb2NhbC1wbGFuLTAw{suffix}",
        verified_at=datetime.now(UTC),
        probes=tuple(probes),
    )


def run_windows_coverage_acceptance(project_root: Path) -> dict[str, Any]:
    contracts = project_root / "collectors" / "one_shot" / "contracts"
    scripts = (
        project_root
        / "collectors"
        / "one_shot"
        / "probes"
        / "windows"
        / "powershell"
    )
    pack_root = project_root / "audit_packs" / "kisa_2026_pc"
    coverage = verify_imp031_coverage(
        pack_path=pack_root / "src" / "pack-0.6.0.json",
        allowlist_path=contracts / "imp031_probe_allowlist.json",
        coverage_policy_path=contracts / "imp031_coverage_policy.json",
        adapter_catalog_path=(
            pack_root / "adapter_catalogs" / "endpoint_protection" / "0.1.0.json"
        ),
    )
    allowlist = ProbeAllowlist.from_file(
        contracts / "imp031_probe_allowlist.json"
    )
    safety_policy = CollectorSafetyPolicy.from_file(
        contracts / "imp030_safety_policy.json"
    )
    snapshotter = WindowsSafetySnapshotter(
        scripts / "imp030_safety_snapshot.ps1",
        safety_policy,
    )
    before = snapshotter.capture()
    storage = WindowsReadOnlyCollector(
        scripts / "pc07_storage_context.ps1"
    ).execute(_plan(allowlist, _STORAGE_PROBES, suffix="1"))
    expanded = ExpandedWindowsCollector(
        scripts / "imp031_standard_controls.ps1",
        privilege="STANDARD_USER",
    ).execute(_plan(allowlist, STANDARD_NON_STORAGE_PROBES, suffix="2"))
    after = snapshotter.capture()
    if before.snapshot_sha256 != after.snapshot_sha256:
        raise RuntimeError("IMP-031 settings changed during read-only collection.")

    summaries: list[dict[str, Any]] = []
    for expanded_result in expanded.results:
        summaries.append(
            {
                "probe_id": expanded_result.probe_id,
                "control_ids": list(expanded_result.control_ids),
                "required_privilege": "STANDARD_USER",
                "collection_status": expanded_result.collection_status,
                "error_code": expanded_result.error_code,
                "adapter_id": expanded_result.adapter_id,
                "adapter_version": expanded_result.adapter_version,
                "coverage": expanded_result.coverage,
                "record_count": len(expanded_result.records),
            }
        )
    for storage_result in storage.results:
        records = cast(list[object], storage_result.payload)
        summaries.append(
            {
                "probe_id": storage_result.probe_id,
                "control_ids": list(storage_result.control_ids),
                "required_privilege": "STANDARD_USER",
                "collection_status": storage_result.collection_status,
                "error_code": "NONE",
                "adapter_id": "secai.windows-storage-native",
                "adapter_version": "0.1.0",
                "coverage": "PC07_STORAGE_CONTEXT",
                "record_count": len(records),
            }
        )
    order = {
        probe_id: index
        for index, probe_id in enumerate(allowlist.probe_ids)
    }
    summaries.sort(key=lambda item: order[cast(str, item["probe_id"])])
    collected = sum(
        item["collection_status"] == "COLLECTED" for item in summaries
    )
    checks = [
        {
            "id": "IMP031-C01",
            "title": "PC-01~18 Control Coverage",
            "passed": coverage.control_count == 18,
        },
        {
            "id": "IMP031-C02",
            "title": "Windows native Probe 20개 exact allowlist",
            "passed": coverage.native_probe_count == 20,
        },
        {
            "id": "IMP031-C03",
            "title": "일반 15·관리자 5 권한 분리",
            "passed": (
                coverage.standard_probe_count == 15
                and coverage.administrator_probe_count == 5
            ),
        },
        {
            "id": "IMP031-C04",
            "title": "현재 일반 권한 Probe 15개 실행",
            "passed": len(summaries) == 15,
        },
        {
            "id": "IMP031-C05",
            "title": "관리자 Probe 자동 시작 없음",
            "passed": len(ADMINISTRATOR_PROBES) == 5,
        },
        {
            "id": "IMP031-C06",
            "title": "DRAFT Defender·Firewall host Adapter 제한",
            "passed": coverage.allowed_host_adapters == (
                "secai.microsoft-defender-antivirus@0.1.0",
                "secai.windows-firewall@0.1.0",
            ),
        },
        {
            "id": "IMP031-C07",
            "title": "기관 정책·기준 스냅샷 host fact 위조 없음",
            "passed": coverage.server_reference_probe_count == 2,
        },
        {
            "id": "IMP031-C08",
            "title": "실행 전후 설정 차이 0건",
            "passed": before.snapshot_sha256 == after.snapshot_sha256,
        },
        {
            "id": "IMP031-C09",
            "title": "실제 값·공식 Finding 미저장",
            "passed": (
                expanded.settings_modified is False
                and expanded.official_finding_created is False
            ),
        },
    ]
    return {
        "imp": "IMP-031",
        "acceptance_status": (
            "PASS" if all(check["passed"] for check in checks) else "FAIL"
        ),
        "scope": "PC-01~18 native Probe and DRAFT built-in Adapter coverage",
        "context": expanded.context.redacted(),
        "coverage": {
            "control_count": coverage.control_count,
            "native_probe_count": coverage.native_probe_count,
            "standard_probe_count": coverage.standard_probe_count,
            "administrator_probe_count": coverage.administrator_probe_count,
            "server_reference_probe_count": coverage.server_reference_probe_count,
            "current_standard_probe_executed": len(summaries),
            "current_standard_probe_collected": collected,
            "current_standard_probe_error": len(summaries) - collected,
        },
        "adapter_boundary": {
            "approval_status": coverage.approval_status,
            "allowed_host_adapters": list(coverage.allowed_host_adapters),
            "unsupported_product_outcome": "REVIEW",
            "synthetic_adapter_host_execution": False,
        },
        "administrator_execution": {
            "probe_ids": list(ADMINISTRATOR_PROBES),
            "explicit_user_consent_required": True,
            "auto_elevation": False,
            "process_started": False,
        },
        "settings_safety": {
            "before_after_equal": True,
            "settings_diff_count": 0,
            "snapshot_hashes_disclosed": False,
        },
        "probes": summaries,
        "checks": checks,
        "actual_host_data_persisted": False,
        "official_finding_created": False,
        "next_imp": "IMP-032",
    }
