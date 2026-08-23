from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from security_audit.collector import ProbeAllowlist
from security_audit.collector.contracts import (
    VerifiedExecutionPlan,
    VerifiedProbeRequest,
)
from security_audit.collector.coverage import (
    CoverageContractError,
    verify_imp031_coverage,
)
from security_audit.collector.expanded import (
    STANDARD_NON_STORAGE_PROBES,
    ExpandedCollectionCode,
    ExpandedCollectionError,
    ExpandedWindowsCollector,
)
from security_audit.collector.process import BoundedCommandResult

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "collectors" / "one_shot" / "contracts"
SCRIPTS = (
    ROOT
    / "collectors"
    / "one_shot"
    / "probes"
    / "windows"
    / "powershell"
)
PACK_ROOT = ROOT / "audit_packs" / "kisa_2026_pc"
FIXTURE = (
    ROOT
    / "collectors"
    / "one_shot"
    / "fixtures"
    / "imp031"
    / "standard_probe_sample.json"
)


def _coverage(**overrides: Path) -> Any:
    paths = {
        "pack_path": PACK_ROOT / "src" / "pack-0.6.0.json",
        "allowlist_path": CONTRACTS / "imp031_probe_allowlist.json",
        "coverage_policy_path": CONTRACTS / "imp031_coverage_policy.json",
        "adapter_catalog_path": (
            PACK_ROOT / "adapter_catalogs" / "endpoint_protection" / "0.1.0.json"
        ),
    }
    paths.update(overrides)
    return verify_imp031_coverage(**paths)


def _plan() -> VerifiedExecutionPlan:
    allowlist = ProbeAllowlist.from_file(
        CONTRACTS / "imp031_probe_allowlist.json"
    )
    probes = []
    for probe_id in STANDARD_NON_STORAGE_PROBES:
        contract = allowlist.get(probe_id)
        assert contract is not None
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
        manifest_id="31000000-0000-4000-8000-000000000001",
        manifest_sha256="1" * 64,
        job_id="31000000-0000-4000-8000-000000000002",
        asset_id="31000000-0000-4000-8000-000000000003",
        nonce="SU1QLTAzMS10ZXN0LW5vbmNl",
        verified_at=datetime(2026, 7, 23, 8, 0, tzinfo=UTC),
        probes=tuple(probes),
    )


def _powershell(tmp_path: Path) -> Path:
    path = tmp_path / "powershell.exe"
    path.write_bytes(b"synthetic executable")
    return path


def test_imp031_exact_pack_probe_privilege_and_adapter_coverage() -> None:
    summary = _coverage()

    assert summary.control_count == 18
    assert summary.native_probe_count == 20
    assert summary.standard_probe_count == 15
    assert summary.administrator_probe_count == 5
    assert summary.server_reference_probe_count == 2
    assert summary.approval_status == "DRAFT"
    assert summary.allowed_host_adapters == (
        "secai.microsoft-defender-antivirus@0.1.0",
        "secai.windows-firewall@0.1.0",
    )


def test_missing_native_probe_is_rejected(tmp_path: Path) -> None:
    raw = json.loads(
        (CONTRACTS / "imp031_probe_allowlist.json").read_text(encoding="utf-8")
    )
    raw["probes"].pop()
    changed = tmp_path / "allowlist.json"
    changed.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(CoverageContractError):
        _coverage(allowlist_path=changed)


def test_synthetic_only_adapter_cannot_become_host_adapter(tmp_path: Path) -> None:
    raw = json.loads(
        (CONTRACTS / "imp031_coverage_policy.json").read_text(encoding="utf-8")
    )
    raw["adapter_boundary"]["allowed_host_adapters"].append(
        "secai.synthetic-third-party-firewall@0.1.0"
    )
    changed = tmp_path / "coverage.json"
    changed.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(CoverageContractError):
        _coverage(coverage_policy_path=changed)


def test_standard_group_accepts_only_fixed_sanitized_results(tmp_path: Path) -> None:
    def executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> BoundedCommandResult:
        assert command[-2] == "-Command"
        assert "ScriptBlock" in command[-1]
        assert timeout_seconds == 30
        assert max_output_bytes == 65_536
        assert b"Start-Process" not in stdin_bytes
        return BoundedCommandResult(0, FIXTURE.read_bytes(), b"")

    run = ExpandedWindowsCollector(
        SCRIPTS / "imp031_standard_controls.ps1",
        privilege="STANDARD_USER",
        executor=executor,
        platform_name="nt",
        powershell_path=_powershell(tmp_path),
    ).execute(_plan())

    assert run.privilege == "STANDARD_USER"
    assert len(run.results) == 12
    assert all(result.collection_status == "COLLECTED" for result in run.results)
    assert run.settings_modified is False
    assert run.official_finding_created is False


def test_probe_output_cannot_include_secret_content(tmp_path: Path) -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw["results"][0]["records"][0]["password"] = True

    def executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> BoundedCommandResult:
        return BoundedCommandResult(0, json.dumps(raw).encode(), b"")

    collector = ExpandedWindowsCollector(
        SCRIPTS / "imp031_standard_controls.ps1",
        privilege="STANDARD_USER",
        executor=executor,
        platform_name="nt",
        powershell_path=_powershell(tmp_path),
    )
    with pytest.raises(ExpandedCollectionError) as captured:
        collector.execute(_plan())

    assert captured.value.code == ExpandedCollectionCode.PROBE_OUTPUT_INVALID


def test_collection_error_never_becomes_a_finding(tmp_path: Path) -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw["results"][0]["collection_status"] = "ERROR"
    raw["results"][0]["error_code"] = "PERMISSION_DENIED"
    raw["results"][0]["records"] = []

    def executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> BoundedCommandResult:
        return BoundedCommandResult(0, json.dumps(raw).encode(), b"")

    run = ExpandedWindowsCollector(
        SCRIPTS / "imp031_standard_controls.ps1",
        privilege="STANDARD_USER",
        executor=executor,
        platform_name="nt",
        powershell_path=_powershell(tmp_path),
    ).execute(_plan())

    assert run.results[0].collection_status == "ERROR"
    assert run.results[0].error_code == "PERMISSION_DENIED"
    assert run.official_finding_created is False
    assert not hasattr(run, "finding")


def test_scripts_never_auto_elevate_or_modify_security_settings() -> None:
    source = (
        (SCRIPTS / "imp031_standard_controls.ps1").read_text(encoding="ascii")
        + (SCRIPTS / "imp031_administrator_controls.ps1").read_text(
            encoding="ascii"
        )
    ).casefold()
    prohibited = (
        "start-process",
        "-verb runas",
        "set-itemproperty",
        "set-executionpolicy",
        "set-disk",
        "set-partition",
        "format-volume",
        "manage-bde",
        "diskpart",
    )

    assert all(item not in source for item in prohibited)
    assert "standard_process_must_not_be_elevated" in source
    assert "administrator_process_required" in source


def test_windows_scripts_accept_client_10_and_11_but_reject_server() -> None:
    source = (
        (SCRIPTS / "imp031_standard_controls.ps1").read_text(encoding="ascii")
        + (SCRIPTS / "imp031_administrator_controls.ps1").read_text(
            encoding="ascii"
        )
    ).casefold()

    assert "$buildnumber -ge 22000" in source
    assert "$buildnumber -ge 10240" in source
    assert '$installationtype -eq "client"' in source
    assert '} elseif ($buildnumber -ge 10240) {\n    "10"' in source
    assert '} elseif ($buildnumber -ge 22000) {\n    "11"' in source
