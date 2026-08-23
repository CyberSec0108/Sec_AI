from __future__ import annotations

import json
from base64 import b64decode
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType

import pytest

from security_audit.collector import (
    CommandResult,
    VerifiedExecutionPlan,
    VerifiedProbeRequest,
    WindowsCollectionCode,
    WindowsCollectionError,
    WindowsReadOnlyCollector,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = (
    PROJECT_ROOT
    / "collectors"
    / "one_shot"
    / "probes"
    / "windows"
    / "powershell"
    / "pc07_storage_context.ps1"
)
FIXTURE_PATH = (
    PROJECT_ROOT
    / "collectors"
    / "one_shot"
    / "fixtures"
    / "imp029"
    / "windows_read_only_sample.json"
)


def _plan() -> VerifiedExecutionPlan:
    requests = (
        VerifiedProbeRequest(
            probe_id="win.storage.disks",
            probe_version="0.1.0",
            control_ids=("PC-07",),
            required_privilege="STANDARD_USER",
            timeout_seconds=30,
            max_output_bytes=65536,
            parameters=MappingProxyType({}),
        ),
        VerifiedProbeRequest(
            probe_id="win.storage.partitions",
            probe_version="0.1.0",
            control_ids=("PC-07",),
            required_privilege="STANDARD_USER",
            timeout_seconds=30,
            max_output_bytes=65536,
            parameters=MappingProxyType({}),
        ),
        VerifiedProbeRequest(
            probe_id="win.storage.volumes",
            probe_version="0.1.0",
            control_ids=("PC-07",),
            required_privilege="STANDARD_USER",
            timeout_seconds=30,
            max_output_bytes=65536,
            parameters=MappingProxyType({"include_fixed": True}),
        ),
    )
    return VerifiedExecutionPlan(
        manifest_id="29000000-0000-4000-8000-000000000001",
        manifest_sha256="a" * 64,
        job_id="29000000-0000-4000-8000-000000000002",
        asset_id="29000000-0000-4000-8000-000000000003",
        nonce="SU1QLTAyOS1ub25jZS0wMDAx",
        verified_at=datetime(2026, 7, 23, 7, 0, tzinfo=UTC),
        probes=requests,
    )


def _powershell(tmp_path: Path) -> Path:
    path = tmp_path / "powershell.exe"
    path.write_bytes(b"fixture executable placeholder")
    return path


def _expect_code(
    collector: WindowsReadOnlyCollector,
    expected: WindowsCollectionCode,
    *,
    plan: VerifiedExecutionPlan | None = None,
) -> None:
    with pytest.raises(WindowsCollectionError) as captured:
        collector.execute(plan or _plan())
    assert captured.value.code is expected


def test_fixed_read_only_probe_returns_real_non_finding_results(
    tmp_path: Path,
) -> None:
    commands: list[tuple[str, ...]] = []

    def executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> CommandResult:
        commands.append(command)
        assert timeout_seconds == 30
        assert max_output_bytes == 65536
        assert stdin_bytes == b""
        return CommandResult(0, FIXTURE_PATH.read_bytes(), b"")

    collector = WindowsReadOnlyCollector(
        SCRIPT_PATH,
        executor=executor,
        platform_name="nt",
        powershell_path=_powershell(tmp_path),
    )

    run = collector.execute(_plan())

    assert run.execution_mode == "WINDOWS_READ_ONLY"
    assert run.real_os_access is True
    assert run.elevation_requested is False
    assert run.settings_modified is False
    assert run.context.os_version == "11"
    assert run.context.platform_fingerprint().product_family == "WINDOWS_CLIENT_11"
    assert run.context.adapter_selection().adapter_id == "secai.windows.pc.readonly.v1"
    assert run.context.redacted()["sid_format_valid"] is True
    assert run.context.process_sid not in json.dumps(run.context.redacted())
    assert [result.probe_id for result in run.results] == [
        "win.storage.disks",
        "win.storage.partitions",
        "win.storage.volumes",
    ]
    assert all(result.synthetic is False for result in run.results)
    assert all(result.collection_status == "COLLECTED" for result in run.results)
    assert not hasattr(run, "finding")
    assert not hasattr(run, "finding_status")
    assert len(commands) == 1
    assert commands[0][1:5] == (
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
    )
    assert b64decode(commands[0][5]).decode("utf-16le") == SCRIPT_PATH.read_text(
        encoding="utf-8"
    )
    assert "-ExecutionPolicy" not in commands[0]


def test_non_windows_host_is_rejected_before_execution(tmp_path: Path) -> None:
    called = False

    def executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> CommandResult:
        nonlocal called
        called = True
        return CommandResult(0, b"{}", b"")

    collector = WindowsReadOnlyCollector(
        SCRIPT_PATH,
        executor=executor,
        platform_name="posix",
        powershell_path=_powershell(tmp_path),
    )

    _expect_code(collector, WindowsCollectionCode.UNSUPPORTED_OS)
    assert called is False


def test_output_limit_fails_closed_without_finding(tmp_path: Path) -> None:
    def executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> CommandResult:
        return CommandResult(0, b"x" * 65537, b"")

    collector = WindowsReadOnlyCollector(
        SCRIPT_PATH,
        executor=executor,
        platform_name="nt",
        powershell_path=_powershell(tmp_path),
    )

    _expect_code(collector, WindowsCollectionCode.OUTPUT_TOO_LARGE)


def test_invalid_sid_and_target_context_are_rejected(tmp_path: Path) -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    fixture["context"]["process_sid"] = "not-a-sid"

    def executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> CommandResult:
        return CommandResult(0, json.dumps(fixture).encode(), b"")

    collector = WindowsReadOnlyCollector(
        SCRIPT_PATH,
        executor=executor,
        platform_name="nt",
        powershell_path=_powershell(tmp_path),
    )

    _expect_code(collector, WindowsCollectionCode.PROBE_OUTPUT_INVALID)


def test_probe_script_contains_only_read_side_storage_commands() -> None:
    script = SCRIPT_PATH.read_text(encoding="utf-8").casefold()
    required = (
        "get-itemproperty",
        "get-disk",
        "get-partition",
        "get-volume",
        "get-bitlockervolume",
    )
    prohibited = (
        "set-itemproperty",
        "new-item",
        "remove-item",
        "set-disk",
        "set-partition",
        "resize-partition",
        "format-volume",
        "clear-disk",
        "initialize-disk",
        "manage-bde",
        "diskpart",
        "start-process",
    )

    assert all(command in script for command in required)
    assert all(command not in script for command in prohibited)
    assert all("param(" not in line for line in script.splitlines()[0:5])


def test_storage_permission_denial_is_preserved_as_collection_outcome(
    tmp_path: Path,
) -> None:
    def executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> CommandResult:
        return CommandResult(
            1,
            b"",
            b"Get-Disk HRESULT 0x80041003",
        )

    collector = WindowsReadOnlyCollector(
        SCRIPT_PATH,
        executor=executor,
        platform_name="nt",
        powershell_path=_powershell(tmp_path),
    )

    _expect_code(collector, WindowsCollectionCode.PERMISSION_DENIED)


def test_fixture_and_script_omit_excess_host_identifiers() -> None:
    combined = (
        FIXTURE_PATH.read_text(encoding="utf-8")
        + SCRIPT_PATH.read_text(encoding="utf-8")
    ).casefold()

    for forbidden in (
        "hostname",
        "computername",
        "volumelabel",
        "friendlyname",
        "serialnumber",
        "productid",
        "macaddress",
        "userprincipalname",
    ):
        assert forbidden not in combined
