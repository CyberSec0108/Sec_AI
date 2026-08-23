from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType

import pytest

from security_audit.collector import (
    BoundedCommandResult,
    BoundedExecutionCode,
    BoundedExecutionError,
    BoundedProcessExecutor,
    CollectorSafetyCode,
    CollectorSafetyError,
    CollectorSafetyPolicy,
    CommandResult,
    SafeWindowsCollectionCoordinator,
    VerifiedExecutionPlan,
    VerifiedProbeRequest,
    WindowsCollectionCode,
    WindowsCollectionError,
    WindowsReadOnlyCollector,
    WindowsSafetySnapshotter,
    authorize_elevated_plan,
    split_execution_plan,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = (
    PROJECT_ROOT
    / "collectors"
    / "one_shot"
    / "contracts"
    / "imp030_safety_policy.json"
)
PROBE_SCRIPT = (
    PROJECT_ROOT
    / "collectors"
    / "one_shot"
    / "probes"
    / "windows"
    / "powershell"
    / "pc07_storage_context.ps1"
)
SNAPSHOT_SCRIPT = (
    PROJECT_ROOT
    / "collectors"
    / "one_shot"
    / "probes"
    / "windows"
    / "powershell"
    / "imp030_safety_snapshot.ps1"
)
WINDOWS_FIXTURE = (
    PROJECT_ROOT
    / "collectors"
    / "one_shot"
    / "fixtures"
    / "imp029"
    / "windows_read_only_sample.json"
)


def _probe(
    probe_id: str,
    privilege: str,
    *,
    parameters: dict[str, int | float | str | None] | None = None,
) -> VerifiedProbeRequest:
    return VerifiedProbeRequest(
        probe_id=probe_id,
        probe_version="0.1.0",
        control_ids=("PC-07",),
        required_privilege=privilege,
        timeout_seconds=30,
        max_output_bytes=65536,
        parameters=MappingProxyType(parameters or {}),
    )


def _plan(*, include_elevated: bool = False) -> VerifiedExecutionPlan:
    probes = [
        _probe("win.storage.disks", "STANDARD_USER"),
        _probe("win.storage.partitions", "STANDARD_USER"),
        _probe(
            "win.storage.volumes",
            "STANDARD_USER",
            parameters={"include_fixed": True},
        ),
    ]
    if include_elevated:
        probes.append(_probe("win.security.future-admin", "ADMINISTRATOR"))
    return VerifiedExecutionPlan(
        manifest_id="30000000-0000-4000-8000-000000000001",
        manifest_sha256="a" * 64,
        job_id="30000000-0000-4000-8000-000000000002",
        asset_id="30000000-0000-4000-8000-000000000003",
        nonce="SU1QLTAzMC1ub25jZS0wMDAx",
        verified_at=datetime(2026, 7, 23, 8, 0, tzinfo=UTC),
        probes=tuple(probes),
    )


def _powershell(tmp_path: Path) -> Path:
    path = tmp_path / "powershell.exe"
    path.write_bytes(b"fixture executable placeholder")
    return path


def _snapshot_payload(digest: str) -> bytes:
    return json.dumps(
        {
            "schema_version": "1.0.0",
            "snapshot_sha256": digest,
            "collected_at_utc": "2026-07-23T08:00:00.000Z",
        },
        separators=(",", ":"),
    ).encode()


def test_bounded_process_returns_small_output() -> None:
    executor = BoundedProcessExecutor(platform_name="posix")

    result = executor(
        (sys.executable, "-c", "print('bounded-ok', end='')"),
        5,
        b"",
        1024,
    )

    assert result.returncode == 0
    assert result.stdout == b"bounded-ok"
    assert result.stderr == b""


def test_bounded_process_stops_live_output_over_limit() -> None:
    executor = BoundedProcessExecutor(platform_name="posix")

    with pytest.raises(BoundedExecutionError) as captured:
        executor(
            (sys.executable, "-c", "import sys; sys.stdout.write('x' * 200000)"),
            5,
            b"",
            1024,
        )

    assert captured.value.code is BoundedExecutionCode.OUTPUT_TOO_LARGE


def test_timeout_terminates_child_process_tree(tmp_path: Path) -> None:
    marker = tmp_path / "orphan-marker.txt"
    child = (
        "import pathlib,time;"
        "time.sleep(2);"
        f"pathlib.Path({str(marker)!r}).write_text('orphan', encoding='utf-8')"
    )
    parent = (
        "import subprocess,sys,time;"
        f"subprocess.Popen([sys.executable, '-c', {child!r}]);"
        "time.sleep(10)"
    )
    executor = BoundedProcessExecutor(platform_name="posix")

    with pytest.raises(BoundedExecutionError) as captured:
        executor((sys.executable, "-c", parent), 1, b"", 4096)
    time.sleep(2.2)

    assert captured.value.code is BoundedExecutionCode.TIMEOUT
    assert not marker.exists()


def test_policy_rejects_auto_elevation_downgrade(tmp_path: Path) -> None:
    raw = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    raw["auto_elevation"] = True
    path = tmp_path / "unsafe-policy.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(CollectorSafetyError) as captured:
        CollectorSafetyPolicy.from_file(path)

    assert captured.value.code is CollectorSafetyCode.POLICY_INVALID


def test_privilege_split_never_authorizes_elevation_without_consent() -> None:
    policy = CollectorSafetyPolicy.from_file(POLICY_PATH)
    plans = split_execution_plan(_plan(include_elevated=True), policy)

    assert plans.standard is not None
    assert len(plans.standard.probes) == 3
    assert plans.elevated is not None
    assert tuple(item.probe_id for item in plans.elevated.probes) == (
        "win.security.future-admin",
    )
    assert plans.elevation_notice.required is True
    assert plans.elevation_notice.auto_start is False
    with pytest.raises(CollectorSafetyError) as captured:
        authorize_elevated_plan(plans, explicit_user_consent=False)
    assert captured.value.code is CollectorSafetyCode.EXPLICIT_CONSENT_REQUIRED
    assert authorize_elevated_plan(plans, explicit_user_consent=True) is plans.elevated


def test_pc07_plan_is_standard_only_and_needs_no_elevation() -> None:
    policy = CollectorSafetyPolicy.from_file(POLICY_PATH)

    plans = split_execution_plan(_plan(), policy)

    assert plans.standard is not None
    assert plans.elevated is None
    assert plans.elevation_notice.required is False
    assert plans.elevation_notice.probe_ids == ()
    assert plans.elevation_notice.auto_start is False


def test_standard_collection_proves_settings_diff_zero(tmp_path: Path) -> None:
    policy = CollectorSafetyPolicy.from_file(POLICY_PATH)
    snapshot_calls = 0

    def snapshot_executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> BoundedCommandResult:
        nonlocal snapshot_calls
        snapshot_calls += 1
        assert timeout_seconds == 15
        assert max_output_bytes == 8192
        return BoundedCommandResult(0, _snapshot_payload("b" * 64), b"")

    def collector_executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> CommandResult:
        return CommandResult(0, WINDOWS_FIXTURE.read_bytes(), b"")

    powershell = _powershell(tmp_path)
    collector = WindowsReadOnlyCollector(
        PROBE_SCRIPT,
        executor=collector_executor,
        platform_name="nt",
        powershell_path=powershell,
    )
    snapshotter = WindowsSafetySnapshotter(
        SNAPSHOT_SCRIPT,
        policy,
        executor=snapshot_executor,
        platform_name="nt",
        powershell_path=powershell,
    )
    coordinator = SafeWindowsCollectionCoordinator(policy, collector, snapshotter)

    result = coordinator.collect_standard(_plan())

    assert snapshot_calls == 2
    assert result.privilege.value == "STANDARD_USER"
    assert result.settings_before_after_equal is True
    assert result.settings_diff_count == 0
    assert result.auto_elevation is False
    assert result.elevated_probe_count == 0
    assert result.collection.settings_modified is False


def test_settings_change_is_fail_closed_not_a_finding(tmp_path: Path) -> None:
    policy = CollectorSafetyPolicy.from_file(POLICY_PATH)
    digests = iter(("c" * 64, "d" * 64))

    def snapshot_executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> BoundedCommandResult:
        return BoundedCommandResult(0, _snapshot_payload(next(digests)), b"")

    def collector_executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> CommandResult:
        return CommandResult(0, WINDOWS_FIXTURE.read_bytes(), b"")

    powershell = _powershell(tmp_path)
    coordinator = SafeWindowsCollectionCoordinator(
        policy,
        WindowsReadOnlyCollector(
            PROBE_SCRIPT,
            executor=collector_executor,
            platform_name="nt",
            powershell_path=powershell,
        ),
        WindowsSafetySnapshotter(
            SNAPSHOT_SCRIPT,
            policy,
            executor=snapshot_executor,
            platform_name="nt",
            powershell_path=powershell,
        ),
    )

    with pytest.raises(CollectorSafetyError) as captured:
        coordinator.collect_standard(_plan())

    assert captured.value.code is CollectorSafetyCode.SETTINGS_CHANGED
    assert not hasattr(captured.value, "finding")


def test_standard_pc07_probe_rejects_an_elevated_token(tmp_path: Path) -> None:
    raw = json.loads(WINDOWS_FIXTURE.read_text(encoding="utf-8"))
    cast_context = raw["context"]
    cast_context["is_administrator"] = True

    def executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> CommandResult:
        return CommandResult(0, json.dumps(raw).encode(), b"")

    collector = WindowsReadOnlyCollector(
        PROBE_SCRIPT,
        executor=executor,
        platform_name="nt",
        powershell_path=_powershell(tmp_path),
    )

    with pytest.raises(WindowsCollectionError) as captured:
        collector.execute(_plan())

    assert captured.value.code is WindowsCollectionCode.UNEXPECTED_ELEVATION


def test_scripts_and_policy_contain_no_auto_elevation_or_setting_writes() -> None:
    combined = (
        PROBE_SCRIPT.read_text(encoding="utf-8")
        + SNAPSHOT_SCRIPT.read_text(encoding="utf-8")
        + POLICY_PATH.read_text(encoding="utf-8")
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

    assert all(item not in combined for item in prohibited)
    assert '"auto_elevation": false' in combined
    assert '"terminate_process_tree": true' in combined
