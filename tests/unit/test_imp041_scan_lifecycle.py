from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_audit.application import windows_host_collection_acceptance
from security_audit.application.windows_host_collection_acceptance import (
    HostCollectionCancelled,
)
from security_audit.collector.expanded import STANDARD_NON_STORAGE_PROBES
from security_audit.collector.launcher import create_launcher_bridge

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ORIGIN = "http://127.0.0.1:18480"
TOKEN = "c" * 43


def _successful_receipt() -> dict[str, object]:
    return {
        "observed_at_utc": "2026-07-23T09:00:00Z",
        "vulnerability_inventory": {
            "os_name": "Windows 11",
            "display_version": "24H2",
            "build_number": "26100",
            "ubr": 8875,
            "architecture": "x86_64",
        },
        "settings_diff_count": 0,
        "results": [
            {
                "probe_id": f"win.test.{index}",
                "control_ids": [f"PC-{index:02d}"],
                "privilege": "STANDARD_USER",
                "collection_status": "COLLECTED",
                "error_code": "NONE",
                "record_count": 1,
            }
            for index in range(1, 16)
        ],
    }


def _request(
    bridge_port: int,
    path: str,
    *,
    method: str = "GET",
) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(  # noqa: S310 - fixed loopback test URL
        f"http://127.0.0.1:{bridge_port}{path}",
        method=method,
        data=b"" if method == "POST" else None,
        headers={
            "Origin": ORIGIN,
            "X-SecAI-Launcher-Token": TOKEN,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(  # noqa: S310 - fixed loopback test URL
            request,
            timeout=3,
        ) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _wait_for(
    bridge_port: int,
    expected: str,
    *,
    timeout: float = 3,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _, body = _request(bridge_port, "/v1/status")
        if body["status"] == expected:
            return body
        time.sleep(0.01)
    raise AssertionError(f"Launcher did not reach {expected}.")


def test_imp041_policy_defines_safe_progress_cancel_and_retry() -> None:
    policy = json.loads(
        (
            PROJECT_ROOT
            / "collectors"
            / "one_shot"
            / "contracts"
            / "imp041_scan_lifecycle_policy.json"
        ).read_text(encoding="utf-8")
    )

    assert policy["progress"]["refresh_safe"] is True
    assert policy["progress"]["current_item_disclosed"] is True
    assert policy["cancellation"]["cooperative"] is True
    assert policy["cancellation"]["settings_modified"] is False
    assert policy["retry"]["allowed_after"] == ["CANCELLED", "FAILED"]
    assert policy["retry"]["same_job_id"] is True
    assert policy["duplicate_prevention"]["maximum_active_runs"] == 1
    assert policy["duplicate_prevention"]["official_finding_created"] is False


def test_cooperative_cancel_still_verifies_settings_before_returning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cancelled = threading.Event()
    snapshot_calls = 0

    class Snapshotter:
        def __init__(self, *_: object) -> None:
            return

        def capture(self) -> SimpleNamespace:
            nonlocal snapshot_calls
            snapshot_calls += 1
            return SimpleNamespace(snapshot_sha256="same")

    class ExpandedCollector:
        def __init__(self, *_: object, **__: object) -> None:
            return

        def execute(self, _: object) -> SimpleNamespace:
            cancelled.set()
            rows = [
                SimpleNamespace(
                    probe_id=probe_id,
                    control_ids=("PC-01",),
                    collection_status="COLLECTED",
                    error_code="NONE",
                    records=({"safe": True},),
                )
                for probe_id in STANDARD_NON_STORAGE_PROBES
            ]
            return SimpleNamespace(
                context=SimpleNamespace(collected_at_utc="2026-07-23T09:00:00Z"),
                results=rows,
            )

    class UnexpectedStorageCollector:
        def __init__(self, *_: object, **__: object) -> None:
            raise AssertionError("Cancellation must stop before the next group.")

    monkeypatch.setattr(
        windows_host_collection_acceptance,
        "WindowsSafetySnapshotter",
        Snapshotter,
    )
    monkeypatch.setattr(
        windows_host_collection_acceptance,
        "ExpandedWindowsCollector",
        ExpandedCollector,
    )
    monkeypatch.setattr(
        windows_host_collection_acceptance,
        "WindowsReadOnlyCollector",
        UnexpectedStorageCollector,
    )

    with pytest.raises(HostCollectionCancelled):
        windows_host_collection_acceptance.run_standard_host_collection(
            PROJECT_ROOT,
            cancel_check=cancelled.is_set,
        )

    assert snapshot_calls == 2


def test_launcher_reports_progress_and_blocks_refresh_duplicate(
    tmp_path: Path,
) -> None:
    started = threading.Event()
    release = threading.Event()
    calls = 0

    def progressive_runner(
        _: Path,
        progress: Callable[[str, int, str], None],
        cancelled: Callable[[], bool],
    ) -> dict[str, object]:
        nonlocal calls
        calls += 1
        progress("ACCOUNT_AND_PROTECTION", 40, "계정 및 보호 설정을 확인하고 있습니다.")
        started.set()
        assert release.wait(timeout=3)
        assert cancelled() is False
        return _successful_receipt()

    bridge = create_launcher_bridge(
        tmp_path,
        token=TOKEN,
        progressive_scan_runner=progressive_runner,
        port=0,
    )
    server_thread = threading.Thread(target=bridge.serve_forever, daemon=True)
    server_thread.start()
    try:
        code, started_body = _request(bridge.server_port, "/v1/scan", method="POST")
        assert code == 202
        assert started.wait(timeout=1)

        code, refreshed = _request(bridge.server_port, "/v1/status")
        assert code == 200
        assert refreshed["status"] == "RUNNING"
        assert refreshed["progress_percent"] == 40
        assert refreshed["current_step"] == "ACCOUNT_AND_PROTECTION"
        assert refreshed["job_id"] == started_body["job_id"]
        assert refreshed["can_cancel"] is True

        code, duplicate = _request(bridge.server_port, "/v1/scan", method="POST")
        assert code == 409
        assert duplicate["status"] == "RUNNING"
        assert duplicate["job_id"] == refreshed["job_id"]
        assert calls == 1

        release.set()
        completed = _wait_for(bridge.server_port, "COMPLETED")
        assert completed["progress_percent"] == 100
        assert completed["summary"] == {
            "collected_probes": 15,
            "error_probes": 0,
            "official_finding_created": False,
            "settings_modified": False,
            "total_probes": 15,
        }
        assert completed["result"]["vulnerability_inventory"] == (
            _successful_receipt()["vulnerability_inventory"]
        )
    finally:
        release.set()
        bridge.shutdown()
        bridge.server_close()
        server_thread.join(timeout=3)


def test_launcher_reports_completed_pc_control_ids(tmp_path: Path) -> None:
    control_reported = threading.Event()
    release = threading.Event()

    def progressive_runner(
        _: Path,
        progress: Callable[[str, int, str], None],
        cancelled: Callable[[], bool],
    ) -> dict[str, object]:
        progress("CONTROL_PC_01", 35, "PC-01 설정을 확인했습니다.")
        control_reported.set()
        assert release.wait(timeout=3)
        assert cancelled() is False
        return _successful_receipt()

    bridge = create_launcher_bridge(
        tmp_path,
        token=TOKEN,
        progressive_scan_runner=progressive_runner,
        port=0,
    )
    server_thread = threading.Thread(target=bridge.serve_forever, daemon=True)
    server_thread.start()
    try:
        code, _ = _request(bridge.server_port, "/v1/scan", method="POST")
        assert code == 202
        assert control_reported.wait(timeout=1)

        code, report = _request(bridge.server_port, "/v1/status")
        assert code == 200
        assert report["current_control_id"] == "PC-01"
        assert report["completed_control_ids"] == ["PC-01"]
        assert report["message"] == "PC-01 설정을 확인했습니다."
    finally:
        release.set()
        bridge.shutdown()
        bridge.server_close()
        server_thread.join(timeout=3)


def test_collection_reports_each_completed_control_in_order() -> None:
    events: list[tuple[str, int, str]] = []

    windows_host_collection_acceptance._report_completed_controls(
        lambda step, percent, message: events.append((step, percent, message)),
        ["PC-03", "PC-01", "PC-03"],
        start_percent=30,
        end_percent=60,
    )

    assert [event[0] for event in events] == ["CONTROL_PC_01", "CONTROL_PC_03"]
    assert [event[1] for event in events] == [45, 60]
    assert events[0][2].startswith("PC-01")


def test_launcher_cancels_at_safe_boundary_and_retries_without_overlap(
    tmp_path: Path,
) -> None:
    first_started = threading.Event()
    first_release = threading.Event()
    starts = 0
    active = 0
    maximum_active = 0

    def progressive_runner(
        _: Path,
        progress: Callable[[str, int, str], None],
        cancelled: Callable[[], bool],
    ) -> dict[str, object]:
        nonlocal starts, active, maximum_active
        starts += 1
        active += 1
        maximum_active = max(maximum_active, active)
        try:
            if starts == 1:
                progress("STORAGE", 70, "저장 장치 설정을 확인하고 있습니다.")
                first_started.set()
                assert first_release.wait(timeout=3)
                if cancelled():
                    raise HostCollectionCancelled
            return _successful_receipt()
        finally:
            active -= 1

    bridge = create_launcher_bridge(
        tmp_path,
        token=TOKEN,
        progressive_scan_runner=progressive_runner,
        port=0,
    )
    server_thread = threading.Thread(target=bridge.serve_forever, daemon=True)
    server_thread.start()
    try:
        code, first = _request(bridge.server_port, "/v1/scan", method="POST")
        assert code == 202
        assert first_started.wait(timeout=1)

        code, cancelling = _request(
            bridge.server_port,
            "/v1/cancel",
            method="POST",
        )
        assert code == 202
        assert cancelling["status"] == "CANCELLING"
        assert cancelling["message"] == (
            "현재 확인 항목을 안전하게 마친 뒤 점검을 취소합니다."
        )

        code, retry_too_soon = _request(
            bridge.server_port,
            "/v1/retry",
            method="POST",
        )
        assert code == 409
        assert retry_too_soon["status"] == "CANCELLING"

        first_release.set()
        cancelled = _wait_for(bridge.server_port, "CANCELLED")
        assert cancelled["can_retry"] is True
        assert cancelled["progress_percent"] == 70
        assert cancelled["job_id"] == first["job_id"]

        code, retry = _request(bridge.server_port, "/v1/retry", method="POST")
        assert code == 202
        assert retry["job_id"] == first["job_id"]
        assert retry["attempt"] == 2

        completed = _wait_for(bridge.server_port, "COMPLETED")
        assert completed["attempt"] == 2
        assert starts == 2
        assert maximum_active == 1
        assert completed["summary"]["official_finding_created"] is False  # type: ignore[index]
    finally:
        first_release.set()
        bridge.shutdown()
        bridge.server_close()
        server_thread.join(timeout=3)


def test_launcher_failure_returns_reference_and_allows_retry(tmp_path: Path) -> None:
    calls = 0

    def progressive_runner(
        _: Path,
        progress: Callable[[str, int, str], None],
        cancelled: Callable[[], bool],
    ) -> dict[str, object]:
        nonlocal calls
        calls += 1
        progress("PREPARING", 10, "점검을 준비하고 있습니다.")
        assert cancelled() is False
        if calls == 1:
            raise RuntimeError("sensitive internal failure")
        return _successful_receipt()

    bridge = create_launcher_bridge(
        tmp_path,
        token=TOKEN,
        progressive_scan_runner=progressive_runner,
        port=0,
    )
    server_thread = threading.Thread(target=bridge.serve_forever, daemon=True)
    server_thread.start()
    try:
        code, _ = _request(bridge.server_port, "/v1/scan", method="POST")
        assert code == 202
        failed = _wait_for(bridge.server_port, "FAILED")
        assert failed["can_retry"] is True
        assert isinstance(failed["error_reference"], str)
        assert "sensitive" not in json.dumps(failed)

        code, retry = _request(bridge.server_port, "/v1/retry", method="POST")
        assert code == 202
        assert retry["attempt"] == 2
        assert _wait_for(bridge.server_port, "COMPLETED")["status"] == "COMPLETED"
    finally:
        bridge.shutdown()
        bridge.server_close()
        server_thread.join(timeout=3)
