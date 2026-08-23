from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from security_audit.application.product_features import (
    FeatureState,
    public_feature_registry,
)
from security_audit.collector.launcher import (
    LauncherBridge,
    create_launcher_bridge,
    run_launcher_bridge,
    run_one_click_standard_scan,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_imp040_policy_keeps_one_click_scan_inside_safe_boundary() -> None:
    policy = json.loads(
        (
            PROJECT_ROOT
            / "collectors"
            / "one_shot"
            / "contracts"
            / "imp040_product_launcher_policy.json"
        ).read_text(encoding="utf-8")
    )

    assert policy["launcher"]["maximum_user_actions_after_open"] == 1
    assert policy["launcher"]["powershell_command_required_from_user"] is False
    assert policy["launcher"]["docker_command_required_from_user"] is False
    assert policy["launcher"]["automatic_elevation"] is False
    assert policy["launcher"]["bridge"]["host"] == "127.0.0.1"
    assert policy["launcher"]["bridge"]["port"] == 18481
    assert policy["launcher"]["bridge"]["token_bits"] == 256
    assert policy["launcher"]["bridge"]["single_scan_per_process"] is True
    assert policy["standard_scan"]["probe_count"] == 15
    assert policy["standard_scan"]["settings_modified"] is False
    assert policy["standard_scan"]["official_finding_created"] is False
    assert policy["feature_states"] == ["LIVE", "PREVIEW", "BLOCKED", "HIDDEN"]
    assert policy["blocked_boundary"]["administrator_scan_http_status"] == 423


def _successful_receipt() -> dict[str, object]:
    return {
        "observed_at_utc": "2026-07-23T09:00:00Z",
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


def test_feature_registry_has_one_live_scan_and_hides_internal_draft() -> None:
    registry = public_feature_registry()

    assert registry["pc_scan"].state is FeatureState.LIVE
    assert registry["known_vulnerability_check"].state is FeatureState.LIVE
    assert registry["known_vulnerability_check"].title == "알려진 취약점 점검"
    assert registry["known_vulnerability_check"].href == "/ui/vulnerability-check"
    assert registry["results"].state is FeatureState.LIVE
    assert registry["administrator_scan"].state is FeatureState.LIVE
    assert registry["guide_chat"].state is FeatureState.LIVE
    assert "history" not in registry
    assert "agent_assistance" not in registry
    assert "audit_pack_draft_assist" not in registry
    assert {item.state.value for item in registry.values()} <= {
        "LIVE",
        "PREVIEW",
        "BLOCKED",
    }


def test_one_click_launcher_runs_standard_scan_once_without_persisting_raw_data(
    tmp_path: Path,
) -> None:
    calls = {"scan": 0}
    opened: list[str] = []

    def scan_runner(_: Path) -> dict[str, object]:
        calls["scan"] += 1
        return _successful_receipt()

    def browser_opener(url: str) -> bool:
        opened.append(url)
        return True

    result = run_one_click_standard_scan(
        tmp_path,
        confirmed=True,
        scan_runner=scan_runner,
        browser_opener=browser_opener,
    )

    assert calls["scan"] == 1
    assert result["status"] == "COMPLETED"
    assert result["total_probes"] == 15
    assert result["collected_probes"] == 15
    assert result["error_probes"] == 0
    assert result["settings_modified"] is False
    assert result["official_finding_created"] is False
    assert len(opened) == 1
    assert opened[0].startswith("http://localhost:18480/ui/launcher-return?")
    assert "observed_at_utc" not in result
    assert "results" not in result
    assert not list(tmp_path.rglob("*.json"))


def test_launcher_cancel_does_not_collect_or_open_browser(tmp_path: Path) -> None:
    def unexpected(_: Path) -> dict[str, object]:
        raise AssertionError("Collection must not run after cancellation.")

    def unexpected_open(_: str) -> bool:
        raise AssertionError("Browser must not open after cancellation.")

    result = run_one_click_standard_scan(
        tmp_path,
        confirmed=False,
        scan_runner=unexpected,
        browser_opener=unexpected_open,
    )

    assert result["status"] == "CANCELLED"
    assert result["actual_collection_started"] is False


def test_launcher_opens_pre_auth_token_handoff_page(tmp_path: Path) -> None:
    opened: list[str] = []

    def browser_opener(url: str) -> bool:
        opened.append(url)
        return False

    try:
        run_launcher_bridge(tmp_path, browser_opener=browser_opener)
    except RuntimeError as exc:
        assert "could not be opened" in str(exc)
    else:
        raise AssertionError("A rejected browser open must stop the bridge.")

    assert len(opened) == 1
    assert opened[0].startswith(
        "http://localhost:18480/ui/launcher-connect#launcher_token="
    )


def test_launcher_rejects_receipt_with_settings_change(tmp_path: Path) -> None:
    receipt = _successful_receipt()
    receipt["settings_diff_count"] = 1

    def scan_runner(_: Path) -> dict[str, object]:
        return receipt

    try:
        run_one_click_standard_scan(
            tmp_path,
            confirmed=True,
            scan_runner=scan_runner,
            browser_opener=_unused_browser,
        )
    except RuntimeError as exc:
        assert "settings" in str(exc).casefold()
    else:
        raise AssertionError("Unsafe receipt must fail closed.")


def test_local_launcher_bridge_requires_exact_origin_and_token(tmp_path: Path) -> None:
    bridge = create_launcher_bridge(
        tmp_path,
        token="a" * 43,
        scan_runner=lambda _: _successful_receipt(),
        port=0,
    )
    thread = threading.Thread(target=bridge.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{bridge.server_port}/v1/status"
    try:
        valid = urllib.request.Request(  # noqa: S310 - fixed loopback URL
            url,
            headers={
                "Origin": "http://127.0.0.1:18480",
                "X-SecAI-Launcher-Token": "a" * 43,
            },
        )
        with urllib.request.urlopen(  # noqa: S310 - fixed loopback URL
            valid,
            timeout=3,
        ) as response:
            body = json.loads(response.read())
        assert response.status == 200
        assert body["scan_available"] is True
        assert body["status"] == "READY"
        assert body["progress_percent"] == 0
        assert body["can_cancel"] is False
        assert body["can_retry"] is False

        wrong_origin = urllib.request.Request(  # noqa: S310 - fixed loopback URL
            url,
            headers={
                "Origin": "https://example.invalid",
                "X-SecAI-Launcher-Token": "a" * 43,
            },
        )
        try:
            urllib.request.urlopen(  # noqa: S310 - fixed loopback URL
                wrong_origin,
                timeout=3,
            )
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
        else:
            raise AssertionError("An unrelated website must not call the Launcher.")
    finally:
        bridge.shutdown()
        bridge.server_close()
        thread.join(timeout=3)


def test_launcher_bridge_disallows_multiple_processes_on_the_same_port() -> None:
    assert LauncherBridge.allow_reuse_address is False


def test_existing_launcher_accepts_only_internal_restart_request(
    tmp_path: Path,
) -> None:
    bridge = create_launcher_bridge(
        tmp_path,
        token="r" * 43,
        scan_runner=lambda _: _successful_receipt(),
        port=0,
    )
    thread = threading.Thread(target=bridge.serve_forever, daemon=True)
    thread.start()
    url = (
        f"http://127.0.0.1:{bridge.server_port}"
        "/v1/internal/restart-for-relaunch"
    )
    try:
        denied = urllib.request.Request(  # noqa: S310 - fixed loopback URL
            url,
            method="POST",
            data=b"",
        )
        try:
            urllib.request.urlopen(denied, timeout=3)  # noqa: S310
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
        else:
            raise AssertionError("Restart without the internal header must fail.")

        accepted = urllib.request.Request(  # noqa: S310 - fixed loopback URL
            url,
            method="POST",
            data=b"",
            headers={
                "X-SecAI-Launcher-Restart": "SecAI-Collector-Relaunch-v1",
            },
        )
        with urllib.request.urlopen(accepted, timeout=3) as response:  # noqa: S310
            body = json.loads(response.read())
        assert response.status == 202
        assert response.headers["X-SecAI-Launcher-Protocol"] == "1"
        assert body == {"status": "RESTARTING"}
        thread.join(timeout=3)
        assert not thread.is_alive()
    finally:
        bridge.shutdown()
        bridge.server_close()
        thread.join(timeout=3)


def test_second_launcher_replaces_existing_launcher_without_port_error(
    tmp_path: Path,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = int(reservation.getsockname()[1])

    first_opened = threading.Event()
    first_errors: list[Exception] = []

    def open_first_launcher(_: str) -> bool:
        first_opened.set()
        return True

    def first_launcher() -> None:
        try:
            run_launcher_bridge(
                tmp_path,
                browser_opener=open_first_launcher,
                port=port,
            )
        except Exception as exc:  # pragma: no cover - asserted below
            first_errors.append(exc)

    first_thread = threading.Thread(target=first_launcher, daemon=True)
    first_thread.start()
    assert first_opened.wait(timeout=3)

    try:
        run_launcher_bridge(
            tmp_path,
            browser_opener=lambda _: False,
            port=port,
        )
    except RuntimeError as exc:
        assert "could not be opened" in str(exc)
    else:
        raise AssertionError("The replacement Launcher must reach browser handoff.")

    first_thread.join(timeout=3)
    assert not first_thread.is_alive()
    assert first_errors == []


def test_local_launcher_bridge_runs_one_scan_and_blocks_duplicate(
    tmp_path: Path,
) -> None:
    calls = 0

    def scan_runner(_: Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return _successful_receipt()

    bridge = create_launcher_bridge(
        tmp_path,
        token="b" * 43,
        scan_runner=scan_runner,
        port=0,
    )
    thread = threading.Thread(target=bridge.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{bridge.server_port}/v1/scan"

    def request() -> urllib.request.Request:
        return urllib.request.Request(  # noqa: S310 - fixed loopback URL
            url,
            method="POST",
            data=b"",
            headers={
                "Origin": "http://127.0.0.1:18480",
                "X-SecAI-Launcher-Token": "b" * 43,
                "Content-Type": "application/json",
            },
        )

    try:
        with urllib.request.urlopen(  # noqa: S310 - fixed loopback URL
            request(),
            timeout=3,
        ) as response:
            body = json.loads(response.read())
        assert response.status == 202
        assert body["status"] in {"RUNNING", "COMPLETED"}

        try:
            urllib.request.urlopen(  # noqa: S310 - fixed loopback URL
                request(),
                timeout=3,
            )
        except urllib.error.HTTPError as exc:
            assert exc.code == 409
        else:
            raise AssertionError("A second click must not start a duplicate scan.")
        assert calls == 1
        deadline = time.monotonic() + 3
        status_url = f"http://127.0.0.1:{bridge.server_port}/v1/status"
        while time.monotonic() < deadline:
            status_request = urllib.request.Request(  # noqa: S310
                status_url,
                headers={
                    "Origin": "http://127.0.0.1:18480",
                    "X-SecAI-Launcher-Token": "b" * 43,
                },
            )
            with urllib.request.urlopen(  # noqa: S310
                status_request,
                timeout=3,
            ) as status_response:
                status_body = json.loads(status_response.read())
            if status_body["status"] == "COMPLETED":
                break
            time.sleep(0.01)
        assert status_body["summary"]["collected_probes"] == 15
        assert status_body["summary"]["official_finding_created"] is False
    finally:
        bridge.shutdown()
        bridge.server_close()
        thread.join(timeout=3)


def _unused_browser(_: str) -> bool:
    return True
