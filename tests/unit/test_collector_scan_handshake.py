from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from security_audit.collector.scan_handshake import (
    GrantedScan,
    ScanHandshakeError,
    ScanHandshakeErrorCode,
    perform_scan_handshake,
)
from security_audit.collector.scan_sidecar import ScanSidecar

NOW = datetime(2026, 8, 23, 6, 0, tzinfo=UTC)
SIDECAR = ScanSidecar(
    server_origin="http://192.168.0.10:18480",
    token="0123456789ab.secret-value",  # noqa: S106 - 형식만 확인하는 시험값입니다.
    expires_at=NOW + timedelta(hours=24),
    max_runs=3,
)
REQUEST_ID = "46000000-0000-4000-8000-000000000010"
APPROVE_URL = f"http://192.168.0.10:18480/ui/scan-approve?req={REQUEST_ID}"


class _Transport:
    def __init__(self, states: list[str]) -> None:
        self.states = states
        self.registered: dict[str, object] = {}
        self.polls = 0

    def register(self, url: str, payload: dict[str, object]) -> dict[str, object]:
        self.registered = {"url": url, "payload": payload}
        return {
            "request_id": REQUEST_ID,
            "approve_url": APPROVE_URL,
            "expires_at": "2026-08-23T06:10:00Z",
            "remaining_runs": 2,
        }

    def poll(self, url: str) -> dict[str, object]:
        del url
        state = self.states[min(self.polls, len(self.states) - 1)]
        self.polls += 1
        return {
            "request_id": REQUEST_ID,
            "state": state,
            "elevated_consent": state == "APPROVED",
        }


def _run(
    states: list[str],
    *,
    opener: Callable[[str], bool] = lambda _url: True,
    sleeps: Callable[[float], None] | None = None,
) -> tuple[GrantedScan, _Transport]:
    transport = _Transport(states)
    granted = perform_scan_handshake(
        SIDECAR,
        device_name="DESKTOP-A17",
        register=transport.register,
        poll=transport.poll,
        open_browser=opener,
        sleep=sleeps if sleeps is not None else (lambda _seconds: None),
    )
    return granted, transport


def test_handshake_registers_then_waits_for_the_owner_approval() -> None:
    granted, transport = _run(["PENDING", "PENDING", "APPROVED"])

    assert transport.registered["url"] == (
        "http://192.168.0.10:18480/api/v1/scan/approvals"
    )
    assert transport.registered["payload"] == {
        "token": SIDECAR.token,
        "device_name": "DESKTOP-A17",
    }
    assert transport.polls == 3
    assert granted.elevated_consent is True
    assert granted.approve_url == APPROVE_URL


def test_headless_server_still_prints_the_link_instead_of_failing() -> None:
    granted, _transport = _run(["APPROVED"], opener=lambda _url: False)

    assert granted.browser_opened is False
    assert granted.approve_url == APPROVE_URL


def test_declined_and_expired_decisions_stop_the_collector() -> None:
    with pytest.raises(ScanHandshakeError) as declined:
        _run(["DECLINED"])
    assert declined.value.code is ScanHandshakeErrorCode.DECLINED

    with pytest.raises(ScanHandshakeError) as expired:
        _run(["EXPIRED"])
    assert expired.value.code is ScanHandshakeErrorCode.EXPIRED


def test_waiting_forever_is_refused_after_the_attempt_budget() -> None:
    transport = _Transport(["PENDING"])

    with pytest.raises(ScanHandshakeError) as timed_out:
        perform_scan_handshake(
            SIDECAR,
            device_name="DESKTOP-A17",
            register=transport.register,
            poll=transport.poll,
            open_browser=lambda _url: True,
            sleep=lambda _seconds: None,
            max_attempts=5,
        )

    assert timed_out.value.code is ScanHandshakeErrorCode.TIMED_OUT
    assert transport.polls == 5
