"""수집기가 실행 승인을 받는 절차.

사용자는 일회용 코드를 입력하지 않습니다. 수집기가 사이드카 토큰으로 승인
요청을 만들고 브라우저를 열어주며, 사용자는 이미 로그인된 화면에서 대상
장비를 확인한 뒤 승인합니다. 브라우저가 없는 서버에서는 주소만 출력합니다.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

APPROVAL_API_PATH = "/api/v1/scan/approvals"
DEFAULT_POLL_SECONDS = 2.0
DEFAULT_MAX_ATTEMPTS = 300

type RegisterCall = Callable[[str, dict[str, object]], dict[str, Any]]
type PollCall = Callable[[str], dict[str, Any]]
type BrowserOpener = Callable[[str], bool]
type Sleeper = Callable[[float], None]


class ScanHandshakeErrorCode(StrEnum):
    DECLINED = "SCAN_HANDSHAKE_DECLINED"
    EXPIRED = "SCAN_HANDSHAKE_EXPIRED"
    TIMED_OUT = "SCAN_HANDSHAKE_TIMED_OUT"
    RESPONSE_INVALID = "SCAN_HANDSHAKE_RESPONSE_INVALID"


class ScanHandshakeError(RuntimeError):
    def __init__(self, code: ScanHandshakeErrorCode) -> None:
        super().__init__("점검 실행 승인을 받지 못했습니다.")
        self.code = code


@dataclass(frozen=True, slots=True)
class GrantedScan:
    request_id: str
    approve_url: str
    elevated_consent: bool
    browser_opened: bool


def _text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ScanHandshakeError(ScanHandshakeErrorCode.RESPONSE_INVALID)
    return value


def perform_scan_handshake(
    sidecar: Any,
    *,
    device_name: str,
    register: RegisterCall,
    poll: PollCall,
    open_browser: BrowserOpener,
    sleep: Sleeper,
    poll_seconds: float = DEFAULT_POLL_SECONDS,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> GrantedScan:
    """승인 요청을 만들고 소유자가 결정할 때까지 기다립니다."""

    if max_attempts <= 0:
        raise ValueError("승인 대기 횟수가 올바르지 않습니다.")
    registered = register(
        f"{sidecar.server_origin}{APPROVAL_API_PATH}",
        {"token": sidecar.token, "device_name": device_name},
    )
    request_id = _text(registered, "request_id")
    approve_url = _text(registered, "approve_url")
    browser_opened = bool(open_browser(approve_url))
    poll_url = f"{sidecar.server_origin}{APPROVAL_API_PATH}/{request_id}"
    for attempt in range(max_attempts):
        decision = poll(poll_url)
        state = _text(decision, "state")
        if state == "APPROVED":
            return GrantedScan(
                request_id=request_id,
                approve_url=approve_url,
                elevated_consent=bool(decision.get("elevated_consent")),
                browser_opened=browser_opened,
            )
        if state == "DECLINED":
            raise ScanHandshakeError(ScanHandshakeErrorCode.DECLINED)
        if state == "EXPIRED":
            raise ScanHandshakeError(ScanHandshakeErrorCode.EXPIRED)
        if attempt + 1 < max_attempts:
            sleep(poll_seconds)
    raise ScanHandshakeError(ScanHandshakeErrorCode.TIMED_OUT)
