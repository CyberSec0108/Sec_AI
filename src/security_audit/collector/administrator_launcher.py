"""IMP-043 explicitly requested elevated child and result bridge."""

from __future__ import annotations

import ctypes
import json
import os
import secrets
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

from security_audit.application.administrator_scan import (
    CONSENT_VERSION,
    build_administrator_results,
    validate_administrator_selection,
)
from security_audit.collector.criteria_contract import (
    encode_criteria_execution_context,
)
from security_audit.application.current_host_regression import (
    ProbeObservation,
    evaluate_live_draft_observations,
)
from security_audit.application.windows_host_collection_acceptance import (
    HostCollectionReceiptError,
    run_selected_administrator_host_collection,
)
from security_audit.collector.expanded import ExpandedCollectionError

ADMINISTRATOR_BRIDGE_HOST = "127.0.0.1"
ADMINISTRATOR_BRIDGE_PORT = 18482
LOCAL_RESULT_URL = "http://localhost:18480/ui/results"
ALLOWED_ORIGINS = frozenset(
    {
        "http://127.0.0.1:18480",
        "http://localhost:18480",
    }
)
ELEVATION_STARTED = "STARTED"
ELEVATION_CANCELLED = "CANCELLED_OR_DENIED"
ELEVATION_UNAVAILABLE = "UNAVAILABLE"
type BrowserOpener = Callable[[str], bool]


def _administrator_failure_result(
    stage: str,
    error: Exception,
) -> dict[str, object]:
    """Return only a stable, non-sensitive failure classification."""

    if isinstance(error, ExpandedCollectionError):
        failure_code = str(error.code)
    elif isinstance(error, HostCollectionReceiptError):
        failure_code = "COLLECTION_RECEIPT_INVALID"
    else:
        failure_code = f"{stage}_FAILED"
    messages = {
        "COLLECTION": (
            "Windows에서 관리자 점검 자료를 읽지 못했습니다. "
            "필요한 항목을 선택해 다시 점검해 주세요."
        ),
        "EVALUATION": (
            "수집한 관리자 점검 자료를 판정하지 못했습니다. "
            "필요한 항목을 선택해 다시 점검해 주세요."
        ),
        "RESULT_BUILD": (
            "관리자 점검 결과를 화면용으로 정리하지 못했습니다. "
            "필요한 항목을 선택해 다시 점검해 주세요."
        ),
    }
    return {
        "status": "FAILED",
        "message": messages.get(
            stage,
            "관리자 추가 점검을 완료하지 못했습니다.",
        ),
        "failure_stage": stage,
        "failure_code": failure_code,
        "error_reference": secrets.token_hex(6),
        "settings_modified": False,
        "raw_values_persisted": False,
        "official_finding_created": False,
    }


def request_elevated_administrator_process(
    selected_probe_ids: tuple[str, ...],
    criteria_context: Mapping[str, object] | None = None,
    *,
    result_token: str | None = None,
) -> str:
    """Ask Windows for one visible UAC decision after in-product consent."""

    selected = validate_administrator_selection(selected_probe_ids)
    if os.name != "nt" or not bool(getattr(sys, "frozen", False)):
        return ELEVATION_UNAVAILABLE
    arguments = [
        "administrator-launch",
        "--consent-version",
        CONSENT_VERSION,
        "--result-token",
        _validate_administrator_token(
            result_token or secrets.token_urlsafe(32)
        ),
    ]
    for probe_id in selected:
        arguments.extend(("--probe-id", probe_id))
    if criteria_context is not None:
        arguments.extend(
            (
                "--criteria-context",
                encode_criteria_execution_context(criteria_context),
            )
        )
    parameters = subprocess.list2cmdline(arguments)
    win_dll = getattr(  # noqa: B009 - absent from non-Windows type stubs
        ctypes,
        "WinDLL",
    )
    shell32 = win_dll("shell32", use_last_error=True)
    shell_execute = shell32.ShellExecuteW
    shell_execute.argtypes = (
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_int,
    )
    shell_execute.restype = ctypes.c_void_p
    result = shell_execute(
        None,
        "runas",
        sys.executable,
        parameters,
        None,
        1,
    )
    return ELEVATION_STARTED if int(result or 0) > 32 else ELEVATION_CANCELLED


class AdministratorResultBridge(ThreadingHTTPServer):
    allow_reuse_address = False
    allow_reuse_port = False
    result: dict[str, object]
    token: str


def _validate_administrator_token(token: str) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    if len(token) != 43 or any(character not in alphabet for character in token):
        raise ValueError("Administrator token must be 256-bit base64url text.")
    return token


class _AdministratorResultHandler(BaseHTTPRequestHandler):
    server_version = "SecAI-Administrator-Result"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        return

    def _server(self) -> AdministratorResultBridge:
        return cast(AdministratorResultBridge, self.server)

    def _origin(self) -> str | None:
        origin = self.headers.get("Origin")
        return origin if origin in ALLOWED_ORIGINS else None

    def _authorized(self) -> bool:
        supplied = self.headers.get("X-SecAI-Administrator-Token", "")
        return self._origin() is not None and secrets.compare_digest(
            supplied,
            self._server().token,
        )

    def _send(self, code: int, payload: Mapping[str, object]) -> None:
        body = json.dumps(
            dict(payload),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        origin = self._origin()
        if origin is not None:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        origin = self._origin()
        if origin is None:
            self._send(403, {"status": "FORBIDDEN"})
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header(
            "Access-Control-Allow-Headers",
            "X-SecAI-Administrator-Token",
        )
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Max-Age", "60")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Vary", "Origin")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path != "/v1/status":
            self._send(404, {"status": "NOT_FOUND"})
            return
        if not self._authorized():
            self._send(403, {"status": "FORBIDDEN"})
            return
        self._send(200, self._server().result)
        shutdown_timer = threading.Timer(0.5, self._server().shutdown)
        shutdown_timer.daemon = True
        shutdown_timer.start()


def create_administrator_result_bridge(
    result: Mapping[str, object],
    *,
    token: str,
    port: int = ADMINISTRATOR_BRIDGE_PORT,
) -> AdministratorResultBridge:
    _validate_administrator_token(token)
    server = AdministratorResultBridge(
        (ADMINISTRATOR_BRIDGE_HOST, port),
        _AdministratorResultHandler,
    )
    server.result = dict(result)
    server.token = token
    return server


def run_administrator_result_bridge(
    project_root: Path,
    *,
    selected_probe_ids: tuple[str, ...],
    browser_opener: BrowserOpener,
    criteria_context: Mapping[str, object] | None = None,
    result_token: str | None = None,
) -> None:
    """Collect in the elevated child, then expose only a sanitized receipt."""

    token = _validate_administrator_token(
        result_token or secrets.token_urlsafe(32)
    )
    stage = "COLLECTION"
    try:
        receipt = run_selected_administrator_host_collection(
            project_root,
            selected_probe_ids=selected_probe_ids,
            explicit_consent=True,
            include_evaluation_values=True,
        )
        observation_values = receipt.get("_evaluation_observations")
        observations = (
            tuple(
                item
                for item in observation_values
                if isinstance(item, ProbeObservation)
            )
            if isinstance(observation_values, tuple)
            else ()
        )
        stage = "EVALUATION"
        assessments = evaluate_live_draft_observations(
            project_root,
            observations=observations,
            criteria_context=criteria_context,
        )
        stage = "RESULT_BUILD"
        result = build_administrator_results(
            receipt,
            assessments=assessments,
        )
        result["criteria_context"] = (
            dict(criteria_context) if criteria_context is not None else None
        )
    except Exception as error:
        result = _administrator_failure_result(stage, error)
    bridge = create_administrator_result_bridge(result, token=token)
    if result_token is None:
        product_url = f"{LOCAL_RESULT_URL}#admin_launcher_token={token}"
        if not browser_opener(product_url):
            bridge.server_close()
            raise RuntimeError("The local result page could not be opened.")
    shutdown_timer = threading.Timer(600.0, bridge.shutdown)
    shutdown_timer.daemon = True
    shutdown_timer.start()
    try:
        bridge.serve_forever(poll_interval=0.25)
    finally:
        shutdown_timer.cancel()
        bridge.server_close()
