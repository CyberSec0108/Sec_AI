"""IMP-040 one-click Windows Launcher boundary."""

from __future__ import annotations

import json
import secrets
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast
from urllib.parse import urlencode

from security_audit.application.administrator_scan import (
    AdministratorConsentError,
    validate_administrator_consent_request,
)
from security_audit.application.current_host_regression import (
    ProbeObservation,
    evaluate_live_draft_observations,
)
from security_audit.application.result_explanation_input import (
    build_scan_explanation_inputs,
)
from security_audit.application.result_explanation_presentation import (
    build_result_explanation_presentations,
)
from security_audit.application.result_recheck_comparison import (
    build_recheck_comparison,
)
from security_audit.application.scan_result_guidance import (
    build_control_results,
    summarize_control_results,
    summarize_draft_assessments,
)
from security_audit.application.windows_host_collection_acceptance import (
    CollectionCancelCheck,
    CollectionProgressCallback,
    HostCollectionCancelled,
    run_standard_host_collection,
)
from security_audit.collector.administrator_launcher import (
    ELEVATION_CANCELLED,
    ELEVATION_STARTED,
    ELEVATION_UNAVAILABLE,
    request_elevated_administrator_process,
)
from security_audit.collector.criteria_contract import (
    CriteriaContractError,
    validate_criteria_execution_context,
)

LOCAL_PRODUCT_URL = "http://localhost:18480"
LOCAL_LAUNCHER_HOST = "127.0.0.1"
LOCAL_LAUNCHER_PORT = 18481
LOCAL_RESTART_PATH = "/v1/internal/restart-for-relaunch"
LOCAL_RESTART_HEADER = "X-SecAI-Launcher-Restart"
LOCAL_RESTART_VALUE = "SecAI-Collector-Relaunch-v1"
ALLOWED_PRODUCT_ORIGINS = frozenset(
    {
        "http://127.0.0.1:18480",
        "http://localhost:18480",
    }
)
type ScanRunner = Callable[[Path], dict[str, object]]
type ProgressiveScanRunner = Callable[
    [Path, CollectionProgressCallback, CollectionCancelCheck],
    dict[str, object],
]
type BrowserOpener = Callable[[str], bool]
type ElevationLauncher = Callable[[tuple[str, ...]], str]


class LauncherPortInUseError(RuntimeError):
    """The fixed loopback port is held by an unrelated or unresponsive process."""


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise CriteriaContractError("점검 기준에 중복된 항목이 있습니다.")
    return {key: value for key, value in pairs}


def _criteria_request(raw: bytes) -> dict[str, object]:
    try:
        request = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CriteriaContractError("점검 기준 요청을 읽을 수 없습니다.") from exc
    if not isinstance(request, dict) or frozenset(request) != {"criteria_context"}:
        raise CriteriaContractError("점검 기준 요청 형식이 올바르지 않습니다.")
    return validate_criteria_execution_context(request["criteria_context"])


def _summarize_receipt(receipt: Mapping[str, object]) -> tuple[int, int, int]:
    if receipt.get("settings_diff_count") != 0:
        raise RuntimeError("Windows settings changed during the standard scan.")
    values = receipt.get("results")
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
        raise RuntimeError("Standard scan receipt is invalid.")
    total = len(values)
    if total != 15:
        raise RuntimeError("Standard scan must return the fixed 15-Probe receipt.")
    collected = 0
    errors = 0
    for value in values:
        if not isinstance(value, Mapping):
            raise RuntimeError("Standard scan result is invalid.")
        status = value.get("collection_status")
        if status == "COLLECTED":
            collected += 1
        elif status in {"ERROR", "UNSUPPORTED"}:
            errors += 1
        else:
            raise RuntimeError("Standard scan returned an unknown status.")
    return total, collected, errors


def run_one_click_standard_scan(
    project_root: Path,
    *,
    confirmed: bool,
    scan_runner: ScanRunner = run_standard_host_collection,
    browser_opener: BrowserOpener,
) -> dict[str, object]:
    """Run once after explicit user confirmation and retain summary only."""

    if not confirmed:
        return {
            "status": "CANCELLED",
            "actual_collection_started": False,
            "settings_modified": False,
            "official_finding_created": False,
        }
    receipt = scan_runner(project_root)
    total, collected, errors = _summarize_receipt(receipt)
    query = urlencode(
        {
            "status": "COMPLETED",
            "total": total,
            "collected": collected,
            "errors": errors,
        }
    )
    browser_opened = browser_opener(f"{LOCAL_PRODUCT_URL}/ui/launcher-return?{query}")
    return {
        "status": "COMPLETED",
        "actual_collection_started": True,
        "total_probes": total,
        "collected_probes": collected,
        "error_probes": errors,
        "browser_opened": browser_opened,
        "settings_modified": False,
        "official_finding_created": False,
        "raw_values_persisted": False,
    }


@dataclass(slots=True)
class _BridgeState:
    project_root: Path
    token: str
    progressive_scan_runner: ProgressiveScanRunner
    elevation_launcher: ElevationLauncher
    auto_shutdown_on_complete: bool
    lock: threading.Lock = field(default_factory=threading.Lock)
    status: str = "READY"
    job_id: str | None = None
    attempt: int = 0
    progress_percent: int = 0
    current_step: str = "READY"
    current_control_id: str | None = None
    completed_control_ids: set[str] = field(default_factory=set)
    message: str = "점검을 시작할 수 있습니다."
    summary: dict[str, object] | None = None
    result_history: list[dict[str, object]] = field(default_factory=list)
    error_reference: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)
    worker: threading.Thread | None = None
    administrator_status: str = "NOT_REQUESTED"
    administrator_selected_probe_ids: tuple[str, ...] = ()
    administrator_result_token: str | None = None
    criteria_context: dict[str, object] | None = None


def _default_progressive_scan_runner(
    project_root: Path,
    progress_callback: CollectionProgressCallback,
    cancel_check: CollectionCancelCheck,
) -> dict[str, object]:
    return run_standard_host_collection(
        project_root,
        progress_callback=progress_callback,
        cancel_check=cancel_check,
        include_evaluation_values=True,
    )


def _adapt_scan_runner(scan_runner: ScanRunner) -> ProgressiveScanRunner:
    def adapted(
        project_root: Path,
        progress_callback: CollectionProgressCallback,
        cancel_check: CollectionCancelCheck,
    ) -> dict[str, object]:
        if cancel_check():
            raise HostCollectionCancelled
        progress_callback(
            "COLLECTING",
            30,
            "PC 보안 설정을 확인하고 있습니다.",
        )
        receipt = scan_runner(project_root)
        if cancel_check():
            raise HostCollectionCancelled
        return receipt

    return adapted


def _state_payload_unlocked(state: _BridgeState) -> dict[str, object]:
    administrator: dict[str, object] = {
        "available": state.status == "COMPLETED",
        "status": state.administrator_status,
        "selected_probe_ids": list(state.administrator_selected_probe_ids),
        "automatic_elevation": False,
        "standard_result_preserved": bool(state.result_history),
    }
    if state.administrator_result_token is not None:
        administrator["result_token"] = state.administrator_result_token
    payload: dict[str, object] = {
        "status": state.status,
        "job_id": state.job_id,
        "attempt": state.attempt,
        "progress_percent": state.progress_percent,
        "current_step": state.current_step,
        "current_control_id": state.current_control_id,
        "completed_control_ids": sorted(state.completed_control_ids),
        "message": state.message,
        "scan_available": state.status == "READY",
        "can_cancel": state.status == "RUNNING",
        "can_retry": state.status in {"CANCELLED", "FAILED"},
        "can_recheck": state.status == "COMPLETED",
        "administrator": administrator,
    }
    if state.summary is not None:
        payload["summary"] = dict(state.summary)
    if state.status == "COMPLETED" and state.result_history:
        payload["result"] = dict(state.result_history[-1])
    payload["history"] = [
        {
            "result_id": result["result_id"],
            "sequence": result["sequence"],
            "attempt": result["attempt"],
            "observed_at_utc": result["observed_at_utc"],
            "counts": dict(cast(Mapping[str, int], result["counts"])),
            "assessment_counts": dict(
                cast(Mapping[str, int], result["assessment_counts"])
            ),
            "changed_control_count": result["changed_control_count"],
            "comparison_summary": (
                dict(
                    cast(
                        Mapping[str, int],
                        cast(Mapping[str, object], result["comparison"])[
                            "summary"
                        ],
                    )
                )
                if isinstance(result.get("comparison"), Mapping)
                else None
            ),
        }
        for result in state.result_history
    ]
    if state.error_reference is not None:
        payload["error_reference"] = state.error_reference
    return payload


def _state_payload(state: _BridgeState) -> dict[str, object]:
    with state.lock:
        return _state_payload_unlocked(state)


def _run_scan_job(
    server: LauncherBridge,
    *,
    attempt: int,
    cancel_event: threading.Event,
) -> None:
    state = server.state

    def progress(step: str, percent: int, message: str) -> None:
        if not 0 <= percent <= 99:
            raise ValueError("Running progress must be between 0 and 99.")
        with state.lock:
            if state.attempt != attempt or cancel_event.is_set():
                return
            state.status = "RUNNING"
            state.current_step = step
            if step.startswith("CONTROL_PC_"):
                control_id = step.removeprefix("CONTROL_").replace("_", "-")
                state.current_control_id = control_id
                state.completed_control_ids.add(control_id)
            else:
                state.current_control_id = None
            state.progress_percent = max(state.progress_percent, percent)
            state.message = message

    try:
        receipt = state.progressive_scan_runner(
            state.project_root,
            progress,
            cancel_event.is_set,
        )
        if cancel_event.is_set():
            raise HostCollectionCancelled
        total, collected, errors = _summarize_receipt(receipt)
        observation_values = receipt.get("_evaluation_observations")
        observations = (
            tuple(
                value
                for value in observation_values
                if isinstance(value, ProbeObservation)
            )
            if isinstance(observation_values, Sequence)
            and not isinstance(observation_values, (str, bytes, bytearray))
            else ()
        )
        assessments = (
            evaluate_live_draft_observations(
                state.project_root,
                observations=observations,
                criteria_context=state.criteria_context,
            )
            if observations
            else {}
        )
        controls = build_control_results(receipt, assessments=assessments)
        control_counts = summarize_control_results(controls)
        assessment_counts = summarize_draft_assessments(controls)
        has_complete_rule_results = all(
            control.get("assessment_status") is not None for control in controls
        )
        explanations = (
            build_result_explanation_presentations(
                state.project_root,
                controls=controls,
            )
            if has_complete_rule_results
            else []
        )
        ai_explanation_inputs = (
            build_scan_explanation_inputs(
                state.project_root,
                controls=controls,
                collected_probe_results=cast(
                    Sequence[Mapping[str, object]],
                    receipt["results"],
                ),
            )
            if has_complete_rule_results
            else []
        )
    except HostCollectionCancelled:
        with state.lock:
            if state.attempt != attempt:
                return
            state.status = "CANCELLED"
            state.current_step = "CANCELLED"
            state.message = "점검을 취소했습니다. 원하면 같은 화면에서 다시 시도할 수 있습니다."
            state.summary = None
            state.error_reference = None
        return
    except Exception:
        with state.lock:
            if state.attempt != attempt:
                return
            state.status = "FAILED"
            state.current_step = "FAILED"
            state.message = "점검을 완료하지 못했습니다. 잠시 후 다시 시도해 주세요."
            state.summary = None
            state.error_reference = secrets.token_hex(6)
        return

    with state.lock:
        if state.attempt != attempt:
            return
        state.status = "COMPLETED"
        state.current_step = "COMPLETED"
        state.progress_percent = 100
        state.message = "일반 권한 점검을 마쳤습니다."
        state.summary = {
            "total_probes": total,
            "collected_probes": collected,
            "error_probes": errors,
            "settings_modified": False,
            "official_finding_created": False,
        }
        previous = state.result_history[-1] if state.result_history else None
        result_id = secrets.token_hex(8)
        sequence = len(state.result_history) + 1
        comparison = (
            build_recheck_comparison(
                previous_result_id=cast(str, previous["result_id"]),
                previous_result_version=cast(int, previous["sequence"]),
                previous_controls=cast(
                    Sequence[Mapping[str, object]],
                    previous["controls"],
                ),
                current_result_id=result_id,
                current_result_version=sequence,
                current_controls=controls,
            )
            if previous is not None
            and has_complete_rule_results
            and previous.get("result_kind") == "LIVE_DRAFT_ASSESSMENT"
            else None
        )
        previous_statuses = (
            {
                str(control["control_id"]): str(
                    control.get("assessment_status", control["display_status"])
                )
                for control in cast(
                    Sequence[Mapping[str, object]], previous["controls"]
                )
            }
            if previous is not None
            else {}
        )
        changed_control_count = sum(
            1
            for control in controls
            if previous_statuses
            and previous_statuses.get(str(control["control_id"]))
            != str(control.get("assessment_status", control["display_status"]))
        )
        if comparison is not None:
            comparison_summary = cast(
                Mapping[str, int],
                comparison["summary"],
            )
            changed_control_count = (
                comparison_summary["improved"]
                + comparison_summary["worsened"]
            )
        observed_at = receipt.get("observed_at_utc")
        vulnerability_inventory = receipt.get("vulnerability_inventory")
        state.result_history.append(
            {
                "result_id": result_id,
                "sequence": sequence,
                "attempt": attempt,
                "observed_at_utc": (
                    observed_at if isinstance(observed_at, str) else "UNKNOWN"
                ),
                "vulnerability_inventory": (
                    dict(vulnerability_inventory)
                    if isinstance(vulnerability_inventory, Mapping)
                    else None
                ),
                "counts": control_counts,
                "assessment_counts": assessment_counts,
                "changed_control_count": changed_control_count,
                "comparison": comparison,
                "controls": controls,
                "explanations": explanations,
                "ai_explanation_inputs": ai_explanation_inputs,
                "ai_input_contains_raw_evidence": False,
                "raw_values_persisted": False,
                "settings_modified": False,
                "official_finding_created": False,
                "result_kind": (
                    "LIVE_DRAFT_ASSESSMENT"
                    if assessments
                    else "COLLECTION_GUIDANCE"
                ),
                "criteria_context": (
                    dict(state.criteria_context)
                    if state.criteria_context is not None
                    else None
                ),
            }
        )
        state.error_reference = None


def _begin_scan(
    server: LauncherBridge,
    *,
    action: str,
    criteria_context: Mapping[str, object] | None = None,
) -> tuple[int, dict[str, object]]:
    state = server.state
    with state.lock:
        allowed_by_action = {
            "scan": {"READY"},
            "retry": {"CANCELLED", "FAILED"},
            "recheck": {"COMPLETED"},
        }
        allowed = allowed_by_action[action]
        if state.status not in allowed:
            return 409, _state_payload_unlocked(state)
        if state.worker is not None and state.worker.is_alive():
            return 409, _state_payload_unlocked(state)
        if state.job_id is None:
            state.job_id = secrets.token_hex(8)
        state.attempt += 1
        attempt = state.attempt
        state.status = "RUNNING"
        state.progress_percent = 0
        state.current_step = "STARTING"
        state.current_control_id = None
        state.completed_control_ids.clear()
        state.message = "점검을 시작하고 있습니다."
        state.summary = None
        state.error_reference = None
        if criteria_context is not None:
            state.criteria_context = dict(criteria_context)
        state.cancel_event = threading.Event()
        worker = threading.Thread(
            target=_run_scan_job,
            kwargs={
                "server": server,
                "attempt": attempt,
                "cancel_event": state.cancel_event,
            },
            name="secai-standard-scan",
            daemon=True,
        )
        state.worker = worker
        payload = _state_payload_unlocked(state)
    worker.start()
    return 202, payload


class LauncherBridge(ThreadingHTTPServer):
    """Loopback-only HTTP bridge with an ephemeral browser-held token."""

    allow_reuse_address = False
    allow_reuse_port = False
    state: _BridgeState


class _LauncherRequestHandler(BaseHTTPRequestHandler):
    server_version = "SecAI-Launcher"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        return

    def _state(self) -> _BridgeState:
        return cast(LauncherBridge, self.server).state

    def _origin(self) -> str | None:
        origin = self.headers.get("Origin")
        return origin if origin in ALLOWED_PRODUCT_ORIGINS else None

    def _authorized(self) -> bool:
        supplied = self.headers.get("X-SecAI-Launcher-Token", "")
        return self._origin() is not None and secrets.compare_digest(
            supplied,
            self._state().token,
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
        self.send_header("X-SecAI-Launcher-Protocol", "1")
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
            "Content-Type, X-SecAI-Launcher-Token",
        )
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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
        state = self._state()
        self._send(200, _state_payload(state))

    def do_POST(self) -> None:
        if self.path == LOCAL_RESTART_PATH:
            self._restart_for_relaunch()
            return
        if self.path not in {
            "/v1/scan",
            "/v1/cancel",
            "/v1/retry",
            "/v1/recheck",
            "/v1/administrator/launch",
            "/v1/administrator/reset",
        }:
            self._send(404, {"status": "NOT_FOUND"})
            return
        if not self._authorized():
            self._send(403, {"status": "FORBIDDEN"})
            return
        state = self._state()
        server = cast(LauncherBridge, self.server)
        if self.path == "/v1/administrator/launch":
            self._launch_administrator(server)
            return
        if self.path == "/v1/administrator/reset":
            self._reset_administrator(server)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = -1
        criteria_context: dict[str, object] | None = None
        if self.path in {"/v1/scan", "/v1/retry", "/v1/recheck"}:
            if content_length != 0:
                if (
                    content_length < 1
                    or content_length > 16384
                    or self.headers.get("Content-Type", "").split(";", 1)[0].strip()
                    != "application/json"
                ):
                    self._send(400, {"status": "INVALID_REQUEST"})
                    return
                try:
                    criteria_context = _criteria_request(
                        self.rfile.read(content_length)
                    )
                except CriteriaContractError:
                    self._send(400, {"status": "INVALID_CRITERIA"})
                    return
        elif content_length != 0:
            self._send(400, {"status": "INVALID_REQUEST"})
            return
        if self.path == "/v1/scan":
            code, payload = _begin_scan(
                server,
                action="scan",
                criteria_context=criteria_context,
            )
            self._send(code, payload)
            return
        if self.path == "/v1/retry":
            code, payload = _begin_scan(
                server,
                action="retry",
                criteria_context=criteria_context,
            )
            self._send(code, payload)
            return
        if self.path == "/v1/recheck":
            code, payload = _begin_scan(
                server,
                action="recheck",
                criteria_context=criteria_context,
            )
            self._send(code, payload)
            return
        with state.lock:
            if state.status == "RUNNING":
                state.cancel_event.set()
                state.status = "CANCELLING"
                state.current_step = "CANCELLING"
                state.message = (
                    "현재 확인 항목을 안전하게 마친 뒤 점검을 취소합니다."
                )
                self._send(202, _state_payload_unlocked(state))
                return
            if state.status == "CANCELLING":
                self._send(202, _state_payload_unlocked(state))
                return
            self._send(409, _state_payload_unlocked(state))

    def _restart_for_relaunch(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = -1
        if (
            self.headers.get("Origin") is not None
            or content_length != 0
            or not secrets.compare_digest(
                self.headers.get(LOCAL_RESTART_HEADER, ""),
                LOCAL_RESTART_VALUE,
            )
        ):
            self._send(403, {"status": "FORBIDDEN"})
            return
        self._send(202, {"status": "RESTARTING"})
        shutdown_thread = threading.Thread(
            target=self.server.shutdown,
            name="secai-launcher-relaunch-shutdown",
            daemon=True,
        )
        shutdown_thread.start()

    def _reset_administrator(self, server: LauncherBridge) -> None:
        state = server.state
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = -1
        if content_length not in {0, 2}:
            self._send(400, {"status": "INVALID_REQUEST"})
            return
        if content_length == 2 and self.rfile.read(content_length) != b"{}":
            self._send(400, {"status": "INVALID_REQUEST"})
            return
        with state.lock:
            if state.status != "COMPLETED" or state.administrator_status not in {
                ELEVATION_STARTED,
                ELEVATION_CANCELLED,
                "FAILED",
                ELEVATION_UNAVAILABLE,
            }:
                self._send(409, _state_payload_unlocked(state))
                return
            state.administrator_status = "NOT_REQUESTED"
            state.administrator_selected_probe_ids = ()
            state.administrator_result_token = None
            self._send(200, _state_payload_unlocked(state))

    def _launch_administrator(self, server: LauncherBridge) -> None:
        state = server.state
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = -1
        if (
            content_length < 1
            or content_length > 4096
            or self.headers.get("Content-Type", "").split(";", 1)[0].strip()
            != "application/json"
        ):
            self._send(400, {"status": "INVALID_REQUEST"})
            return
        try:
            raw = self.rfile.read(content_length)
            pairs = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=lambda values: values,
            )
            if (
                not isinstance(pairs, list)
                or any(
                    not isinstance(pair, tuple) or len(pair) != 2
                    for pair in pairs
                )
            ):
                raise AdministratorConsentError("Consent JSON must be an object.")
            keys = [pair[0] for pair in pairs]
            if len(set(keys)) != len(keys):
                raise AdministratorConsentError("Duplicate consent field.")
            request = {str(key): value for key, value in pairs}
            selected = validate_administrator_consent_request(request)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            AdministratorConsentError,
        ):
            self._send(400, {"status": "INVALID_CONSENT"})
            return
        with state.lock:
            if (
                state.status != "COMPLETED"
                or state.administrator_status
                not in {"NOT_REQUESTED", ELEVATION_CANCELLED, "FAILED"}
            ):
                self._send(409, _state_payload_unlocked(state))
                return
            state.administrator_status = "REQUESTING_UAC"
            state.administrator_selected_probe_ids = selected
            state.administrator_result_token = secrets.token_urlsafe(32)
        try:
            outcome = (
                request_elevated_administrator_process(
                    selected,
                    state.criteria_context,
                    result_token=state.administrator_result_token,
                )
                if state.elevation_launcher
                is request_elevated_administrator_process
                else state.elevation_launcher(selected)
            )
        except Exception:
            outcome = "FAILED"
        with state.lock:
            state.administrator_status = outcome
            if outcome != ELEVATION_STARTED:
                state.administrator_result_token = None
            payload = _state_payload_unlocked(state)
        if outcome == ELEVATION_STARTED:
            self._send(202, payload)
        elif outcome == ELEVATION_CANCELLED:
            self._send(200, payload)
        else:
            self._send(503, payload)


def create_launcher_bridge(
    project_root: Path,
    *,
    token: str,
    scan_runner: ScanRunner | None = None,
    progressive_scan_runner: ProgressiveScanRunner | None = None,
    elevation_launcher: ElevationLauncher = request_elevated_administrator_process,
    port: int = LOCAL_LAUNCHER_PORT,
    auto_shutdown_on_complete: bool = False,
) -> LauncherBridge:
    """Create a strict loopback server; callers control its lifetime."""

    base64url_alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    if len(token) != 43 or any(
        character not in base64url_alphabet for character in token
    ):
        raise ValueError("Launcher token must be 256-bit base64url text.")
    if scan_runner is not None and progressive_scan_runner is not None:
        raise ValueError("Choose one Launcher scan runner.")
    selected_runner = progressive_scan_runner
    if selected_runner is None:
        selected_runner = (
            _adapt_scan_runner(scan_runner)
            if scan_runner is not None
            else _default_progressive_scan_runner
        )
    server = LauncherBridge(
        (LOCAL_LAUNCHER_HOST, port),
        _LauncherRequestHandler,
    )
    server.state = _BridgeState(
        project_root=project_root,
        token=token,
        progressive_scan_runner=selected_runner,
        elevation_launcher=elevation_launcher,
        auto_shutdown_on_complete=auto_shutdown_on_complete,
    )
    return server


def run_launcher_bridge(
    project_root: Path,
    *,
    browser_opener: BrowserOpener,
    port: int = LOCAL_LAUNCHER_PORT,
) -> None:
    """Open the product UI and serve one authenticated local scan."""

    token = secrets.token_urlsafe(32)
    bridge = _create_relaunching_bridge(
        project_root,
        token=token,
        port=port,
        auto_shutdown_on_complete=False,
    )
    product_url = (
        f"{LOCAL_PRODUCT_URL}/ui/launcher-connect#launcher_token={token}"
    )
    if not browser_opener(product_url):
        bridge.server_close()
        raise RuntimeError("The local product page could not be opened.")
    try:
        bridge.serve_forever(poll_interval=0.25)
    finally:
        bridge.server_close()


def _address_is_in_use(error: OSError) -> bool:
    return getattr(error, "winerror", None) == 10048 or error.errno in {
        48,
        98,
        10048,
    }


def _request_existing_launcher_restart(port: int) -> bool:
    request = urllib.request.Request(  # noqa: S310 - fixed loopback URL
        f"http://{LOCAL_LAUNCHER_HOST}:{port}{LOCAL_RESTART_PATH}",
        method="POST",
        data=b"",
        headers={LOCAL_RESTART_HEADER: LOCAL_RESTART_VALUE},
    )
    try:
        with urllib.request.urlopen(request, timeout=1.0) as response:  # noqa: S310
            response.read()
            status = response.getcode()
            protocol = response.headers.get("X-SecAI-Launcher-Protocol")
            return (
                status == 202
                and isinstance(protocol, str)
                and protocol == "1"
            )
    except (OSError, TimeoutError, urllib.error.URLError):
        return False


def _create_relaunching_bridge(
    project_root: Path,
    *,
    token: str,
    port: int,
    auto_shutdown_on_complete: bool,
) -> LauncherBridge:
    try:
        return create_launcher_bridge(
            project_root,
            token=token,
            port=port,
            auto_shutdown_on_complete=auto_shutdown_on_complete,
        )
    except OSError as error:
        if not _address_is_in_use(error):
            raise
        if not _request_existing_launcher_restart(port):
            raise LauncherPortInUseError(
                "The Launcher port is held by another process."
            ) from error

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        time.sleep(0.05)
        try:
            return create_launcher_bridge(
                project_root,
                token=token,
                port=port,
                auto_shutdown_on_complete=auto_shutdown_on_complete,
            )
        except OSError as error:
            if not _address_is_in_use(error):
                raise
    raise LauncherPortInUseError(
        "The previous Launcher did not release its port in time."
    )
