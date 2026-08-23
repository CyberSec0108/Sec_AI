from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

import pytest
from apps.api.main import app
from fastapi.testclient import TestClient

from security_audit.application.administrator_scan import (
    CONSENT_VERSION,
    AdministratorConsentError,
    build_administrator_results,
    validate_administrator_consent_request,
    validate_administrator_selection,
)
from security_audit.application.current_host_regression import (
    ProbeObservation,
    evaluate_live_draft_observations,
)
from security_audit.collector import ProbeAllowlist
from security_audit.collector.administrator_launcher import (
    ELEVATION_CANCELLED,
    ELEVATION_STARTED,
    _administrator_failure_result,
    create_administrator_result_bridge,
)
from security_audit.collector.contracts import (
    VerifiedExecutionPlan,
    VerifiedProbeRequest,
)
from security_audit.collector.expanded import (
    ADMINISTRATOR_PROBES,
    ExpandedCollectionCode,
    ExpandedCollectionError,
    ExpandedWindowsCollector,
)
from security_audit.collector.launcher import create_launcher_bridge
from security_audit.collector.process import BoundedCommandResult

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = PROJECT_ROOT / "collectors" / "one_shot" / "contracts"
SCRIPTS = (
    PROJECT_ROOT
    / "collectors"
    / "one_shot"
    / "probes"
    / "windows"
    / "powershell"
)
ORIGIN = "http://127.0.0.1:18480"
TOKEN = "d" * 43
ADMIN_TOKEN = "e" * 43
SELECTED = (
    "win.security.password-policy",
    "win.boot.entries",
    "win.update.compliance",
)
ADAPTERS = {
    "win.security.password-policy": ("secai.windows-account-policy", "0.1.0"),
    "win.boot.entries": ("secai.windows-bcdedit-native", "0.1.0"),
    "win.update.compliance": (
        "secai.windows-update-history-build",
        "0.1.0",
    ),
}


def _standard_receipt() -> dict[str, object]:
    return {
        "observed_at_utc": "2026-07-24T01:00:00Z",
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


def _administrator_receipt() -> dict[str, object]:
    return {
        "observed_at_utc": "2026-07-24T01:02:00Z",
        "explicit_consent": True,
        "selected_probe_ids": list(SELECTED),
        "settings_diff_count": 0,
        "results": [
            {
                "probe_id": probe_id,
                "control_ids": ["PC-02", "PC-03"],
                "privilege": "ADMINISTRATOR",
                "collection_status": (
                    "COLLECTED" if index != 1 else "ERROR"
                ),
                "error_code": (
                    "NONE" if index != 1 else "PERMISSION_DENIED"
                ),
                "record_count": 1 if index != 1 else 0,
            }
            for index, probe_id in enumerate(SELECTED)
        ],
    }


def _plan(selected: tuple[str, ...]) -> VerifiedExecutionPlan:
    allowlist = ProbeAllowlist.from_file(
        CONTRACTS / "imp031_probe_allowlist.json"
    )
    probes: list[VerifiedProbeRequest] = []
    for probe_id in selected:
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
        manifest_id="43000000-0000-4000-8000-000000000001",
        manifest_sha256="4" * 64,
        job_id="43000000-0000-4000-8000-000000000002",
        asset_id="43000000-0000-4000-8000-000000000003",
        nonce="SU1QLTA0My1hZG1pbi10ZXN0",
        verified_at=datetime(2026, 7, 24, 1, 0, tzinfo=UTC),
        probes=tuple(probes),
    )


def _admin_output(plan: VerifiedExecutionPlan) -> bytes:
    return json.dumps(
        {
            "schema_version": "1.0.0",
            "context": {
                "os_family": "WINDOWS",
                "os_version": "11",
                "product_name": "Windows 11 Pro",
                "display_version": "24H2",
                "build_number": "26100",
                "ubr": 1,
                "architecture": "x86_64",
                "process_sid": "S-1-5-21-1-2-3-1001",
                "is_administrator": True,
                "integrity_level": "HIGH",
                "collected_at_utc": "2026-07-24T01:02:00Z",
            },
            "results": [
                {
                    "probe_id": probe.probe_id,
                    "probe_version": probe.probe_version,
                    "control_ids": list(probe.control_ids),
                    "collection_status": "COLLECTED",
                    "error_code": "NONE",
                    "adapter_id": ADAPTERS[probe.probe_id][0],
                    "adapter_version": ADAPTERS[probe.probe_id][1],
                    "coverage": "SELECTED_ADMINISTRATOR_SCOPE",
                    "records": [{"record_count": 1}],
                }
                for probe in plan.probes
            ],
        },
        separators=(",", ":"),
    ).encode()


def _launcher_request(
    port: int,
    path: str,
    *,
    payload: dict[str, object] | None = None,
) -> tuple[int, dict[str, object]]:
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(  # noqa: S310 - fixed loopback test URL
        f"http://127.0.0.1:{port}{path}",
        method="GET" if payload is None else "POST",
        data=data,
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


def _wait_for_completed(port: int) -> dict[str, object]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        _, body = _launcher_request(port, "/v1/status")
        if body["status"] == "COMPLETED":
            return body
        time.sleep(0.01)
    raise AssertionError("Standard scan did not complete.")


def _mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    return value


def test_administrator_failure_result_exposes_only_safe_stage_and_code() -> None:
    result = _administrator_failure_result(
        "COLLECTION",
        ExpandedCollectionError(
            ExpandedCollectionCode.PROBE_EXECUTION_FAILED,
            "sensitive local path and command output",
        ),
    )

    assert result["status"] == "FAILED"
    assert result["failure_stage"] == "COLLECTION"
    assert result["failure_code"] == "PROBE_EXECUTION_FAILED"
    assert result["settings_modified"] is False
    serialized = json.dumps(result, ensure_ascii=False)
    assert "sensitive local path" not in serialized
    assert "command output" not in serialized


def test_imp043_policy_requires_selection_consent_and_no_automatic_elevation() -> None:
    policy = json.loads(
        (
            CONTRACTS / "imp043_administrator_consent_policy.json"
        ).read_text(encoding="utf-8")
    )

    assert policy["consent_version"] == CONSENT_VERSION
    assert policy["selection"]["minimum_probe_count"] == 1
    assert policy["selection"]["maximum_probe_count"] == 5
    assert policy["selection"]["allowlist_order_required"] is True
    assert policy["consent"]["separate_consent_checkbox_required"] is True
    assert policy["consent"]["automatic_elevation"] is False
    assert policy["cancellation"]["standard_result_preserved"] is True
    assert policy["safety"]["settings_modified"] is False
    assert policy["safety"]["official_finding_created"] is False


def test_selection_and_consent_fail_closed() -> None:
    assert validate_administrator_selection(SELECTED) == SELECTED
    assert validate_administrator_consent_request(
        {
            "consent": True,
            "consent_version": CONSENT_VERSION,
            "probe_ids": list(SELECTED),
        }
    ) == SELECTED

    invalid_values: tuple[tuple[object, ...], ...] = (
        (),
        (SELECTED[1], SELECTED[0]),
        (SELECTED[0], SELECTED[0]),
        ("win.unknown",),
    )
    for value in invalid_values:
        with pytest.raises(AdministratorConsentError):
            validate_administrator_selection(value)
    with pytest.raises(AdministratorConsentError):
        validate_administrator_consent_request(
            {
                "consent": False,
                "consent_version": CONSENT_VERSION,
                "probe_ids": list(SELECTED),
            }
        )


def test_selected_administrator_probes_are_the_only_command_arguments(
    tmp_path: Path,
) -> None:
    plan = _plan(SELECTED)
    powershell = tmp_path / "powershell.exe"
    powershell.write_bytes(b"synthetic executable")

    def executor(
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> BoundedCommandResult:
        assert "-File" in command
        assert command[-2:] == (
            "-SelectedProbeIdsCsv",
            ",".join(SELECTED),
        )
        assert all(
            probe_id not in command[-1].split(",")
            for probe_id in ADMINISTRATOR_PROBES
            if probe_id not in SELECTED
        )
        assert command[command.index("-File") + 1] == str(
            (SCRIPTS / "imp031_administrator_controls.ps1").resolve()
        )
        assert stdin_bytes == b""
        assert timeout_seconds == 30
        assert max_output_bytes == 65_536
        return BoundedCommandResult(0, _admin_output(plan), b"")

    result = ExpandedWindowsCollector(
        SCRIPTS / "imp031_administrator_controls.ps1",
        privilege="ADMINISTRATOR",
        executor=executor,
        platform_name="nt",
        powershell_path=powershell,
    ).execute(plan)

    assert tuple(item.probe_id for item in result.results) == SELECTED
    assert result.settings_modified is False
    assert result.official_finding_created is False


def test_partial_administrator_result_is_guidance_not_a_finding() -> None:
    result = build_administrator_results(_administrator_receipt())

    assert result["status"] == "COMPLETED"
    assert result["selected_probe_count"] == 3
    assert result["collected_probe_count"] == 2
    assert result["review_required_count"] == 1
    assert result["collection_error_count"] == 1
    assert result["assessment_review_count"] == 0
    assert result["settings_modified"] is False
    assert result["raw_values_persisted"] is False
    assert result["official_finding_created"] is False
    serialized = json.dumps(result, ensure_ascii=False)
    assert "PERMISSION_DENIED" not in serialized
    assert "record_count" not in serialized
    assert "PASS" not in serialized
    assert "FAIL" not in serialized
    rows = cast(list[dict[str, object]], result["results"])
    assert [row["collection_status"] for row in rows] == [
        "COLLECTED",
        "ERROR",
        "COLLECTED",
    ]
    failed = rows[1]
    assert failed["collection_status_label"] == "자료 수집 실패"
    assert failed["judgement_explanation"] == (
        "Windows가 해당 정보를 읽을 권한을 허용하지 않았습니다."
    )


def test_collected_review_is_separate_from_collection_error() -> None:
    result = build_administrator_results(
        _administrator_receipt(),
        assessments={
            "PC-02": {
                "status": "REVIEW",
                "status_label": "기준 확인 필요 (REVIEW)",
                "actual": "비밀번호 정책 자료를 수집했습니다.",
                "expected": "선택한 조직 기준과 비교",
                "result_code": "ORGANIZATION_PASSWORD_STANDARD_REQUIRED",
                "assessment_kind": "DEVELOPMENT_DRAFT",
                "judgement_explanation": "적용할 조직 기준을 확인해야 합니다.",
            }
        },
    )

    first = cast(list[dict[str, object]], result["results"])[0]
    assert result["collection_error_count"] == 1
    assert result["assessment_review_count"] == 1
    assert first["collection_status"] == "COLLECTED"
    assert first["assessment_status"] == "REVIEW"


def test_live_administrator_records_match_draft_rule_input_contract() -> None:
    observed_at = "2026-07-26T01:02:03Z"
    observations = (
        ProbeObservation(
            probe_id="win.security.password-policy",
            collection_status="COLLECTED",
            error_code="NONE",
            adapter_id="secai.windows-account-policy",
            adapter_version="0.1.0",
            privilege="ADMINISTRATOR",
            collected_at=observed_at,
            records=(
                {
                    "minimum_password_length": 12,
                    "maximum_password_age_days": 90,
                    "complexity_enabled": None,
                    "password_required": True,
                    "policy_source": "WINDOWS_EFFECTIVE",
                },
            ),
        ),
        ProbeObservation(
            probe_id="win.network.smb-shares",
            collection_status="COLLECTED",
            error_code="NONE",
            adapter_id="secai.windows-smb-native",
            adapter_version="0.1.0",
            privilege="ADMINISTRATOR",
            collected_at=observed_at,
            records=(
                {
                    "share_count": 4,
                    "default_admin_share_count": 3,
                    "unrestricted_everyone_share_count": 0,
                    "auto_share_wks_disabled": False,
                },
            ),
        ),
        ProbeObservation(
            probe_id="win.software.messengers",
            collection_status="COLLECTED",
            error_code="NONE",
            adapter_id="secai.windows-installed-software-inventory",
            adapter_version="0.1.0",
            privilege="ADMINISTRATOR",
            collected_at=observed_at,
            records=(
                {
                    "installed_product_count": 128,
                    "messenger_catalog_status": "NOT_APPROVED",
                    "denied_product_evaluation_performed": False,
                },
            ),
        ),
        ProbeObservation(
            probe_id="win.boot.entries",
            collection_status="COLLECTED",
            error_code="NONE",
            adapter_id="secai.windows-bcdedit-native",
            adapter_version="0.1.0",
            privilege="ADMINISTRATOR",
            collected_at=observed_at,
            records=(
                {
                    "bootable_os_count": 1,
                    "parser_profile": "BCDEDIT_OSLOADER_IDENTIFIER_COUNT",
                },
            ),
        ),
        ProbeObservation(
            probe_id="win.update.compliance",
            collection_status="COLLECTED",
            error_code="NONE",
            adapter_id="secai.windows-update-history-build",
            adapter_version="0.1.0",
            privilege="ADMINISTRATOR",
            collected_at=observed_at,
            records=(
                {
                    "product_name": "Windows 11 Pro",
                    "display_version": "24H2",
                    "edition_group": "Professional",
                    "os_build": "26100",
                    "ubr": 1,
                    "update_inventory_source": "WINDOWS_UPDATE_HISTORY_AND_BUILD",
                    "history_record_count": 42,
                    "latest_history_at": "2026-07-20T01:02:03Z",
                    "automatic_updates_enabled": True,
                    "restart_pending": False,
                },
            ),
        ),
    )

    result = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=observations,
    )

    assert result["PC-02"]["status"] == "REVIEW"
    assert result["PC-04"]["status"] == "REVIEW"
    assert result["PC-06"]["status"] == "REVIEW"
    assert result["PC-08"]["status"] == "PASS"
    assert result["PC-10"]["status"] == "REVIEW"
    assert "수집 자료를 시험 기준으로 판정하지 못했습니다" not in {
        value["actual"] for value in result.values()
    }


def test_parent_bridge_launches_only_after_standard_result_and_preserves_it(
    tmp_path: Path,
) -> None:
    launches: list[tuple[str, ...]] = []

    def elevation_launcher(selected: tuple[str, ...]) -> str:
        launches.append(selected)
        return ELEVATION_STARTED

    bridge = create_launcher_bridge(
        tmp_path,
        token=TOKEN,
        scan_runner=lambda _: _standard_receipt(),
        elevation_launcher=elevation_launcher,
        port=0,
    )
    thread = threading.Thread(target=bridge.serve_forever, daemon=True)
    thread.start()
    consent = {
        "consent": True,
        "consent_version": CONSENT_VERSION,
        "probe_ids": list(SELECTED),
    }
    try:
        code, body = _launcher_request(
            bridge.server_port,
            "/v1/administrator/launch",
            payload=consent,
        )
        assert code == 409
        assert _mapping(body["administrator"])["status"] == "NOT_REQUESTED"

        code, _ = _launcher_request(
            bridge.server_port,
            "/v1/scan",
            payload={},
        )
        assert code == 400
        request = urllib.request.Request(  # noqa: S310 - loopback test URL
            f"http://127.0.0.1:{bridge.server_port}/v1/scan",
            method="POST",
            data=b"",
            headers={
                "Origin": ORIGIN,
                "X-SecAI-Launcher-Token": TOKEN,
            },
        )
        with urllib.request.urlopen(request, timeout=3) as response:  # noqa: S310
            assert response.status == 202
        completed = _wait_for_completed(bridge.server_port)
        result_id = _mapping(completed["result"])["result_id"]

        code, launched = _launcher_request(
            bridge.server_port,
            "/v1/administrator/launch",
            payload=consent,
        )
        assert code == 202
        launched_administrator = _mapping(launched["administrator"])
        assert launched_administrator["status"] == ELEVATION_STARTED
        assert len(str(launched_administrator["result_token"])) == 43
        assert launched_administrator["automatic_elevation"] is False
        assert _mapping(launched["result"])["result_id"] == result_id
        assert launches == [SELECTED]

        code, reset = _launcher_request(
            bridge.server_port,
            "/v1/administrator/reset",
            payload={},
        )
        assert code == 200
        assert _mapping(reset["administrator"])["status"] == "NOT_REQUESTED"

        code, relaunched = _launcher_request(
            bridge.server_port,
            "/v1/administrator/launch",
            payload=consent,
        )
        assert code == 202
        assert _mapping(relaunched["administrator"])["status"] == ELEVATION_STARTED
        assert launches == [SELECTED, SELECTED]
    finally:
        bridge.shutdown()
        bridge.server_close()
        thread.join(timeout=3)


def test_uac_cancel_allows_retry_and_keeps_standard_result(tmp_path: Path) -> None:
    outcomes = iter((ELEVATION_CANCELLED, ELEVATION_STARTED))

    bridge = create_launcher_bridge(
        tmp_path,
        token=TOKEN,
        scan_runner=lambda _: _standard_receipt(),
        elevation_launcher=lambda _: next(outcomes),
        port=0,
    )
    thread = threading.Thread(target=bridge.serve_forever, daemon=True)
    thread.start()
    consent = {
        "consent": True,
        "consent_version": CONSENT_VERSION,
        "probe_ids": [SELECTED[0]],
    }
    try:
        request = urllib.request.Request(  # noqa: S310 - loopback test URL
            f"http://127.0.0.1:{bridge.server_port}/v1/scan",
            method="POST",
            data=b"",
            headers={"Origin": ORIGIN, "X-SecAI-Launcher-Token": TOKEN},
        )
        with urllib.request.urlopen(request, timeout=3):  # noqa: S310
            pass
        completed = _wait_for_completed(bridge.server_port)
        result_id = _mapping(completed["result"])["result_id"]

        code, cancelled = _launcher_request(
            bridge.server_port,
            "/v1/administrator/launch",
            payload=consent,
        )
        assert code == 200
        assert (
            _mapping(cancelled["administrator"])["status"]
            == ELEVATION_CANCELLED
        )
        assert _mapping(cancelled["result"])["result_id"] == result_id

        code, retried = _launcher_request(
            bridge.server_port,
            "/v1/administrator/launch",
            payload=consent,
        )
        assert code == 202
        assert (
            _mapping(retried["administrator"])["status"]
            == ELEVATION_STARTED
        )
        assert _mapping(retried["result"])["result_id"] == result_id
    finally:
        bridge.shutdown()
        bridge.server_close()
        thread.join(timeout=3)


def test_administrator_result_bridge_requires_exact_origin_and_token() -> None:
    result = build_administrator_results(_administrator_receipt())
    bridge = create_administrator_result_bridge(
        result,
        token=ADMIN_TOKEN,
        port=0,
    )
    assert bridge.allow_reuse_address is False
    assert bridge.allow_reuse_port is False
    thread = threading.Thread(target=bridge.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{bridge.server_port}/v1/status"
    try:
        request = urllib.request.Request(  # noqa: S310 - loopback test URL
            url,
            headers={
                "Origin": ORIGIN,
                "X-SecAI-Administrator-Token": ADMIN_TOKEN,
            },
        )
        with urllib.request.urlopen(request, timeout=3) as response:  # noqa: S310
            body = json.loads(response.read())
        assert response.status == 200
        assert body["selected_probe_count"] == 3
        assert response.headers["Cache-Control"] == "no-store"

        bad = urllib.request.Request(  # noqa: S310 - loopback test URL
            url,
            headers={
                "Origin": "https://example.invalid",
                "X-SecAI-Administrator-Token": ADMIN_TOKEN,
            },
        )
        with pytest.raises(urllib.error.HTTPError) as captured:
            urllib.request.urlopen(bad, timeout=3)  # noqa: S310
        assert captured.value.code == 403
    finally:
        bridge.shutdown()
        bridge.server_close()
        thread.join(timeout=3)


def test_product_ui_explains_five_options_and_separate_consent(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_DEMO_CSRF_TOKEN", "imp043-test-csrf")
    with TestClient(app) as client:
        response = client.get("/ui/results")
        features = client.get("/api/v1/product/features").json()["features"]

    assert response.status_code == 200
    assert response.text.count('name="administrator-probe"') == 5
    assert "다시 확인할 항목을 선택하세요" in response.text
    assert "이후에는 필요한 항목만 골라 다시 점검할 수 있습니다." in response.text
    assert 'id="administrator-consent"' in response.text
    assert f'data-consent-version="{CONSENT_VERSION}"' in response.text
    assert (
        "선택한 항목을 읽기 전용으로 다시 확인하기 위해 "
        "Windows 권한 확인창을 표시하는 데 동의합니다."
    ) in response.text
    assert 'id="administrator-result-panel"' not in response.text
    assert 'id="restart-administrator-scan"' not in response.text
    assert features["administrator_scan"]["state"] == "LIVE"
