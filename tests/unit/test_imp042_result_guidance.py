from __future__ import annotations

import json
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, cast

from apps.api.main import app
from fastapi.testclient import TestClient

from security_audit.application.current_host_regression import (
    ProbeObservation,
    evaluate_live_draft_observations,
)
from security_audit.application.scan_result_guidance import (
    build_control_results,
    summarize_control_results,
)
from security_audit.collector.launcher import create_launcher_bridge

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ORIGIN = "http://127.0.0.1:18480"


def _standard_receipt(*, error_probe: str | None = None) -> dict[str, object]:
    allowlist = json.loads(
        (
            PROJECT_ROOT
            / "collectors"
            / "one_shot"
            / "contracts"
            / "imp031_probe_allowlist.json"
        ).read_text(encoding="utf-8")
    )
    results = []
    for probe in allowlist["probes"]:
        if probe["required_privilege"] != "STANDARD_USER":
            continue
        probe_id = probe["probe_id"]
        results.append(
            {
                "probe_id": probe_id,
                "control_ids": probe["control_ids"],
                "privilege": "STANDARD_USER",
                "collection_status": (
                    "ERROR" if probe_id == error_probe else "COLLECTED"
                ),
                "error_code": (
                    "READ_FAILED" if probe_id == error_probe else "NONE"
                ),
                "record_count": 0 if probe_id == error_probe else 1,
            }
        )
    assert len(results) == 15
    return {
        "observed_at_utc": "2026-07-24T01:02:03Z",
        "settings_diff_count": 0,
        "results": results,
    }


def _request(
    bridge_port: int,
    token: str,
    path: str,
    *,
    method: str = "GET",
) -> dict[str, Any]:
    request = urllib.request.Request(  # noqa: S310 - fixed loopback URL
        f"http://127.0.0.1:{bridge_port}{path}",
        method=method,
        data=b"" if method == "POST" else None,
        headers={
            "Origin": ORIGIN,
            "X-SecAI-Launcher-Token": token,
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(  # noqa: S310 - fixed loopback URL
        request,
        timeout=3,
    ) as response:
        return cast(dict[str, Any], json.loads(response.read()))


def _wait_completed(bridge_port: int, token: str) -> dict[str, Any]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        report = _request(bridge_port, token, "/v1/status")
        if report["status"] == "COMPLETED":
            return report
        time.sleep(0.01)
    raise AssertionError("Launcher did not complete.")


def test_imp042_policy_separates_collection_guidance_from_official_finding() -> None:
    policy = json.loads(
        (
            PROJECT_ROOT
            / "collectors"
            / "one_shot"
            / "contracts"
            / "imp042_result_guidance_policy.json"
        ).read_text(encoding="utf-8")
    )

    assert policy["control_count"] == 18
    assert policy["wording"]["evidence_collected_is_pass"] is False
    assert policy["recheck"]["history_append_only"] is True
    assert policy["safety"] == {
        "raw_windows_values_in_response": False,
        "raw_windows_values_persisted": False,
        "settings_modified": False,
        "automatic_remediation": False,
        "official_finding_created": False,
        "administrator_collection_started": False,
    }


def test_result_guidance_covers_18_controls_and_sorts_importance_first() -> None:
    controls = build_control_results(_standard_receipt())
    counts = summarize_control_results(controls)

    assert len(controls) == 18
    assert {item["control_id"] for item in controls} == {
        f"PC-{index:02d}" for index in range(1, 19)
    }
    importance = [str(item["importance"]) for item in controls]
    assert importance == sorted(importance, key={"상": 0, "중": 1}.__getitem__)
    assert counts == {
        "evidence_collected": 13,
        "review_required": 0,
        "administrator_required": 5,
    }
    assert all("source" in item and "action_guidance" in item for item in controls)
    assert "PASS" not in json.dumps(controls, ensure_ascii=False)


def test_collection_error_becomes_review_not_fail() -> None:
    controls = build_control_results(
        _standard_receipt(error_probe="win.user.screensaver-policy")
    )
    pc16 = next(item for item in controls if item["control_id"] == "PC-16")

    assert pc16["display_status"] == "REVIEW_REQUIRED"
    assert pc16["status_label"] == "추가 확인 필요"
    assert summarize_control_results(controls)["review_required"] == 1


def test_live_draft_assessment_exposes_safe_actual_expected_and_status() -> None:
    assessments = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=(
            ProbeObservation(
                probe_id="win.security.password-age",
                collection_status="COLLECTED",
                error_code="NONE",
                adapter_id="secai.windows-native",
                adapter_version="0.1.0",
                privilege="STANDARD_USER",
                collected_at="2026-07-24T01:02:03Z",
                records=({"maximum_password_age_days": 42},),
            ),
        ),
    )

    pc01 = assessments["PC-01"]
    assert pc01["status"] in {"PASS", "FAIL", "ERROR", "REVIEW", "N/A"}
    assert pc01["status_label"]
    assert "42" in str(pc01["actual"])
    assert pc01["expected"]
    assert pc01["result_code"]
    assert pc01["assessment_kind"] == "DEVELOPMENT_DRAFT"
    assert pc01["official_finding_created"] is False


def test_live_draft_assessment_marks_uncollected_controls_as_not_confirmed() -> None:
    assessments = evaluate_live_draft_observations(
        PROJECT_ROOT,
        observations=(
            ProbeObservation(
                probe_id="win.security.password-age",
                collection_status="COLLECTED",
                error_code="NONE",
                adapter_id="secai.windows-native",
                adapter_version="0.1.0",
                privilege="STANDARD_USER",
                collected_at="2026-07-24T01:02:03Z",
                records=({"maximum_password_age_days": 42},),
            ),
        ),
    )

    assert len(assessments) == 18
    assert assessments["PC-02"] == {
        "status": "ERROR",
        "status_label": "확인 필요 (ERROR)",
        "actual": "관리자 권한이 필요한 자료를 아직 확인하지 못했습니다",
        "expected": "해당 KISA 점검 기준 충족",
        "result_code": "LIVE_DRAFT_EVIDENCE_NOT_COLLECTED",
        "assessment_kind": "DEVELOPMENT_DRAFT",
        "official_finding_created": False,
    }


def test_recheck_appends_history_and_never_returns_raw_values(tmp_path: Path) -> None:
    calls = 0

    def scan_runner(_: Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return _standard_receipt(
            error_probe="win.user.screensaver-policy" if calls == 2 else None
        )

    token = "r" * 43
    bridge = create_launcher_bridge(
        tmp_path,
        token=token,
        scan_runner=scan_runner,
        port=0,
    )
    thread = threading.Thread(target=bridge.serve_forever, daemon=True)
    thread.start()
    try:
        first_start = _request(bridge.server_port, token, "/v1/scan", method="POST")
        assert first_start["status"] in {"RUNNING", "COMPLETED"}
        first = _wait_completed(bridge.server_port, token)
        job_id = first["job_id"]
        assert first["can_recheck"] is True
        assert len(first["history"]) == 1

        second_start = _request(
            bridge.server_port,
            token,
            "/v1/recheck",
            method="POST",
        )
        assert second_start["job_id"] == job_id
        second = _wait_completed(bridge.server_port, token)

        assert calls == 2
        assert second["job_id"] == job_id
        assert second["attempt"] == 2
        assert len(second["history"]) == 2
        assert [item["sequence"] for item in second["history"]] == [1, 2]
        assert second["result"]["changed_control_count"] == 1
        assert second["result"]["official_finding_created"] is False
        assert second["result"]["raw_values_persisted"] is False
        serialized = json.dumps(second, ensure_ascii=False)
        assert "registry_value" not in serialized
        assert "DefaultPassword" not in serialized
    finally:
        bridge.shutdown()
        bridge.server_close()
        thread.join(timeout=3)


def test_product_result_page_is_live_and_explains_non_official_boundary(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_DEMO_CSRF_TOKEN", "product-result-test-csrf")
    with TestClient(app) as client:
        page = client.get("/ui/results")
        features = client.get("/api/v1/product/features").json()["features"]

    assert page.status_code == 200
    for phrase in (
        "내 PC 점검 결과",
        "확인한 Windows 설정값",
        "이전 결과와 비교",
    ):
        assert phrase in page.text
    assert 'src="/static/app/product-results.js"' in page.text
    assert features["results"]["state"] == "LIVE"
    assert features["results"]["href"] == "/ui/result-center"
