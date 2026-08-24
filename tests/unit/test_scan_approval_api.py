from __future__ import annotations

from pathlib import Path

from apps.api.scan_approval import (
    RegisterScanSessionBody,
    _approval_view_payload,
    router,
)

from security_audit.collector.scan_approval import (
    ScanApprovalState,
    ScanApprovalView,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _routes() -> set[tuple[str, frozenset[str]]]:
    return {
        (getattr(route, "path", ""), frozenset(getattr(route, "methods", set())))
        for route in router.routes
    }


def test_router_exposes_the_collector_and_owner_endpoints() -> None:
    paths = {path for path, _ in _routes()}

    assert "/api/v1/scan/approvals" in paths
    assert "/api/v1/scan/approvals/{request_id}" in paths
    assert "/ui/scan-approve" in paths
    assert "/ui/scan-approve/{request_id}/decision" in paths


def test_register_body_rejects_unknown_fields_and_keeps_the_device_name() -> None:
    body = RegisterScanSessionBody(
        token="abc.def",  # noqa: S106 - 형식만 확인하는 시험값입니다.
        device_name="DESKTOP-A17",
    )

    assert body.device_name == "DESKTOP-A17"
    assert RegisterScanSessionBody.model_config["extra"] == "forbid"


def test_poll_payload_hides_everything_except_the_decision() -> None:
    view = ScanApprovalView(
        request_id="46000000-0000-4000-8000-000000000010",
        device_name="DESKTOP-A17",
        state=ScanApprovalState.APPROVED,
        elevated_consent=True,
        decided_at=None,
    )

    payload = _approval_view_payload(view)

    assert payload == {
        "request_id": "46000000-0000-4000-8000-000000000010",
        "state": "APPROVED",
        "elevated_consent": True,
    }
    assert "device_name" not in payload


def test_approval_page_shows_the_target_device_and_the_elevated_consent_choice() -> None:
    page = (
        PROJECT_ROOT / "apps/web/templates/pages/scan_approve.html"
    ).read_text(encoding="utf-8")

    assert "{{ device_name }}" in page
    assert 'name="elevated_consent"' in page
    assert 'name="csrf_token"' in page
    assert 'value="APPROVE"' in page
    assert 'value="DECLINE"' in page
    assert "이 PC가 맞는지 확인" in page


def test_router_issues_the_download_sidecar_for_the_signed_collector() -> None:
    paths = {path for path, _ in _routes()}

    assert "/api/v1/scan/sidecar" in paths


def test_sidecar_filename_keeps_the_signed_artifact_untouched() -> None:
    from apps.api.scan_approval import _sidecar_filename

    assert _sidecar_filename("SecAI-Collector-Windows-x64.exe") == (
        "SecAI-Collector-Windows-x64.exe.secai-scan.json"
    )
    assert _sidecar_filename("secai-linux-check-x86_64") == (
        "secai-linux-check-x86_64.secai-scan.json"
    )
