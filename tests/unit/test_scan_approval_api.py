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
        "SecAI-Collector-Windows-x64.secai-scan.json"
    )
    assert _sidecar_filename("secai-linux-check-x86_64") == (
        "secai-linux-check-x86_64.secai-scan.json"
    )


def test_router_hands_the_code_over_a_token_protected_endpoint() -> None:
    paths = {path for path, _ in _routes()}

    assert "/api/v1/scan/approvals/{request_id}/grant" in paths


def test_poll_payload_never_carries_the_code() -> None:
    view = ScanApprovalView(
        request_id="46000000-0000-4000-8000-000000000010",
        device_name="DESKTOP-A17",
        state=ScanApprovalState.APPROVED,
        elevated_consent=True,
        decided_at=None,
        grant_code="ABCD-EFGH-JKLM-NPQR-STUV",
    )

    payload = _approval_view_payload(view)

    assert "grant_code" not in payload
    assert payload["state"] == "APPROVED"


def test_download_page_offers_the_sidecar_for_remote_servers() -> None:
    script = (
        PROJECT_ROOT / "apps/web/static/app/dev-signed-downloads.js"
    ).read_text(encoding="utf-8")

    assert '"/api/v1/scan/sidecar"' in script
    assert "artifact_filename" in script
    assert "secai-scan.json" in script


def test_one_button_downloads_the_program_and_its_settings_together() -> None:
    page = (
        PROJECT_ROOT / "apps/web/templates/pages/dev_signed_downloads.html"
    ).read_text(encoding="utf-8")
    script = (
        PROJECT_ROOT / "apps/web/static/app/dev-signed-downloads.js"
    ).read_text(encoding="utf-8")

    assert 'data-action="sidecar"' not in page
    assert page.count('data-action="browser"') == 2
    assert "설정 파일" in page
    assert "실행 파일과 같은 폴더" in page
    assert "downloadSidecar(card)" in script


def test_the_server_signs_every_sidecar_it_issues() -> None:
    source = (PROJECT_ROOT / "apps/api/scan_approval.py").read_text(encoding="utf-8")

    assert "signer_from_seed" in source
    assert "sign=" in source
    assert "SECAI_SCAN_SIDECAR_SIGNING_KEY_FILE" in source


def test_the_signing_secret_is_mounted_for_the_gateway() -> None:
    compose = (PROJECT_ROOT / "deploy/compose/compose.yml").read_text(encoding="utf-8")

    assert "scan_sidecar_signing_key" in compose
    assert "/run/secrets/scan_sidecar_signing_key" in compose


def test_the_dev_secret_bootstrap_creates_the_signing_seed() -> None:
    script = (PROJECT_ROOT / "tools/init-dev-secrets.ps1").read_text(encoding="utf-8")

    assert "scan_sidecar_signing_key" in script
