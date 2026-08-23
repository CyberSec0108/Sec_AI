from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from apps.api import switch_audit as switch_api
from apps.api.switch_audit import StartSwitchAuditBody
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from security_audit.application.device_report import build_switch_report_document
from security_audit.application.product_features import home_feature_registry
from security_audit.application.switch_ai_token_stream import (
    SwitchAITokenStreamService,
    public_switch_control,
)
from security_audit.application.switch_audit_service import (
    SwitchLabTarget,
    build_switch_audit_result,
    present_switch_control,
    present_switch_controls,
    resolve_switch_target_platform,
)
from security_audit.common.canonical_json import JsonValue
from security_audit.llm import ChatCompletionInput, ChatCompletionStreamChunk
from security_audit.persistence.database.switch_audit_repository import (
    SwitchAuditRunRecord,
)
from security_audit.platforms.aruba_rest import ArubaRestProjection
from security_audit.platforms.kisa_network import (
    NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS,
    KisaNetworkAssessmentProfile,
)
from security_audit.security.auth import AuthenticatedPrincipal, HumanRole
from security_audit.security.rbac import Permission, authorize

NOW = datetime(2026, 8, 6, tzinfo=UTC)
RUN_ID = UUID("c1aa8a2d-2481-4ea0-a0d2-76244a1164a7")
ASSET_ID = UUID("530130f1-a5f4-5a3d-8d13-cfd20e661511")
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _target() -> SwitchLabTarget:
    return SwitchLabTarget(
        key="aruba-aos-cx-10.13.1170-lab",
        label="Aruba AOS-CX 10.13.1170 시험 스위치",
        host="192.168.11.10",
        platform_version="10.13.1170",
        certificate_pin_file=Path("/run/secai-vmware/aruba_https_certificate.sha256"),
        asset_id=ASSET_ID,
    )


def _synthetic_credential() -> str:
    return "synthetic-" + "credential"


def test_switch_target_auto_selects_aoscx_rest_adapter_without_vendor_input() -> None:
    fingerprint, selection = resolve_switch_target_platform(_target())

    assert fingerprint.vendor == "HPE_ARUBA"
    assert fingerprint.product_family == "AOS_CX"
    assert selection.adapter_id == "secai.aruba-aos-cx.rest.v1"
    assert selection.audit_pack_id == "KISA-NETWORK-N01-N38"


def _secure_projection() -> ArubaRestProjection:
    return ArubaRestProjection(
        api_version="v10.13",
        controls={f"SW-0{index}": True for index in range(1, 7)},
        canonical_bytes=b'{"redaction_applied":true}',
        facts={
            "auth.admin_password_set": True,
            "identity.password_complexity_enabled": True,
            "identity.password_storage_encrypted": True,
            "identity.ssh_maximum_authentication_attempts": 3,
            "identity.builtin_role_count": 3,
            "identity.rbac_rule_count": 0,
            "identity.user_count": 2,
            "identity.administrator_user_count": 1,
            "identity.non_administrator_user_count": 1,
            "identity.unknown_role_user_count": 0,
            "management.ssh_allowlist_enabled": True,
            "management.ssh_allowlist_count": 1,
            "management.cli_timeout_minutes": 10,
            "management.web_timeout_minutes": 10,
            "management.mgmt_ssh_enabled": True,
            "management.telnet_enabled_vrf_count": 0,
            "management.usb_auxiliary_disabled": True,
            "management.bluetooth_disabled": True,
            "management.login_banner_configured": True,
            "management.login_banner_discloses_system_information": False,
            "management.https_enabled_vrf_count": 1,
            "management.https_non_management_vrf_count": 0,
            "logging.remote_server_count": 1,
            "logging.auditable_remote_server_count": 1,
            "logging.persistent_storage_configured": True,
            "logging.notification_threshold_configured": True,
            "logging.event_timestamp_present": True,
            "time.ntp_client_enabled": True,
            "time.ntp_server_count": 1,
            "snmp.enabled_vrf_count": 1,
            "snmp.v3_only": True,
            "snmp.community_count": 0,
            "snmp.community_acl_count": 0,
            "snmp.user_count": 1,
            "snmp.secure_read_only_user_count": 1,
            "snmp.non_management_vrf_count": 0,
            "discovery.cdp_mode": "disable",
            "network.icmp_unreachable_disabled": True,
            "network.icmp_redirect_disabled": True,
            "network.routed_interface_count": 1,
            "network.source_lockdown_interface_count": 1,
            "network.physical_interface_count": 0,
            "network.active_physical_interface_count": 0,
            "network.active_undocumented_interface_count": 0,
            "network.directed_broadcast_enabled_count": 0,
            "network.proxy_arp_enabled_count": 0,
            "network.dns_server_count": 0,
            "network.copp_effective_policy": True,
            "platform.software_version": "Virtual.10.13.1170",
            "platform.hot_patch_count": 0,
            "platform.family": "AOS-CX",
        },
    )


def _principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=uuid4(),
        username="switch-user",
        display_name="스위치 점검 사용자",
        organization_id=uuid4(),
        roles=frozenset({HumanRole.USER}),
        asset_ids=frozenset(),
        auth_methods=frozenset({"PASSWORD", "DEV_CODE"}),
        session_created_at=NOW,
        reauthenticated_at=NOW,
    )


class _StreamingModel:
    def __init__(self) -> None:
        self.requests: list[ChatCompletionInput] = []

    def stream(self, request: ChatCompletionInput) -> Iterator[ChatCompletionStreamChunk]:
        self.requests.append(request)
        yield ChatCompletionStreamChunk(
            model_id="test",
            content_delta="## 1. 왜 중요한가요?\n\n",
        )
        yield ChatCompletionStreamChunk(
            model_id="test",
            content_delta="스위치 관리면 보호가 필요합니다.[1][2][3]",
        )
        yield ChatCompletionStreamChunk(model_id="test", content_delta="", finish_reason="stop")


def test_switch_feature_is_live_and_opens_dedicated_scan_page() -> None:
    feature = home_feature_registry()["network_switch_scan"]

    assert feature.state.value == "LIVE"
    assert feature.href == "/ui/switch-scan"
    assert "Aruba AOS-CX" in feature.availability


def test_switch_result_is_redacted_and_contains_all_network_controls() -> None:
    projection = _secure_projection()

    result = build_switch_audit_result(
        run_id=RUN_ID,
        target=_target(),
        projection=projection,
        criteria_profile=KisaNetworkAssessmentProfile(),
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )

    assert result["run_id"] == str(RUN_ID)
    asset = cast(dict[str, JsonValue], result["asset"])
    controls = cast(list[dict[str, JsonValue]], result["controls"])
    assert asset["platform"] == "ARUBA_AOS_CX"
    assert [item["control_id"] for item in controls] == [
        f"N-{index:02d}" for index in range(1, 39)
    ]
    rendered = str(result).casefold()
    assert "password" not in rendered
    assert "cookie" not in rendered
    assert result["raw_evidence_included"] is False
    assert len(cast(list[object], result["official_explanations"])) == 38
    assert len(cast(list[object], result["ai_explanation_inputs"])) == 38


def test_switch_start_body_masks_password() -> None:
    credential = _synthetic_credential()
    body = StartSwitchAuditBody(
        asset_key="aruba-aos-cx-10.13.1170-lab",
        username="admin",
        password=SecretStr(credential),
        criteria=KisaNetworkAssessmentProfile().public_values(),
    )

    assert credential not in repr(body)


def test_switch_start_requires_closed_structured_criteria_values() -> None:
    payload = {
        "asset_key": "aruba-aos-cx-10.13.1170-lab",
        "username": "admin",
        "password": _synthetic_credential(),
        "criteria": KisaNetworkAssessmentProfile().public_values(),
    }

    body = StartSwitchAuditBody.model_validate(payload)

    assert body.criteria["tftp_disabled"] is True


def test_switch_start_body_rejects_unregistered_target_and_network_overrides() -> None:
    payload = {
        "asset_key": "unregistered-switch",
        "username": "admin",
        "password": _synthetic_credential(),
        "host": "203.0.113.10",
    }

    with pytest.raises(ValidationError):
        StartSwitchAuditBody.model_validate(payload)


def test_switch_execute_permission_excludes_approval_only_role() -> None:
    user = _principal()
    approver = AuthenticatedPrincipal(
        user_id=user.user_id,
        username=user.username,
        display_name=user.display_name,
        organization_id=user.organization_id,
        roles=frozenset({HumanRole.APPROVER}),
        asset_ids=user.asset_ids,
        auth_methods=user.auth_methods,
        session_created_at=user.session_created_at,
        reauthenticated_at=user.reauthenticated_at,
    )

    assert authorize(user, Permission.SWITCH_AUDIT_EXECUTE).allowed is True
    assert authorize(approver, Permission.SWITCH_AUDIT_EXECUTE).allowed is False


def test_switch_start_api_checks_csrf_and_never_returns_password(
    monkeypatch: Any,
) -> None:
    principal = _principal()
    credential = _synthetic_credential()
    started: dict[str, object] = {}

    monkeypatch.setattr(switch_api, "_require_switch_access", lambda request: principal)
    monkeypatch.setattr(switch_api, "_audit_access", lambda *args, **kwargs: None)
    monkeypatch.setattr(switch_api, "_engine", lambda: object())
    monkeypatch.setattr(
        switch_api,
        "_begin_switch_run",
        lambda **kwargs: (RUN_ID, False),
    )

    def fake_start(**kwargs: object) -> None:
        started.update(kwargs)

    monkeypatch.setattr(switch_api, "start_switch_audit_thread", fake_start)
    checked: list[str | None] = []
    monkeypatch.setattr(
        switch_api,
        "verify_browser_csrf",
        lambda request, token: checked.append(token),
    )
    app = FastAPI()
    app.include_router(switch_api.router)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/switch/audits",
            headers={"X-CSRF-Token": "csrf-value"},
            json={
                "asset_key": "aruba-aos-cx-10.13.1170-lab",
                "username": "admin",
                "password": credential,
                "criteria": KisaNetworkAssessmentProfile().public_values(),
            },
        )

    assert response.status_code == 202
    assert response.json() == {"run_id": str(RUN_ID), "reused": False}
    assert checked == ["csrf-value"]
    assert started["password"] == credential
    assert started["criteria_profile"] == KisaNetworkAssessmentProfile()
    assert credential not in response.text


def test_switch_scan_page_has_unpopulated_password_field(monkeypatch: Any) -> None:
    monkeypatch.setenv("SECAI_DEMO_CSRF_TOKEN", "switch-ui-test-csrf")
    monkeypatch.setattr(switch_api, "_require_switch_access", lambda request: _principal())
    app = FastAPI()
    app.include_router(switch_api.router)

    with TestClient(app) as client:
        response = client.get("/ui/switch-scan")

    assert response.status_code == 200
    assert "Aruba AOS-CX 10.13.1170" in response.text
    assert 'type="password"' in response.text
    assert 'value="synthetic-credential"' not in response.text
    assert 'name="host"' not in response.text
    assert 'name="certificate"' not in response.text
    assert response.text.count('data-control-id="N-') == 38
    assert "N-01~N-38 점검 시작" in response.text
    assert response.text.count("data-switch-criteria-key=") == 28
    assert response.text.count("data-switch-supplemental-key=") == 2
    assert "조직 보완 판정값" in response.text
    assert "장비 수집값이 아닙니다" in response.text
    assert "장비에서 수집한 값은 바뀌지 않습니다" in response.text
    assert "기본 점검값으로 되돌리기" in response.text


def test_legacy_generic_switch_result_is_presented_with_control_specific_reason() -> None:
    control = {
        "control_id": "SW-02",
        "title": "원격 관리 SSH 사용",
        "status": "PASS",
        "observed_summary": "필요한 보안 설정을 구조화된 REST 응답에서 확인했습니다.",
        "expected_summary": "관리 VRF의 SSH 서버 활성화",
    }

    presented = present_switch_control(control)

    assert presented["what_was_checked"] == (
        "관리 VRF에서 SSH 서버가 활성화되어 있는지 확인했습니다."
    )
    assert presented["observed_summary"] == "관리 VRF SSH 서버: 활성화"
    assert presented["judgement_explanation"] == (
        "관리 VRF의 SSH 서버가 활성화되어 원격 관리 SSH 사용 기준을 충족합니다."
    )


def test_n01_n38_cards_have_control_specific_values_reasons_and_sources() -> None:
    result = build_switch_audit_result(
        run_id=RUN_ID,
        target=_target(),
        projection=_secure_projection(),
        criteria_profile=KisaNetworkAssessmentProfile(),
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )
    controls = cast(list[dict[str, Any]], result["controls"])
    presented = present_switch_controls(controls)

    assert len(presented) == 38
    assert len({item["observed_summary"] for item in presented}) == 38
    assert len({item["judgement_explanation"] for item in presented}) == 38
    assert presented[0]["source_pages"] == "391~394"
    assert presented[-1]["source_pages"] == "466"


def test_switch_result_snapshots_criteria_without_changing_rest_observation() -> None:
    defaults = KisaNetworkAssessmentProfile()
    changed_values = defaults.public_values()
    changed_values["n12_patch_advisory_assessment"] = "FAIL"
    changed = KisaNetworkAssessmentProfile.from_values(changed_values)

    default_result = build_switch_audit_result(
        run_id=RUN_ID,
        target=_target(),
        projection=_secure_projection(),
        criteria_profile=defaults,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )
    changed_result = build_switch_audit_result(
        run_id=RUN_ID,
        target=_target(),
        projection=_secure_projection(),
        criteria_profile=changed,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )
    default_n12 = cast(list[dict[str, Any]], default_result["controls"])[11]
    changed_n12 = cast(list[dict[str, Any]], changed_result["controls"])[11]
    criteria_summary = cast(dict[str, Any], changed_result["criteria_summary"])

    assert default_result["criteria_sha256"] != changed_result["criteria_sha256"]
    assert default_result["result_sha256"] != changed_result["result_sha256"]
    assert default_n12["observed_summary"] == changed_n12["observed_summary"]
    assert default_n12["status"] == "PASS"
    assert changed_n12["status"] == "FAIL"
    assert default_n12["expected_summary"] != changed_n12["expected_summary"]
    assert criteria_summary["organization_criteria"] == changed.public_values()
    assert criteria_summary["organization_supplemental_assessments"] == (
        changed.supplemental_values()
    )
    assert criteria_summary["organization_supplemental_assessment_applied_count"] == 2
    assert criteria_summary["observed_values_overwritten"] is False


def test_switch_result_page_renders_all_integrity_checked_controls(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEMO_CSRF_TOKEN", "switch-result-test-csrf")
    projection = _secure_projection()
    result = build_switch_audit_result(
        run_id=RUN_ID,
        target=_target(),
        projection=projection,
        criteria_profile=KisaNetworkAssessmentProfile(),
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )
    result_sha256 = cast(str, result["result_sha256"])
    record = SwitchAuditRunRecord(
        id=RUN_ID,
        asset_key=_target().key,
        asset_id=ASSET_ID,
        platform="ARUBA_AOS_CX",
        platform_version="10.13.1170",
        status="COMPLETED",
        result_json=cast(dict[str, Any], result),
        result_sha256=result_sha256,
        error_code=None,
        created_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )
    monkeypatch.setattr(switch_api, "_require_switch_access", lambda request: _principal())
    monkeypatch.setattr(switch_api, "_load_run", lambda principal, run_id: record)
    app = FastAPI()
    app.include_router(switch_api.router)

    with TestClient(app) as client:
        response = client.get(f"/ui/switch-results?run_id={RUN_ID}")

    assert response.status_code == 200
    assert response.text.count('class="integrated-control-card') == 38
    assert '/static/app/restricted-markdown.js' in response.text
    assert '/static/app/switch-results.js' in response.text
    assert 'id="switch-integrated-results"' in response.text
    assert 'id="switch-ai-summary"' in response.text
    assert 'id="switch-ai-start"' in response.text
    assert 'id="switch-result-report-panel"' in response.text
    assert 'id="switch-user-pdf"' in response.text
    assert 'id="switch-technical-pdf"' in response.text
    assert f"/api/v1/switch/audits/{RUN_ID}/report.pdf?kind=USER" in response.text
    assert f"/api/v1/switch/audits/{RUN_ID}/report.pdf?kind=TECHNICAL" in response.text
    assert 'id="switch-recheck-panel"' in response.text
    assert "결과 보고서(PDF) 받기" in response.text
    assert "현재 설정된 모델 게이트웨이로 전달됩니다" in response.text
    assert "무엇을 확인했나요" in response.text
    assert "내 스위치에서 확인한 값" in response.text
    assert "적용된 안전 기준" in response.text
    assert "판정 이유" in response.text
    assert "판정 출처" not in response.text
    assert "점검 전에 선택한 조직 보완 판정" in response.text
    assert (
        f"조직 입력 판정값 {len(NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS)}개를 저장했고"
        in response.text
    )
    assert "관리 VRF SSH: 활성화, Telnet 활성 VRF: 0개" in response.text
    assert "N-01~N-38 결과 요약" in response.text
    assert "필요한 보안 설정을 구조화된 REST 응답에서 확인했습니다." not in response.text
    assert "확인값이 적용된 안전 기준을 충족합니다." not in response.text
    assert "AI 상세 설명" in response.text
    assert result_sha256 in response.text
    assert "공식 Finding은 생성하지 않았습니다" in response.text
    assert _synthetic_credential() not in response.text


def test_switch_reports_match_user_and_technical_information_boundaries() -> None:
    result = build_switch_audit_result(
        run_id=RUN_ID,
        target=_target(),
        projection=_secure_projection(),
        criteria_profile=KisaNetworkAssessmentProfile(),
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )

    user_report = build_switch_report_document(result, technical=False)
    technical_report = build_switch_report_document(result, technical=True)
    user_text = "\n".join(user_report.lines)
    technical_text = "\n".join(technical_report.lines)

    assert "네트워크 스위치 보안 점검 보고서" in user_report.title
    assert user_report.report_kind.value == "USER"
    assert technical_report.report_kind.value == "TECHNICAL"
    assert user_text.count("N-") >= 38
    assert "개발용 DRAFT 판정" in user_text
    assert "조직 보완 판정" in user_text
    assert "KISA 근거:" in user_text
    assert "내부 판정 코드:" not in user_text
    assert "원문 해시:" not in user_text
    assert "기술 확인 위치:" not in user_text
    assert "내부 판정 코드:" in technical_text
    assert "원문 해시:" in technical_text
    assert "정규화 해시:" in technical_text
    assert "기술 확인 위치:" in technical_text
    assert _synthetic_credential() not in user_text
    assert _synthetic_credential() not in technical_text


def test_switch_pdf_api_allows_user_report_and_protects_technical_report(
    monkeypatch: Any,
) -> None:
    result = build_switch_audit_result(
        run_id=RUN_ID,
        target=_target(),
        projection=_secure_projection(),
        criteria_profile=KisaNetworkAssessmentProfile(),
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )
    record = SwitchAuditRunRecord(
        id=RUN_ID,
        asset_key=_target().key,
        asset_id=ASSET_ID,
        platform="ARUBA_AOS_CX",
        platform_version="10.13.1170",
        status="COMPLETED",
        result_json=cast(dict[str, Any], result),
        result_sha256=cast(str, result["result_sha256"]),
        error_code=None,
        created_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )
    monkeypatch.setattr(switch_api, "_require_switch_access", lambda request: _principal())
    monkeypatch.setattr(switch_api, "_load_completed_run", lambda *_args: record)
    app = FastAPI()
    app.include_router(switch_api.router)

    with TestClient(app) as client:
        user_report = client.get(
            f"/api/v1/switch/audits/{RUN_ID}/report.pdf?kind=USER"
        )
        technical_report = client.get(
            f"/api/v1/switch/audits/{RUN_ID}/report.pdf?kind=TECHNICAL"
        )

    assert user_report.status_code == 200
    assert user_report.content.startswith(b"%PDF-1.4")
    assert user_report.headers["content-type"] == "application/pdf"
    assert "switch-n01-n38" in user_report.headers["content-disposition"]
    assert user_report.headers["cache-control"] == "no-store"
    assert technical_report.status_code == 403


def test_switch_ai_uses_kisa_source_without_claiming_approved_pack() -> None:
    projection = _secure_projection()
    result = build_switch_audit_result(
        run_id=RUN_ID,
        target=_target(),
        projection=projection,
        criteria_profile=KisaNetworkAssessmentProfile(),
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )
    controls = cast(list[dict[str, Any]], result["controls"])
    public = public_switch_control(controls[0])
    model = _StreamingModel()

    deltas = list(SwitchAITokenStreamService(model).stream_control(controls[0]))

    assert deltas == [
        "## 1. 왜 중요한가요?\n\n",
        "스위치 관리면 보호가 필요합니다.[1][2][3]",
    ]
    assert public["source_grades"] == {
        "1": "이 스위치의 실제 확인값",
        "2": "KISA 2026 원문·개발용 AOS-CX 판정 매핑",
        "3": "AI 일반 보안지식(설명 보조)",
    }
    prompt = model.requests[0].messages[0].content
    payload = model.requests[0].messages[-1].content
    assert "Aruba AOS-CX" in prompt
    assert "## 2. 이 스위치 결과의 의미" in prompt
    assert "KISA 원문은 공식 출처" in prompt
    assert "Audit Pack은 DRAFT" in prompt
    assert '"rule_status"' not in payload
    assert '"status_authority"' not in payload
    assert "password" not in payload.casefold()
    assert "cookie" not in payload.casefold()


def test_switch_result_javascript_streams_summary_controls_and_sources() -> None:
    script = (PROJECT_ROOT / "apps/web/static/app/switch-results.js").read_text(
        encoding="utf-8"
    )

    assert "/api/v1/switch/audits/${runId}/ai/stream" in script
    assert '"X-CSRF-Token": csrf' in script
    assert "result_context_processing_approved: true" in script
    assert "response.body.getReader()" in script
    assert 'type === "SUMMARY_STARTED"' in script
    assert 'type === "CONTROL_STARTED"' in script
    assert 'type === "CONTROL_DELTA"' in script
    assert 'type === "CONTROL_FAILED"' in script
    assert "SecAIRestrictedMarkdown" in script
    assert "allowedCitationIds" in script
    assert "knowledge_sources" in script
    assert "createStreamingRenderer" in script
    assert "/api/v1/switch/audits/${runId}/ai/cancel" in script
    assert 'startButton.addEventListener("click"' in script
    assert "void startAI();\n}());" not in script


def test_switch_ai_api_streams_summary_and_all_network_controls(
    monkeypatch: Any,
) -> None:
    projection = _secure_projection()
    result = build_switch_audit_result(
        run_id=RUN_ID,
        target=_target(),
        projection=projection,
        criteria_profile=KisaNetworkAssessmentProfile(),
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )
    for control in cast(list[dict[str, Any]], result["controls"]):
        control["observed_summary"] = (
            "필요한 보안 설정을 구조화된 REST 응답에서 확인했습니다."
        )
    record = SwitchAuditRunRecord(
        id=RUN_ID,
        asset_key=_target().key,
        asset_id=ASSET_ID,
        platform="ARUBA_AOS_CX",
        platform_version="10.13.1170",
        status="COMPLETED",
        result_json=cast(dict[str, Any], result),
        result_sha256=cast(str, result["result_sha256"]),
        error_code=None,
        created_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )

    class _FakeService:
        def __init__(self, _model: object) -> None:
            pass

        def stream_summary(
            self, _controls: object, *, profile: str
        ) -> Iterator[str]:
            yield "## 1. 전체 상태\n\n전체 요약"

        def stream_control(
            self, control: dict[str, object], *, profile: str
        ) -> Iterator[str]:
            yield f"{control['control_id']} AI 설명[1][2][3]"

    principal = _principal()
    monkeypatch.setattr(switch_api, "_require_switch_access", lambda request: principal)
    monkeypatch.setattr(switch_api, "_load_completed_run", lambda *_args: record)
    monkeypatch.setattr(switch_api, "verify_browser_csrf", lambda *_args: None)
    monkeypatch.setattr(
        switch_api,
        "_load_ai_output_best_effort",
        lambda **_kwargs: "과거 공통 확인값으로 생성된 캐시",
    )
    monkeypatch.setattr(switch_api, "_store_ai_output_best_effort", lambda **_kwargs: True)
    monkeypatch.setattr(switch_api, "SwitchAITokenStreamService", _FakeService)
    monkeypatch.setattr(
        switch_api.InternalModelGatewayClient,
        "from_environment",
        staticmethod(lambda: object()),
    )
    app = FastAPI()
    app.include_router(switch_api.router)

    with TestClient(app) as client:
        rejected = client.post(
            f"/api/v1/switch/audits/{RUN_ID}/ai/stream",
            headers={"X-CSRF-Token": "csrf-value"},
            json={"profile": "FAST"},
        )
        response = client.post(
            f"/api/v1/switch/audits/{RUN_ID}/ai/stream",
            headers={"X-CSRF-Token": "csrf-value"},
            json={"profile": "FAST", "result_context_processing_approved": True},
        )

    assert rejected.status_code == 422
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.text.count("event: CONTROL_STARTED") == 38
    assert response.text.count("event: CONTROL_COMPLETED") == 38
    assert "event: SUMMARY_STARTED" in response.text
    assert "event: ANALYSIS_COMPLETED" in response.text
    assert "과거 공통 확인값으로 생성된 캐시" not in response.text
    assert "password" not in response.text.casefold()
    assert "cookie" not in response.text.casefold()


def test_switch_migration_enforces_owner_scope_and_one_active_run() -> None:
    migration = (
        Path(__file__).resolve().parents[2]
        / "database/alembic/versions/0025_switch_audit_ui.py"
    ).read_text(encoding="utf-8")

    assert 'down_revision: str | None = "0024_linux_oneshot_active"' in migration
    assert "FORCE ROW LEVEL SECURITY" in migration
    assert "uq_switch_audit_one_active" in migration
    assert "GRANT SELECT, INSERT, UPDATE ON switch_audit_runs TO secai_runtime" in migration


def test_switch_ai_output_migration_is_append_only_and_owner_scoped() -> None:
    migration = (
        PROJECT_ROOT
        / "database/alembic/versions/0026_switch_audit_ai_outputs.py"
    ).read_text(encoding="utf-8")

    assert 'down_revision: str | None = "0025_switch_audit_ui"' in migration
    assert "CREATE TABLE switch_audit_ai_outputs" in migration
    assert "REFERENCES switch_audit_runs(id) ON DELETE RESTRICT" in migration
    assert "FORCE ROW LEVEL SECURITY" in migration
    assert "GRANT SELECT, INSERT ON switch_audit_ai_outputs TO secai_runtime" in migration
    assert "UPDATE switch_audit_ai_outputs" not in migration


def test_switch_n01_n38_ai_cache_migration_preserves_legacy_keys() -> None:
    migration = (
        PROJECT_ROOT
        / "database/alembic/versions/0027_switch_n01_n38_ai_keys.py"
    ).read_text(encoding="utf-8")

    assert 'down_revision: str | None = "0026_switch_audit_ai_outputs"' in migration
    assert "V1:(SW-0[1-6]|SUMMARY)" in migration
    assert "V2:(N-(0[1-9]|[12][0-9]|3[0-8])|SUMMARY)" in migration


def test_switch_completed_ai_snapshot_requires_summary_and_all_38_controls() -> None:
    result = build_switch_audit_result(
        run_id=RUN_ID,
        target=_target(),
        projection=_secure_projection(),
        criteria_profile=KisaNetworkAssessmentProfile(),
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=2),
    )
    controls = cast(list[object], result["controls"])
    outputs = {"V2:SUMMARY": "저장된 Switch 종합 설명"}
    outputs.update(
        {f"V2:N-{number:02d}": f"N-{number:02d} 저장 설명" for number in range(1, 39)}
    )

    snapshot = switch_api._completed_switch_ai_snapshot(controls, outputs)

    assert snapshot["available"] is True
    assert snapshot["total_controls"] == 38
    restored = snapshot["controls"]
    assert isinstance(restored, list)
    assert restored[-1]["content"] == "N-38 저장 설명"
    del outputs["V2:N-38"]
    assert switch_api._completed_switch_ai_snapshot(controls, outputs) == {
        "available": False,
        "version": "V2",
    }
