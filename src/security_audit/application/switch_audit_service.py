"""승인된 Aruba 시험 장비의 REST 읽기 전용 KISA N-01~N-38 실행 서비스."""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from security_audit.application.audit_history import attach_device_history_context
from security_audit.common.canonical_json import JsonValue, canonical_sha256
from security_audit.persistence.database.switch_audit_repository import (
    append_switch_audit_event,
    finish_switch_audit_run,
    mark_switch_audit_running,
)
from security_audit.platforms import (
    AdapterSelection,
    AssetContext,
    DeviceAuditResult,
    PlatformFingerprint,
    current_platform_support_catalog,
    discover_aruba_aoscx_platform,
)
from security_audit.platforms.aruba_rest import (
    ArubaRestCollectionError,
    ArubaRestProjection,
    ArubaRestTarget,
    collect_aruba_rest_projection,
    evaluate_aruba_rest_baseline,
)
from security_audit.platforms.kisa_network import (
    KISA_NETWORK_CONTROLS,
    NETWORK_CONTROL_BY_ID,
    KisaNetworkAssessmentProfile,
)


@dataclass(frozen=True, slots=True)
class SwitchLabTarget:
    key: str
    label: str
    host: str
    platform_version: str
    certificate_pin_file: Path
    asset_id: UUID

    def public_view(self) -> dict[str, str]:
        return {
            "key": self.key,
            "label": self.label,
            "platform": "ARUBA_AOS_CX",
            "platform_version": self.platform_version,
            "connection": "HTTPS REST v10.13 · 인증서 고정 · 읽기 전용",
        }


_LEGACY_GENERIC_OBSERVED = frozenset(
    {
        "필요한 보안 설정을 구조화된 REST 응답에서 확인했습니다.",
        "필요한 보안 설정을 구조화된 REST 응답에서 확인하지 못했습니다.",
    }
)

_CONTROL_PRESENTATION = {
    "SW-01": {
        "what": "REST 로그인 권한과 현재 사용자의 관리자 권한을 확인했습니다.",
        "pass_observed": "REST 관리자 권한 인증: 성공",
        "fail_observed": "REST 관리자 권한 인증: 실패",
        "pass_reason": (
            "관리자 권한으로 REST 인증되어 비밀번호로 보호된 관리자 인증 기준을 "
            "충족합니다."
        ),
        "fail_reason": (
            "관리자 권한 REST 인증을 확인하지 못해 관리자 인증 보호 기준을 "
            "충족하지 않습니다."
        ),
    },
    "SW-02": {
        "what": "관리 VRF에서 SSH 서버가 활성화되어 있는지 확인했습니다.",
        "pass_observed": "관리 VRF SSH 서버: 활성화",
        "fail_observed": "관리 VRF SSH 서버: 비활성화",
        "pass_reason": (
            "관리 VRF의 SSH 서버가 활성화되어 원격 관리 SSH 사용 기준을 충족합니다."
        ),
        "fail_reason": (
            "관리 VRF의 SSH 서버가 비활성화되어 원격 관리 SSH 사용 기준을 "
            "충족하지 않습니다."
        ),
    },
    "SW-03": {
        "what": "SNMPv3 전용 모드와 인증·암호화 사용자가 함께 구성됐는지 확인했습니다.",
        "pass_observed": "SNMPv3 전용 모드와 인증·암호화 사용자: 기준 충족",
        "fail_observed": "SNMPv3 전용 모드 또는 인증·암호화 사용자: 기준 미충족",
        "pass_reason": (
            "SNMPv3 전용 모드와 인증·암호화 사용자가 모두 확인되어 안전한 SNMP "
            "설정 기준을 충족합니다."
        ),
        "fail_reason": (
            "SNMPv3 전용 모드 또는 인증·암호화 사용자 조건이 부족해 안전한 SNMP "
            "설정 기준을 충족하지 않습니다."
        ),
    },
    "SW-04": {
        "what": "사용 가능한 원격 syslog 서버가 구성되어 있는지 확인했습니다.",
        "pass_observed": "활성 원격 syslog 서버: 1개 이상",
        "fail_observed": "활성 원격 syslog 서버: 0개",
        "pass_reason": (
            "활성 원격 syslog 서버가 1개 이상 확인되어 원격 로그 전송 기준을 "
            "충족합니다."
        ),
        "fail_reason": (
            "활성 원격 syslog 서버가 없어 원격 로그 전송 기준을 충족하지 않습니다."
        ),
    },
    "SW-05": {
        "what": "NTP client와 관리 VRF의 NTP 서버 구성을 확인했습니다.",
        "pass_observed": "NTP client와 관리 VRF NTP 서버: 구성됨",
        "fail_observed": "NTP client 또는 관리 VRF NTP 서버: 기준 미충족",
        "pass_reason": (
            "NTP client가 활성화되고 관리 VRF의 NTP 서버가 확인되어 시각 동기화 "
            "기준을 충족합니다."
        ),
        "fail_reason": (
            "NTP client 활성화 또는 관리 VRF NTP 서버 구성이 부족해 시각 동기화 "
            "기준을 충족하지 않습니다."
        ),
    },
    "SW-06": {
        "what": "CLI와 HTTPS 관리 세션의 유휴 시간 제한을 확인했습니다.",
        "pass_observed": "CLI·HTTPS 유휴 제한: 각각 15분 이하",
        "fail_observed": "CLI·HTTPS 유휴 제한: 한 개 이상 미설정 또는 15분 초과",
        "pass_reason": (
            "CLI와 HTTPS 유휴 시간 제한이 모두 1~15분 범위여서 관리 세션 제한 "
            "기준을 충족합니다."
        ),
        "fail_reason": (
            "CLI 또는 HTTPS 유휴 시간 제한이 없거나 15분을 초과해 관리 세션 제한 "
            "기준을 충족하지 않습니다."
        ),
    },
}


def present_switch_control(control: Mapping[str, Any]) -> dict[str, Any]:
    """저장 결과의 판정을 바꾸지 않고 항목별 사용자 표시 문구를 구성합니다."""

    control_id = str(control.get("control_id", ""))
    details = _CONTROL_PRESENTATION.get(control_id)
    network_definition = NETWORK_CONTROL_BY_ID.get(control_id)
    if details is None and network_definition is None:
        raise ValueError("SWITCH_CONTROL_PRESENTATION_INVALID")
    status = str(control.get("status", ""))
    presented = dict(control)
    observed = control.get("observed_summary")
    if network_definition is not None:
        observed_text = (
            observed
            if isinstance(observed, str) and observed not in _LEGACY_GENERIC_OBSERVED
            else f"{network_definition.review_requirement}: 저장된 비식별 값 없음"
        )
        presented["observed_summary"] = observed_text
        presented["value_source"] = "REST_OBSERVED"
        presented["value_source_label"] = "내 스위치에서 확인한 값"
        presented["what_was_checked"] = (
            f"{network_definition.title}에 필요한 {network_definition.review_requirement}을 "
            "확인했습니다."
        )
        result_code = str(control.get("result_code", ""))
        organization_input = result_code.endswith("_ORGANIZATION_INPUT")
        if organization_input:
            status_label = {
                "PASS": "충족",
                "FAIL": "미충족",
                "REVIEW": "확인 필요",
                "N/A": "해당 없음",
            }.get(status, "확인 필요")
            presented["judgement_source"] = "ORGANIZATION_INPUT"
            presented["judgement_source_label"] = (
                "조직 보완 판정 입력 · 장비 수집값 아님"
            )
            presented["judgement_explanation"] = (
                f"{observed_text}. 장비 REST 값만으로 안전 여부를 확정하지 않고, "
                f"별도로 선택한 조직 보완 판정 '{status_label}'에 따라 개발용 상태를 "
                "표시했습니다. 이 판정값은 장비에서 수집한 값이 아닙니다."
            )
        elif status == "PASS":
            presented["judgement_explanation"] = (
                f"{observed_text}. 따라서 {network_definition.title}의 개발용 안전 조건을 "
                "충족합니다."
            )
        elif status == "FAIL":
            presented["judgement_explanation"] = (
                f"{observed_text}. 따라서 {network_definition.title}의 개발용 안전 조건을 "
                "충족하지 않습니다."
            )
        elif status == "REVIEW":
            presented["judgement_explanation"] = (
                f"{observed_text}. 이 값만으로 {network_definition.title}의 안전 여부를 "
                f"확정할 수 없어 {network_definition.review_requirement} 추가 확인이 필요합니다."
            )
        elif status == "ERROR":
            presented["judgement_explanation"] = (
                f"{network_definition.title} 판정에 필요한 값을 읽지 못해 안전 여부를 "
                "확정하지 않았습니다."
            )
        else:
            presented["judgement_explanation"] = (
                f"{observed_text}. 현재 구성에서는 {network_definition.title}의 적용 대상이 "
                "아닙니다."
            )
        presented["source_pages"] = network_definition.source_pages
        presented["severity"] = network_definition.severity
        presented["category"] = network_definition.category
        return presented

    if details is None:
        raise ValueError("SWITCH_CONTROL_PRESENTATION_INVALID")
    if not isinstance(observed, str) or observed in _LEGACY_GENERIC_OBSERVED:
        observed_key = "pass_observed" if status == "PASS" else "fail_observed"
        presented["observed_summary"] = details[observed_key]
    presented["what_was_checked"] = details["what"]
    if status == "PASS":
        presented["judgement_explanation"] = details["pass_reason"]
    elif status == "FAIL":
        presented["judgement_explanation"] = details["fail_reason"]
    elif status == "ERROR":
        presented["judgement_explanation"] = (
            f"{control_id} 판정에 필요한 REST 값을 정상적으로 읽지 못해 안전 여부를 "
            "확정하지 않았습니다."
        )
    elif status == "REVIEW":
        presented["judgement_explanation"] = (
            f"{control_id} 확인값만으로 안전 여부를 확정할 수 없어 추가 검토가 필요합니다."
        )
    else:
        presented["judgement_explanation"] = (
            f"{control_id}은 현재 스위치에 적용되지 않는 항목입니다."
        )
    return presented


def present_switch_controls(
    controls: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """N-01~N-38 및 과거 SW-01~06 저장 순서를 유지해 표시합니다."""

    return [present_switch_control(control) for control in controls]


def switch_lab_targets() -> dict[str, SwitchLabTarget]:
    runtime = Path(os.getenv("SECAI_SWITCH_RUNTIME_ROOT", "/run/secai-vmware"))
    key = "aruba-aos-cx-10.13.1170-lab"
    target = SwitchLabTarget(
        key=key,
        label="Aruba AOS-CX 10.13.1170 시험 스위치",
        host=os.getenv("SECAI_ARUBA_AOS_CX_HOST", "192.168.11.10"),
        platform_version="10.13.1170",
        certificate_pin_file=runtime / "aruba_https_certificate.sha256",
        asset_id=uuid5(NAMESPACE_URL, f"secai-switch-lab:{key}"),
    )
    return {key: target}


def _criteria_sha256(profile: KisaNetworkAssessmentProfile) -> str:
    return canonical_sha256(
        {
            "benchmark_id": "SECAI-KISA-2026-N01-N38-AOSCX-DRAFT",
            "benchmark_version": "0.4.0-DRAFT",
            "controls": [item.control_id for item in KISA_NETWORK_CONTROLS],
            "organization_criteria": profile.public_values(),
            "official_finding_write_allowed": False,
        }
    )


def resolve_switch_target_platform(
    target: SwitchLabTarget,
) -> tuple[PlatformFingerprint, AdapterSelection]:
    """등록된 단일 대상의 지원 버전과 REST Adapter를 추측 없이 선택합니다."""

    fingerprint = discover_aruba_aoscx_platform(
        version=target.platform_version,
        capabilities=("HTTPS_REST",),
    )
    return fingerprint, current_platform_support_catalog().resolve(fingerprint)


def build_switch_audit_result(
    *,
    run_id: UUID,
    target: SwitchLabTarget,
    projection: ArubaRestProjection,
    criteria_profile: KisaNetworkAssessmentProfile,
    started_at: datetime,
    completed_at: datetime,
) -> dict[str, JsonValue]:
    controls = evaluate_aruba_rest_baseline(
        projection,
        captured_at=completed_at,
        criteria_profile=criteria_profile,
    )
    supplemental_applied_controls = [
        item.control_id
        for item in controls
        if item.result_code.endswith("_ORGANIZATION_INPUT")
    ]
    result = DeviceAuditResult(
        schema_version="1.0.0",
        run_id=run_id,
        asset=AssetContext(
            asset_id=target.asset_id,
            asset_type="NETWORK_SWITCH",
            platform="ARUBA_AOS_CX",
            platform_version=target.platform_version,
            vendor="HPE Aruba Networking",
            product_family="AOS-CX Virtual",
        ),
        benchmark_id="SECAI-KISA-2026-N01-N38-AOSCX-DRAFT",
        benchmark_version="0.4.0-DRAFT",
        criteria_profile_id=None,
        criteria_sha256=_criteria_sha256(criteria_profile),
        started_at=started_at,
        completed_at=completed_at,
        controls=controls,
        criteria_summary={
            "scope": "DEVELOPMENT_DRAFT",
            "collection": "AOS-CX v10.13 fixed REST GET",
            "coverage": "KISA 2026 network equipment N-01 through N-38",
            "source_pages": "391~466",
            "criteria_profile": "KISA·SecAI Switch 안전 기준·조직 보완 판정",
            "organization_criteria": criteria_profile.public_values(),
            "organization_supplemental_assessments": (
                criteria_profile.supplemental_values()
            ),
            "organization_supplemental_assessment_count": len(
                criteria_profile.supplemental_values()
            ),
            "organization_supplemental_assessment_applied_count": len(
                supplemental_applied_controls
            ),
            "organization_supplemental_assessment_applied_controls": (
                cast(JsonValue, supplemental_applied_controls)
            ),
            "supplemental_assessments_are_device_observations": False,
            "observed_values_overwritten": False,
            "unproven_status_without_organization_input": "REVIEW",
            "official_finding_created": False,
        },
    )
    result_json = result.to_json()
    stored_controls = cast(list[dict[str, Any]], result_json["controls"])
    official_explanations = [
        present_switch_control(control) for control in stored_controls
    ]
    # 지연 import로 AI stream → switch service의 기존 의존 방향을 유지합니다.
    from security_audit.application.switch_ai_token_stream import (
        public_switch_control,
    )

    ai_explanation_inputs = [
        public_switch_control(control) for control in stored_controls
    ]
    return attach_device_history_context(
        result_json,
        official_explanations=official_explanations,
        ai_explanation_inputs=ai_explanation_inputs,
    )


def validate_stored_switch_result(
    result: dict[str, Any],
    expected_sha256: str,
) -> None:
    embedded = result.get("result_sha256")
    if not isinstance(embedded, str) or embedded != expected_sha256:
        raise ValueError("SWITCH_RESULT_HASH_MISMATCH")
    hash_input = dict(result)
    hash_input.pop("result_sha256", None)
    if canonical_sha256(cast(dict[str, JsonValue], hash_input)) != expected_sha256:
        raise ValueError("SWITCH_RESULT_CONTENT_MISMATCH")


ProjectionCollector = Callable[[ArubaRestTarget], ArubaRestProjection]


def collect_switch_audit_result(
    *,
    run_id: UUID,
    target: SwitchLabTarget,
    username: str,
    password: str,
    criteria_profile: KisaNetworkAssessmentProfile,
    started_at: datetime,
    collector: ProjectionCollector = collect_aruba_rest_projection,
) -> dict[str, JsonValue]:
    try:
        certificate_pin = target.certificate_pin_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ArubaRestCollectionError("CERTIFICATE_PIN_UNAVAILABLE") from exc
    projection = collector(
        ArubaRestTarget(
            host=target.host,
            username=username,
            password=password,
            certificate_sha256=certificate_pin,
        )
    )
    return build_switch_audit_result(
        run_id=run_id,
        target=target,
        projection=projection,
        criteria_profile=criteria_profile,
        started_at=started_at,
        completed_at=datetime.now(UTC),
    )


def _event(
    engine: Engine,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    event_type: str,
    payload: dict[str, object],
) -> None:
    with Session(engine) as session, session.begin():
        append_switch_audit_event(
            session,
            organization_id=organization_id,
            owner_user_id=owner_user_id,
            run_id=run_id,
            event_type=event_type,
            payload=payload,
        )


def start_switch_audit_thread(
    engine: Engine,
    *,
    run_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    target: SwitchLabTarget,
    username: str,
    password: str,
    criteria_profile: KisaNetworkAssessmentProfile,
) -> None:
    thread = threading.Thread(
        target=_run_switch_audit,
        kwargs={
            "engine": engine,
            "run_id": run_id,
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "target": target,
            "username": username,
            "password": password,
            "criteria_profile": criteria_profile,
        },
        name=f"switch-audit-{run_id}",
        daemon=True,
    )
    thread.start()


def _run_switch_audit(
    *,
    engine: Engine,
    run_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    target: SwitchLabTarget,
    username: str,
    password: str,
    criteria_profile: KisaNetworkAssessmentProfile,
) -> None:
    started_at = datetime.now(UTC)
    try:
        with Session(engine) as session, session.begin():
            mark_switch_audit_running(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                run_id=run_id,
            )
        _event(
            engine,
            organization_id,
            owner_user_id,
            run_id,
            "RUN_STARTED",
            {"asset": target.public_view(), "total_controls": len(KISA_NETWORK_CONTROLS)},
        )
        fingerprint, selection = resolve_switch_target_platform(target)
        _event(
            engine,
            organization_id,
            owner_user_id,
            run_id,
            "PLATFORM_IDENTIFIED",
            {
                "fingerprint": fingerprint.to_json(),
                "selection": selection.to_json(),
            },
        )
        result = collect_switch_audit_result(
            run_id=run_id,
            target=target,
            username=username,
            password=password,
            criteria_profile=criteria_profile,
            started_at=started_at,
        )
        result_sha256 = cast(str, result["result_sha256"])
        controls = cast(list[dict[str, JsonValue]], result["controls"])
        status_counts = {
            status: sum(1 for item in controls if item["status"] == status)
            for status in ("PASS", "FAIL", "ERROR", "REVIEW", "N/A")
        }
        with Session(engine) as session, session.begin():
            finish_switch_audit_run(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                run_id=run_id,
                status="COMPLETED",
                result_json=cast(dict[str, object], result),
                result_sha256=result_sha256,
            )
        _event(
            engine,
            organization_id,
            owner_user_id,
            run_id,
            "RUN_COMPLETED",
            {"result_sha256": result_sha256, "status_counts": status_counts},
        )
    except ArubaRestCollectionError as exc:
        _finish_failed(
            engine,
            organization_id=organization_id,
            owner_user_id=owner_user_id,
            run_id=run_id,
            error_code=exc.code,
        )
    except Exception as exc:
        import traceback
        traceback.print_exc()
        _finish_failed(
            engine,
            organization_id=organization_id,
            owner_user_id=owner_user_id,
            run_id=run_id,
            error_code="SWITCH_AUDIT_FAILED",
        )
    finally:
        password = ""


def _finish_failed(
    engine: Engine,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    error_code: str,
) -> None:
    with Session(engine) as session, session.begin():
        finish_switch_audit_run(
            session,
            organization_id=organization_id,
            owner_user_id=owner_user_id,
            run_id=run_id,
            status="FAILED",
            error_code=error_code,
        )
    _event(
        engine,
        organization_id,
        owner_user_id,
        run_id,
        "RUN_FAILED",
        {"error_code": error_code},
    )
