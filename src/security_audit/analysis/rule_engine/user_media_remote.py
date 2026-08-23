"""Deterministic IMP-025 rules for KISA PC-16 through PC-18."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Never, cast


class UserMediaRemoteRuleError(ValueError):
    """Reject malformed evidence or non-allowlisted IMP-025 rules."""


@dataclass(frozen=True, slots=True)
class UserMediaRemoteDecision:
    """Immutable PC-16~18 decision for the synthetic development screen."""

    control_id: str
    status: str
    result_code: str
    actual: str
    expected: str
    scope_label: str
    rationale_code: str
    error_codes: tuple[str, ...]
    policy_source: str
    coverage: str

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["error_codes"] = list(self.error_codes)
        return value


_RULES: dict[str, dict[str, object]] = {
    "PC-16": {
        "probe_id": "win.user.screensaver-policy",
        "subject_scope": "USER",
        "applicability": ("pc16.user-screensaver-applicability", "0.1.0"),
        "evaluation": ("pc16.screensaver-lock", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "USER",
            "current_user_evaluation": True,
            "asset_coverage_field": "user_coverage_complete",
            "incomplete_coverage_status": "REVIEW",
            "collection_failure_status": "ERROR",
        },
        "evaluation_parameters": {
            "required_active_value": "1",
            "minimum_timeout_seconds": 1,
            "maximum_timeout_seconds": 600,
            "required_secure_value": "1",
            "screen_saver_executable_decisive": False,
            "violation_status": "FAIL",
            "collection_failure_status": "ERROR",
        },
    },
    "PC-17": {
        "probe_id": "win.media.autoplay-policy",
        "subject_scope": "POLICY",
        "applicability": ("pc17.removable-media-applicability", "0.1.0"),
        "evaluation": ("pc17.removable-media-controls", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "POLICY",
            "supported_policy_sources": ["LOCAL", "DOMAIN", "MDM", "WINDOWS_EFFECTIVE"],
            "collection_failure_status": "ERROR",
        },
        "evaluation_parameters": {
            "organization_policy_required": True,
            "turn_off_autoplay_required": True,
            "required_autoplay_scope": "ALL_DRIVES",
            "required_autorun_default_behavior": "DO_NOT_EXECUTE",
            "disallow_non_volume_autoplay_required": True,
            "approved_procedure_status": "APPROVED",
            "missing_organization_policy_status": "REVIEW",
            "missing_procedure_attestation_status": "REVIEW",
            "technical_violation_status": "FAIL",
            "collection_failure_status": "ERROR",
        },
    },
    "PC-18": {
        "probe_id": "win.remote-assistance.policy",
        "subject_scope": "POLICY",
        "applicability": ("pc18.remote-assistance-applicability", "0.1.0"),
        "evaluation": ("pc18.remote-assistance-disabled", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "POLICY",
            "required_policy_values": ["fAllowToGetHelp", "fAllowUnsolicited"],
            "collection_failure_status": "ERROR",
        },
        "evaluation_parameters": {
            "solicited_disabled_values": ["0"],
            "offer_disabled_values": ["0"],
            "not_configured_value": "MISSING",
            "not_configured_status": "REVIEW",
            "enabled_status": "FAIL",
            "quick_assist_in_scope": False,
            "remote_desktop_in_scope": False,
            "collection_failure_status": "ERROR",
        },
    },
}


def _reject(message: str) -> Never:
    raise UserMediaRemoteRuleError(message)


def _mapping(value: object, message: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(message)
    return cast(Mapping[str, object], value)


def _string(value: object, message: str) -> str:
    if not isinstance(value, str) or not value:
        _reject(message)
    return value


def _integer(value: object, message: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _reject(message)
    return value


def _boolean(value: object, message: str) -> bool:
    if not isinstance(value, bool):
        _reject(message)
    return value


def _rule_ref(value: object) -> tuple[tuple[str, str], Mapping[str, object]]:
    rule = _mapping(value, "Rule reference must be an object.")
    if set(rule) != {"rule_id", "rule_version", "parameters"}:
        _reject("Rule reference fields are invalid.")
    return (
        (
            _string(rule.get("rule_id"), "Rule ID is invalid."),
            _string(rule.get("rule_version"), "Rule version is invalid."),
        ),
        _mapping(rule.get("parameters"), "Rule parameters are invalid."),
    )


def _exact_parameters(actual: Mapping[str, object], expected: object) -> bool:
    expected_mapping = cast(Mapping[str, object], expected)
    return actual == expected_mapping and all(
        type(actual[key]) is type(value) for key, value in expected_mapping.items()
    )


def _decision(
    control_id: str,
    status: str,
    result_code: str,
    actual: str,
    expected: str,
    scope_label: str,
    *,
    policy_source: str,
    coverage: str,
    error_codes: tuple[str, ...] = (),
) -> UserMediaRemoteDecision:
    return UserMediaRemoteDecision(
        control_id=control_id,
        status=status,
        result_code=result_code,
        actual=actual,
        expected=expected,
        scope_label=scope_label,
        rationale_code=result_code,
        error_codes=error_codes,
        policy_source=policy_source,
        coverage=coverage,
    )


def _collection_error(control_id: str, error_code: str) -> UserMediaRemoteDecision:
    return _decision(
        control_id,
        "ERROR",
        f"{control_id.replace('-', '')}_COLLECTION_FAILED",
        "점검 정보를 가져오지 못함",
        "필수 정책값을 오류 없이 수집",
        "수집 오류",
        policy_source="UNKNOWN",
        coverage="COLLECTION_FAILED",
        error_codes=(error_code,),
    )


def _evaluate_pc16(value: Mapping[str, object]) -> UserMediaRemoteDecision:
    active = _string(value.get("screen_save_active"), "ScreenSaveActive is invalid.")
    secure = _string(
        value.get("screen_saver_is_secure"), "ScreenSaverIsSecure is invalid."
    )
    executable_present = _boolean(
        value.get("screen_saver_executable_present"),
        "Screen saver executable state is invalid.",
    )
    source = _string(value.get("effective_policy_source"), "Policy source is invalid.")
    coverage_complete = _boolean(
        value.get("user_coverage_complete"), "User coverage is invalid."
    )
    raw_timeout = value.get("screen_save_timeout_seconds")
    if not isinstance(raw_timeout, int) or isinstance(raw_timeout, bool) or raw_timeout < 0:
        return _decision(
            "PC-16",
            "ERROR",
            "SCREEN_SAVER_POLICY_INCOMPLETE",
            "화면보호기 대기 시간을 확인하지 못함",
            "평가 사용자별 화면보호기 사용, 대기 1~600초, 재개 시 암호 보호",
            "현재 사용자 설정 수집 불완전",
            policy_source=source,
            coverage=(
                "ASSET_USER_COVERAGE_COMPLETE"
                if coverage_complete
                else "ASSET_USER_COVERAGE_INCOMPLETE"
            ),
            error_codes=("EVIDENCE_INCOMPLETE",),
        )
    timeout = raw_timeout
    actual = (
        f"화면보호기 {'사용' if active == '1' else '사용 안 함'}, "
        f"대기 {timeout}초, 암호 보호 {'사용' if secure == '1' else '사용 안 함'}"
    )
    expected = "평가 사용자별 화면보호기 사용, 대기 1~600초, 재개 시 암호 보호"
    if active != "1" or not 1 <= timeout <= 600 or secure != "1":
        return _decision(
            "PC-16",
            "FAIL",
            "SCREEN_SAVER_LOCK_POLICY_VIOLATION",
            actual,
            expected,
            "현재 평가 사용자",
            policy_source=source,
            coverage="CURRENT_USER_EVALUATED",
        )
    if not coverage_complete:
        return _decision(
            "PC-16",
            "REVIEW",
            "SCREEN_SAVER_USER_COVERAGE_INCOMPLETE",
            actual,
            expected,
            "현재 사용자는 양호, 자산 사용자 범위 확인 필요",
            policy_source=source,
            coverage="ASSET_USER_COVERAGE_INCOMPLETE",
        )
    executable_note = "선택 확인" if executable_present else "선택 정보 없음(보조 증적)"
    return _decision(
        "PC-16",
        "PASS",
        "SCREEN_SAVER_LOCK_POLICY_COMPLIANT",
        f"{actual}, 화면보호기 {executable_note}",
        expected,
        "승인된 평가 사용자 범위",
        policy_source=source,
        coverage="ASSET_USER_COVERAGE_COMPLETE",
    )


def _procedure_status(
    organization_policy: Mapping[str, object] | None,
) -> tuple[str, str]:
    if organization_policy is None:
        return "MISSING", "NONE"
    _string(organization_policy.get("standard_id"), "Organization standard ID is invalid.")
    _string(organization_policy.get("version"), "Organization standard version is invalid.")
    attestation_id = _string(
        organization_policy.get("procedure_attestation_id"),
        "Procedure attestation ID is invalid.",
    )
    status = _string(
        organization_policy.get("procedure_status"), "Procedure status is invalid."
    )
    scope = _string(
        organization_policy.get("media_scope"), "Procedure media scope is invalid."
    )
    if scope != "CD_DVD_USB_AND_REMOVABLE":
        return "SCOPE_INCOMPLETE", attestation_id
    return status, attestation_id


def _evaluate_pc17(
    value: Mapping[str, object],
    organization_policy: Mapping[str, object] | None,
) -> UserMediaRemoteDecision:
    autoplay_off = _boolean(
        value.get("turn_off_autoplay_enabled"), "Turn off AutoPlay state is invalid."
    )
    scope = _string(value.get("autoplay_scope"), "AutoPlay scope is invalid.")
    autorun_behavior = _string(
        value.get("autorun_default_behavior"), "AutoRun behavior is invalid."
    )
    non_volume_blocked = _boolean(
        value.get("non_volume_autoplay_disallowed"),
        "Non-volume AutoPlay state is invalid.",
    )
    source = _string(value.get("effective_policy_source"), "Policy source is invalid.")
    actual = (
        f"자동실행 차단 {'사용' if autoplay_off else '사용 안 함'}, "
        f"범위 {scope}, 기본 동작 {autorun_behavior}, "
        f"비볼륨 장치 {'차단' if non_volume_blocked else '허용'}"
    )
    expected = "모든 드라이브 자동실행 차단과 승인된 이동식 미디어 관리 절차"
    technical_ok = (
        autoplay_off
        and scope == "ALL_DRIVES"
        and autorun_behavior == "DO_NOT_EXECUTE"
        and non_volume_blocked
    )
    if not technical_ok:
        return _decision(
            "PC-17",
            "FAIL",
            "REMOVABLE_MEDIA_AUTORUN_CONTROL_VIOLATION",
            actual,
            expected,
            "Windows 유효 자동실행 정책",
            policy_source=source,
            coverage="TECHNICAL_CONTROL_INCOMPLETE",
        )
    procedure_status, attestation_id = _procedure_status(organization_policy)
    if procedure_status != "APPROVED":
        return _decision(
            "PC-17",
            "REVIEW",
            "REMOVABLE_MEDIA_PROCEDURE_ATTESTATION_REQUIRED",
            f"{actual}, 내부 절차 {procedure_status}",
            expected,
            "기술 설정 양호, 조직 절차 확인 필요",
            policy_source=source,
            coverage=f"PROCEDURE_{attestation_id}",
        )
    return _decision(
        "PC-17",
        "PASS",
        "REMOVABLE_MEDIA_CONTROLS_COMPLIANT",
        f"{actual}, 내부 절차 승인",
        expected,
        "Windows 정책과 조직 절차",
        policy_source=source,
        coverage=f"PROCEDURE_{attestation_id}",
    )


def _evaluate_pc18(value: Mapping[str, object]) -> UserMediaRemoteDecision:
    solicited = _string(
        value.get("f_allow_to_get_help"), "fAllowToGetHelp value is invalid."
    )
    offer = _string(
        value.get("f_allow_unsolicited"), "fAllowUnsolicited value is invalid."
    )
    source = _string(value.get("effective_policy_source"), "Policy source is invalid.")
    allowed = {"0", "1", "MISSING"}
    actual = f"요청형 원격지원 {solicited}, 제공형 원격지원 {offer}"
    expected = "요청형·제공형 Windows Remote Assistance 모두 명시적 사용 안 함(0)"
    if solicited not in allowed or offer not in allowed:
        return _decision(
            "PC-18",
            "ERROR",
            "REMOTE_ASSISTANCE_VALUE_UNRECOGNIZED",
            actual,
            expected,
            "Windows Remote Assistance 정책",
            policy_source=source,
            coverage="VALUE_UNRECOGNIZED",
            error_codes=("PARSE_ERROR",),
        )
    if "1" in {solicited, offer}:
        return _decision(
            "PC-18",
            "FAIL",
            "REMOTE_ASSISTANCE_ENABLED",
            actual,
            expected,
            "Windows Remote Assistance 정책",
            policy_source=source,
            coverage="SOLICITED_AND_OFFER",
        )
    if "MISSING" in {solicited, offer}:
        return _decision(
            "PC-18",
            "REVIEW",
            "REMOTE_ASSISTANCE_POLICY_NOT_EXPLICIT",
            actual,
            expected,
            "Quick Assist·원격 데스크톱 제외",
            policy_source=source,
            coverage="POLICY_NOT_CONFIGURED",
        )
    return _decision(
        "PC-18",
        "PASS",
        "REMOTE_ASSISTANCE_EXPLICITLY_DISABLED",
        actual,
        expected,
        "Quick Assist·원격 데스크톱 제외",
        policy_source=source,
        coverage="SOLICITED_AND_OFFER",
    )


class UserMediaRemoteRuleRegistry:
    """Execute only the exact IMP-025 PC-16~18 rule contracts."""

    def evaluate(
        self,
        *,
        control_id: str,
        applicability_rule: Mapping[str, object],
        evaluation_rule: Mapping[str, object],
        evidence: Mapping[str, object],
        organization_policy: Mapping[str, object] | None = None,
    ) -> UserMediaRemoteDecision:
        definition = _RULES.get(control_id)
        if definition is None:
            _reject("Control rule is not allowlisted by IMP-025.")
        applicability_identity, applicability_parameters = _rule_ref(applicability_rule)
        evaluation_identity, evaluation_parameters = _rule_ref(evaluation_rule)
        if (
            applicability_identity != definition["applicability"]
            or evaluation_identity != definition["evaluation"]
        ):
            _reject("Rule ID or version is not allowlisted.")
        if not _exact_parameters(
            applicability_parameters, definition["applicability_parameters"]
        ) or not _exact_parameters(
            evaluation_parameters, definition["evaluation_parameters"]
        ):
            _reject("Rule parameters differ from the allowlisted version.")
        if evidence.get("control_id") != control_id:
            _reject("Evidence Control scope differs.")
        if (
            evidence.get("probe_id") != definition["probe_id"]
            or evidence.get("probe_version") != "0.1.0"
        ):
            _reject("Evidence Probe is not allowlisted.")
        subject = _mapping(evidence.get("subject"), "Evidence subject is invalid.")
        if subject.get("scope") != definition["subject_scope"]:
            _reject("Evidence subject scope differs from the rule.")
        if evidence.get("collection_status") != "COLLECTED":
            error_code = _string(
                evidence.get("error_code"), "Collection error code is missing."
            )
            if error_code == "NONE":
                _reject("Failed collection cannot use NONE error code.")
            return _collection_error(control_id, error_code)
        if evidence.get("error_code") != "NONE":
            _reject("Collected evidence must use NONE error code.")
        value = _mapping(evidence.get("normalized_value"), "Normalized value is missing.")
        if control_id == "PC-16":
            return _evaluate_pc16(value)
        if control_id == "PC-17":
            return _evaluate_pc17(value, organization_policy)
        return _evaluate_pc18(value)
