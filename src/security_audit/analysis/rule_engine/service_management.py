"""Deterministic IMP-022 rules for KISA PC-04, 05, 06, 08 and 09."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Never, cast


class ServiceManagementRuleError(ValueError):
    """Reject a non-allowlisted rule or malformed IMP-022 input."""


@dataclass(frozen=True, slots=True)
class ServiceManagementDecision:
    """Immutable result exposed by the synthetic IMP-022 screen."""

    control_id: str
    status: str
    result_code: str
    actual: str
    expected: str
    scope_label: str
    rationale_code: str
    error_codes: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["error_codes"] = list(self.error_codes)
        return value


_RULES: dict[str, dict[str, object]] = {
    "PC-04": {
        "probe_id": "win.network.smb-shares",
        "subject_scope": "ASSET",
        "applicability": ("pc04.share-applicability", "0.1.0"),
        "evaluation": ("pc04.share-access", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "ASSET",
            "supported_windows_versions": ["11"],
            "unresolved_scope_status": "ERROR",
        },
        "evaluation_parameters": {
            "organization_policy_required": True,
            "default_admin_share_count_maximum": 0,
            "unrestricted_everyone_share_count_maximum": 0,
            "least_privilege_violation_count_maximum": 0,
            "authentication_gap_count_maximum": 0,
            "auto_share_wks_disabled_required": True,
            "missing_organization_policy_status": "REVIEW",
            "collection_failure_status": "ERROR",
        },
    },
    "PC-05": {
        "probe_id": "win.services.inventory",
        "subject_scope": "ASSET",
        "applicability": ("pc05.service-applicability", "0.1.0"),
        "evaluation": ("pc05.unnecessary-services", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "ASSET",
            "supported_windows_versions": ["11"],
            "unresolved_scope_status": "ERROR",
        },
        "evaluation_parameters": {
            "organization_policy_required": True,
            "running_unnecessary_service_count_maximum": 0,
            "automatic_unnecessary_service_count_maximum": 0,
            "missing_organization_policy_status": "REVIEW",
            "collection_failure_status": "ERROR",
        },
    },
    "PC-06": {
        "probe_id": "win.software.messengers",
        "subject_scope": "ASSET",
        "applicability": ("pc06.messenger-applicability", "0.1.0"),
        "evaluation": ("pc06.unapproved-messengers", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "ASSET",
            "supported_windows_versions": ["11"],
            "unresolved_scope_status": "ERROR",
        },
        "evaluation_parameters": {
            "organization_policy_required": True,
            "installed_denied_product_count_maximum": 0,
            "running_denied_product_count_maximum": 0,
            "low_confidence_match_status": "REVIEW",
            "missing_organization_policy_status": "REVIEW",
            "collection_failure_status": "ERROR",
        },
    },
    "PC-08": {
        "probe_id": "win.boot.entries",
        "subject_scope": "ASSET",
        "applicability": ("pc08.multiboot-applicability", "0.1.0"),
        "evaluation": ("pc08.bootable-os-count", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "ASSET",
            "excluded_entry_types": ["RECOVERY", "DIAGNOSTIC", "VIRTUALIZATION"],
            "wsl_is_multiboot": False,
            "hyper_v_guest_is_multiboot": False,
        },
        "evaluation_parameters": {
            "maximum_bootable_os_count": 1,
            "zero_bootable_os_status": "ERROR",
            "multiple_bootable_os_status": "FAIL",
            "collection_failure_status": "ERROR",
        },
    },
    "PC-09": {
        "probe_id": "win.browser.wininet-cache-policy",
        "subject_scope": "POLICY",
        "applicability": ("pc09.wininet-applicability", "0.1.0"),
        "evaluation": ("pc09.empty-cache-on-exit", "0.1.0"),
        "applicability_parameters": {
            "applicable_uses": ["IE_DESKTOP", "IE_MODE", "WININET"],
            "not_applicable_requires_scope_confirmation": True,
            "unknown_applicability_status": "REVIEW",
        },
        "evaluation_parameters": {
            "required_value": True,
            "enabled_status": "PASS",
            "disabled_status": "FAIL",
            "not_applicable_status": "N/A",
            "collection_failure_status": "ERROR",
        },
    },
}


def _reject(message: str) -> Never:
    raise ServiceManagementRuleError(message)


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


def _policy_ids(
    organization_policy: Mapping[str, object] | None,
    field: str,
) -> tuple[str, ...] | None:
    if organization_policy is None:
        return None
    _string(organization_policy.get("standard_id"), "Organization standard ID is invalid.")
    _string(organization_policy.get("version"), "Organization standard version is invalid.")
    value = organization_policy.get(field)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        _reject(f"Organization policy field {field} is invalid.")
    identifiers = tuple(
        _string(item, f"Organization policy field {field} contains an invalid ID.")
        for item in value
    )
    if len(set(identifiers)) != len(identifiers):
        _reject(f"Organization policy field {field} contains duplicate IDs.")
    return identifiers


def _decision(
    control_id: str,
    status: str,
    result_code: str,
    actual: str,
    expected: str,
    scope_label: str,
    *,
    error_codes: tuple[str, ...] = (),
) -> ServiceManagementDecision:
    return ServiceManagementDecision(
        control_id=control_id,
        status=status,
        result_code=result_code,
        actual=actual,
        expected=expected,
        scope_label=scope_label,
        rationale_code=result_code,
        error_codes=error_codes,
    )


def _collection_error(control_id: str, error_code: str) -> ServiceManagementDecision:
    return _decision(
        control_id,
        "ERROR",
        f"{control_id.replace('-', '')}_COLLECTION_FAILED",
        "점검 정보를 가져오지 못함",
        "필수 정보를 오류 없이 수집",
        "수집 오류",
        error_codes=(error_code,),
    )


def _evaluate_pc04(
    value: Mapping[str, object], policy: Mapping[str, object] | None
) -> ServiceManagementDecision:
    unnecessary = _integer(value.get("default_admin_share_count"), "Share count is invalid.")
    everyone = _integer(
        value.get("unrestricted_everyone_share_count"), "Everyone share count is invalid."
    )
    least_privilege = _integer(
        value.get("least_privilege_violation_count"), "Least privilege count is invalid."
    )
    authentication = _integer(
        value.get("authentication_gap_count"), "Authentication gap count is invalid."
    )
    auto_share_disabled = _boolean(
        value.get("auto_share_wks_disabled"), "AutoShareWks state is invalid."
    )
    policy_ids = _policy_ids(policy, "approved_share_ids")
    actual = (
        f"기본 공유 {unnecessary}개, Everyone 무제한 {everyone}개, "
        f"최소 권한 위반 {least_privilege}개, 인증 누락 {authentication}개"
    )
    if policy_ids is None:
        return _decision(
            "PC-04", "REVIEW", "ORGANIZATION_SHARE_STANDARD_REQUIRED", actual,
            "승인된 업무 공유와 권한 기준 등록", "조직 기준 없음",
        )
    compliant = (
        unnecessary == 0
        and everyone == 0
        and least_privilege == 0
        and authentication == 0
        and auto_share_disabled
    )
    return _decision(
        "PC-04",
        "PASS" if compliant else "FAIL",
        "SHARES_APPROVED_AND_LEAST_PRIVILEGE"
        if compliant
        else "UNNECESSARY_OR_UNRESTRICTED_SHARE_FOUND",
        actual,
        "불필요한 기본 공유 없음, 승인된 공유만 최소 권한·인증 적용",
        f"조직 공유 기준 {len(policy_ids)}개",
    )


def _evaluate_pc05(
    value: Mapping[str, object], policy: Mapping[str, object] | None
) -> ServiceManagementDecision:
    evaluated = _integer(
        value.get("evaluated_unnecessary_service_count"), "Evaluated service count is invalid."
    )
    running = _integer(
        value.get("running_unnecessary_service_count"), "Running service count is invalid."
    )
    automatic = _integer(
        value.get("automatic_unnecessary_service_count"), "Automatic service count is invalid."
    )
    policy_ids = _policy_ids(policy, "unnecessary_service_ids")
    actual = f"불필요 지정 {evaluated}개 중 실행 {running}개, 자동 시작 {automatic}개"
    if policy_ids is None:
        return _decision(
            "PC-05", "REVIEW", "ORGANIZATION_SERVICE_STANDARD_REQUIRED", actual,
            "조직에서 불필요 서비스 목록 등록", "조직 기준 없음",
        )
    if evaluated != len(policy_ids):
        return _decision(
            "PC-05", "ERROR", "SERVICE_POLICY_COVERAGE_INCOMPLETE", actual,
            f"조직 목록 {len(policy_ids)}개를 모두 확인", "기준 대조 불완전",
            error_codes=("EVIDENCE_INCOMPLETE",),
        )
    compliant = running == 0 and automatic == 0
    return _decision(
        "PC-05",
        "PASS" if compliant else "FAIL",
        "UNNECESSARY_SERVICES_STOPPED"
        if compliant
        else "UNNECESSARY_SERVICE_RUNNING_OR_AUTOMATIC",
        actual,
        "조직이 불필요하다고 지정한 서비스는 중지하고 자동 시작 해제",
        f"조직 서비스 기준 {len(policy_ids)}개",
    )


def _evaluate_pc06(
    value: Mapping[str, object], policy: Mapping[str, object] | None
) -> ServiceManagementDecision:
    evaluated = _integer(
        value.get("evaluated_denied_product_count"), "Evaluated product count is invalid."
    )
    installed = _integer(
        value.get("installed_denied_product_count"), "Installed product count is invalid."
    )
    running = _integer(
        value.get("running_denied_product_count"), "Running product count is invalid."
    )
    low_confidence = _integer(
        value.get("low_confidence_match_count"), "Low-confidence count is invalid."
    )
    policy_ids = _policy_ids(policy, "denied_product_ids")
    actual = (
        f"금지 목록 {evaluated}개 대조, 설치 {installed}개, 실행 {running}개, "
        f"식별 불확실 {low_confidence}개"
    )
    if policy_ids is None:
        return _decision(
            "PC-06", "REVIEW", "ORGANIZATION_MESSENGER_STANDARD_REQUIRED", actual,
            "조직에서 허용·금지 메신저 기준 등록", "조직 기준 없음",
        )
    if evaluated != len(policy_ids):
        return _decision(
            "PC-06", "ERROR", "MESSENGER_POLICY_COVERAGE_INCOMPLETE", actual,
            f"조직 목록 {len(policy_ids)}개를 모두 확인", "기준 대조 불완전",
            error_codes=("EVIDENCE_INCOMPLETE",),
        )
    if low_confidence:
        return _decision(
            "PC-06", "REVIEW", "MESSENGER_IDENTIFICATION_REVIEW_REQUIRED", actual,
            "제품을 확실하게 식별한 뒤 금지 목록과 대조", "제품 식별 확인 필요",
        )
    compliant = installed == 0 and running == 0
    return _decision(
        "PC-06",
        "PASS" if compliant else "FAIL",
        "DENIED_MESSENGERS_NOT_PRESENT"
        if compliant
        else "DENIED_MESSENGER_INSTALLED_OR_RUNNING",
        actual,
        "조직이 금지한 메신저가 설치·실행되지 않음",
        f"조직 메신저 기준 {len(policy_ids)}개",
    )


def _evaluate_pc08(value: Mapping[str, object]) -> ServiceManagementDecision:
    count = _integer(value.get("bootable_os_count"), "Bootable OS count is invalid.")
    recovery = _integer(
        value.get("excluded_recovery_entry_count"), "Recovery entry count is invalid."
    )
    diagnostic = _integer(
        value.get("excluded_diagnostic_entry_count"), "Diagnostic entry count is invalid."
    )
    virtualization = _integer(
        value.get("excluded_virtualization_entry_count"), "Virtualization count is invalid."
    )
    actual = (
        f"부팅 가능한 OS {count}개 (제외: 복구 {recovery}, 진단 {diagnostic}, "
        f"가상화 {virtualization})"
    )
    if count == 0:
        return _decision(
            "PC-08", "ERROR", "BOOTABLE_OS_NOT_IDENTIFIED", actual,
            "실제 부팅 가능한 OS 1개", "부팅 구성",
            error_codes=("EVIDENCE_INCOMPLETE",),
        )
    compliant = count == 1
    return _decision(
        "PC-08",
        "PASS" if compliant else "FAIL",
        "SINGLE_BOOTABLE_OS" if compliant else "MULTIPLE_BOOTABLE_OS_FOUND",
        actual,
        "복구·진단·가상화 항목을 제외한 부팅 가능한 OS 1개",
        "부팅 구성",
    )


def _evaluate_pc09(value: Mapping[str, object]) -> ServiceManagementDecision:
    applicability = _string(value.get("applicability"), "Applicability is invalid.")
    if applicability not in {"APPLICABLE", "NOT_APPLICABLE", "UNKNOWN"}:
        _reject("Applicability is not allowlisted.")
    ie_desktop = _boolean(value.get("ie_desktop_used"), "IE desktop use state is invalid.")
    ie_mode = _boolean(value.get("ie_mode_used"), "IE mode use state is invalid.")
    wininet = _boolean(value.get("wininet_used"), "WinINet use state is invalid.")
    confirmed = _boolean(
        value.get("organization_scope_confirmed"), "Scope confirmation state is invalid."
    )
    users = _integer(value.get("evaluated_user_count"), "Evaluated user count is invalid.")
    if applicability == "UNKNOWN":
        return _decision(
            "PC-09", "REVIEW", "WININET_APPLICABILITY_REVIEW_REQUIRED",
            "IE·IE 모드·WinINet 사용 여부를 확정하지 못함",
            "조직 사용 범위를 먼저 확인", "적용성 확인 필요",
        )
    if applicability == "NOT_APPLICABLE":
        if confirmed and not any((ie_desktop, ie_mode, wininet)):
            return _decision(
                "PC-09", "N/A", "WININET_NOT_USED_CONFIRMED",
                "조직 범위에서 IE·IE 모드·WinINet을 사용하지 않음",
                "해당 기술을 사용할 때만 평가", "적용 대상 아님",
            )
        return _decision(
            "PC-09", "REVIEW", "WININET_NOT_APPLICABLE_CLAIM_UNCONFIRMED",
            "미사용 주장을 충분히 확인하지 못함",
            "조직 사용 범위와 사용자 범위 확인", "적용성 확인 필요",
        )
    if users == 0:
        return _decision(
            "PC-09", "ERROR", "WININET_USER_SCOPE_EMPTY",
            "평가한 사용자가 없음", "적용 사용자 전체의 설정 확인", "사용자 범위 오류",
            error_codes=("EVIDENCE_INCOMPLETE",),
        )
    enabled = _boolean(value.get("empty_cache_on_exit"), "Cache-on-exit state is invalid.")
    if not confirmed:
        return _decision(
            "PC-09",
            "REVIEW",
            "WININET_USER_COVERAGE_REVIEW_REQUIRED",
            (
                "현재 사용자 설정은 확인했으나 조직의 전체 사용자 범위를 "
                "확인하지 못함"
            ),
            "IE·IE 모드·WinINet을 사용하는 전체 사용자 설정 확인",
            "사용자 범위 확인 필요",
        )
    return _decision(
        "PC-09",
        "PASS" if enabled else "FAIL",
        "WININET_CACHE_CLEARED_ON_EXIT"
        if enabled
        else "WININET_CACHE_NOT_CLEARED_ON_EXIT",
        f"종료 시 임시 인터넷 파일 삭제 {'사용' if enabled else '사용 안 함'} ({users}명 확인)",
        "IE·IE 모드·WinINet 종료 시 임시 인터넷 파일 삭제 사용",
        "사용자별 브라우저 정책",
    )


class ServiceManagementRuleRegistry:
    """Execute only the exact IMP-022 rule IDs, versions and parameters."""

    def evaluate(
        self,
        *,
        control_id: str,
        applicability_rule: Mapping[str, object],
        evaluation_rule: Mapping[str, object],
        evidence: Mapping[str, object],
        organization_policy: Mapping[str, object] | None = None,
    ) -> ServiceManagementDecision:
        definition = _RULES.get(control_id)
        if definition is None:
            _reject("Control rule is not allowlisted by IMP-022.")
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
            error_code = _string(evidence.get("error_code"), "Collection error code is missing.")
            if error_code == "NONE":
                _reject("Failed collection cannot use NONE error code.")
            return _collection_error(control_id, error_code)
        if evidence.get("error_code") != "NONE":
            _reject("Collected evidence must use NONE error code.")
        value = _mapping(evidence.get("normalized_value"), "Normalized value is missing.")
        if control_id == "PC-04":
            return _evaluate_pc04(value, organization_policy)
        if control_id == "PC-05":
            return _evaluate_pc05(value, organization_policy)
        if control_id == "PC-06":
            return _evaluate_pc06(value, organization_policy)
        if control_id == "PC-08":
            return _evaluate_pc08(value)
        return _evaluate_pc09(value)
