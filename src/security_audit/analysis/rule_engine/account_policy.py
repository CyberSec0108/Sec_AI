"""Deterministic PC-01~03 rules for synthetic account-policy evidence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Never, cast


class AccountPolicyRuleError(ValueError):
    """Reject a non-allowlisted rule or malformed account-policy input."""


@dataclass(frozen=True, slots=True)
class AccountPolicyDecision:
    """Immutable result used by the IMP-021 test UI."""

    control_id: str
    status: str
    result_code: str
    actual: str
    expected: str
    policy_source: str
    policy_source_label: str
    rationale_code: str
    error_codes: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["error_codes"] = list(self.error_codes)
        return value


_SOURCE_LABELS = {
    "LOCAL": "이 PC에서 설정",
    "DOMAIN": "조직에서 일괄 설정",
    "MDM": "기기 관리 시스템에서 설정",
    "WINDOWS_DEFAULT": "Windows 기본값",
    "UNKNOWN": "설정 출처를 확인하지 못함",
}

_RULES: dict[str, dict[str, object]] = {
    "PC-01": {
        "probe_id": "win.security.password-age",
        "applicability": ("pc01.account-policy-applicability", "0.1.0"),
        "evaluation": ("pc01.password-age", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "POLICY",
            "supported_policy_sources": ["LOCAL", "DOMAIN", "MDM", "WINDOWS_DEFAULT"],
            "unresolved_source_status": "ERROR",
        },
        "evaluation_parameters": {
            "minimum_password_age_days": 1,
            "maximum_password_age_days": 90,
            "unlimited_value": 0,
            "within_range_status": "PASS",
            "outside_range_status": "FAIL",
            "collection_failure_status": "ERROR",
        },
    },
    "PC-02": {
        "probe_id": "win.security.password-policy",
        "applicability": ("pc02.account-policy-applicability", "0.1.0"),
        "evaluation": ("pc02.password-policy", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "POLICY",
            "supported_policy_sources": ["LOCAL", "DOMAIN", "MDM", "WINDOWS_DEFAULT"],
            "unresolved_source_status": "ERROR",
        },
        "evaluation_parameters": {
            "organization_policy_required": True,
            "missing_organization_policy_status": "REVIEW",
            "required_policy_fields": [
                "minimum_password_length",
                "complexity_required",
                "password_required",
            ],
            "comparison_profile": "EFFECTIVE_POLICY_MEETS_ORGANIZATION_STANDARD",
            "collection_failure_status": "ERROR",
        },
    },
    "PC-03": {
        "probe_id": "win.security.recovery-console",
        "applicability": ("pc03.account-policy-applicability", "0.1.0"),
        "evaluation": ("pc03.recovery-console-logon", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "POLICY",
            "supported_policy_sources": ["LOCAL", "DOMAIN", "MDM", "WINDOWS_DEFAULT"],
            "unresolved_source_status": "ERROR",
        },
        "evaluation_parameters": {
            "compliant_states": ["DISABLED", "NOT_DEFINED"],
            "noncompliant_state": "ENABLED",
            "unknown_state_status": "ERROR",
            "collection_failure_status": "ERROR",
        },
    },
}


def _reject(message: str) -> Never:
    raise AccountPolicyRuleError(message)


def _mapping(value: object, message: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(message)
    return cast(Mapping[str, object], value)


def _string(value: object, message: str) -> str:
    if not isinstance(value, str) or not value:
        _reject(message)
    return value


def _rule_ref(value: object) -> tuple[tuple[str, str], Mapping[str, object]]:
    rule = _mapping(value, "Rule reference must be an object.")
    if set(rule) != {"rule_id", "rule_version", "parameters"}:
        _reject("Rule reference fields are invalid.")
    identity = (
        _string(rule.get("rule_id"), "Rule ID is invalid."),
        _string(rule.get("rule_version"), "Rule version is invalid."),
    )
    return identity, _mapping(rule.get("parameters"), "Rule parameters are invalid.")


def _exact_parameters(actual: Mapping[str, object], expected: object) -> bool:
    expected_mapping = cast(Mapping[str, object], expected)
    return actual == expected_mapping and all(
        type(actual[key]) is type(value) for key, value in expected_mapping.items()
    )


def _source(value: object) -> tuple[str, str]:
    source = _string(value, "Effective policy source is missing.")
    if source not in _SOURCE_LABELS:
        _reject("Effective policy source is not allowlisted.")
    return source, _SOURCE_LABELS[source]


def _decision(
    control_id: str,
    status: str,
    result_code: str,
    actual: str,
    expected: str,
    source: str,
    *,
    error_codes: tuple[str, ...] = (),
) -> AccountPolicyDecision:
    return AccountPolicyDecision(
        control_id=control_id,
        status=status,
        result_code=result_code,
        actual=actual,
        expected=expected,
        policy_source=source,
        policy_source_label=_SOURCE_LABELS[source],
        rationale_code=result_code,
        error_codes=error_codes,
    )


def _collection_error(control_id: str, expected: str, error_code: str) -> AccountPolicyDecision:
    return _decision(
        control_id,
        "ERROR",
        f"{control_id.replace('-', '')}_POLICY_COLLECTION_FAILED",
        "설정 정보를 가져오지 못함",
        expected,
        "UNKNOWN",
        error_codes=(error_code,),
    )


def _evaluate_pc01(value: Mapping[str, object], source: str) -> AccountPolicyDecision:
    days = value.get("maximum_password_age_days")
    if not isinstance(days, int) or isinstance(days, bool) or days < 0:
        _reject("Maximum password age is invalid.")
    actual = "변경 기한 없음" if days == 0 else f"{days}일마다 변경"
    if 1 <= days <= 90:
        return _decision(
            "PC-01", "PASS", "PASSWORD_CHANGE_PERIOD_WITHIN_90_DAYS",
            actual, "1~90일 이내에 변경", source,
        )
    return _decision(
        "PC-01", "FAIL", "PASSWORD_CHANGE_PERIOD_NOT_COMPLIANT",
        actual, "1~90일 이내에 변경", source,
    )


def _evaluate_pc02(
    value: Mapping[str, object],
    source: str,
    organization_policy: Mapping[str, object] | None,
) -> AccountPolicyDecision:
    length = value.get("minimum_password_length")
    complexity = value.get("complexity_enabled")
    password_required = value.get("password_required")
    if (
        not isinstance(length, int)
        or isinstance(length, bool)
        or length < 0
        or not isinstance(complexity, bool)
        or not isinstance(password_required, bool)
    ):
        _reject("Effective password policy value is invalid.")
    actual = (
        f"최소 {length}자, 복잡성 {'사용' if complexity else '사용 안 함'}, "
        f"비밀번호 {'사용' if password_required else '사용 안 함'}"
    )
    if organization_policy is None:
        return _decision(
            "PC-02", "REVIEW", "ORGANIZATION_PASSWORD_STANDARD_REQUIRED",
            actual, "조직의 비밀번호 기준을 먼저 등록해야 함", source,
        )
    minimum = organization_policy.get("minimum_password_length")
    complexity_required = organization_policy.get("complexity_required")
    required = organization_policy.get("password_required")
    if (
        not isinstance(minimum, int)
        or isinstance(minimum, bool)
        or minimum < 1
        or not isinstance(complexity_required, bool)
        or not isinstance(required, bool)
        or not isinstance(organization_policy.get("standard_id"), str)
        or not isinstance(organization_policy.get("version"), str)
    ):
        _reject("Organization password standard is invalid.")
    expected = (
        f"조직 기준: 최소 {minimum}자, 복잡성 "
        f"{'사용' if complexity_required else '선택'}, 비밀번호 {'사용' if required else '선택'}"
    )
    compliant = (
        length >= minimum
        and (not complexity_required or complexity)
        and (not required or password_required)
    )
    return _decision(
        "PC-02",
        "PASS" if compliant else "FAIL",
        "PASSWORD_POLICY_MEETS_ORGANIZATION_STANDARD"
        if compliant
        else "PASSWORD_POLICY_BELOW_ORGANIZATION_STANDARD",
        actual,
        expected,
        source,
    )


def _evaluate_pc03(value: Mapping[str, object], source: str) -> AccountPolicyDecision:
    state = value.get("automatic_admin_logon")
    labels = {
        "DISABLED": "자동 관리자 로그인 사용 안 함",
        "NOT_DEFINED": "자동 관리자 로그인 별도 설정 없음",
        "ENABLED": "자동 관리자 로그인 사용",
    }
    if not isinstance(state, str) or state not in labels:
        return _decision(
            "PC-03", "ERROR", "RECOVERY_CONSOLE_POLICY_STATE_UNKNOWN",
            "설정 상태를 확인하지 못함", "사용 안 함 또는 별도 설정 없음", source,
            error_codes=("EVIDENCE_INCOMPLETE",),
        )
    compliant = state in {"DISABLED", "NOT_DEFINED"}
    return _decision(
        "PC-03",
        "PASS" if compliant else "FAIL",
        "RECOVERY_CONSOLE_AUTO_LOGON_BLOCKED"
        if compliant
        else "RECOVERY_CONSOLE_AUTO_LOGON_ENABLED",
        labels[state],
        "사용 안 함 또는 별도 설정 없음",
        source,
    )


class AccountPolicyRuleRegistry:
    """Execute only the exact IMP-021 PC-01~03 rule versions."""

    def evaluate(
        self,
        *,
        control_id: str,
        applicability_rule: Mapping[str, object],
        evaluation_rule: Mapping[str, object],
        evidence: Mapping[str, object],
        organization_policy: Mapping[str, object] | None = None,
    ) -> AccountPolicyDecision:
        definition = _RULES.get(control_id)
        if definition is None:
            _reject("Control rule is not allowlisted.")
        applicability_identity, applicability_parameters = _rule_ref(applicability_rule)
        evaluation_identity, evaluation_parameters = _rule_ref(evaluation_rule)
        if (
            applicability_identity != definition["applicability"]
            or evaluation_identity != definition["evaluation"]
        ):
            _reject("Rule ID or version is not allowlisted.")
        if not _exact_parameters(applicability_parameters, definition["applicability_parameters"]):
            _reject("Applicability parameters differ from the allowlisted version.")
        if not _exact_parameters(evaluation_parameters, definition["evaluation_parameters"]):
            _reject("Evaluation parameters differ from the allowlisted version.")

        if evidence.get("control_id") != control_id:
            _reject("Evidence Control scope differs.")
        if (
            evidence.get("probe_id") != definition["probe_id"]
            or evidence.get("probe_version") != "0.1.0"
        ):
            _reject("Evidence Probe is not allowlisted.")
        subject = _mapping(evidence.get("subject"), "Evidence subject is invalid.")
        if subject.get("scope") != "POLICY":
            _reject("Account policy evidence requires POLICY scope.")
        collection_status = evidence.get("collection_status")
        expected = {
            "PC-01": "1~90일 이내에 변경",
            "PC-02": "조직의 비밀번호 기준 충족",
            "PC-03": "사용 안 함 또는 별도 설정 없음",
        }[control_id]
        if collection_status != "COLLECTED":
            error_code = _string(evidence.get("error_code"), "Collection error code is missing.")
            if error_code == "NONE":
                _reject("Failed collection cannot use NONE error code.")
            return _collection_error(control_id, expected, error_code)
        if evidence.get("error_code") != "NONE":
            _reject("Collected evidence must use NONE error code.")
        value = _mapping(evidence.get("normalized_value"), "Normalized policy value is missing.")
        source, _ = _source(value.get("policy_source"))
        if evidence.get("policy_source") != source:
            _reject("Effective policy source fields differ.")

        if control_id == "PC-01":
            return _evaluate_pc01(value, source)
        if control_id == "PC-02":
            return _evaluate_pc02(value, source, organization_policy)
        return _evaluate_pc03(value, source)
