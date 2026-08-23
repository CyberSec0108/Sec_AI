"""Deterministic IMP-024 rules for KISA PC-12 through PC-15."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Never, cast

from security_audit.common.canonical_json import JsonValue, canonical_sha256_without_fields


class EndpointProtectionRuleError(ValueError):
    """Reject malformed evidence, rule parameters or Adapter catalogs."""


@dataclass(frozen=True, slots=True)
class EndpointProtectionDecision:
    """Immutable PC-12~15 result for the development screen."""

    control_id: str
    status: str
    result_code: str
    actual: str
    expected: str
    scope_label: str
    rationale_code: str
    error_codes: tuple[str, ...]
    adapter_id: str
    adapter_version: str
    adapter_coverage: str

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["error_codes"] = list(self.error_codes)
        return value


_CATALOG_ID = "secai-endpoint-protection-adapters-0.1.0"
_CATALOG_VERSION = "0.1.0"
_CATALOG_SHA256 = "934b1ac7b769321756c1550ef78fdb0dd0df5741e4db663dcf884146187e7758"
_CATALOG_PARAMETERS: dict[str, object] = {
    "adapter_catalog_required": True,
    "adapter_catalog_id": _CATALOG_ID,
    "adapter_catalog_version": _CATALOG_VERSION,
    "adapter_catalog_sha256": _CATALOG_SHA256,
    "allowed_catalog_approval_statuses": ["DRAFT"],
    "unsupported_adapter_status": "REVIEW",
}

_RULES: dict[str, dict[str, object]] = {
    "PC-12": {
        "probe_id": "win.autologon.config",
        "applicability": ("pc12.autologon-applicability", "0.1.0"),
        "evaluation": ("pc12.autologon-disabled", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "ASSET",
            "registry_source": "HKLM_WINLOGON",
            "collection_failure_status": "ERROR",
        },
        "evaluation_parameters": {
            "enabled_value": "1",
            "disabled_values": ["0", "MISSING"],
            "enabled_status": "FAIL",
            "disabled_status": "PASS",
            "unknown_value_status": "ERROR",
            "password_content_collection_forbidden": True,
        },
    },
    "PC-13": {
        "probe_id": "win.antivirus.update-status",
        "applicability": ("pc13.antivirus-applicability", "0.1.0"),
        "evaluation": ("pc13.antivirus-freshness", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "ASSET",
            "target_product_kind": "ANTIVIRUS",
            "not_installed_status": "FAIL",
            "collection_failure_status": "ERROR",
        },
        "evaluation_parameters": {
            **_CATALOG_PARAMETERS,
            "organization_freshness_policy_required": True,
            "missing_policy_status": "REVIEW",
            "active_product_required": True,
            "automatic_updates_required": True,
            "healthy_state": "HEALTHY",
            "stale_signature_status": "FAIL",
            "inactive_product_status": "FAIL",
        },
    },
    "PC-14": {
        "probe_id": "win.antivirus.realtime-status",
        "applicability": ("pc14.antivirus-applicability", "0.1.0"),
        "evaluation": ("pc14.realtime-protection", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "ASSET",
            "target_product_kind": "ANTIVIRUS",
            "not_installed_status": "FAIL",
            "collection_failure_status": "ERROR",
        },
        "evaluation_parameters": {
            **_CATALOG_PARAMETERS,
            "active_product_required": True,
            "service_enabled_required": True,
            "real_time_protection_required": True,
            "passive_or_unknown_mode_status": "REVIEW",
            "disabled_realtime_status": "FAIL",
        },
    },
    "PC-15": {
        "probe_id": "win.firewall.effective-profiles",
        "applicability": ("pc15.firewall-applicability", "0.1.0"),
        "evaluation": ("pc15.firewall-effective-state", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "ASSET",
            "required_profile_names": ["DOMAIN", "PRIVATE", "PUBLIC"],
            "collection_failure_status": "ERROR",
        },
        "evaluation_parameters": {
            **_CATALOG_PARAMETERS,
            "required_policy_store": "ACTIVE_STORE",
            "all_applicable_profiles_enabled": True,
            "approved_third_party_equivalent_allowed": True,
            "unknown_third_party_status": "REVIEW",
            "no_effective_firewall_status": "FAIL",
        },
    },
}


def _reject(message: str) -> Never:
    raise EndpointProtectionRuleError(message)


def _mapping(value: object, message: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(message)
    return cast(Mapping[str, object], value)


def _sequence(value: object, message: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        _reject(message)
    return value


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


def _timestamp(value: object, message: str) -> datetime:
    text = _string(value, message)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        _reject(message)
    if parsed.tzinfo is None:
        _reject(message)
    return parsed.astimezone(UTC)


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
    adapter_id: str,
    adapter_version: str,
    adapter_coverage: str,
    error_codes: tuple[str, ...] = (),
) -> EndpointProtectionDecision:
    return EndpointProtectionDecision(
        control_id=control_id,
        status=status,
        result_code=result_code,
        actual=actual,
        expected=expected,
        scope_label=scope_label,
        rationale_code=result_code,
        error_codes=error_codes,
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        adapter_coverage=adapter_coverage,
    )


def _collection_error(control_id: str, error_code: str) -> EndpointProtectionDecision:
    return _decision(
        control_id,
        "ERROR",
        f"{control_id.replace('-', '')}_COLLECTION_FAILED",
        "점검 정보를 가져오지 못함",
        "필수 정보를 오류 없이 수집",
        "수집 오류",
        adapter_id="NOT_EVALUATED",
        adapter_version="NOT_EVALUATED",
        adapter_coverage="COLLECTION_FAILED",
        error_codes=(error_code,),
    )


def _validated_catalog(catalog: Mapping[str, object]) -> Mapping[str, object]:
    if catalog.get("catalog_id") != _CATALOG_ID:
        _reject("Adapter catalog ID differs from the allowlisted rule.")
    if catalog.get("version") != _CATALOG_VERSION:
        _reject("Adapter catalog version differs from the allowlisted rule.")
    if catalog.get("content_sha256") != _CATALOG_SHA256:
        _reject("Adapter catalog hash differs from the allowlisted rule.")
    catalog_json = cast(dict[str, JsonValue], catalog)
    if (
        canonical_sha256_without_fields(catalog_json, {"content_sha256", "approval"})
        != _CATALOG_SHA256
    ):
        _reject("Adapter catalog payload integrity failed.")
    approval = _mapping(catalog.get("approval"), "Adapter catalog approval is invalid.")
    if approval.get("status") != "DRAFT" or approval.get("usage") != "SYNTHETIC_TEST_ONLY":
        _reject("Adapter catalog approval status is not allowlisted.")
    return catalog


def _catalog_adapter(
    catalog: Mapping[str, object],
    adapter_id: str,
    adapter_version: str,
    control_id: str,
) -> Mapping[str, object] | None:
    for item in _sequence(catalog.get("adapters"), "Adapter catalog records are invalid."):
        adapter = _mapping(item, "Adapter catalog record is invalid.")
        controls = _sequence(adapter.get("controls"), "Adapter Control coverage is invalid.")
        if (
            adapter.get("adapter_id") == adapter_id
            and adapter.get("adapter_version") == adapter_version
            and control_id in controls
        ):
            return adapter
    return None


def _product_adapter(
    product: Mapping[str, object],
    catalog: Mapping[str, object],
    control_id: str,
) -> Mapping[str, object] | None:
    return _catalog_adapter(
        catalog,
        _string(product.get("adapter_id"), "Adapter ID is invalid."),
        _string(product.get("adapter_version"), "Adapter version is invalid."),
        control_id,
    )


def _evaluate_pc12(value: Mapping[str, object]) -> EndpointProtectionDecision:
    forbidden = {
        "defaultpassword",
        "default_password",
        "default_password_value",
        "password",
        "password_value",
        "lsa_secret",
    }
    if forbidden.intersection(key.casefold() for key in value):
        _reject("Automatic logon evidence contains forbidden secret content.")
    state = _string(value.get("auto_admin_logon_value"), "AutoAdminLogon value is invalid.")
    present = _boolean(
        value.get("related_autologon_configuration_present"),
        "Related autologon configuration state is invalid.",
    )
    password_present = _boolean(
        value.get("default_password_present"), "Password presence flag is invalid."
    )
    actual = (
        f"AutoAdminLogon={state}, 관련 구성 {'있음' if present else '없음'}, "
        f"암호 값 존재 여부 {'있음' if password_present else '없음'}"
    )
    if state in {"0", "MISSING"}:
        return _decision(
            "PC-12",
            "PASS",
            "WINDOWS_AUTOMATIC_LOGON_DISABLED",
            actual,
            "AutoAdminLogon 값이 없거나 0",
            "HKLM Winlogon 최소노출 확인",
            adapter_id="secai.winlogon-native",
            adapter_version="0.1.0",
            adapter_coverage="AUTO_ADMIN_LOGON_STATE_ONLY",
        )
    if state == "1":
        return _decision(
            "PC-12",
            "FAIL",
            "WINDOWS_AUTOMATIC_LOGON_ENABLED",
            actual,
            "AutoAdminLogon 값이 없거나 0",
            "자동 로그인 활성",
            adapter_id="secai.winlogon-native",
            adapter_version="0.1.0",
            adapter_coverage="AUTO_ADMIN_LOGON_STATE_ONLY",
        )
    return _decision(
        "PC-12",
        "ERROR",
        "AUTO_ADMIN_LOGON_VALUE_UNRECOGNIZED",
        actual,
        "AutoAdminLogon 값 0·1 또는 값 없음",
        "레지스트리 값 해석 실패",
        adapter_id="secai.winlogon-native",
        adapter_version="0.1.0",
        adapter_coverage="VALUE_UNRECOGNIZED",
        error_codes=("PARSE_ERROR",),
    )


def _freshness_policy(policy: Mapping[str, object] | None) -> tuple[str, int] | None:
    if policy is None:
        return None
    standard_id = _string(policy.get("standard_id"), "Freshness standard ID is invalid.")
    _string(policy.get("version"), "Freshness standard version is invalid.")
    if policy.get("approved_adapter_catalog_id") != _CATALOG_ID:
        return None
    maximum_age = _integer(
        policy.get("maximum_signature_age_hours"), "Signature age threshold is invalid."
    )
    if maximum_age < 1:
        _reject("Signature age threshold must be positive.")
    return standard_id, maximum_age


def _evaluate_pc13(
    value: Mapping[str, object],
    evidence: Mapping[str, object],
    catalog: Mapping[str, object],
    policy: Mapping[str, object] | None,
) -> EndpointProtectionDecision:
    present = _boolean(value.get("product_present"), "Product presence is invalid.")
    if not present:
        return _decision(
            "PC-13", "FAIL", "ANTIVIRUS_NOT_INSTALLED", "확인된 백신 없음",
            "승인 Adapter로 확인된 활성 백신과 최신 보안 인텔리전스",
            "백신 미설치", adapter_id="NONE", adapter_version="NONE",
            adapter_coverage="NO_PRODUCT",
        )
    adapter = _product_adapter(value, catalog, "PC-13")
    if adapter is None:
        return _decision(
            "PC-13", "REVIEW", "ANTIVIRUS_ADAPTER_NOT_SUPPORTED",
            "설치 제품의 승인 Adapter를 찾지 못함",
            "승인된 제품 Adapter와 기관 최신성 기준", "제품 Adapter 확인 필요",
            adapter_id="UNSUPPORTED", adapter_version="UNKNOWN",
            adapter_coverage="UNSUPPORTED_PRODUCT",
        )
    if value.get("product_state") != "ACTIVE" or value.get("service_enabled") is not True:
        if value.get("product_state") in {"PASSIVE", "UNKNOWN"}:
            return _decision(
                "PC-13", "REVIEW", "ACTIVE_ANTIVIRUS_ADAPTER_COVERAGE_REQUIRED",
                "승인 Adapter에서 활성 백신을 확정하지 못함",
                "현재 보호를 담당하는 백신의 승인 Adapter", "활성 제품 확인 필요",
                adapter_id="PARTIAL", adapter_version="UNKNOWN",
                adapter_coverage="ACTIVE_PRODUCT_UNRESOLVED",
            )
        return _decision(
            "PC-13", "FAIL", "ANTIVIRUS_NOT_ACTIVE", "설치된 백신이 비활성",
            "활성 백신", "백신 비활성", adapter_id="KNOWN",
            adapter_version="0.1.0", adapter_coverage="KNOWN_INACTIVE",
        )
    freshness = _freshness_policy(policy)
    adapter_id = _string(value.get("adapter_id"), "Adapter ID is invalid.")
    adapter_version = _string(value.get("adapter_version"), "Adapter version is invalid.")
    product_name = _string(value.get("product_name"), "Product name is invalid.")
    signature_version = _string(
        value.get("signature_version"), "Signature version is invalid."
    )
    if freshness is None:
        return _decision(
            "PC-13", "REVIEW", "ANTIVIRUS_FRESHNESS_POLICY_REQUIRED",
            f"{product_name}, 서명 {signature_version}",
            "기관의 서명 최신성 시간 기준", "최신성 기준 없음",
            adapter_id=adapter_id, adapter_version=adapter_version,
            adapter_coverage="SUPPORTED_NO_POLICY",
        )
    standard_id, maximum_age = freshness
    collected_at = _timestamp(evidence.get("collected_at"), "Collected timestamp is invalid.")
    updated_at = _timestamp(
        value.get("signature_updated_at"), "Signature update timestamp is invalid."
    )
    if updated_at > collected_at:
        _reject("Signature update timestamp cannot be later than collection time.")
    signature_age = int((collected_at - updated_at).total_seconds() // 3600)
    actual = f"{product_name}, 서명 {signature_version}, 업데이트 {signature_age}시간 전"
    expected = f"서명 업데이트 {maximum_age}시간 이내, 자동 업데이트와 정상 상태"
    if signature_age > maximum_age:
        return _decision(
            "PC-13", "FAIL", "ANTIVIRUS_SIGNATURE_STALE", actual, expected,
            f"기관 기준 {standard_id}", adapter_id=adapter_id,
            adapter_version=adapter_version, adapter_coverage="SUPPORTED",
        )
    if value.get("automatic_updates_enabled") is not True:
        return _decision(
            "PC-13", "FAIL", "ANTIVIRUS_AUTOMATIC_UPDATE_DISABLED", actual, expected,
            f"기관 기준 {standard_id}", adapter_id=adapter_id,
            adapter_version=adapter_version, adapter_coverage="SUPPORTED",
        )
    if value.get("health_state") != "HEALTHY":
        return _decision(
            "PC-13", "FAIL", "ANTIVIRUS_HEALTH_NOT_OK", actual, expected,
            f"기관 기준 {standard_id}", adapter_id=adapter_id,
            adapter_version=adapter_version, adapter_coverage="SUPPORTED",
        )
    return _decision(
        "PC-13", "PASS", "ANTIVIRUS_CURRENT_AND_MANAGED", actual, expected,
        f"기관 기준 {standard_id}", adapter_id=adapter_id,
        adapter_version=adapter_version, adapter_coverage="SUPPORTED",
    )


def _evaluate_pc14(
    value: Mapping[str, object],
    catalog: Mapping[str, object],
) -> EndpointProtectionDecision:
    present = _boolean(value.get("product_present"), "Product presence is invalid.")
    if not present:
        return _decision(
            "PC-14", "FAIL", "ANTIVIRUS_NOT_INSTALLED", "확인된 백신 없음",
            "설치 백신의 실시간 감시 활성", "백신 미설치",
            adapter_id="NONE", adapter_version="NONE", adapter_coverage="NO_PRODUCT",
        )
    if _product_adapter(value, catalog, "PC-14") is None:
        return _decision(
            "PC-14", "REVIEW", "ANTIVIRUS_ADAPTER_NOT_SUPPORTED",
            "설치 제품의 승인 Adapter를 찾지 못함", "승인된 실시간 감시 Adapter",
            "제품 Adapter 확인 필요", adapter_id="UNSUPPORTED",
            adapter_version="UNKNOWN", adapter_coverage="UNSUPPORTED_PRODUCT",
        )
    if value.get("product_state") != "ACTIVE":
        return _decision(
            "PC-14", "REVIEW", "ACTIVE_ANTIVIRUS_ADAPTER_COVERAGE_REQUIRED",
            "Defender가 수동 모드이거나 활성 제품을 확정하지 못함",
            "현재 보호를 담당하는 백신의 승인 Adapter", "동작 모드 확인 필요",
            adapter_id="PARTIAL", adapter_version="0.1.0",
            adapter_coverage="PASSIVE_OR_UNKNOWN",
        )
    adapter_id = _string(value.get("adapter_id"), "Adapter ID is invalid.")
    adapter_version = _string(value.get("adapter_version"), "Adapter version is invalid.")
    product_name = _string(value.get("product_name"), "Product name is invalid.")
    realtime = _boolean(
        value.get("real_time_protection_enabled"), "Real-time state is invalid."
    )
    service = _boolean(value.get("service_enabled"), "Service state is invalid.")
    actual = (
        f"{product_name}, 실시간 감시 {'사용' if realtime else '사용 안 함'}, "
        f"서비스 {'실행' if service else '중지'}"
    )
    if not realtime or not service:
        return _decision(
            "PC-14", "FAIL", "ANTIVIRUS_REALTIME_PROTECTION_DISABLED", actual,
            "활성 백신의 실시간 감시와 서비스 사용", "실시간 감시 비활성",
            adapter_id=adapter_id, adapter_version=adapter_version,
            adapter_coverage="SUPPORTED",
        )
    return _decision(
        "PC-14", "PASS", "ANTIVIRUS_REALTIME_PROTECTION_ENABLED", actual,
        "활성 백신의 실시간 감시와 서비스 사용", "실시간 감시 활성",
        adapter_id=adapter_id, adapter_version=adapter_version,
        adapter_coverage="SUPPORTED",
    )


def _evaluate_pc15(
    value: Mapping[str, object],
    catalog: Mapping[str, object],
) -> EndpointProtectionDecision:
    adapter_id = _string(value.get("adapter_id"), "Firewall Adapter ID is invalid.")
    adapter_version = _string(
        value.get("adapter_version"), "Firewall Adapter version is invalid."
    )
    adapter = _catalog_adapter(catalog, adapter_id, adapter_version, "PC-15")
    if adapter is None:
        return _decision(
            "PC-15", "REVIEW", "WINDOWS_FIREWALL_ADAPTER_NOT_SUPPORTED",
            "Windows 방화벽 Adapter를 해석할 수 없음", "승인된 ActiveStore Adapter",
            "Adapter 확인 필요", adapter_id=adapter_id,
            adapter_version=adapter_version, adapter_coverage="UNSUPPORTED",
        )
    if value.get("policy_store") != "ACTIVE_STORE":
        return _decision(
            "PC-15", "ERROR", "FIREWALL_POLICY_STORE_NOT_EFFECTIVE",
            f"정책 저장소 {value.get('policy_store')}", "ActiveStore 유효 정책",
            "유효 정책 수집 오류", adapter_id=adapter_id,
            adapter_version=adapter_version, adapter_coverage="WRONG_POLICY_STORE",
            error_codes=("EVIDENCE_INCOMPLETE",),
        )
    required_fields = {
        "domain_applicable",
        "domain_enabled",
        "private_applicable",
        "private_enabled",
        "public_applicable",
        "public_enabled",
        "third_party_present",
    }
    missing_fields = sorted(required_fields - set(value))
    if missing_fields:
        return _decision(
            "PC-15", "ERROR", "FIREWALL_PROFILE_COVERAGE_INCOMPLETE",
            f"누락 필드 {','.join(missing_fields)}",
            "Domain·Private·Public ActiveStore 프로필", "프로필 수집 누락",
            adapter_id=adapter_id, adapter_version=adapter_version,
            adapter_coverage="INCOMPLETE_PROFILES",
            error_codes=("EVIDENCE_INCOMPLETE",),
        )
    profile_states = {
        "DOMAIN": (
            _boolean(value.get("domain_applicable"), "Domain applicability is invalid."),
            _boolean(value.get("domain_enabled"), "Domain firewall state is invalid."),
        ),
        "PRIVATE": (
            _boolean(value.get("private_applicable"), "Private applicability is invalid."),
            _boolean(value.get("private_enabled"), "Private firewall state is invalid."),
        ),
        "PUBLIC": (
            _boolean(value.get("public_applicable"), "Public applicability is invalid."),
            _boolean(value.get("public_enabled"), "Public firewall state is invalid."),
        ),
    }
    applicable = [name for name, (is_applicable, _) in profile_states.items() if is_applicable]
    if not applicable:
        _reject("At least one firewall profile must be applicable.")
    disabled = [
        name for name in applicable if not profile_states[name][1]
    ]
    profile_labels = {
        "DOMAIN": "도메인",
        "PRIVATE": "개인",
        "PUBLIC": "공용",
    }
    applicable_names = ", ".join(profile_labels[name] for name in applicable)
    disabled_summary = (
        f"{len(disabled)}개({', '.join(profile_labels[name] for name in disabled)})"
        if disabled
        else "없음"
    )
    actual = (
        f"적용 프로필 {len(applicable)}개({applicable_names}), "
        f"Windows 방화벽 비활성 {disabled_summary}"
    )
    if not disabled:
        return _decision(
            "PC-15", "PASS", "WINDOWS_FIREWALL_ALL_APPLICABLE_PROFILES_ENABLED",
            actual, "모든 적용 프로필의 유효 방화벽 활성", "Windows ActiveStore",
            adapter_id=adapter_id, adapter_version=adapter_version,
            adapter_coverage="DOMAIN_PRIVATE_PUBLIC",
        )
    third_party_present = _boolean(
        value.get("third_party_present"), "Third-party firewall presence is invalid."
    )
    if not third_party_present:
        return _decision(
            "PC-15", "FAIL", "NO_EFFECTIVE_FIREWALL_FOR_APPLICABLE_PROFILES", actual,
            "Windows 방화벽 또는 승인된 대체 방화벽", "유효 방화벽 없음",
            adapter_id=adapter_id, adapter_version=adapter_version,
            adapter_coverage="WINDOWS_ONLY",
        )
    product_id = _string(
        value.get("third_party_adapter_id"), "Third-party Adapter ID is invalid."
    )
    product_version = _string(
        value.get("third_party_adapter_version"), "Third-party Adapter version is invalid."
    )
    product_adapter = _catalog_adapter(catalog, product_id, product_version, "PC-15")
    if product_adapter is None:
        return _decision(
            "PC-15", "REVIEW", "THIRD_PARTY_FIREWALL_ADAPTER_COVERAGE_REQUIRED",
            f"{actual}, 승인되지 않은 타사 방화벽", "승인된 타사 Adapter의 유효 보호",
            "타사 방화벽 Adapter 확인 필요", adapter_id=product_id,
            adapter_version=product_version, adapter_coverage="THIRD_PARTY_UNRESOLVED",
        )
    synthetic_only = _boolean(
        product_adapter.get("synthetic_test_only"), "Synthetic Adapter flag is invalid."
    )
    if synthetic_only and value.get("synthetic_test_case") is not True:
        return _decision(
            "PC-15", "REVIEW", "THIRD_PARTY_FIREWALL_ADAPTER_COVERAGE_REQUIRED",
            f"{actual}, 합성시험 전용 Adapter를 실증적으로 사용할 수 없음",
            "운영 승인된 타사 Adapter의 유효 보호", "운영 Adapter 확인 필요",
            adapter_id=product_id, adapter_version=product_version,
            adapter_coverage="SYNTHETIC_TEST_ONLY",
        )
    covered = {
        name.strip()
        for name in _string(
            value.get("third_party_covered_profiles"),
            "Covered firewall profiles are invalid.",
        ).split(",")
        if name.strip()
    }
    if (
        value.get("third_party_product_state") == "ACTIVE"
        and value.get("third_party_service_enabled") is True
        and value.get("third_party_health_state") == "HEALTHY"
        and set(disabled) <= covered
    ):
        return _decision(
            "PC-15", "PASS", "APPROVED_ALTERNATIVE_FIREWALL_EFFECTIVE",
            f"{actual}, 합성 대체 방화벽이 {','.join(sorted(covered))} 보호",
            "모든 적용 프로필의 유효 방화벽 활성", "대체 방화벽 분기 합성시험",
            adapter_id=product_id, adapter_version=product_version,
            adapter_coverage="SYNTHETIC_TEST_ONLY",
        )
    return _decision(
        "PC-15", "FAIL", "ALTERNATIVE_FIREWALL_NOT_EFFECTIVE",
        f"{actual}, 승인 Adapter의 보호 상태 불충분",
        "승인된 타사 Adapter의 유효 보호", "대체 방화벽 비활성 또는 범위 부족",
        adapter_id=product_id, adapter_version=product_version,
        adapter_coverage="KNOWN_INEFFECTIVE",
    )


class EndpointProtectionRuleRegistry:
    """Execute only the exact IMP-024 PC-12~15 rule contracts."""

    def evaluate(
        self,
        *,
        control_id: str,
        applicability_rule: Mapping[str, object],
        evaluation_rule: Mapping[str, object],
        evidence: Mapping[str, object],
        adapter_catalog: Mapping[str, object] | None,
        organization_policy: Mapping[str, object] | None = None,
    ) -> EndpointProtectionDecision:
        definition = _RULES.get(control_id)
        if definition is None:
            _reject("Control rule is not allowlisted by IMP-024.")
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
        if subject.get("scope") != "ASSET":
            _reject("IMP-024 evidence requires ASSET scope.")
        if evidence.get("collection_status") != "COLLECTED":
            error_code = _string(evidence.get("error_code"), "Collection error code is missing.")
            if error_code == "NONE":
                _reject("Failed collection cannot use NONE error code.")
            return _collection_error(control_id, error_code)
        if evidence.get("error_code") != "NONE":
            _reject("Collected evidence must use NONE error code.")
        value = _mapping(evidence.get("normalized_value"), "Normalized value is missing.")
        if control_id == "PC-12":
            return _evaluate_pc12(value)
        if adapter_catalog is None:
            return _decision(
                control_id, "REVIEW", "ADAPTER_CATALOG_REQUIRED",
                "Adapter 기준을 불러오지 못함", "유효한 제품 Adapter Catalog",
                "Adapter 기준 없음", adapter_id="NOT_PROVIDED",
                adapter_version="NOT_PROVIDED", adapter_coverage="MISSING_CATALOG",
            )
        catalog = _validated_catalog(adapter_catalog)
        if control_id == "PC-13":
            return _evaluate_pc13(value, evidence, catalog, organization_policy)
        if control_id == "PC-14":
            return _evaluate_pc14(value, catalog)
        return _evaluate_pc15(value, catalog)
