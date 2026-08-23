"""Deterministic IMP-023 rules for KISA PC-10 and PC-11."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from typing import Never, cast

from security_audit.common.canonical_json import JsonValue, canonical_sha256_without_fields


class PatchLifecycleRuleError(ValueError):
    """Reject malformed evidence, rule parameters or reference snapshots."""


@dataclass(frozen=True, slots=True)
class PatchLifecycleDecision:
    """Immutable PC-10 or PC-11 result for the IMP-023 development screen."""

    control_id: str
    status: str
    result_code: str
    actual: str
    expected: str
    scope_label: str
    rationale_code: str
    error_codes: tuple[str, ...]
    reference_snapshot_id: str
    reference_as_of: str
    reference_valid_until: str

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["error_codes"] = list(self.error_codes)
        return value


_SNAPSHOT_ID = "microsoft-windows-11-2026-07-23"
_SNAPSHOT_VERSION = "1.0.0"
_SNAPSHOT_SHA256 = "9bb9fcc8fb8461e053ba22d33d5fbf15d4a9113651f32a834faaffc199911054"

_COMMON_REFERENCE_PARAMETERS: dict[str, object] = {
    "reference_snapshot_required": True,
    "reference_snapshot_id": _SNAPSHOT_ID,
    "reference_snapshot_version": _SNAPSHOT_VERSION,
    "reference_snapshot_sha256": _SNAPSHOT_SHA256,
    "allowed_snapshot_approval_statuses": ["DRAFT"],
    "missing_reference_status": "REVIEW",
    "expired_reference_status": "REVIEW",
}

_RULES: dict[str, dict[str, object]] = {
    "PC-10": {
        "probe_id": "win.update.compliance",
        "applicability": ("pc10.patch-applicability", "0.1.0"),
        "evaluation": ("pc10.patch-baseline", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "ASSET",
            "target_product": "WINDOWS_11",
            "supported_architectures": ["x86_64"],
            "unknown_product_status": "ERROR",
        },
        "evaluation_parameters": {
            **_COMMON_REFERENCE_PARAMETERS,
            "organization_procedure_required": True,
            "missing_procedure_status": "REVIEW",
            "accepted_inventory_sources": [
                "WINDOWS_UPDATE_AGENT",
                "WINDOWS_UPDATE_HISTORY_AND_BUILD",
                "WSUS_OR_INTUNE_COMPLIANCE",
            ],
            "forbidden_solo_source": "GET_HOTFIX",
            "automatic_updates_required": True,
            "missing_required_update_status": "FAIL",
            "below_minimum_build_status": "FAIL",
            "restart_pending_status": "REVIEW",
            "stale_scan_status": "ERROR",
            "collection_failure_status": "ERROR",
        },
    },
    "PC-11": {
        "probe_id": "win.os.lifecycle",
        "applicability": ("pc11.lifecycle-applicability", "0.1.0"),
        "evaluation": ("pc11.support-lifecycle", "0.1.0"),
        "applicability_parameters": {
            "subject_scope": "ASSET",
            "target_product": "WINDOWS_11",
            "supported_architectures": ["x86_64"],
            "unknown_product_status": "ERROR",
        },
        "evaluation_parameters": {
            **_COMMON_REFERENCE_PARAMETERS,
            "organization_procedure_required": True,
            "missing_procedure_status": "REVIEW",
            "support_state_rule": "COLLECTED_AT_ON_OR_BEFORE_SUPPORT_END",
            "eol_status": "FAIL",
            "unknown_edition_or_version_status": "REVIEW",
            "collection_failure_status": "ERROR",
        },
    },
}


def _reject(message: str) -> Never:
    raise PatchLifecycleRuleError(message)


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


def _timestamp(value: object, message: str) -> datetime:
    text = _string(value, message)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        _reject(message)
    if parsed.tzinfo is None:
        _reject(message)
    return parsed.astimezone(UTC)


def _date(value: object, message: str) -> date:
    text = _string(value, message)
    try:
        return date.fromisoformat(text)
    except ValueError:
        _reject(message)


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
    reference: Mapping[str, object] | None,
    *,
    error_codes: tuple[str, ...] = (),
) -> PatchLifecycleDecision:
    return PatchLifecycleDecision(
        control_id=control_id,
        status=status,
        result_code=result_code,
        actual=actual,
        expected=expected,
        scope_label=scope_label,
        rationale_code=result_code,
        error_codes=error_codes,
        reference_snapshot_id=(
            _string(reference.get("snapshot_id"), "Snapshot ID is invalid.")
            if reference is not None
            else "NOT_PROVIDED"
        ),
        reference_as_of=(
            _string(reference.get("as_of"), "Snapshot date is invalid.")
            if reference is not None
            else "NOT_PROVIDED"
        ),
        reference_valid_until=(
            _string(reference.get("valid_until"), "Snapshot expiry is invalid.")
            if reference is not None
            else "NOT_PROVIDED"
        ),
    )


def _collection_error(control_id: str, error_code: str) -> PatchLifecycleDecision:
    return _decision(
        control_id,
        "ERROR",
        f"{control_id.replace('-', '')}_COLLECTION_FAILED",
        "점검 정보를 가져오지 못함",
        "필수 정보를 오류 없이 수집",
        "수집 오류",
        None,
        error_codes=(error_code,),
    )


def _validated_reference(
    snapshot: Mapping[str, object],
    parameters: Mapping[str, object],
) -> Mapping[str, object]:
    if snapshot.get("snapshot_id") != parameters["reference_snapshot_id"]:
        _reject("Reference snapshot ID differs from the allowlisted rule.")
    if snapshot.get("version") != parameters["reference_snapshot_version"]:
        _reject("Reference snapshot version differs from the allowlisted rule.")
    if snapshot.get("content_sha256") != parameters["reference_snapshot_sha256"]:
        _reject("Reference snapshot hash differs from the allowlisted rule.")
    snapshot_json = cast(dict[str, JsonValue], snapshot)
    actual_hash = canonical_sha256_without_fields(
        snapshot_json, {"content_sha256", "approval"}
    )
    if actual_hash != snapshot.get("content_sha256"):
        _reject("Reference snapshot payload integrity failed.")
    approval = _mapping(snapshot.get("approval"), "Reference approval is invalid.")
    statuses = cast(Sequence[object], parameters["allowed_snapshot_approval_statuses"])
    if approval.get("status") not in statuses:
        _reject("Reference snapshot approval status is not allowlisted.")
    _timestamp(snapshot.get("as_of"), "Reference as-of timestamp is invalid.")
    _timestamp(snapshot.get("valid_until"), "Reference expiry timestamp is invalid.")
    return snapshot


def _procedure(
    policy: Mapping[str, object] | None,
) -> tuple[str, str, int] | None:
    if policy is None:
        return None
    _string(policy.get("standard_id"), "Organization standard ID is invalid.")
    _string(policy.get("version"), "Organization standard version is invalid.")
    attestation_id = _string(
        policy.get("procedure_attestation_id"), "Procedure attestation ID is invalid."
    )
    snapshot_id = _string(
        policy.get("approved_snapshot_id"), "Approved snapshot ID is invalid."
    )
    maximum_scan_age_hours = _integer(
        policy.get("maximum_scan_age_hours"), "Maximum scan age is invalid."
    )
    if maximum_scan_age_hours < 1:
        _reject("Maximum scan age must be positive.")
    return attestation_id, snapshot_id, maximum_scan_age_hours


def _records(snapshot: Mapping[str, object], field: str) -> Sequence[object]:
    value = snapshot.get(field)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        _reject(f"Reference snapshot field {field} is invalid.")
    return value


def _patch_baseline(
    snapshot: Mapping[str, object], display_version: str
) -> Mapping[str, object] | None:
    for item in _records(snapshot, "patch_baselines"):
        record = _mapping(item, "Patch baseline record is invalid.")
        if record.get("display_version") == display_version:
            return record
    return None


def _lifecycle_record(
    snapshot: Mapping[str, object], edition_group: str, display_version: str
) -> Mapping[str, object] | None:
    for item in _records(snapshot, "lifecycle_records"):
        record = _mapping(item, "Lifecycle record is invalid.")
        if (
            record.get("edition_group") == edition_group
            and record.get("display_version") == display_version
        ):
            return record
    return None


def _evaluate_pc10(
    value: Mapping[str, object],
    evidence: Mapping[str, object],
    snapshot: Mapping[str, object],
    policy: Mapping[str, object] | None,
) -> PatchLifecycleDecision:
    display_version = _string(value.get("display_version"), "Display version is invalid.")
    os_build = _integer(value.get("os_build"), "OS build is invalid.")
    ubr = _integer(value.get("ubr"), "OS UBR is invalid.")
    installed_kb = _string(
        value.get("installed_cumulative_kb"), "Installed cumulative KB is invalid."
    )
    missing = _integer(
        value.get("missing_required_update_count"), "Missing update count is invalid."
    )
    automatic = _boolean(
        value.get("automatic_updates_enabled"), "Automatic update state is invalid."
    )
    inventory_source = _string(
        value.get("update_inventory_source"), "Update inventory source is invalid."
    )
    restart_pending = _boolean(
        value.get("restart_pending"), "Restart pending state is invalid."
    )
    baseline = _patch_baseline(snapshot, display_version)
    actual = (
        f"Windows {display_version} Build {os_build}.{ubr}, {installed_kb}, "
        f"필수 업데이트 누락 {missing}개"
    )
    if baseline is None:
        return _decision(
            "PC-10", "REVIEW", "PATCH_BASELINE_NOT_FOUND", actual,
            "해당 Windows Version의 승인 패치 기준", "참조 기준 확인 필요", snapshot,
        )
    rule_parameters = cast(
        Mapping[str, object], _RULES["PC-10"]["evaluation_parameters"]
    )
    accepted_sources = cast(
        Sequence[object], rule_parameters["accepted_inventory_sources"]
    )
    if inventory_source not in accepted_sources:
        return _decision(
            "PC-10", "ERROR", "PATCH_INVENTORY_SOURCE_INSUFFICIENT", actual,
            "Windows Update Agent·이력·Build 또는 WSUS/Intune 자료", "수집 방법 오류",
            snapshot, error_codes=("EVIDENCE_INCOMPLETE",),
        )
    required_build = _integer(baseline.get("base_build"), "Baseline build is invalid.")
    required_ubr = _integer(baseline.get("minimum_ubr"), "Baseline UBR is invalid.")
    required_kb = _string(baseline.get("baseline_kb"), "Baseline KB is invalid.")
    expected = f"최소 Build {required_build}.{required_ubr} ({required_kb}) 이상"
    if os_build != required_build:
        return _decision(
            "PC-10", "ERROR", "PATCH_BUILD_VERSION_INCONSISTENT", actual, expected,
            "OS 정보 불일치", snapshot, error_codes=("EVIDENCE_INCOMPLETE",),
        )
    if ubr < required_ubr or missing > 0:
        return _decision(
            "PC-10", "FAIL", "REQUIRED_SECURITY_UPDATE_MISSING", actual, expected,
            "Microsoft 패치 기준", snapshot,
        )
    if not automatic:
        return _decision(
            "PC-10", "FAIL", "AUTOMATIC_UPDATE_DISABLED", actual,
            f"{expected}, 자동 업데이트 사용", "업데이트 정책", snapshot,
        )
    if restart_pending:
        return _decision(
            "PC-10", "REVIEW", "PATCH_RESTART_PENDING", actual,
            "재부팅 후 패치 적용 완료 확인", "재부팅 확인 필요", snapshot,
        )
    procedure = _procedure(policy)
    if procedure is None:
        return _decision(
            "PC-10", "REVIEW", "PATCH_MANAGEMENT_PROCEDURE_REQUIRED", actual,
            "승인 패치 기준과 내부 관리 절차 증적", "조직 절차 없음", snapshot,
        )
    attestation_id, approved_snapshot_id, maximum_scan_age_hours = procedure
    if approved_snapshot_id != snapshot["snapshot_id"]:
        return _decision(
            "PC-10", "REVIEW", "PATCH_REFERENCE_NOT_APPROVED_BY_ORGANIZATION", actual,
            "조직이 승인한 동일 참조 스냅샷", "참조 승인 불일치", snapshot,
        )
    collected_at = _timestamp(evidence.get("collected_at"), "Collected timestamp is invalid.")
    scanned_at = _timestamp(
        value.get("last_successful_scan_at"), "Last successful scan timestamp is invalid."
    )
    if scanned_at > collected_at:
        _reject("Update scan timestamp cannot be later than collection time.")
    scan_age_hours = (collected_at - scanned_at).total_seconds() / 3600
    if scan_age_hours > maximum_scan_age_hours:
        return _decision(
            "PC-10", "ERROR", "UPDATE_SCAN_TOO_OLD", actual,
            f"최근 {maximum_scan_age_hours}시간 이내 업데이트 검색", "검색 결과 오래됨",
            snapshot, error_codes=("EVIDENCE_INCOMPLETE",),
        )
    return _decision(
        "PC-10", "PASS", "PATCH_BASELINE_AND_PROCEDURE_COMPLIANT", actual,
        f"{expected}, 자동 업데이트와 내부 관리 절차", f"절차 증적 {attestation_id}",
        snapshot,
    )


def _evaluate_pc11(
    value: Mapping[str, object],
    evidence: Mapping[str, object],
    snapshot: Mapping[str, object],
    policy: Mapping[str, object] | None,
) -> PatchLifecycleDecision:
    product_name = _string(value.get("product_name"), "Product name is invalid.")
    edition_group = _string(value.get("edition_group"), "Edition group is invalid.")
    display_version = _string(value.get("display_version"), "Display version is invalid.")
    os_build = _integer(value.get("os_build"), "OS build is invalid.")
    ubr = _integer(value.get("ubr"), "OS UBR is invalid.")
    architecture = _string(value.get("architecture"), "Architecture is invalid.")
    actual = (
        f"{product_name} {display_version} {edition_group}, "
        f"Build {os_build}.{ubr} ({architecture})"
    )
    if product_name != "Windows 11" or architecture != "x86_64":
        return _decision(
            "PC-11", "ERROR", "OS_PRODUCT_SCOPE_MISMATCH", actual,
            "Windows 11 x86_64", "제품 범위 오류", snapshot,
            error_codes=("UNSUPPORTED_OS",),
        )
    record = _lifecycle_record(snapshot, edition_group, display_version)
    if record is None:
        return _decision(
            "PC-11", "REVIEW", "LIFECYCLE_RECORD_NOT_FOUND", actual,
            "Edition과 Version이 일치하는 Microsoft 수명주기 기준",
            "수명주기 기준 확인 필요", snapshot,
        )
    support_end = _date(record.get("support_end"), "Support end date is invalid.")
    collected_at = _timestamp(evidence.get("collected_at"), "Collected timestamp is invalid.")
    expected = f"Microsoft 지원 종료일 {support_end.isoformat()} 이내"
    if collected_at.date() > support_end:
        return _decision(
            "PC-11", "FAIL", "WINDOWS_VERSION_END_OF_SUPPORT", actual, expected,
            "Microsoft 제품 수명주기", snapshot,
        )
    procedure = _procedure(policy)
    if procedure is None:
        return _decision(
            "PC-11", "REVIEW", "OS_LIFECYCLE_PROCEDURE_REQUIRED", actual,
            f"{expected}, 내부 관리 절차 증적", "조직 절차 없음", snapshot,
        )
    attestation_id, approved_snapshot_id, _ = procedure
    if approved_snapshot_id != snapshot["snapshot_id"]:
        return _decision(
            "PC-11", "REVIEW", "LIFECYCLE_REFERENCE_NOT_APPROVED_BY_ORGANIZATION",
            actual, "조직이 승인한 동일 수명주기 스냅샷", "참조 승인 불일치", snapshot,
        )
    return _decision(
        "PC-11", "PASS", "WINDOWS_VERSION_SUPPORTED_AND_MANAGED", actual,
        f"{expected}, 내부 관리 절차", f"절차 증적 {attestation_id}", snapshot,
    )


class PatchLifecycleRuleRegistry:
    """Execute only the exact IMP-023 PC-10 and PC-11 rule contracts."""

    def evaluate(
        self,
        *,
        control_id: str,
        applicability_rule: Mapping[str, object],
        evaluation_rule: Mapping[str, object],
        evidence: Mapping[str, object],
        reference_snapshot: Mapping[str, object] | None,
        organization_policy: Mapping[str, object] | None = None,
    ) -> PatchLifecycleDecision:
        definition = _RULES.get(control_id)
        if definition is None:
            _reject("Control rule is not allowlisted by IMP-023.")
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
            _reject("Patch and lifecycle evidence requires ASSET scope.")
        if evidence.get("collection_status") != "COLLECTED":
            error_code = _string(evidence.get("error_code"), "Collection error code is missing.")
            if error_code == "NONE":
                _reject("Failed collection cannot use NONE error code.")
            return _collection_error(control_id, error_code)
        if evidence.get("error_code") != "NONE":
            _reject("Collected evidence must use NONE error code.")
        value = _mapping(evidence.get("normalized_value"), "Normalized value is missing.")
        if reference_snapshot is None:
            return _decision(
                control_id, "REVIEW", "REFERENCE_SNAPSHOT_REQUIRED",
                "참조 기준을 불러오지 못함", "유효한 Microsoft 참조 스냅샷",
                "참조 기준 없음", None,
            )
        snapshot = _validated_reference(reference_snapshot, evaluation_parameters)
        collected_at = _timestamp(evidence.get("collected_at"), "Collected timestamp is invalid.")
        as_of = _timestamp(snapshot.get("as_of"), "Reference as-of timestamp is invalid.")
        valid_until = _timestamp(
            snapshot.get("valid_until"), "Reference expiry timestamp is invalid."
        )
        if collected_at < as_of:
            _reject("Evidence predates the reference snapshot.")
        if collected_at > valid_until:
            return _decision(
                control_id, "REVIEW", "REFERENCE_SNAPSHOT_EXPIRED",
                f"수집 시각 {collected_at.date().isoformat()}",
                f"참조 유효기한 {valid_until.date().isoformat()} 이내", "참조 갱신 필요",
                snapshot,
            )
        if control_id == "PC-10":
            return _evaluate_pc10(value, evidence, snapshot, organization_policy)
        return _evaluate_pc11(value, evidence, snapshot, organization_policy)
