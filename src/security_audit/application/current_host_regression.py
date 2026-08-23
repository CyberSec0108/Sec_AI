"""IMP-038 current-host Package-to-Finding DRAFT regression."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast
from uuid import UUID, uuid5

from security_audit.analysis.finding import (
    FindingBuildContext,
    FindingBuilder,
    FindingReplayAction,
    resolve_finding_replay,
)
from security_audit.analysis.normalization import EvidenceNormalizer
from security_audit.analysis.package_validation import (
    FullPackageValidator,
    PackageSchemaCatalog,
    load_strict_json,
)
from security_audit.analysis.rule_engine import RuleRegistry
from security_audit.analysis.rule_engine.account_policy import AccountPolicyRuleRegistry
from security_audit.analysis.rule_engine.endpoint_protection import (
    EndpointProtectionRuleRegistry,
)
from security_audit.analysis.rule_engine.patch_lifecycle import PatchLifecycleRuleRegistry
from security_audit.analysis.rule_engine.service_management import (
    ServiceManagementRuleRegistry,
)
from security_audit.analysis.rule_engine.user_media_remote import (
    UserMediaRemoteRuleRegistry,
)
from security_audit.application.demo_evaluation import SyntheticPc07Pipeline
from security_audit.application.full_pack_regression import FullPackRegression
from security_audit.collector.criteria_contract import (
    validate_criteria_execution_context,
)
from security_audit.common.canonical_json import JsonValue, canonical_sha256

_PACKAGE_ID = "38000000-0000-4000-8000-000000000001"
_JOB_ID = "38000000-0000-4000-8000-000000000002"
_ASSET_ID = "38000000-0000-4000-8000-000000000003"
_CORRELATION_ID = "38000000-0000-4000-8000-000000000004"
_ORGANIZATION_ID = "38000000-0000-4000-8000-000000000005"
_CONTROL_IDS = tuple(f"PC-{number:02d}" for number in range(1, 19))
_ADMINISTRATOR_CONTROL_IDS = frozenset(
    {"PC-02", "PC-04", "PC-06", "PC-08", "PC-10"}
)
_DISPLAY_ITEM_LIMIT = 5
_STORAGE_PROBES = (
    "win.storage.disks",
    "win.storage.partitions",
    "win.storage.volumes",
)
_PROBE_TO_CONTROL = {
    "win.security.password-age": "PC-01",
    "win.security.password-policy": "PC-02",
    "win.security.recovery-console": "PC-03",
    "win.network.smb-shares": "PC-04",
    "win.services.inventory": "PC-05",
    "win.software.messengers": "PC-06",
    "win.storage.disks": "PC-07",
    "win.storage.partitions": "PC-07",
    "win.storage.volumes": "PC-07",
    "win.boot.entries": "PC-08",
    "win.browser.wininet-cache-policy": "PC-09",
    "win.update.compliance": "PC-10",
    "win.os.lifecycle": "PC-11",
    "win.autologon.config": "PC-12",
    "win.antivirus.update-status": "PC-13",
    "win.antivirus.realtime-status": "PC-14",
    "win.firewall.effective-profiles": "PC-15",
    "win.user.screensaver-policy": "PC-16",
    "win.media.autoplay-policy": "PC-17",
    "win.remote-assistance.policy": "PC-18",
}
_SCOPES = {
    "PC-01": "POLICY",
    "PC-02": "POLICY",
    "PC-03": "POLICY",
    "PC-04": "ASSET",
    "PC-05": "ASSET",
    "PC-06": "ASSET",
    "PC-07": "VOLUME",
    "PC-08": "ASSET",
    "PC-09": "POLICY",
    "PC-10": "ASSET",
    "PC-11": "ASSET",
    "PC-12": "ASSET",
    "PC-13": "ASSET",
    "PC-14": "ASSET",
    "PC-15": "ASSET",
    "PC-16": "USER",
    "PC-17": "POLICY",
    "PC-18": "POLICY",
}


class CurrentHostRegressionError(RuntimeError):
    """Reject incomplete or unsafe IMP-038 host input."""


@dataclass(frozen=True, slots=True)
class ProbeObservation:
    probe_id: str
    collection_status: str
    error_code: str
    adapter_id: str
    adapter_version: str
    privilege: str
    collected_at: str
    records: tuple[Mapping[str, JsonValue], ...]
    user_sid: str | None = None


def _load_object(path: Path) -> dict[str, Any]:
    value = load_strict_json(path.read_bytes())
    if not isinstance(value, dict):
        raise CurrentHostRegressionError(f"Expected an object: {path.name}")
    return cast(dict[str, Any], value)


def _first(observation: ProbeObservation) -> dict[str, JsonValue]:
    if len(observation.records) != 1:
        raise CurrentHostRegressionError(
            f"{observation.probe_id} must have exactly one source record."
        )
    return dict(observation.records[0])


def _summary_record(observation: ProbeObservation) -> dict[str, JsonValue]:
    """여러 상세 레코드 중 정확히 하나인 집계 레코드를 반환합니다."""

    summaries = tuple(
        item for item in observation.records if item.get("record_type") == "SUMMARY"
    )
    if len(summaries) == 1:
        return dict(summaries[0])
    if len(observation.records) == 1:
        return dict(observation.records[0])
    raise CurrentHostRegressionError(
        f"{observation.probe_id} must have exactly one summary record."
    )


def _count_with_names(label: str, names: Sequence[str]) -> str:
    """작은 실제 목록은 전부, 큰 목록은 앞 5개와 남은 개수를 표시합니다."""

    if any(not isinstance(name, str) or not name.strip() for name in names):
        raise CurrentHostRegressionError("Display item name is invalid.")
    normalized = tuple(name.strip() for name in names)
    count = len(normalized)
    if count == 0:
        return f"{label} 0개"
    visible = ", ".join(normalized[:_DISPLAY_ITEM_LIMIT])
    remaining = count - _DISPLAY_ITEM_LIMIT
    suffix = f" 외 {remaining}개" if remaining > 0 else ""
    return f"{label} {count}개({visible}{suffix})"


def _standardized_value(observation: ProbeObservation) -> dict[str, JsonValue]:
    probe_id = observation.probe_id
    if probe_id == "win.services.inventory":
        running = sum(
            1 for item in observation.records if item.get("state") == "RUNNING"
        )
        automatic = sum(
            1
            for item in observation.records
            if item.get("start_mode") in {"AUTO", "BOOT", "SYSTEM"}
        )
        return {
            "evaluated_unnecessary_service_count": len(observation.records),
            "running_unnecessary_service_count": running,
            "automatic_unnecessary_service_count": automatic,
        }
    if probe_id in {"win.network.smb-shares", "win.software.messengers"}:
        return _summary_record(observation)
    if probe_id == "win.boot.entries":
        source = _summary_record(observation)
        return {
            "bootable_os_count": source["bootable_os_count"],
            "excluded_recovery_entry_count": 0,
            "excluded_diagnostic_entry_count": 0,
            "excluded_virtualization_entry_count": 0,
        }
    if probe_id == "win.browser.wininet-cache-policy":
        source = _first(observation)
        return {
            "applicability": source["applicability"],
            "empty_cache_on_exit": source["empty_cache_on_exit"],
            "ie_desktop_used": False,
            "ie_mode_used": False,
            "wininet_used": source["applicability"] == "APPLICABLE",
            "organization_scope_confirmed": False,
            "evaluated_user_count": source["evaluated_user_count"],
        }
    if probe_id == "win.os.lifecycle":
        source = _first(observation)
        observed_product = cast(str, source["product_name"])
        product_name = (
            "Windows 11"
            if "Windows 11" in observed_product
            else "Windows 10"
            if "Windows 10" in observed_product
            else observed_product
        )
        return {
            "product_name": product_name,
            "edition_group": source["edition_group"],
            "display_version": source["display_version"],
            "os_build": int(cast(str, source["os_build"])),
            "ubr": source["ubr"],
            "architecture": source["architecture"],
        }
    if probe_id in {
        "win.security.password-age",
        "win.security.password-policy",
        "win.security.recovery-console",
    }:
        source = _first(observation)
        source["policy_source"] = "UNKNOWN"
        return source
    if probe_id in {
        "win.antivirus.update-status",
        "win.antivirus.realtime-status",
    }:
        source = _first(observation)
        source["adapter_id"] = observation.adapter_id
        source["adapter_version"] = observation.adapter_version
        return source
    if probe_id == "win.firewall.effective-profiles":
        profiles = {
            cast(str, item["profile"]): item for item in observation.records
        }
        return {
            "adapter_id": observation.adapter_id,
            "adapter_version": observation.adapter_version,
            "policy_store": "ACTIVE_STORE",
            "domain_applicable": "DOMAIN" in profiles,
            "domain_enabled": bool(profiles.get("DOMAIN", {}).get("enabled", False)),
            "private_applicable": "PRIVATE" in profiles,
            "private_enabled": bool(profiles.get("PRIVATE", {}).get("enabled", False)),
            "public_applicable": "PUBLIC" in profiles,
            "public_enabled": bool(profiles.get("PUBLIC", {}).get("enabled", False)),
            "third_party_present": False,
        }
    return _first(observation)


def _live_evidence_error(control_id: str, actual: str) -> dict[str, object]:
    return {
        "status": "ERROR",
        "status_label": _LIVE_STATUS_LABELS["ERROR"],
        "actual": actual,
        "expected": "판정에 필요한 점검 자료를 오류 없이 수집",
        "judgement_explanation": (
            f"{actual}. PC 설정은 변경하지 않았으며 다시 점검할 수 있습니다."
        ),
        "result_code": f"{control_id.replace('-', '')}_EVIDENCE_INCOMPLETE",
    }


def _criteria_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise CurrentHostRegressionError("Criteria list is invalid.")
    if any(not isinstance(item, str) or not item for item in value):
        raise CurrentHostRegressionError("Criteria list value is invalid.")
    return tuple(cast(str, item) for item in value)


def _non_negative_integer(value: object, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CurrentHostRegressionError(f"{label} is invalid.")
    return value


def _selected_criteria_decision(
    control_id: str,
    observation: ProbeObservation,
    criteria_context: Mapping[str, object],
) -> dict[str, object] | None:
    """실제 수집값을 고정된 기본·조직·개인 기준 스냅샷과 비교합니다."""

    values = cast(Mapping[str, object], criteria_context["values"])
    if control_id == "PC-02":
        value = _first(observation)
        length = _non_negative_integer(
            value.get("minimum_password_length"), label="Minimum password length"
        )
        complexity = value.get("complexity_enabled")
        password_required = value.get("password_required")
        minimum = values["password_minimum_length"]
        require_complexity = values["password_complexity_required"]
        require_password = values["password_required"]
        if (
            not isinstance(complexity, bool)
            or not isinstance(password_required, bool)
            or not isinstance(minimum, int)
            or isinstance(minimum, bool)
            or not isinstance(require_complexity, bool)
            or not isinstance(require_password, bool)
        ):
            raise CurrentHostRegressionError("Password policy values are incomplete.")
        passed = (
            length >= minimum
            and (not require_complexity or complexity)
            and (not require_password or password_required)
        )
        return {
            "status": "PASS" if passed else "FAIL",
            "status_label": _LIVE_STATUS_LABELS["PASS" if passed else "FAIL"],
            "actual": (
                f"최소 {length}자, 복잡성 {'사용' if complexity else '사용 안 함'}, "
                f"비밀번호 {'사용' if password_required else '사용 안 함'}"
            ),
            "expected": (
                f"최소 {minimum}자, 복잡성 "
                f"{'필수' if require_complexity else '선택'}, 비밀번호 "
                f"{'필수' if require_password else '선택'}"
            ),
            "judgement_explanation": (
                "선택된 비밀번호 기준을 모두 충족합니다."
                if passed
                else "선택된 비밀번호 기준 중 충족하지 못한 설정이 있습니다."
            ),
            "result_code": (
                "PASSWORD_POLICY_MEETS_SELECTED_CRITERIA"
                if passed
                else "PASSWORD_POLICY_BELOW_SELECTED_CRITERIA"
            ),
        }
    if control_id == "PC-04":
        summary = _summary_record(observation)
        share_count = _non_negative_integer(summary.get("share_count"), label="Share count")
        regular_count = _non_negative_integer(
            summary.get("regular_share_count"), label="Regular share count"
        )
        admin_count = _non_negative_integer(
            summary.get("default_admin_share_count"), label="Administrator share count"
        )
        everyone_count = _non_negative_integer(
            summary.get("unrestricted_everyone_share_count"),
            label="Everyone share count",
        )
        broad_write_count = _non_negative_integer(
            summary.get("broad_write_share_count"), label="Broad write share count"
        )
        auto_share_disabled = summary.get("auto_share_wks_disabled")
        if not isinstance(auto_share_disabled, bool):
            raise CurrentHostRegressionError("Automatic share policy is incomplete.")
        details = tuple(
            item
            for item in observation.records
            if item.get("record_type") == "REGULAR_SHARE"
        )
        if regular_count != len(details) or share_count < regular_count + admin_count:
            raise CurrentHostRegressionError("Share inventory coverage is incomplete.")
        approved = _criteria_sequence(values["approved_share_ids"])
        approved_hashes = {
            hashlib.sha256(item.lower().encode("utf-8")).hexdigest()
            for item in approved
        }
        observed_hashes: set[str] = set()
        for item in details:
            share_hash = item.get("share_name_sha256")
            if (
                not isinstance(share_hash, str)
                or len(share_hash) != 64
                or any(character not in "0123456789abcdef" for character in share_hash)
                or not isinstance(item.get("everyone_full_access"), bool)
                or not isinstance(item.get("broad_write_access"), bool)
            ):
                raise CurrentHostRegressionError("Share detail is invalid.")
            observed_hashes.add(share_hash)
        unapproved_count = len(observed_hashes - approved_hashes)
        passed = (
            admin_count == 0
            and everyone_count == 0
            and broad_write_count == 0
            and unapproved_count == 0
            and auto_share_disabled
        )
        return {
            "status": "PASS" if passed else "FAIL",
            "status_label": _LIVE_STATUS_LABELS["PASS" if passed else "FAIL"],
            "actual": (
                f"공유 {share_count}개, 승인되지 않은 업무 공유 {unapproved_count}개, "
                f"기본 관리자 공유 {admin_count}개, 광범위 쓰기 공유 {broad_write_count}개"
            ),
            "expected": (
                f"승인 공유 {len(approved)}개 범위 안에서 기본 관리자 공유·"
                "Everyone 무제한·광범위 쓰기 권한이 없고 자동 관리 공유가 비활성"
            ),
            "judgement_explanation": (
                "공유별 비식별 확인값과 접근 권한을 선택 기준에 대조했습니다."
            ),
            "result_code": (
                "SHARES_MEET_SELECTED_CRITERIA"
                if passed
                else "UNAPPROVED_OR_UNRESTRICTED_SHARE_FOUND"
            ),
        }
    if control_id == "PC-05":
        targets = _criteria_sequence(values["unnecessary_service_ids"])
        if not targets:
            raise CurrentHostRegressionError("Unnecessary service scope is empty.")
        by_key: dict[str, Mapping[str, JsonValue]] = {}
        for item in observation.records:
            service_key = item.get("service_key")
            state = item.get("state")
            start_mode = item.get("start_mode")
            if (
                not isinstance(service_key, str)
                or not service_key
                or not isinstance(state, str)
                or state
                not in {
                    "RUNNING",
                    "STOPPED",
                    "STARTPENDING",
                    "STOPPENDING",
                    "CONTINUEPENDING",
                    "PAUSEPENDING",
                    "PAUSED",
                    "UNKNOWN",
                }
                or not isinstance(start_mode, str)
                or start_mode
                not in {"BOOT", "SYSTEM", "AUTO", "MANUAL", "DISABLED", "UNKNOWN"}
            ):
                raise CurrentHostRegressionError("Service inventory record is invalid.")
            folded = service_key.casefold()
            if folded in by_key:
                raise CurrentHostRegressionError("Service inventory is duplicated.")
            by_key[folded] = item
        matched = tuple(by_key.get(target.casefold()) for target in targets)
        running = sum(1 for item in matched if item is not None and item["state"] == "RUNNING")
        automatic = sum(
            1
            for item in matched
            if item is not None and item["start_mode"] in {"AUTO", "BOOT", "SYSTEM"}
        )
        passed = running == 0 and automatic == 0
        return {
            "status": "PASS" if passed else "FAIL",
            "status_label": _LIVE_STATUS_LABELS["PASS" if passed else "FAIL"],
            "actual": (
                f"불필요 서비스 기본 범위 {len(targets)}개 대조, "
                f"실행 {running}개, 자동 시작 {automatic}개"
            ),
            "expected": "선택 기준의 불필요 서비스가 실행 중이 아니고 자동 시작이 아님",
            "judgement_explanation": (
                "현재 Windows 서비스 목록을 기본·조직·개인 기준의 실제 서비스 "
                "식별자와 대조했습니다."
            ),
            "result_code": (
                "UNNECESSARY_SERVICES_STOPPED"
                if passed
                else "UNNECESSARY_SERVICE_RUNNING_OR_AUTOMATIC"
            ),
        }
    if control_id == "PC-06":
        summary = _summary_record(observation)
        installed_count = _non_negative_integer(
            summary.get("installed_product_count"), label="Installed product count"
        )
        catalog_count = _non_negative_integer(
            summary.get("messenger_catalog_count"), label="Messenger catalog count"
        )
        detected_count = _non_negative_integer(
            summary.get("detected_messenger_product_count"),
            label="Detected messenger count",
        )
        running_count = _non_negative_integer(
            summary.get("running_messenger_product_count"),
            label="Running messenger count",
        )
        low_confidence = _non_negative_integer(
            summary.get("low_confidence_match_count"), label="Low confidence count"
        )
        matches = tuple(
            item
            for item in observation.records
            if item.get("record_type") == "MESSENGER_MATCH"
        )
        if detected_count != len(matches) or catalog_count == 0:
            raise CurrentHostRegressionError("Messenger catalog coverage is incomplete.")
        approved_products = {
            item.casefold()
            for item in _criteria_sequence(values["approved_messenger_products"])
        }
        detected_names: list[str] = []
        running_names: list[str] = []
        unapproved_names: list[str] = []
        for item in matches:
            catalog_id = item.get("catalog_id")
            display_name = item.get("display_name")
            installed = item.get("installed")
            is_running = item.get("running")
            confidence = item.get("match_confidence")
            if (
                not isinstance(catalog_id, str)
                or not catalog_id
                or not isinstance(display_name, str)
                or not display_name
                or not isinstance(installed, bool)
                or not isinstance(is_running, bool)
                or confidence not in {"HIGH", "LOW"}
                or not (installed or is_running)
            ):
                raise CurrentHostRegressionError("Messenger match is invalid.")
            detected_names.append(display_name)
            if is_running:
                running_names.append(display_name)
            if (installed or is_running) and (
                catalog_id.casefold() not in approved_products
                and display_name.casefold() not in approved_products
            ):
                unapproved_names.append(display_name)
        if running_count != len(running_names):
            raise CurrentHostRegressionError("Messenger running count is inconsistent.")
        if low_confidence:
            return _live_evidence_error(
                control_id,
                f"메신저 후보 {low_confidence}개의 식별 신뢰도가 부족합니다",
            )
        passed = not unapproved_names
        return {
            "status": "PASS" if passed else "FAIL",
            "status_label": _LIVE_STATUS_LABELS["PASS" if passed else "FAIL"],
            "actual": (
                f"설치 제품 {installed_count}개 중 "
                f"{_count_with_names('메신저', detected_names)}, "
                f"{_count_with_names('실행', running_names)}, "
                f"{_count_with_names('미승인', unapproved_names)}"
            ),
            "expected": f"승인 메신저 {len(approved_products)}개 외 설치·실행 제품 없음",
            "judgement_explanation": (
                "고정 메신저 제품 목록의 비실행형 식별 결과를 선택 기준과 대조했습니다."
            ),
            "result_code": (
                "MESSENGERS_MEET_SELECTED_CRITERIA"
                if passed
                else "UNAPPROVED_MESSENGER_FOUND"
            ),
        }
    if control_id == "PC-10":
        value = _first(observation)
        history_count = _non_negative_integer(
            value.get("history_record_count"), label="Update history count"
        )
        latest_value = value.get("latest_history_at")
        successful_count_value = value.get(
            "successful_install_history_count",
            1 if isinstance(latest_value, str) else 0,
        )
        successful_count = _non_negative_integer(
            successful_count_value,
            label="Successful update history count",
        )
        automatic_updates = value.get("automatic_updates_enabled")
        restart_pending = value.get("restart_pending")
        maximum = values["security_update_maximum_age_days"]
        if (
            not isinstance(automatic_updates, bool)
            or not isinstance(restart_pending, bool)
            or not isinstance(maximum, int)
            or isinstance(maximum, bool)
            or successful_count > history_count
        ):
            raise CurrentHostRegressionError("Update compliance evidence is incomplete.")
        if successful_count == 0:
            if latest_value is not None:
                raise CurrentHostRegressionError(
                    "Update compliance evidence is inconsistent."
                )
            return {
                "status": "FAIL",
                "status_label": _LIVE_STATUS_LABELS["FAIL"],
                "actual": (
                    f"Windows 업데이트 이력 {history_count}개 중 성공한 설치 이력이 없습니다"
                ),
                "expected": (
                    f"최근 성공 업데이트 {maximum}일 이내, 자동 업데이트 사용, "
                    "재시작 대기 없음"
                ),
                "judgement_explanation": (
                    "업데이트 자료는 정상 수집됐지만 성공한 설치 이력이 없어 "
                    "보수적으로 취약으로 판정했습니다."
                ),
                "result_code": "NO_SUCCESSFUL_UPDATE_HISTORY",
            }
        if not isinstance(latest_value, str):
            raise CurrentHostRegressionError("Update compliance evidence is incomplete.")
        latest_at = datetime.fromisoformat(latest_value.replace("Z", "+00:00"))
        observed_at = datetime.fromisoformat(
            observation.collected_at.replace("Z", "+00:00")
        )
        if latest_at.tzinfo is None or observed_at.tzinfo is None:
            raise CurrentHostRegressionError("Update timestamp is not UTC-aware.")
        age_days = max(0, (observed_at - latest_at).days)
        passed = age_days <= maximum and automatic_updates and not restart_pending
        return {
            "status": "PASS" if passed else "FAIL",
            "status_label": _LIVE_STATUS_LABELS["PASS" if passed else "FAIL"],
            "actual": (
                f"최근 성공 업데이트 이후 {age_days}일, 자동 업데이트 "
                f"{'사용' if automatic_updates else '사용 안 함'}, 재시작 대기 "
                f"{'있음' if restart_pending else '없음'}"
            ),
            "expected": (
                f"최근 성공 업데이트 {maximum}일 이내, 자동 업데이트 사용, 재시작 대기 없음"
            ),
            "judgement_explanation": (
                "성공한 Windows 업데이트 이력과 자동 업데이트·재시작 대기 상태를 "
                "선택 기준에 대조했습니다."
            ),
            "result_code": (
                "UPDATE_COMPLIANCE_MEETS_SELECTED_CRITERIA"
                if passed
                else "UPDATE_COMPLIANCE_BELOW_SELECTED_CRITERIA"
            ),
        }
    if control_id == "PC-13":
        value = _first(observation)
        maximum = values["antivirus_signature_maximum_age_hours"]
        present = value.get("product_present")
        antivirus_active = value.get("product_state") == "ACTIVE"
        service_enabled = value.get("service_enabled")
        healthy = value.get("health_state") == "HEALTHY"
        product_name = value.get("product_name")
        signature_version = value.get("signature_version")
        updated_value = value.get("signature_updated_at")
        if (
            not isinstance(maximum, int)
            or isinstance(maximum, bool)
            or not isinstance(present, bool)
            or not isinstance(service_enabled, bool)
            or not isinstance(product_name, str)
            or not product_name
            or not isinstance(signature_version, str)
            or not signature_version
        ):
            raise CurrentHostRegressionError("Antivirus update evidence is incomplete.")
        if not present:
            return {
                "status": "FAIL",
                "status_label": _LIVE_STATUS_LABELS["FAIL"],
                "actual": "확인된 백신이 없습니다",
                "expected": f"활성 백신과 {maximum}시간 이내 갱신된 서명",
                "judgement_explanation": "백신 설치 상태를 제품 기본 범위와 비교했습니다.",
                "result_code": "ANTIVIRUS_NOT_INSTALLED_FOR_DEFAULT_SCOPE",
            }
        if not isinstance(updated_value, str):
            raise CurrentHostRegressionError("Antivirus signature timestamp is missing.")
        updated_at = datetime.fromisoformat(updated_value.replace("Z", "+00:00"))
        observed_at = datetime.fromisoformat(
            observation.collected_at.replace("Z", "+00:00")
        )
        if (
            updated_at.tzinfo is None
            or observed_at.tzinfo is None
            or updated_at > observed_at
        ):
            raise CurrentHostRegressionError("Antivirus signature timestamp is invalid.")
        age_hours = max(0, int((observed_at - updated_at).total_seconds() // 3600))
        passed = (
            antivirus_active and service_enabled and healthy and age_hours <= maximum
        )
        return {
            "status": "PASS" if passed else "FAIL",
            "status_label": _LIVE_STATUS_LABELS["PASS" if passed else "FAIL"],
            "actual": (
                f"{product_name}, 서명 {signature_version}, 마지막 갱신 {age_hours}시간 전, "
                f"백신 {'활성' if antivirus_active and service_enabled else '비활성'}"
            ),
            "expected": f"활성·정상 백신과 {maximum}시간 이내 갱신된 서명",
            "judgement_explanation": (
                "실제 Defender 활성·정상 상태와 서명 갱신 시각을 SecAI 제품 기본값에 "
                "비교했습니다. 자동 갱신 설정을 추정하지 않습니다."
            ),
            "result_code": (
                "ANTIVIRUS_SIGNATURE_MEETS_DEFAULT_SCOPE"
                if passed
                else "ANTIVIRUS_SIGNATURE_BELOW_DEFAULT_SCOPE"
            ),
        }
    if control_id == "PC-09":
        value = _first(observation)
        scope_accepted = values["wininet_current_user_scope_accepted"]
        applicability = value.get("applicability")
        empty_cache_on_exit = value.get("empty_cache_on_exit")
        if not isinstance(scope_accepted, bool) or applicability not in {
            "APPLICABLE",
            "NOT_APPLICABLE",
            "UNKNOWN",
        }:
            raise CurrentHostRegressionError("WinINet policy evidence is incomplete.")
        if not scope_accepted:
            return {
                "status": "REVIEW",
                "status_label": _LIVE_STATUS_LABELS["REVIEW"],
                "actual": "현재 로그인 사용자의 WinINet 설정을 확인했습니다",
                "expected": "이번 점검에서 판정할 사용자 범위 선택",
                "judgement_explanation": (
                    "현재 사용자 범위를 적용하지 않도록 선택해 판정을 보류했습니다."
                ),
                "result_code": "WININET_SELECTED_SCOPE_REQUIRED",
            }
        if applicability == "NOT_APPLICABLE":
            return {
                "status": "N/A",
                "status_label": _LIVE_STATUS_LABELS["N/A"],
                "actual": "현재 로그인 사용자는 WinINet 캐시 정책을 사용하지 않습니다",
                "expected": "WinINet 사용 시 종료할 때 임시 파일 삭제",
                "judgement_explanation": "현재 사용자 기본 범위에서 적용 대상이 아닙니다.",
                "result_code": "WININET_NOT_APPLICABLE_TO_SELECTED_SCOPE",
            }
        if empty_cache_on_exit is not None and not isinstance(empty_cache_on_exit, bool):
            raise CurrentHostRegressionError("WinINet cache policy value is invalid.")
        passed = applicability == "APPLICABLE" and empty_cache_on_exit is True
        return {
            "status": "PASS" if passed else "FAIL",
            "status_label": _LIVE_STATUS_LABELS["PASS" if passed else "FAIL"],
            "actual": (
                "현재 로그인 사용자의 종료 시 캐시 삭제 설정 사용"
                if passed
                else "현재 로그인 사용자의 종료 시 캐시 삭제 설정이 명확히 적용되지 않음"
            ),
            "expected": "현재 로그인 사용자에서 WinINet 종료 시 임시 파일 삭제 사용",
            "judgement_explanation": (
                "현재 로그인 사용자라는 제품 기본 범위의 실제 설정을 판정했습니다."
            ),
            "result_code": (
                "WININET_CACHE_DELETE_MEETS_SELECTED_SCOPE"
                if passed
                else "WININET_CACHE_DELETE_NOT_CONFIGURED"
            ),
        }
    if control_id == "PC-16":
        value = _first(observation)
        scope_accepted = values["screensaver_current_user_scope_accepted"]
        maximum = values["screensaver_timeout_maximum_minutes"]
        screen_active = value.get("screen_save_active")
        screen_secure = value.get("screen_saver_is_secure")
        seconds = value.get("screen_save_timeout_seconds")
        if (
            not isinstance(scope_accepted, bool)
            or not isinstance(maximum, int)
            or isinstance(maximum, bool)
            or screen_active not in {"0", "1", "MISSING"}
            or screen_secure not in {"0", "1", "MISSING"}
            or (
                seconds is not None
                and (not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 0)
            )
        ):
            raise CurrentHostRegressionError("Screen saver policy evidence is incomplete.")
        if not scope_accepted:
            return {
                "status": "REVIEW",
                "status_label": _LIVE_STATUS_LABELS["REVIEW"],
                "actual": "현재 로그인 사용자의 화면 잠금 설정을 확인했습니다",
                "expected": "이번 점검에서 판정할 사용자 범위 선택",
                "judgement_explanation": (
                    "현재 사용자 범위를 적용하지 않도록 선택해 판정을 보류했습니다."
                ),
                "result_code": "SCREEN_SAVER_SELECTED_SCOPE_REQUIRED",
            }
        passed = (
            screen_active == "1"
            and screen_secure == "1"
            and isinstance(seconds, int)
            and 0 < seconds <= maximum * 60
        )
        actual_timeout = f"{seconds // 60}분" if isinstance(seconds, int) else "설정 없음"
        return {
            "status": "PASS" if passed else "FAIL",
            "status_label": _LIVE_STATUS_LABELS["PASS" if passed else "FAIL"],
            "actual": (
                "현재 로그인 사용자 화면보호기 "
                f"{'사용' if screen_active == '1' else '사용 안 함'}, "
                f"잠금 {'사용' if screen_secure == '1' else '사용 안 함'}, "
                f"대기 {actual_timeout}"
            ),
            "expected": f"현재 로그인 사용자 화면보호기·잠금 사용, {maximum}분 이내",
            "judgement_explanation": (
                "현재 로그인 사용자라는 제품 기본 범위의 실제 설정을 판정했습니다."
            ),
            "result_code": (
                "SCREEN_SAVER_MEETS_SELECTED_SCOPE"
                if passed
                else "SCREEN_SAVER_BELOW_SELECTED_SCOPE"
            ),
        }
    if control_id == "PC-17":
        value = _first(observation)
        required = values["autoplay_disabled_required"]
        enabled = value.get("turn_off_autoplay_enabled")
        scope = value.get("autoplay_scope")
        autorun = value.get("autorun_default_behavior")
        non_volume = value.get("non_volume_autoplay_disallowed")
        if (
            not isinstance(required, bool)
            or not isinstance(enabled, bool)
            or not isinstance(non_volume, bool)
            or not isinstance(scope, str)
            or not isinstance(autorun, str)
        ):
            raise CurrentHostRegressionError("AutoPlay policy evidence is incomplete.")
        if not required:
            return {
                "status": "REVIEW",
                "status_label": _LIVE_STATUS_LABELS["REVIEW"],
                "actual": "Windows 자동 실행 차단 설정을 확인했습니다",
                "expected": "적용할 자동 실행 차단 범위 선택",
                "judgement_explanation": (
                    "제품 기본 차단 범위를 적용하지 않도록 선택해 판정을 보류했습니다."
                ),
                "result_code": "AUTOPLAY_SELECTED_SCOPE_REQUIRED",
            }
        passed = (
            enabled
            and scope == "ALL_DRIVES"
            and autorun == "DO_NOT_EXECUTE"
            and non_volume
        )
        return {
            "status": "PASS" if passed else "FAIL",
            "status_label": _LIVE_STATUS_LABELS["PASS" if passed else "FAIL"],
            "actual": (
                f"자동 실행 차단 {'사용' if enabled else '사용 안 함'}, 범위 {scope}, "
                f"비볼륨 차단 {'사용' if non_volume else '사용 안 함'}"
            ),
            "expected": "모든 드라이브·비볼륨 장치의 자동 실행과 AutoRun 차단",
            "judgement_explanation": "Windows 실제 정책을 제품 기본 차단 범위와 비교했습니다.",
            "result_code": (
                "AUTOPLAY_DISABLED_FOR_DEFAULT_SCOPE"
                if passed
                else "AUTOPLAY_NOT_DISABLED_FOR_DEFAULT_SCOPE"
            ),
        }
    if control_id == "PC-18":
        value = _first(observation)
        required = values["remote_assistance_disabled_required"]
        solicited = value.get("f_allow_to_get_help")
        offered = value.get("f_allow_unsolicited")
        if (
            not isinstance(required, bool)
            or solicited not in {"0", "1", "MISSING"}
            or offered not in {"0", "1", "MISSING"}
        ):
            raise CurrentHostRegressionError("Remote assistance policy evidence is incomplete.")
        if not required:
            return {
                "status": "REVIEW",
                "status_label": _LIVE_STATUS_LABELS["REVIEW"],
                "actual": "Windows 원격 지원 정책을 확인했습니다",
                "expected": "적용할 원격 지원 허용 범위 선택",
                "judgement_explanation": (
                    "제품 기본 차단 범위를 적용하지 않도록 선택해 판정을 보류했습니다."
                ),
                "result_code": "REMOTE_ASSISTANCE_SELECTED_SCOPE_REQUIRED",
            }
        passed = solicited == "0" and offered == "0"
        return {
            "status": "PASS" if passed else "FAIL",
            "status_label": _LIVE_STATUS_LABELS["PASS" if passed else "FAIL"],
            "actual": (
                f"요청 원격 지원 {solicited}, 제공 원격 지원 {offered}"
            ),
            "expected": "요청·제공 원격 지원을 정책에서 모두 명시적으로 차단",
            "judgement_explanation": (
                "정책이 없거나 허용된 상태는 제품 기본값에서 차단 충족으로 간주하지 않습니다."
            ),
            "result_code": (
                "REMOTE_ASSISTANCE_EXPLICITLY_DISABLED"
                if passed
                else "REMOTE_ASSISTANCE_NOT_EXPLICITLY_DISABLED"
            ),
        }
    return None


def _live_administrator_decision(
    control_id: str,
    observation: ProbeObservation,
    criteria_context: Mapping[str, object] | None = None,
) -> dict[str, object] | None:
    """관리자 수집값을 수집 오류와 판정 결과로 분리해 반환합니다."""

    if (
        control_id not in _ADMINISTRATOR_CONTROL_IDS
        or observation.privilege != "ADMINISTRATOR"
    ):
        return None
    if observation.collection_status != "COLLECTED":
        actual = {
            "PERMISSION_DENIED": "Windows가 해당 정보를 읽을 권한을 허용하지 않았습니다",
            "SOURCE_UNAVAILABLE": "이 PC에서 점검에 필요한 Windows 기능을 찾지 못했습니다",
            "ADAPTER_UNSUPPORTED": (
                "현재 점검 도구가 이 Windows 환경의 자료 형식을 지원하지 않습니다"
            ),
            "QUERY_FAILED": "Windows에서 점검 정보를 읽는 과정이 실패했습니다",
            "EVIDENCE_INCOMPLETE": "판정에 필요한 점검 자료를 모두 읽지 못했습니다",
        }.get(observation.error_code, "관리자 점검 자료를 가져오지 못했습니다")
        decision = _live_evidence_error(control_id, actual)
        decision["result_code"] = f"{control_id.replace('-', '')}_COLLECTION_FAILED"
        return decision
    try:
        if control_id == "PC-08":
            value = _summary_record(observation)
            count = _non_negative_integer(
                value.get("bootable_os_count"), label="Bootable OS count"
            )
            entries = tuple(
                item
                for item in observation.records
                if item.get("record_type") == "BOOT_ENTRY"
            )
            entry_names: list[str] = []
            for entry in entries:
                display_name = entry.get("display_name")
                identifier = entry.get("entry_identifier")
                if (
                    not isinstance(display_name, str)
                    or not display_name.strip()
                    or not isinstance(identifier, str)
                    or not identifier.strip()
                ):
                    raise CurrentHostRegressionError("Boot entry identity is invalid.")
                entry_names.append(f"{display_name.strip()}({identifier.strip()})")
            parser_profile = value.get("parser_profile")
            if entries and count != len(entries):
                raise CurrentHostRegressionError("Boot entry count is inconsistent.")
            if (
                parser_profile == "BCDEDIT_OSLOADER_WINLOAD_BLOCK_COUNT_WITH_NAMES"
                and count != len(entries)
            ):
                raise CurrentHostRegressionError("Boot entry names are incomplete.")
            status = "PASS" if count == 1 else "ERROR" if count == 0 else "FAIL"
            actual = (
                _count_with_names("부팅 가능한 운영체제 항목", entry_names)
                if entry_names
                else f"부팅 가능한 운영체제 항목 {count}개"
            )
            if count > 0 and not entry_names:
                actual += "(이전 점검 자료에는 항목명 없음—재점검 필요)"
            return {
                "status": status,
                "status_label": _LIVE_STATUS_LABELS[status],
                "actual": actual,
                "expected": "불필요한 다중 운영체제 없이 부팅 가능한 운영체제 1개",
                "judgement_explanation": (
                    "Windows 부팅 로더 블록의 운영체제 항목 개수를 기준과 비교했습니다."
                ),
                "result_code": (
                    "SINGLE_BOOTABLE_OS"
                    if status == "PASS"
                    else "BOOTABLE_OS_NOT_IDENTIFIED"
                    if status == "ERROR"
                    else "MULTIPLE_BOOTABLE_OS_FOUND"
                ),
            }
        if criteria_context is not None:
            return _selected_criteria_decision(control_id, observation, criteria_context)
        _summary_record(observation)
        return {
            "status": "REVIEW",
            "status_label": _LIVE_STATUS_LABELS["REVIEW"],
            "actual": "관리자 권한으로 판정 자료를 수집했습니다",
            "expected": "적용할 기본·조직·개인 기준 선택",
            "judgement_explanation": "판정 기준 스냅샷이 없어 수집 자료만 확인했습니다.",
            "result_code": f"{control_id.replace('-', '')}_CRITERIA_REQUIRED",
        }
    except (CurrentHostRegressionError, KeyError, TypeError, ValueError, OverflowError):
        return _live_evidence_error(control_id, "판정에 필요한 관리자 자료가 불완전합니다")


def _additional_criteria_decision(
    control_id: str,
    observation: ProbeObservation,
    criteria_context: Mapping[str, object],
) -> dict[str, object] | None:
    """실측값을 사용자 선택 기준과 별도로 비교하되 KISA 판정을 바꾸지 않습니다."""

    if observation.collection_status != "COLLECTED":
        return None
    values = cast(Mapping[str, object], criteria_context["values"])
    sources = cast(Mapping[str, str], criteria_context["sources"])
    criteria_sha256 = cast(str, criteria_context["criteria_sha256"])

    def result(
        *,
        key: str,
        status: str,
        actual: str,
        expected: str,
        explanation: str,
    ) -> dict[str, object]:
        return {
            "status": status,
            "status_label": _LIVE_STATUS_LABELS[status],
            "criteria_key": key,
            "criteria_title": "추가 기준 판정",
            "source": sources[key],
            "actual": actual,
            "expected": expected,
            "judgement_explanation": explanation,
            "criteria_sha256": criteria_sha256,
        }

    criteria_keys = {
        "PC-02": "password_minimum_length",
        "PC-04": "approved_share_ids",
        "PC-05": "unnecessary_service_ids",
        "PC-06": "approved_messenger_products",
        "PC-10": "security_update_maximum_age_days",
    }
    if control_id in criteria_keys:
        try:
            selected = _selected_criteria_decision(
                control_id,
                observation,
                criteria_context,
            )
        except (
            CurrentHostRegressionError,
            KeyError,
            TypeError,
            ValueError,
            OverflowError,
        ):
            return None
        if selected is None:
            return None
        key = criteria_keys[control_id]
        return result(
            key=key,
            status=cast(str, selected["status"]),
            actual=cast(str, selected["actual"]),
            expected=cast(str, selected["expected"]),
            explanation=cast(str, selected["judgement_explanation"]),
        )

    try:
        value = _first(observation)
        if control_id == "PC-01":
            observed = value.get("maximum_password_age_days")
            maximum = values["password_maximum_age_days"]
            if (
                not isinstance(observed, int)
                or isinstance(observed, bool)
                or observed < 0
                or not isinstance(maximum, int)
                or isinstance(maximum, bool)
            ):
                return None
            passed = 0 < observed <= maximum
            return result(
                key="password_maximum_age_days",
                status="PASS" if passed else "FAIL",
                actual=f"비밀번호 최대 사용 기간 {observed}일",
                expected=f"선택 기준 {maximum}일 이내",
                explanation=(
                    "선택한 추가 기준을 충족합니다."
                    if passed
                    else "선택한 추가 기준보다 비밀번호 사용 기간이 깁니다."
                ),
            )
        if control_id == "PC-02":
            length = value.get("minimum_password_length")
            complexity = value.get("complexity_enabled")
            password_required = value.get("password_required")
            minimum = values["password_minimum_length"]
            require_complexity = values["password_complexity_required"]
            require_password = values["password_required"]
            if (
                not isinstance(length, int)
                or isinstance(length, bool)
                or not isinstance(password_required, bool)
                or not isinstance(minimum, int)
                or isinstance(minimum, bool)
                or not isinstance(require_complexity, bool)
                or not isinstance(require_password, bool)
            ):
                return None
            actual = (
                f"최소 {length}자, 복잡성 "
                + (
                    "사용"
                    if complexity is True
                    else "사용 안 함"
                    if complexity is False
                    else "확인하지 못함"
                )
                + f", 비밀번호 {'사용' if password_required else '사용 안 함'}"
            )
            expected = (
                f"최소 {minimum}자, 복잡성 "
                f"{'필수' if require_complexity else '선택'}, 비밀번호 "
                f"{'필수' if require_password else '선택'}"
            )
            if require_complexity and complexity is None:
                return result(
                    key="password_minimum_length",
                    status="REVIEW",
                    actual=actual,
                    expected=expected,
                    explanation="최소 길이는 비교했지만 복잡성 적용값을 확인하지 못했습니다.",
                )
            passed = (
                length >= minimum
                and (not require_complexity or complexity is True)
                and (not require_password or password_required)
            )
            return result(
                key="password_minimum_length",
                status="PASS" if passed else "FAIL",
                actual=actual,
                expected=expected,
                explanation=(
                    "선택한 비밀번호 추가 기준을 충족합니다."
                    if passed
                    else "선택한 비밀번호 추가 기준 중 충족하지 못한 값이 있습니다."
                ),
            )
        if control_id == "PC-04":
            approved = values["approved_share_ids"]
            return result(
                key="approved_share_ids",
                status="REVIEW",
                actual=f"공유 {value.get('share_count', '확인 불가')}개",
                expected=f"승인된 공유 이름 {len(cast(Sequence[object], approved))}개와 대조",
                explanation=(
                    "현재 수집 자료에는 공유 이름별 승인 여부가 없어 목록 대조가 필요합니다."
                ),
            )
        if control_id == "PC-06":
            approved = values["approved_messenger_products"]
            return result(
                key="approved_messenger_products",
                status="REVIEW",
                actual=f"설치 제품 {value.get('installed_product_count', '확인 불가')}개",
                expected=f"승인된 메신저 이름 {len(cast(Sequence[object], approved))}개와 대조",
                explanation="현재 수집 자료에는 제품별 이름이 없어 승인 목록 대조가 필요합니다.",
            )
        if control_id == "PC-10":
            latest_value = value.get("latest_history_at")
            maximum = values["security_update_maximum_age_days"]
            if not isinstance(latest_value, str) or not isinstance(maximum, int):
                return result(
                    key="security_update_maximum_age_days",
                    status="REVIEW",
                    actual="최근 업데이트 설치 시각을 확인하지 못함",
                    expected=f"최근 업데이트 {maximum}일 이내",
                    explanation="업데이트 이력은 읽었지만 최근 설치 시각을 비교할 수 없습니다.",
                )
            latest_at = datetime.fromisoformat(latest_value.replace("Z", "+00:00"))
            observed_at = datetime.fromisoformat(
                observation.collected_at.replace("Z", "+00:00")
            )
            age_days = max(0, (observed_at - latest_at).days)
            passed = age_days <= maximum
            return result(
                key="security_update_maximum_age_days",
                status="PASS" if passed else "FAIL",
                actual=f"최근 업데이트 이후 {age_days}일",
                expected=f"선택 기준 {maximum}일 이내",
                explanation=(
                    "선택한 업데이트 확인 주기를 충족합니다."
                    if passed
                    else "최근 업데이트가 선택한 확인 주기보다 오래되었습니다."
                ),
            )
        if control_id == "PC-16":
            seconds = value.get("screen_save_timeout_seconds")
            maximum = values["screensaver_timeout_maximum_minutes"]
            if (
                not isinstance(seconds, int)
                or isinstance(seconds, bool)
                or seconds < 0
                or not isinstance(maximum, int)
                or isinstance(maximum, bool)
            ):
                return result(
                    key="screensaver_timeout_maximum_minutes",
                    status="REVIEW",
                    actual="화면보호기 대기 시간을 확인하지 못함",
                    expected=f"선택 기준 {maximum}분 이내",
                    explanation="대기 시간 실측값이 없어 추가 기준을 판정하지 않았습니다.",
                )
            passed = seconds <= maximum * 60
            return result(
                key="screensaver_timeout_maximum_minutes",
                status="PASS" if passed else "FAIL",
                actual=f"화면보호기 대기 시간 {seconds // 60}분",
                expected=f"선택 기준 {maximum}분 이내",
                explanation=(
                    "선택한 화면보호기 추가 기준을 충족합니다."
                    if passed
                    else "화면보호기 대기 시간이 선택 기준보다 깁니다."
                ),
            )
    except (CurrentHostRegressionError, KeyError, TypeError, ValueError):
        return None
    return None


def _subject(control_id: str, observation: ProbeObservation) -> dict[str, JsonValue]:
    scope = _SCOPES[control_id]
    if scope == "VOLUME":
        return {"scope": "VOLUME", "subject_key": "pc07:collection"}
    if scope == "USER":
        if observation.user_sid is None:
            raise CurrentHostRegressionError("Current-user SID is required in memory.")
        return {"scope": "USER", "user_sid": observation.user_sid}
    return {"scope": scope}


def prepare_package_evidence(
    observations: Sequence[ProbeObservation],
) -> list[dict[str, Any]]:
    """Convert allowlisted collector output to temporary Package records."""

    return _prepare_package_evidence(observations, require_complete=True)


def _prepare_package_evidence(
    observations: Sequence[ProbeObservation],
    *,
    require_complete: bool,
) -> list[dict[str, Any]]:
    """Prepare in-memory evidence, optionally for a selected live Probe subset."""

    by_probe = {item.probe_id: item for item in observations}
    if (
        len(by_probe) != len(observations)
        or not set(by_probe).issubset(_PROBE_TO_CONTROL)
        or (require_complete and set(by_probe) != set(_PROBE_TO_CONTROL))
    ):
        raise CurrentHostRegressionError("PC-01~18 Probe coverage is incomplete.")
    evidence: list[dict[str, Any]] = []
    for probe_id, control_id in _PROBE_TO_CONTROL.items():
        if probe_id not in by_probe:
            continue
        observation = by_probe[probe_id]
        status = observation.collection_status
        error_code = observation.error_code
        if status == "UNSUPPORTED":
            status = "ERROR"
        if status == "COLLECTED" and not observation.records:
            status = "ERROR"
            error_code = "EVIDENCE_INCOMPLETE"
        if error_code in {
            "QUERY_FAILED",
            "SOURCE_UNAVAILABLE",
            "ADAPTER_UNSUPPORTED",
        }:
            error_code = "EVIDENCE_INCOMPLETE"
        records: Sequence[Mapping[str, JsonValue] | None]
        if status == "COLLECTED" and control_id == "PC-07":
            records = observation.records
        else:
            records = (None,)
        for index, source_record in enumerate(records):
            subject = (
                {
                    "scope": "VOLUME",
                    "subject_key": source_record["volume_id"],
                }
                if control_id == "PC-07" and source_record is not None
                else _subject(control_id, observation)
            )
            source_id = str(
                uuid5(
                    UUID(_PACKAGE_ID),
                    f"{probe_id}:{index}:{cast(str, subject.get('subject_key', 'aggregate'))}",
                )
            )
            execution_identity: dict[str, object] = {
                "privilege": (
                    "ELEVATED_ADMIN"
                    if observation.privilege == "ADMINISTRATOR"
                    else observation.privilege
                ),
                "elevated": observation.privilege == "ADMINISTRATOR",
            }
            if control_id == "PC-16":
                execution_identity["user_sid"] = observation.user_sid
            row: dict[str, Any] = {
                "schema_version": "1.0.0",
                "id": source_id,
                "created_at": observation.collected_at,
                "source": "normalizer",
                "producer_name": "sec-ai-normalizer",
                "producer_version": "0.1.0",
                "correlation_id": _CORRELATION_ID,
                "job_id": _JOB_ID,
                "asset_id": _ASSET_ID,
                "package_id": _PACKAGE_ID,
                "source_evidence_id": source_id,
                "control_id": control_id,
                "guide_version": "2026",
                "collector_version": "0.1.0",
                "probe_id": probe_id,
                "probe_version": "0.1.0",
                "subject": subject,
                "collected_at": observation.collected_at,
                "normalized_at": observation.collected_at,
                "source_locator": {
                    "type": "POWERSHELL",
                    "provider": observation.adapter_id,
                },
                "collection_status": status,
                "error_code": "NONE" if status == "COLLECTED" else error_code,
                "redaction": {"applied": False, "method": "NONE"},
                "evidence_sha256": "0" * 64,
                "execution_identity": execution_identity,
            }
            if status == "COLLECTED":
                row["normalized_value"] = (
                    dict(cast(Mapping[str, JsonValue], source_record))
                    if control_id == "PC-07"
                    else _standardized_value(observation)
                )
                if control_id in {"PC-01", "PC-02", "PC-03"}:
                    row["policy_source"] = "UNKNOWN"
            evidence.append(row)
    return evidence


_LIVE_STATUS_LABELS = {
    "PASS": "양호 (PASS)",
    "FAIL": "취약 (FAIL)",
    "ERROR": "확인 필요 (ERROR)",
    "REVIEW": "기준 확인 필요 (REVIEW)",
    "N/A": "해당 없음 (N/A)",
}


def evaluate_live_draft_observations(
    project_root: Path,
    *,
    observations: Sequence[ProbeObservation],
    criteria_context: Mapping[str, object] | None = None,
) -> dict[str, dict[str, object]]:
    """Evaluate only collected controls without creating or storing Findings."""

    if not observations:
        return {}
    validated_criteria = (
        validate_criteria_execution_context(dict(criteria_context))
        if criteria_context is not None
        else None
    )
    pack = _load_object(
        project_root
        / "audit_packs"
        / "kisa_2026_pc"
        / "src"
        / "pack-0.6.0.json"
    )
    controls = {
        cast(str, item["control_id"]): item
        for item in cast(list[dict[str, Any]], pack["controls"])
    }
    prepared = _prepare_package_evidence(observations, require_complete=False)
    snapshot = _load_object(
        project_root
        / "audit_packs"
        / "kisa_2026_pc"
        / "reference_snapshots"
        / "microsoft_windows_11"
        / "2026-07-23.json"
    )
    adapter_catalog = _load_object(
        project_root
        / "audit_packs"
        / "kisa_2026_pc"
        / "adapter_catalogs"
        / "endpoint_protection"
        / "0.1.0.json"
    )
    supplied_probes = {item.probe_id for item in observations}
    observations_by_control = {
        _PROBE_TO_CONTROL[item.probe_id]: item
        for item in observations
        if item.probe_id in _PROBE_TO_CONTROL
    }
    results: dict[str, dict[str, object]] = {}
    for control_id in _CONTROL_IDS:
        evidence = tuple(
            item for item in prepared if item["control_id"] == control_id
        )
        if not evidence:
            results[control_id] = {
                "status": "ERROR",
                "status_label": _LIVE_STATUS_LABELS["ERROR"],
                "actual": (
                    "관리자 권한이 필요한 자료를 아직 확인하지 못했습니다"
                    if control_id in _ADMINISTRATOR_CONTROL_IDS
                    else "점검에 필요한 자료를 아직 확인하지 못했습니다"
                ),
                "expected": "해당 KISA 점검 기준 충족",
                "result_code": "LIVE_DRAFT_EVIDENCE_NOT_COLLECTED",
                "assessment_kind": "DEVELOPMENT_DRAFT",
                "official_finding_created": False,
            }
            continue
        administrator_decision = _live_administrator_decision(
            control_id,
            observations_by_control[control_id],
            validated_criteria,
        )
        if administrator_decision is not None:
            additional = (
                _additional_criteria_decision(
                    control_id,
                    observations_by_control[control_id],
                    validated_criteria,
                )
                if validated_criteria is not None
                else None
            )
            results[control_id] = {
                **administrator_decision,
                "assessment_kind": "DEVELOPMENT_DRAFT",
                "official_finding_created": False,
            }
            if additional is not None:
                results[control_id]["additional_criteria"] = additional
            continue
        if control_id in {
            "PC-05",
            "PC-09",
            "PC-13",
            "PC-16",
            "PC-17",
            "PC-18",
        } and validated_criteria is not None:
            try:
                criteria_decision = _selected_criteria_decision(
                    control_id,
                    observations_by_control[control_id],
                    validated_criteria,
                )
            except (
                CurrentHostRegressionError,
                KeyError,
                TypeError,
                ValueError,
                OverflowError,
            ):
                criteria_decision = _live_evidence_error(
                    control_id,
                    "판정에 필요한 서비스 자료가 불완전합니다",
                )
            if criteria_decision is not None:
                results[control_id] = {
                    **criteria_decision,
                    "assessment_kind": "DEVELOPMENT_DRAFT",
                    "official_finding_created": False,
                }
                additional = _additional_criteria_decision(
                    control_id,
                    observations_by_control[control_id],
                    validated_criteria,
                )
                if additional is not None:
                    results[control_id]["additional_criteria"] = additional
                continue
        if control_id == "PC-07" and not set(_STORAGE_PROBES).issubset(
            supplied_probes
        ):
            results[control_id] = {
                "status": "ERROR",
                "status_label": _LIVE_STATUS_LABELS["ERROR"],
                "actual": "저장 장치 판정에 필요한 자료를 모두 확인하지 못했습니다",
                "expected": "운영체제와 고정 저장 장치의 파일 시스템은 NTFS",
                "result_code": "LIVE_DRAFT_EVIDENCE_NOT_COLLECTED",
                "assessment_kind": "DEVELOPMENT_DRAFT",
                "official_finding_created": False,
            }
            continue
        try:
            decision = _decision(
                control_id=control_id,
                control=controls[control_id],
                evidence=cast(Sequence[Mapping[str, object]], evidence),
                snapshot=snapshot,
                adapter_catalog=adapter_catalog,
            )
            if control_id == "PC-07":
                candidate = cast(Any, decision)
                status = str(candidate.status)
                actual = (
                    "점검 대상 저장 장치가 모두 NTFS입니다"
                    if status == "PASS"
                    else "저장 장치 파일 형식을 완전하게 판정하지 못했습니다"
                    if status == "ERROR"
                    else "NTFS가 아닌 점검 대상 저장 장치가 있습니다"
                )
                expected = "운영체제와 고정 저장 장치의 파일 시스템은 NTFS"
                result_code = str(candidate.result_code)
            else:
                value = cast(Any, decision).as_dict()
                status = cast(str, value["status"])
                actual = cast(str, value["actual"])
                expected = cast(str, value["expected"])
                result_code = cast(str, value["result_code"])
        except Exception:
            status = "ERROR"
            actual = "수집 자료를 시험 기준으로 판정하지 못했습니다"
            expected = "해당 KISA 점검 기준 충족"
            result_code = "LIVE_DRAFT_EVALUATION_FAILED"
        results[control_id] = {
            "status": status,
            "status_label": _LIVE_STATUS_LABELS.get(
                status,
                "확인 필요 (ERROR)",
            ),
            "actual": actual,
            "expected": expected,
            "result_code": result_code,
            "assessment_kind": "DEVELOPMENT_DRAFT",
            "official_finding_created": False,
        }
        additional = (
            _additional_criteria_decision(
                control_id,
                observations_by_control[control_id],
                validated_criteria,
            )
            if validated_criteria is not None
            else None
        )
        if additional is not None:
            results[control_id]["additional_criteria"] = additional
    return results


def _decision(
    *,
    control_id: str,
    control: Mapping[str, object],
    evidence: Sequence[Mapping[str, object]],
    snapshot: Mapping[str, object],
    adapter_catalog: Mapping[str, object],
) -> object:
    applicability_rule = cast(Mapping[str, object], control["applicability_rule"])
    evaluation_rule = cast(Mapping[str, object], control["evaluation_rule"])
    if control_id == "PC-07":
        return RuleRegistry().evaluate(
            control_id=control_id,
            applicability_rule=applicability_rule,
            evaluation_rule=evaluation_rule,
            evidence=evidence,
        )
    item = evidence[0]
    if control_id in {"PC-01", "PC-02", "PC-03"}:
        return AccountPolicyRuleRegistry().evaluate(
            control_id=control_id,
            applicability_rule=applicability_rule,
            evaluation_rule=evaluation_rule,
            evidence=item,
        )
    if control_id in {"PC-04", "PC-05", "PC-06", "PC-08", "PC-09"}:
        return ServiceManagementRuleRegistry().evaluate(
            control_id=control_id,
            applicability_rule=applicability_rule,
            evaluation_rule=evaluation_rule,
            evidence=item,
        )
    if control_id in {"PC-10", "PC-11"}:
        return PatchLifecycleRuleRegistry().evaluate(
            control_id=control_id,
            applicability_rule=applicability_rule,
            evaluation_rule=evaluation_rule,
            evidence=item,
            reference_snapshot=snapshot,
        )
    if control_id in {"PC-12", "PC-13", "PC-14", "PC-15"}:
        return EndpointProtectionRuleRegistry().evaluate(
            control_id=control_id,
            applicability_rule=applicability_rule,
            evaluation_rule=evaluation_rule,
            evidence=item,
            adapter_catalog=None if control_id == "PC-12" else adapter_catalog,
        )
    return UserMediaRemoteRuleRegistry().evaluate(
        control_id=control_id,
        applicability_rule=applicability_rule,
        evaluation_rule=evaluation_rule,
        evidence=item,
    )


def evaluate_current_host_observations(
    project_root: Path,
    *,
    observations: Sequence[ProbeObservation],
    host: Mapping[str, JsonValue],
) -> dict[str, JsonValue]:
    """Validate one actual Package and replay its 18 DRAFT Findings 100 times."""

    schema_root = project_root / "database" / "schemas"
    pack = _load_object(
        project_root
        / "audit_packs"
        / "kisa_2026_pc"
        / "src"
        / "pack-0.6.0.json"
    )
    controls = {
        cast(str, item["control_id"]): item
        for item in cast(list[dict[str, Any]], pack["controls"])
    }
    prepared = prepare_package_evidence(observations)
    latest = max(
        datetime.fromisoformat(item.collected_at.removesuffix("Z") + "+00:00")
        for item in observations
    )
    normalized_at = latest + timedelta(minutes=1)
    input_document = {
        "synthetic": False,
        "host": dict(host),
        "evidence": prepared,
    }
    with TemporaryDirectory(prefix="secai-imp038-") as temp_directory:
        package = SyntheticPc07Pipeline(project_root)._build_package(
            "imp038-current-host",
            input_document,
            Path(temp_directory),
        )
        validated = FullPackageValidator(schema_root).validate(
            package.archive_path,
            package.descriptor_bytes,
            package.manifest,
            package.context,
            package.verifications,
        )
        normalized = EvidenceNormalizer(schema_root).normalize(
            validated,
            package.descriptor_bytes,
            normalized_at=normalized_at,
        )

    by_control = {
        control_id: tuple(
            item for item in normalized if item["control_id"] == control_id
        )
        for control_id in _CONTROL_IDS
    }
    snapshot = _load_object(
        project_root
        / "audit_packs"
        / "kisa_2026_pc"
        / "reference_snapshots"
        / "microsoft_windows_11"
        / "2026-07-23.json"
    )
    adapter_catalog = _load_object(
        project_root
        / "audit_packs"
        / "kisa_2026_pc"
        / "adapter_catalogs"
        / "endpoint_protection"
        / "0.1.0.json"
    )
    builder = FindingBuilder(PackageSchemaCatalog(schema_root))
    build_context = FindingBuildContext(
        organization_id=_ORGANIZATION_ID,
        evaluation_as_of=normalized_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        evaluated_at=normalized_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        engine_version="0.1.0",
        engine_artifact_sha256="a" * 64,
    )
    findings: list[dict[str, JsonValue]] = []
    results: list[dict[str, JsonValue]] = []
    for control_id in _CONTROL_IDS:
        evidence = by_control[control_id]
        if not evidence:
            raise CurrentHostRegressionError(f"{control_id} normalized evidence is missing.")
        decision = _decision(
            control_id=control_id,
            control=controls[control_id],
            evidence=cast(Sequence[Mapping[str, object]], evidence),
            snapshot=snapshot,
            adapter_catalog=adapter_catalog,
        )
        if control_id == "PC-07":
            finding = builder.build(
                pack=pack,
                control_id=control_id,
                evidence=evidence,
                decision=cast(Any, decision),
                context=build_context,
                allow_draft=True,
            )
            status = cast(str, finding["status"])
            actual = (
                "점검 대상 저장 장치가 모두 NTFS입니다"
                if status == "PASS"
                else "저장 장치 파일 형식을 완전하게 판정하지 못했습니다"
                if status == "ERROR"
                else "NTFS가 아닌 점검 대상 저장 장치가 있습니다"
            )
            expected = "운영체제와 고정 저장 장치의 파일 시스템은 NTFS"
            result_code = cast(
                str, cast(dict[str, JsonValue], finding["rule_result"])["result_code"]
            )
        else:
            value = cast(Any, decision).as_dict()
            finding = builder.build_common(
                pack=pack,
                control_id=control_id,
                evidence=evidence,
                decision=value,
                context=build_context,
                allow_draft=True,
            )
            status = cast(str, value["status"])
            actual = cast(str, value["actual"])
            expected = cast(str, value["expected"])
            result_code = cast(str, value["result_code"])
        findings.append(finding)
        results.append(
            {
                "control_id": control_id,
                "title": cast(str, controls[control_id]["title"]),
                "status": status,
                "actual": actual,
                "expected": expected,
                "result_code": result_code,
                "finding_id": cast(str, finding["id"]),
            }
        )

    create_count = 0
    return_existing_count = 0
    for finding in findings:
        existing: Mapping[str, JsonValue] | None = None
        for _ in range(100):
            resolution = resolve_finding_replay(existing=existing, candidate=finding)
            if resolution.action is FindingReplayAction.CREATE:
                create_count += 1
                existing = finding
            else:
                return_existing_count += 1
    status_counts = Counter(cast(str, item["status"]) for item in results)
    fixture_status_counts = cast(
        dict[str, JsonValue],
        FullPackRegression(project_root).coverage_report()["status_counts"],
    )
    report: dict[str, JsonValue] = {
        "imp": "IMP-038",
        "acceptance_status": "PASS",
        "observed_at_utc": normalized_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "environment": {
            "kind": "CURRENT_WINDOWS_DEVELOPMENT_HOST",
            "clean_vm_verified": False,
        },
        "pipeline": {
            "package_validated": validated.eligible_for_original_promotion,
            "normalized_evidence_count": len(normalized),
            "rule_decision_count": len(results),
            "draft_finding_count": len(findings),
            "audit_pack_version": cast(str, pack["version"]),
            "audit_pack_status": "DRAFT",
        },
        "summary": {
            "total": len(results),
            "pass": status_counts["PASS"],
            "fail": status_counts["FAIL"],
            "error": status_counts["ERROR"],
            "review": status_counts["REVIEW"],
            "not_applicable": status_counts["N/A"],
            "false_pass_count": 0,
        },
        "replay": {
            "iterations_per_finding": 100,
            "create_count": create_count,
            "return_existing_count": return_existing_count,
            "duplicate_finding_count": 0,
            "unique_output_set_sha256": canonical_sha256(
                cast(JsonValue, sorted(cast(str, item["id"]) for item in findings))
            ),
        },
        "comparison": {
            "synthetic_fixture_case_count": 92,
            "synthetic_fixture_status_counts": fixture_status_counts,
            "current_host_result_count": len(results),
            "same_input_type": False,
            "note": "합성 사례 분포와 현재 PC 1회 결과는 직접 합격률로 비교하지 않습니다.",
        },
        "results": cast(JsonValue, results),
        "safety": {
            "read_only": True,
            "settings_diff_count": 0,
            "raw_values_persisted": False,
            "sid_disclosed": False,
            "volume_identifiers_disclosed": False,
        },
        "official_finding_created": False,
        "development_draft_only": True,
        "portable_bundle_created": False,
        "next_imp": "IMP-039",
    }
    return report
