"""세 플랫폼 점검 이력의 안전한 snapshot·표시 계약입니다."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import NoReturn, cast
from uuid import UUID

from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256,
    canonical_sha256_without_fields,
)

_RESULT_ID = re.compile(r"^[a-f0-9]{16}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_WINDOWS_CONTROL_IDS = frozenset(f"PC-{index:02d}" for index in range(1, 19))
_STATUSES = frozenset({"PASS", "FAIL", "ERROR", "REVIEW", "N/A"})
_DELETION_MODES = frozenset({"HOLD", "TOMBSTONE_AFTER_BACKUP"})
_PRESENTATION_KINDS = frozenset({"ADMINISTRATOR", "AI_COMPLETED"})
_ADMINISTRATOR_CONTROL_IDS = frozenset(
    {"PC-02", "PC-04", "PC-06", "PC-08", "PC-10"}
)
_PROHIBITED_FIELD_TERMS = frozenset(
    {
        "authorization",
        "password_content",
        "default_password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "private_key",
        "credential",
        "cookie",
        "session",
        "user_sid",
        "process_sid",
        "username",
        "user_name",
        "hostname",
        "host_name",
        "volume_label",
        "serial_number",
        "product_key",
    }
)
_CONTROL_TEXT_FIELDS = (
    "title",
    "importance",
    "source",
    "display_status",
    "status_label",
    "checked_summary",
    "evidence_summary",
    "action_guidance",
    "assessment_label",
    "actual",
    "expected",
    "result_code",
    "assessment_kind",
)


class AuditHistoryContractError(ValueError):
    """외부 결과나 보존정책이 이력 계약을 위반할 때 발생합니다."""


def _reject(code: str) -> NoReturn:
    raise AuditHistoryContractError(code)


def _object(value: object, code: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _reject(code)
    return cast(dict[str, object], value)


def _text(value: object, code: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        _reject(code)
    return value.strip()


def _optional_text(value: object, code: str, maximum: int = 4_000) -> str | None:
    if value is None:
        return None
    return _text(value, code, maximum)


def _contains_prohibited_field(value: object) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if any(term == normalized or term in normalized for term in _PROHIBITED_FIELD_TERMS):
                return True
            if _contains_prohibited_field(child):
                return True
    elif isinstance(value, list):
        return any(_contains_prohibited_field(child) for child in value)
    return False


def _json_copy(
    value: object,
    code: str,
    *,
    maximum_bytes: int,
    reject_prohibited_fields: bool = True,
) -> JsonValue:
    if reject_prohibited_fields and _contains_prohibited_field(value):
        _reject(code)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > maximum_bytes:
            _reject(code)
        decoded = json.loads(encoded)
    except (TypeError, ValueError):
        _reject(code)
    return cast(JsonValue, decoded)


def _context_items(
    value: object,
    *,
    expected_ids: frozenset[str],
    kind: str,
) -> list[JsonValue]:
    if not isinstance(value, list) or len(value) != len(expected_ids):
        _reject(f"{kind}_COVERAGE_INVALID")
    copied = _json_copy(value, f"{kind}_INVALID", maximum_bytes=2_000_000)
    if not isinstance(copied, list):
        _reject(f"{kind}_INVALID")
    identifiers: set[str] = set()
    for raw in copied:
        item = _object(raw, f"{kind}_INVALID")
        control_id = item.get("control_id")
        if not isinstance(control_id, str) or control_id not in expected_ids:
            _reject(f"{kind}_COVERAGE_INVALID")
        if control_id in identifiers:
            _reject(f"{kind}_COVERAGE_INVALID")
        identifiers.add(control_id)
        if kind == "OFFICIAL_EXPLANATION":
            if (
                item.get("status_authority") != "RULE_ENGINE"
                or item.get("official_status") not in _STATUSES
            ):
                _reject("OFFICIAL_EXPLANATION_AUTHORITY_INVALID")
            digest = item.get("presentation_sha256")
            if digest is not None and (
                not isinstance(digest, str)
                or _SHA256.fullmatch(digest) is None
                or digest
                != canonical_sha256_without_fields(
                    cast(dict[str, JsonValue], item),
                    {"presentation_sha256"},
                )
            ):
                _reject("OFFICIAL_EXPLANATION_HASH_INVALID")
        elif kind == "AI_EXPLANATION_INPUT":
            if (
                item.get("status_authority") != "RULE_ENGINE"
                or item.get("rule_status") not in _STATUSES
            ):
                _reject("AI_EXPLANATION_INPUT_AUTHORITY_INVALID")
            safety = item.get("safety")
            if not isinstance(safety, dict) or (
                safety.get("raw_evidence_included") is not False
                or safety.get("sensitive_identifiers_included") is not False
                or safety.get("rule_status_unchanged") is not True
            ):
                _reject("AI_EXPLANATION_INPUT_SAFETY_INVALID")
            digest = item.get("explanation_input_sha256")
            if (
                not isinstance(digest, str)
                or _SHA256.fullmatch(digest) is None
                or digest
                != canonical_sha256_without_fields(
                    cast(dict[str, JsonValue], item),
                    {"explanation_input_sha256"},
                )
            ):
                _reject("AI_EXPLANATION_INPUT_HASH_INVALID")
    if identifiers != expected_ids:
        _reject(f"{kind}_COVERAGE_INVALID")
    return copied


def _observed_at(value: object) -> datetime:
    text_value = _text(value, "OBSERVED_AT_INVALID", 64)
    try:
        parsed = datetime.fromisoformat(text_value.replace("Z", "+00:00"))
    except ValueError:
        _reject("OBSERVED_AT_INVALID")
    if parsed.tzinfo is None:
        _reject("OBSERVED_AT_INVALID")
    return parsed.astimezone(UTC)


def summarize_result_controls(result_json: object) -> dict[str, int]:
    """Windows의 assessment_status와 Linux/Switch의 status를 같은 개수로 셉니다."""

    result = _object(result_json, "RESULT_JSON_INVALID")
    values = result.get("controls")
    if not isinstance(values, list):
        _reject("CONTROL_LIST_INVALID")
    counts = {
        "total": len(values),
        "pass": 0,
        "fail": 0,
        "error": 0,
        "review": 0,
        "not_applicable": 0,
    }
    keys = {
        "PASS": "pass",
        "FAIL": "fail",
        "ERROR": "error",
        "REVIEW": "review",
        "N/A": "not_applicable",
    }
    for value in values:
        control = _object(value, "CONTROL_INVALID")
        status = control.get("status", control.get("assessment_status"))
        if status not in _STATUSES:
            _reject("CONTROL_STATUS_INVALID")
        counts[keys[status]] += 1
    return counts


def _windows_control(value: object) -> dict[str, JsonValue]:
    source = _object(value, "CONTROL_INVALID")
    control_id = _text(source.get("control_id"), "CONTROL_ID_INVALID", 5)
    if control_id not in _WINDOWS_CONTROL_IDS:
        _reject("CONTROL_ID_INVALID")
    status = source.get("assessment_status")
    if status not in _STATUSES:
        _reject("CONTROL_STATUS_INVALID")
    projected: dict[str, JsonValue] = {
        "control_id": control_id,
        "status": status,
        "administrator_required": source.get("administrator_required") is True,
    }
    for field in _CONTROL_TEXT_FIELDS:
        value_text = _optional_text(source.get(field), f"{field.upper()}_INVALID")
        if value_text is not None:
            projected[field] = value_text
    return projected


@dataclass(frozen=True, slots=True)
class ValidatedWindowsAuditSnapshot:
    result_id: str
    result_version: int
    observed_at: datetime
    result_json: dict[str, JsonValue]
    result_sha256: str
    criteria_sha256: str | None
    counts: dict[str, int]


def validate_windows_audit_snapshot(value: object) -> ValidatedWindowsAuditSnapshot:
    """Launcher 결과에서 비식별·결정론 필드만 골라 영속 snapshot을 만듭니다."""

    source = _object(value, "WINDOWS_RESULT_INVALID")
    if source.get("raw_values_persisted") is not False:
        _reject("RAW_VALUES_PERSISTED_FORBIDDEN")
    if source.get("settings_modified") is not False:
        _reject("SETTINGS_MODIFIED_FORBIDDEN")
    if source.get("official_finding_created") is not False:
        _reject("OFFICIAL_FINDING_WRITE_FORBIDDEN")
    if source.get("result_kind") != "LIVE_DRAFT_ASSESSMENT":
        _reject("WINDOWS_RESULT_KIND_INVALID")

    result_id = _text(source.get("result_id"), "RESULT_ID_INVALID", 16)
    if _RESULT_ID.fullmatch(result_id) is None:
        _reject("RESULT_ID_INVALID")
    version = source.get("sequence")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or not 1 <= version <= 1_000_000
    ):
        _reject("RESULT_VERSION_INVALID")
    attempt = source.get("attempt")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        _reject("RESULT_ATTEMPT_INVALID")

    values = source.get("controls")
    if not isinstance(values, list) or len(values) != 18:
        _reject("CONTROL_COVERAGE_INVALID")
    controls = [_windows_control(item) for item in values]
    if {str(item["control_id"]) for item in controls} != _WINDOWS_CONTROL_IDS:
        _reject("CONTROL_COVERAGE_INVALID")
    official_explanations = _context_items(
        source.get("explanations"),
        expected_ids=_WINDOWS_CONTROL_IDS,
        kind="OFFICIAL_EXPLANATION",
    )
    ai_explanation_inputs = _context_items(
        source.get("ai_explanation_inputs"),
        expected_ids=_WINDOWS_CONTROL_IDS,
        kind="AI_EXPLANATION_INPUT",
    )

    criteria_sha256: str | None = None
    criteria_context = source.get("criteria_context")
    if criteria_context is not None:
        criteria = _object(criteria_context, "CRITERIA_CONTEXT_INVALID")
        digest = criteria.get("criteria_sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            _reject("CRITERIA_SHA256_INVALID")
        criteria_sha256 = digest

    observed_at = _observed_at(source.get("observed_at_utc"))
    result_json: dict[str, JsonValue] = {
        "schema_version": "secai.windows-audit-history.v1",
        "platform": "WINDOWS",
        "result_id": result_id,
        "result_version": version,
        "attempt": attempt,
        "observed_at_utc": observed_at.isoformat().replace("+00:00", "Z"),
        "result_kind": "LIVE_DRAFT_ASSESSMENT",
        "criteria_sha256": criteria_sha256,
        "controls": cast(list[JsonValue], controls),
        "official_explanations": official_explanations,
        "ai_explanation_inputs": ai_explanation_inputs,
        "raw_values_persisted": False,
        "settings_modified": False,
        "official_finding_created": False,
    }
    counts = summarize_result_controls(result_json)
    result_json["counts"] = cast(dict[str, JsonValue], counts)
    return ValidatedWindowsAuditSnapshot(
        result_id=result_id,
        result_version=version,
        observed_at=observed_at,
        result_json=result_json,
        result_sha256=canonical_sha256(result_json),
        criteria_sha256=criteria_sha256,
        counts=counts,
    )


def attach_device_history_context(
    result_json: dict[str, JsonValue] | dict[str, object],
    *,
    official_explanations: list[dict[str, object]],
    ai_explanation_inputs: list[dict[str, object]],
) -> dict[str, JsonValue]:
    """Linux·Switch 불변 결과에 공식 설명과 실제 AI 입력 snapshot을 함께 묶습니다."""

    copied = _json_copy(
        result_json,
        "DEVICE_RESULT_INVALID",
        maximum_bytes=8_000_000,
        reject_prohibited_fields=False,
    )
    if not isinstance(copied, dict):
        _reject("DEVICE_RESULT_INVALID")
    controls = copied.get("controls")
    if not isinstance(controls, list) or not controls:
        _reject("DEVICE_CONTROL_COVERAGE_INVALID")
    expected_ids = frozenset(
        str(item.get("control_id"))
        for item in controls
        if isinstance(item, dict) and isinstance(item.get("control_id"), str)
    )
    if len(expected_ids) != len(controls):
        _reject("DEVICE_CONTROL_COVERAGE_INVALID")
    official = _json_copy(
        official_explanations,
        "DEVICE_OFFICIAL_EXPLANATIONS_INVALID",
        maximum_bytes=4_000_000,
    )
    ai_inputs = _json_copy(
        ai_explanation_inputs,
        "DEVICE_AI_INPUTS_INVALID",
        maximum_bytes=4_000_000,
    )
    if not isinstance(official, list) or not isinstance(ai_inputs, list):
        _reject("DEVICE_HISTORY_CONTEXT_INVALID")
    for values in (official, ai_inputs):
        identifiers = [
            str(item.get("control_id"))
            for item in values
            if isinstance(item, dict) and isinstance(item.get("control_id"), str)
        ]
        if len(identifiers) != len(controls) or frozenset(identifiers) != expected_ids:
            _reject("DEVICE_HISTORY_CONTEXT_COVERAGE_INVALID")
    copied.pop("result_sha256", None)
    copied["official_explanations"] = official
    copied["ai_explanation_inputs"] = ai_inputs
    copied["result_sha256"] = canonical_sha256(copied)
    return copied


@dataclass(frozen=True, slots=True)
class ValidatedWindowsAuditPresentation:
    result_id: str
    result_version: int
    presentation_kind: str
    payload: dict[str, JsonValue]
    payload_sha256: str


def _non_negative_int(value: object, code: str, maximum: int = 5) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= maximum
    ):
        _reject(code)
    return value


def _administrator_report(
    value: object,
    *,
    required: bool,
) -> dict[str, JsonValue] | None:
    if value is None and not required:
        return None
    report = _object(value, "ADMINISTRATOR_REPORT_INVALID")
    if (
        report.get("status") != "COMPLETED"
        or report.get("settings_modified") is not False
        or report.get("raw_values_persisted") is not False
        or report.get("official_finding_created") is not False
    ):
        _reject("ADMINISTRATOR_REPORT_INVALID")
    observed_at = _text(
        report.get("observed_at_utc"),
        "ADMINISTRATOR_OBSERVED_AT_INVALID",
        64,
    )
    _observed_at(observed_at)
    values = report.get("results")
    if not isinstance(values, list) or not 1 <= len(values) <= 5:
        _reject("ADMINISTRATOR_RESULT_COVERAGE_INVALID")
    selected_count = _non_negative_int(
        report.get("selected_probe_count"),
        "ADMINISTRATOR_COUNT_INVALID",
    )
    if selected_count != len(values):
        _reject("ADMINISTRATOR_COUNT_INVALID")
    counts = {
        field: _non_negative_int(report.get(field), "ADMINISTRATOR_COUNT_INVALID")
        for field in (
            "collected_probe_count",
            "review_required_count",
            "collection_error_count",
            "assessment_review_count",
        )
    }
    projected_results: list[JsonValue] = []
    identifiers: set[str] = set()
    for value_result in values:
        item = _object(value_result, "ADMINISTRATOR_RESULT_INVALID")
        control_id = _text(
            item.get("control_id"), "ADMINISTRATOR_CONTROL_ID_INVALID", 5
        )
        if control_id not in _ADMINISTRATOR_CONTROL_IDS or control_id in identifiers:
            _reject("ADMINISTRATOR_RESULT_COVERAGE_INVALID")
        identifiers.add(control_id)
        collection_status = item.get("collection_status")
        assessment_status = item.get("assessment_status")
        if collection_status not in {"COLLECTED", "ERROR", "UNSUPPORTED"}:
            _reject("ADMINISTRATOR_COLLECTION_STATUS_INVALID")
        if assessment_status not in _STATUSES:
            _reject("ADMINISTRATOR_ASSESSMENT_STATUS_INVALID")
        projected: dict[str, JsonValue] = {
            "control_id": control_id,
            "probe_id": _text(
                item.get("probe_id"), "ADMINISTRATOR_PROBE_ID_INVALID", 128
            ),
            "collection_status": collection_status,
            "assessment_status": assessment_status,
        }
        for field in (
            "title",
            "importance",
            "reason",
            "description",
            "privilege",
            "display_status",
            "status_label",
            "collection_status_label",
            "actual",
            "expected",
            "assessment_kind",
            "result_code",
            "judgement_explanation",
            "collected_summary",
        ):
            field_value = _optional_text(
                item.get(field), f"ADMINISTRATOR_{field.upper()}_INVALID"
            )
            if field_value is not None:
                projected[field] = field_value
        projected_results.append(projected)
    return {
        "status": "COMPLETED",
        "observed_at_utc": observed_at,
        "selected_probe_count": selected_count,
        **counts,
        "results": projected_results,
        "settings_modified": False,
        "raw_values_persisted": False,
        "official_finding_created": False,
    }


def _ai_screen(
    value: object,
    *,
    result_id: str,
    result_version: int,
) -> dict[str, JsonValue]:
    screen = _object(value, "AI_SCREEN_INVALID")
    if screen.get("version") != 1:
        _reject("AI_SCREEN_VERSION_INVALID")
    generation_key = _text(
        screen.get("generation_key"),
        "AI_GENERATION_KEY_INVALID",
        512,
    )
    if not generation_key.startswith(f"{result_id}:{result_version}:"):
        _reject("AI_GENERATION_KEY_INVALID")
    summary_source = _text(
        screen.get("summary_source"),
        "AI_SUMMARY_INVALID",
        100_000,
    )
    values = screen.get("controls")
    if not isinstance(values, list) or len(values) != 18:
        _reject("AI_SCREEN_COVERAGE_INVALID")
    controls: list[JsonValue] = []
    identifiers: set[str] = set()
    for raw in values:
        item = _object(raw, "AI_SCREEN_CONTROL_INVALID")
        control_id = _text(item.get("control_id"), "AI_SCREEN_CONTROL_ID_INVALID", 5)
        if control_id not in _WINDOWS_CONTROL_IDS or control_id in identifiers:
            _reject("AI_SCREEN_COVERAGE_INVALID")
        identifiers.add(control_id)
        sources = _json_copy(
            item.get("knowledge_sources", []),
            "AI_SCREEN_SOURCE_INVALID",
            maximum_bytes=100_000,
        )
        if not isinstance(sources, list) or len(sources) > 8:
            _reject("AI_SCREEN_SOURCE_INVALID")
        controls.append(
            {
                "control_id": control_id,
                "source": _text(
                    item.get("source"),
                    "AI_SCREEN_CONTENT_INVALID",
                    100_000,
                ),
                "knowledge_sources": sources,
            }
        )
    if identifiers != _WINDOWS_CONTROL_IDS:
        _reject("AI_SCREEN_COVERAGE_INVALID")
    return {
        "version": 1,
        "generation_key": generation_key,
        "summary_source": summary_source,
        "controls": controls,
    }


def validate_windows_audit_presentation(
    value: object,
) -> ValidatedWindowsAuditPresentation:
    source = _object(value, "WINDOWS_PRESENTATION_INVALID")
    result_id = _text(source.get("result_id"), "RESULT_ID_INVALID", 16)
    if _RESULT_ID.fullmatch(result_id) is None:
        _reject("RESULT_ID_INVALID")
    result_version = source.get("result_version")
    if (
        not isinstance(result_version, int)
        or isinstance(result_version, bool)
        or not 1 <= result_version <= 1_000_000
    ):
        _reject("RESULT_VERSION_INVALID")
    presentation_kind = source.get("presentation_kind")
    if presentation_kind not in _PRESENTATION_KINDS:
        _reject("PRESENTATION_KIND_INVALID")
    if source.get("test_environment_result") is not True:
        _reject("TEST_ENVIRONMENT_MARKER_REQUIRED")
    administrator_report = _administrator_report(
        source.get("administrator_report"),
        required=presentation_kind == "ADMINISTRATOR",
    )
    ai_screen = (
        _ai_screen(
            source.get("ai_screen"),
            result_id=result_id,
            result_version=result_version,
        )
        if presentation_kind == "AI_COMPLETED"
        else None
    )
    payload: dict[str, JsonValue] = {
        "schema_version": "secai.windows-audit-presentation.v1",
        "result_id": result_id,
        "result_version": result_version,
        "presentation_kind": presentation_kind,
        "administrator_report": administrator_report,
        "ai_screen": ai_screen,
        "test_environment_result": True,
    }
    return ValidatedWindowsAuditPresentation(
        result_id=result_id,
        result_version=result_version,
        presentation_kind=presentation_kind,
        payload=payload,
        payload_sha256=canonical_sha256(payload),
    )


@dataclass(frozen=True, slots=True)
class AuditHistoryPolicy:
    id: UUID | None
    version: int
    retention_days: int
    backup_required: bool
    deletion_mode: str
    created_at: datetime | None

    def __post_init__(self) -> None:
        if self.version < 1:
            _reject("POLICY_VERSION_INVALID")
        if not 30 <= self.retention_days <= 3_650:
            _reject("RETENTION_DAYS_INVALID")
        if self.deletion_mode not in _DELETION_MODES:
            _reject("DELETION_MODE_INVALID")

    def public_view(self) -> dict[str, object]:
        return {
            "policy_id": str(self.id) if self.id is not None else None,
            "version": self.version,
            "retention_days": self.retention_days,
            "backup_required": self.backup_required,
            "deletion_mode": self.deletion_mode,
            "physical_delete_allowed": False,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def default_audit_history_policy() -> AuditHistoryPolicy:
    return AuditHistoryPolicy(
        id=None,
        version=1,
        retention_days=365,
        backup_required=True,
        deletion_mode="HOLD",
        created_at=None,
    )


def audit_history_entry_view(
    *,
    entry_id: UUID,
    platform: str,
    asset_label: str,
    result_id: str,
    result_version: int,
    completed_at: datetime,
    result_json: dict[str, JsonValue],
    result_sha256: str,
    criteria_sha256: str | None,
    policy: AuditHistoryPolicy,
    include_controls: bool = False,
    presentation: dict[str, object] | None = None,
    ai_screen: dict[str, object] | None = None,
) -> dict[str, object]:
    """저장소별 내부 모양을 공통 사용자 응답으로 제한해 변환합니다."""

    counts = summarize_result_controls(result_json)
    retain_until = completed_at + timedelta(days=policy.retention_days)
    view: dict[str, object] = {
        "entry_id": str(entry_id),
        "platform": platform,
        "asset_label": asset_label,
        "result_id": result_id,
        "result_version": result_version,
        "completed_at": completed_at.isoformat(),
        "counts": counts,
        "result_sha256": result_sha256,
        "criteria_sha256": criteria_sha256,
        "retention": {
            "policy_version": policy.version,
            "retain_until": retain_until.isoformat(),
            "backup_required": policy.backup_required,
            "backup_status": "EXTERNAL_VERIFICATION_REQUIRED",
            "deletion_mode": policy.deletion_mode,
            "physical_delete_allowed": False,
        },
        "detail_url": f"/ui/audit-history/{platform.casefold()}/{entry_id}",
    }
    if include_controls:
        controls = cast(list[object], result_json.get("controls", []))
        view["controls"] = [_history_control_view(item) for item in controls]
        view["official_explanations"] = cast(
            list[JsonValue],
            result_json.get("official_explanations", []),
        )
        view["ai_explanation_inputs"] = cast(
            list[JsonValue],
            result_json.get("ai_explanation_inputs", []),
        )
        if presentation is not None:
            view["presentation"] = presentation
        if ai_screen is not None:
            view["ai_screen"] = ai_screen
    return view


def _history_control_view(value: object) -> dict[str, object]:
    control = _object(value, "CONTROL_INVALID")
    status = control.get("status", control.get("assessment_status"))
    if status not in _STATUSES:
        _reject("CONTROL_STATUS_INVALID")
    return {
        "control_id": _text(control.get("control_id"), "CONTROL_ID_INVALID", 16),
        "title": _optional_text(control.get("title"), "CONTROL_TITLE_INVALID", 300)
        or "제목 확인 필요",
        "status": status,
        "actual": _optional_text(
            control.get("actual", control.get("observed_summary")),
            "CONTROL_ACTUAL_INVALID",
        ),
        "expected": _optional_text(
            control.get("expected", control.get("expected_summary")),
            "CONTROL_EXPECTED_INVALID",
        ),
        "result_code": _optional_text(
            control.get("result_code"),
            "CONTROL_RESULT_CODE_INVALID",
            128,
        ),
    }
