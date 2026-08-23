"""Windows 수집기에 전달되는 비실행형 점검 기준 스냅샷 계약."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Sequence
from typing import cast
from uuid import UUID


class CriteriaContractError(ValueError):
    """허용 목록 밖의 기준 또는 잘못된 기준값을 거부합니다."""


_INTEGER_RANGES = {
    "password_maximum_age_days": (1, 365),
    "password_minimum_length": (8, 64),
    "security_update_maximum_age_days": (1, 180),
    "antivirus_signature_maximum_age_hours": (1, 168),
    "screensaver_timeout_maximum_minutes": (1, 60),
}
_BOOLEAN_KEYS = frozenset(
    {
        "password_complexity_required",
        "password_required",
        "wininet_current_user_scope_accepted",
        "screensaver_current_user_scope_accepted",
        "autoplay_disabled_required",
        "remote_assistance_disabled_required",
    }
)
_STRING_LIST_KEYS = frozenset(
    {
        "approved_share_ids",
        "unnecessary_service_ids",
        "approved_messenger_products",
    }
)
_VALUE_KEYS = frozenset(_INTEGER_RANGES) | _BOOLEAN_KEYS | _STRING_LIST_KEYS
_PROFILE_CONTEXT_KEYS = frozenset({"id", "name", "version", "document_sha256"})


def _normalize_list(value: object) -> tuple[str, ...]:
    source: Sequence[object]
    if isinstance(value, str):
        source = value.splitlines()
    elif isinstance(value, (list, tuple)):
        source = value
    else:
        raise CriteriaContractError("점검 기준 이름 목록 형식이 올바르지 않습니다.")
    normalized: list[str] = []
    for item in source:
        if not isinstance(item, str):
            raise CriteriaContractError("점검 기준 이름 목록에 잘못된 값이 있습니다.")
        name = " ".join(item.strip().split())
        if not name:
            continue
        if len(name) > 80 or any(
            character in name for character in ("\x00", "\r", "\n", "|", ";")
        ):
            raise CriteriaContractError("점검 기준 이름에 허용되지 않은 값이 있습니다.")
        if name.casefold() not in {current.casefold() for current in normalized}:
            normalized.append(name)
    if len(normalized) > 50:
        raise CriteriaContractError("점검 기준 이름은 50개 이하로 등록해야 합니다.")
    return tuple(sorted(normalized, key=str.casefold))


def _validate_values(value: object) -> dict[str, int | bool | tuple[str, ...]]:
    if not isinstance(value, dict) or frozenset(value) != _VALUE_KEYS:
        raise CriteriaContractError("점검에 필요한 기준값이 모두 포함되어야 합니다.")
    normalized: dict[str, int | bool | tuple[str, ...]] = {}
    for key, item in value.items():
        if key in _INTEGER_RANGES:
            minimum, maximum = _INTEGER_RANGES[key]
            if (
                not isinstance(item, int)
                or isinstance(item, bool)
                or item < minimum
                or item > maximum
            ):
                raise CriteriaContractError("점검 기준 정수값의 범위가 올바르지 않습니다.")
            normalized[key] = item
        elif key in _BOOLEAN_KEYS:
            if not isinstance(item, bool):
                raise CriteriaContractError("점검 기준 사용 여부가 올바르지 않습니다.")
            normalized[key] = item
        else:
            list_value = _normalize_list(item)
            if key == "unnecessary_service_ids" and not list_value:
                raise CriteriaContractError(
                    "불필요 서비스 최소 점검 범위는 한 개 이상이어야 합니다."
                )
            normalized[key] = list_value
    return normalized


def _json_values(
    values: dict[str, int | bool | tuple[str, ...]],
) -> dict[str, int | bool | list[str]]:
    return {
        key: list(item) if isinstance(item, tuple) else item
        for key, item in values.items()
    }


def _canonical_sha256(values: object) -> str:
    normalized = _json_values(_validate_values(values))
    serialized = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _profile_context(value: object, *, label: str) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or frozenset(value) != _PROFILE_CONTEXT_KEYS:
        raise CriteriaContractError(f"{label} 정보가 올바르지 않습니다.")
    try:
        UUID(str(value.get("id")))
    except (TypeError, ValueError) as exc:
        raise CriteriaContractError(f"{label} 번호가 올바르지 않습니다.") from exc
    name = value.get("name")
    version = value.get("version")
    document_sha256 = value.get("document_sha256")
    if not isinstance(name, str) or not name.strip() or len(name) > 80:
        raise CriteriaContractError(f"{label} 이름이 올바르지 않습니다.")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise CriteriaContractError(f"{label} 버전이 올바르지 않습니다.")
    if (
        not isinstance(document_sha256, str)
        or len(document_sha256) != 64
        or any(character not in "0123456789abcdef" for character in document_sha256)
    ):
        raise CriteriaContractError(f"{label} 확인값이 올바르지 않습니다.")
    return {
        "id": str(value["id"]),
        "name": " ".join(name.strip().split()),
        "version": version,
        "document_sha256": document_sha256,
    }


def validate_criteria_execution_context(value: object) -> dict[str, object]:
    """브라우저가 전달한 점검 기준 스냅샷을 실행 전에 검증합니다."""

    expected_keys = frozenset(
        {
            "values",
            "sources",
            "criteria_sha256",
            "organization_profile",
            "personal_profile",
        }
    )
    if not isinstance(value, dict) or frozenset(value) != expected_keys:
        raise CriteriaContractError("점검 기준 스냅샷 형식이 올바르지 않습니다.")
    normalized = _validate_values(value.get("values"))
    criteria_sha256 = value.get("criteria_sha256")
    if (
        not isinstance(criteria_sha256, str)
        or not hmac.compare_digest(criteria_sha256, _canonical_sha256(normalized))
    ):
        raise CriteriaContractError("점검 기준 확인값이 일치하지 않습니다.")
    sources = value.get("sources")
    allowed_sources = {"KISA_DEFAULT", "ORGANIZATION", "PERSONAL"}
    if (
        not isinstance(sources, dict)
        or frozenset(sources) != _VALUE_KEYS
        or any(source not in allowed_sources for source in sources.values())
    ):
        raise CriteriaContractError("점검 기준 출처가 올바르지 않습니다.")
    return {
        "values": _json_values(normalized),
        "sources": dict(sources),
        "criteria_sha256": criteria_sha256,
        "organization_profile": _profile_context(
            value.get("organization_profile"), label="조직 기본 기준"
        ),
        "personal_profile": _profile_context(
            value.get("personal_profile"), label="개인 기준"
        ),
    }


def encode_criteria_execution_context(value: object) -> str:
    validated = validate_criteria_execution_context(value)
    payload = json.dumps(
        validated,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_criteria_execution_context(value: str) -> dict[str, object]:
    if not value or len(value) > 16384:
        raise CriteriaContractError("점검 기준 전달값의 길이가 올바르지 않습니다.")
    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.b64decode(value + padding, altchars=b"-_", validate=True)
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise CriteriaContractError("점검 기준 전달값을 읽을 수 없습니다.") from exc
    return validate_criteria_execution_context(cast(object, document))
