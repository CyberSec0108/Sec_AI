"""사용자 입력을 실행 코드와 분리한 점검 기준 프로필 계약."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Literal, Protocol, cast
from uuid import UUID

from security_audit.security.auth import AuthenticatedPrincipal, HumanRole

CriteriaValue = int | bool | tuple[str, ...]
CriteriaSource = Literal["KISA_DEFAULT", "ORGANIZATION", "PERSONAL"]
CriteriaSelectionKind = Literal["KISA_DEFAULT", "ORGANIZATION", "PERSONAL"]
CriteriaSelectionSource = Literal["CRITERIA_PAGE", "RESET", "SCAN_START"]


class CriteriaContractError(ValueError):
    """허용 목록 밖의 기준 또는 잘못된 기준값을 거부합니다."""


KISA_PC_GUIDE_REFERENCE = "KISA PC 보안 가이드 2026"
PC05_PRODUCT_DEFAULT_REFERENCE = (
    "SecAI Windows 10·11 최소 기본 점검 범위 (KISA PC-05 보조)"
)
WINDOWS_SCOPE_PRODUCT_DEFAULT_REFERENCE = (
    "SecAI Windows 10·11 현재 PC·로그인 사용자 기본 점검 범위 (KISA 보조)"
)

# KISA 가이드가 제품별 Windows 서비스 이름을 열거하지 않으므로, 기본 상태로
# 운영할 필요가 낮고 원격·레거시 노출 위험이 있는 Windows 서비스만 보수적으로 둡니다.
DEFAULT_UNNECESSARY_SERVICE_IDS = (
    "FTPSVC",
    "MSFTPSVC",
    "RemoteRegistry",
    "SimpTcp",
    "SNMP",
    "SNMPTRAP",
    "TlntSvr",
)


@dataclass(frozen=True, slots=True)
class CriterionDefinition:
    key: str
    control_id: str
    title: str
    description: str
    value_type: Literal["INTEGER", "BOOLEAN", "STRING_LIST"]
    official_value: CriteriaValue
    comparison: Literal["MINIMUM", "MAXIMUM", "REQUIRED", "CATALOG"]
    official_reference: str = KISA_PC_GUIDE_REFERENCE
    unit: str | None = None
    minimum: int | None = None
    maximum: int | None = None

    def public_view(self) -> dict[str, object]:
        value = asdict(self)
        value["official_value"] = _json_value(self.official_value)
        return value


_CATALOG = (
    CriterionDefinition(
        key="password_maximum_age_days",
        control_id="PC-01",
        title="비밀번호 최대 사용 기간",
        description="비밀번호를 다시 변경하기 전까지 사용할 수 있는 최대 기간입니다.",
        value_type="INTEGER",
        official_value=90,
        comparison="MAXIMUM",
        unit="일",
        minimum=1,
        maximum=365,
    ),
    CriterionDefinition(
        key="password_minimum_length",
        control_id="PC-02",
        title="비밀번호 최소 길이",
        description="조직 또는 개인이 요구하는 비밀번호의 최소 글자 수입니다.",
        value_type="INTEGER",
        official_value=10,
        comparison="MINIMUM",
        unit="자",
        minimum=8,
        maximum=64,
    ),
    CriterionDefinition(
        key="password_complexity_required",
        control_id="PC-02",
        title="비밀번호 복잡성 사용",
        description="영문·숫자·특수문자 조합 정책을 사용해야 하는지 정합니다.",
        value_type="BOOLEAN",
        official_value=True,
        comparison="REQUIRED",
    ),
    CriterionDefinition(
        key="password_required",
        control_id="PC-02",
        title="비밀번호 사용",
        description="로그인 계정에 비밀번호 사용을 필수로 요구합니다.",
        value_type="BOOLEAN",
        official_value=True,
        comparison="REQUIRED",
    ),
    CriterionDefinition(
        key="approved_share_ids",
        control_id="PC-04",
        title="승인된 공유 폴더",
        description="업무상 사용을 승인한 공유 이름만 등록합니다.",
        value_type="STRING_LIST",
        official_value=(),
        comparison="CATALOG",
    ),
    CriterionDefinition(
        key="unnecessary_service_ids",
        control_id="PC-05",
        title="불필요 서비스 최소 점검 범위",
        description=(
            "조직 기준이 없어도 확인할 Windows 원격·레거시 서비스 이름입니다. "
            "환경에 필요한 서비스는 조직 또는 개인 기준에서 조정할 수 있습니다."
        ),
        value_type="STRING_LIST",
        official_value=DEFAULT_UNNECESSARY_SERVICE_IDS,
        comparison="CATALOG",
        official_reference=PC05_PRODUCT_DEFAULT_REFERENCE,
    ),
    CriterionDefinition(
        key="approved_messenger_products",
        control_id="PC-06",
        title="승인된 메신저 제품",
        description="조직 또는 개인이 사용을 승인한 메신저 제품 이름입니다.",
        value_type="STRING_LIST",
        official_value=(),
        comparison="CATALOG",
    ),
    CriterionDefinition(
        key="security_update_maximum_age_days",
        control_id="PC-10",
        title="보안 업데이트 확인 주기",
        description="최근 보안 업데이트 이후 허용할 최대 기간입니다.",
        value_type="INTEGER",
        official_value=30,
        comparison="MAXIMUM",
        unit="일",
        minimum=1,
        maximum=180,
    ),
    CriterionDefinition(
        key="antivirus_signature_maximum_age_hours",
        control_id="PC-13",
        title="백신 서명 최대 경과 시간",
        description=(
            "조직 기준이 없어도 현재 백신 서명이 마지막으로 갱신된 뒤 허용할 "
            "최대 시간을 제품 기본 범위로 적용합니다."
        ),
        value_type="INTEGER",
        official_value=24,
        comparison="MAXIMUM",
        official_reference=WINDOWS_SCOPE_PRODUCT_DEFAULT_REFERENCE,
        unit="시간",
        minimum=1,
        maximum=168,
    ),
    CriterionDefinition(
        key="screensaver_timeout_maximum_minutes",
        control_id="PC-16",
        title="화면보호기 최대 대기 시간",
        description="사용하지 않을 때 화면이 잠기기까지 허용할 최대 시간입니다.",
        value_type="INTEGER",
        official_value=10,
        comparison="MAXIMUM",
        unit="분",
        minimum=1,
        maximum=60,
    ),
    CriterionDefinition(
        key="wininet_current_user_scope_accepted",
        control_id="PC-09",
        title="현재 로그인 사용자 WinINet 설정 판정",
        description=(
            "조직 기준이 없어도 이번 점검에서는 현재 로그인 사용자의 WinINet "
            "캐시 삭제 설정을 기본 범위로 판정합니다."
        ),
        value_type="BOOLEAN",
        official_value=True,
        comparison="REQUIRED",
        official_reference=WINDOWS_SCOPE_PRODUCT_DEFAULT_REFERENCE,
    ),
    CriterionDefinition(
        key="screensaver_current_user_scope_accepted",
        control_id="PC-16",
        title="현재 로그인 사용자 화면 잠금 설정 판정",
        description=(
            "조직 기준이 없어도 이번 점검에서는 현재 로그인 사용자의 화면보호기와 "
            "잠금 설정을 기본 범위로 판정합니다."
        ),
        value_type="BOOLEAN",
        official_value=True,
        comparison="REQUIRED",
        official_reference=WINDOWS_SCOPE_PRODUCT_DEFAULT_REFERENCE,
    ),
    CriterionDefinition(
        key="autoplay_disabled_required",
        control_id="PC-17",
        title="모든 미디어 자동 실행 차단",
        description=(
            "조직 기준이 없어도 모든 드라이브와 비볼륨 장치의 자동 실행 차단을 "
            "제품 기본 범위로 판정합니다."
        ),
        value_type="BOOLEAN",
        official_value=True,
        comparison="REQUIRED",
        official_reference=WINDOWS_SCOPE_PRODUCT_DEFAULT_REFERENCE,
    ),
    CriterionDefinition(
        key="remote_assistance_disabled_required",
        control_id="PC-18",
        title="원격 지원 명시적 차단",
        description=(
            "조직 기준이 없어도 요청·제공 원격 지원을 명시적으로 차단했는지 "
            "제품 기본 범위로 판정합니다."
        ),
        value_type="BOOLEAN",
        official_value=True,
        comparison="REQUIRED",
        official_reference=WINDOWS_SCOPE_PRODUCT_DEFAULT_REFERENCE,
    ),
)

CRITERIA_CATALOG = {item.key: item for item in _CATALOG}
_PROFILE_CONTEXT_KEYS = frozenset({"id", "name", "version", "document_sha256"})


def public_criteria_catalog() -> tuple[dict[str, object], ...]:
    return tuple(item.public_view() for item in _CATALOG)


def _json_value(value: CriteriaValue) -> int | bool | list[str]:
    return list(value) if isinstance(value, tuple) else value


def _normalize_list(value: object, definition: CriterionDefinition) -> tuple[str, ...]:
    source: Sequence[object]
    if isinstance(value, str):
        source = value.splitlines()
    elif isinstance(value, (list, tuple)):
        source = value
    else:
        raise CriteriaContractError(f"{definition.title} 값은 이름 목록이어야 합니다.")
    normalized: list[str] = []
    for item in source:
        if not isinstance(item, str):
            raise CriteriaContractError(f"{definition.title} 목록에 잘못된 값이 있습니다.")
        name = " ".join(item.strip().split())
        if not name:
            continue
        if len(name) > 80:
            raise CriteriaContractError(f"{definition.title}의 이름은 80자 이하여야 합니다.")
        if any(character in name for character in ("\x00", "\r", "\n", "|", ";")):
            raise CriteriaContractError(f"{definition.title}에 허용되지 않은 문자가 있습니다.")
        if name.casefold() not in {current.casefold() for current in normalized}:
            normalized.append(name)
    if len(normalized) > 50:
        raise CriteriaContractError(f"{definition.title}은 50개 이하로 등록해야 합니다.")
    if definition.key == "unnecessary_service_ids" and not normalized:
        raise CriteriaContractError(
            "불필요 서비스 최소 점검 범위는 한 개 이상이어야 합니다."
        )
    return tuple(sorted(normalized, key=str.casefold))


def validate_criteria_values(values: object) -> dict[str, CriteriaValue]:
    if not isinstance(values, dict):
        raise CriteriaContractError("점검 기준은 항목과 값으로 구성해야 합니다.")
    normalized: dict[str, CriteriaValue] = {}
    for key, value in values.items():
        if not isinstance(key, str) or key not in CRITERIA_CATALOG:
            raise CriteriaContractError("허용되지 않은 점검 기준이 포함되어 있습니다.")
        definition = CRITERIA_CATALOG[key]
        if definition.value_type == "INTEGER":
            if not isinstance(value, int) or isinstance(value, bool):
                raise CriteriaContractError(f"{definition.title} 값은 정수여야 합니다.")
            if definition.minimum is not None and value < definition.minimum:
                raise CriteriaContractError(
                    f"{definition.title} 값은 {definition.minimum} 이상이어야 합니다."
                )
            if definition.maximum is not None and value > definition.maximum:
                raise CriteriaContractError(
                    f"{definition.title} 값은 {definition.maximum} 이하여야 합니다."
                )
            normalized[key] = value
        elif definition.value_type == "BOOLEAN":
            if not isinstance(value, bool):
                raise CriteriaContractError(f"{definition.title} 값은 사용 여부여야 합니다.")
            normalized[key] = value
        else:
            normalized[key] = _normalize_list(value, definition)
    return normalized


def canonical_criteria_sha256(values: object) -> str:
    normalized = validate_criteria_values(values)
    payload = {
        key: _json_value(value)
        for key, value in sorted(normalized.items())
    }
    serialized = json.dumps(
        payload,
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
    profile_id = value.get("id")
    name = value.get("name")
    version = value.get("version")
    document_sha256 = value.get("document_sha256")
    try:
        UUID(str(profile_id))
    except (TypeError, ValueError) as exc:
        raise CriteriaContractError(f"{label} 번호가 올바르지 않습니다.") from exc
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
        "id": str(profile_id),
        "name": " ".join(name.strip().split()),
        "version": version,
        "document_sha256": document_sha256,
    }


def validate_criteria_execution_context(value: object) -> dict[str, object]:
    """브라우저와 로컬 실행기 사이의 비실행형 기준 스냅샷을 검증합니다."""

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
    normalized = validate_criteria_values(value.get("values"))
    if frozenset(normalized) != frozenset(CRITERIA_CATALOG):
        raise CriteriaContractError("점검에 필요한 기준값이 모두 포함되어야 합니다.")
    criteria_sha256 = value.get("criteria_sha256")
    if (
        not isinstance(criteria_sha256, str)
        or not hmac.compare_digest(
            criteria_sha256,
            canonical_criteria_sha256(normalized),
        )
    ):
        raise CriteriaContractError("점검 기준 확인값이 일치하지 않습니다.")
    sources = value.get("sources")
    if not isinstance(sources, dict) or frozenset(sources) != frozenset(normalized):
        raise CriteriaContractError("점검 기준 출처가 올바르지 않습니다.")
    allowed_sources = {"KISA_DEFAULT", "ORGANIZATION", "PERSONAL"}
    if any(source not in allowed_sources for source in sources.values()):
        raise CriteriaContractError("허용되지 않은 점검 기준 출처가 있습니다.")
    return {
        "values": {
            key: _json_value(item) for key, item in normalized.items()
        },
        "sources": dict(sources),
        "criteria_sha256": criteria_sha256,
        "organization_profile": _profile_context(
            value.get("organization_profile"),
            label="조직 기본 기준",
        ),
        "personal_profile": _profile_context(
            value.get("personal_profile"),
            label="개인 기준",
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
    return validate_criteria_execution_context(document)


def _strength(definition: CriterionDefinition, value: CriteriaValue) -> str:
    official = definition.official_value
    if value == official:
        return "SAME"
    if definition.comparison == "MINIMUM":
        return "STRONGER" if cast(int, value) > cast(int, official) else "WEAKER"
    if definition.comparison == "MAXIMUM":
        return "STRONGER" if cast(int, value) < cast(int, official) else "WEAKER"
    if definition.comparison == "REQUIRED":
        return "STRONGER" if value is True else "WEAKER"
    return "CUSTOM"


def build_effective_criteria(
    *,
    organization_values: object | None = None,
    personal_values: object | None = None,
) -> dict[str, dict[str, object]]:
    organization = validate_criteria_values(organization_values or {})
    personal = validate_criteria_values(personal_values or {})
    result: dict[str, dict[str, object]] = {}
    for definition in _CATALOG:
        source: CriteriaSource = "KISA_DEFAULT"
        value = definition.official_value
        if definition.key in organization:
            value = organization[definition.key]
            source = "ORGANIZATION"
        if definition.key in personal:
            value = personal[definition.key]
            source = "PERSONAL"
        result[definition.key] = {
            "key": definition.key,
            "control_id": definition.control_id,
            "title": definition.title,
            "value": _json_value(value),
            "unit": definition.unit,
            "source": source,
            "strength": _strength(definition, value),
            "official_value": _json_value(definition.official_value),
            "official_reference": definition.official_reference,
        }
    return result


@dataclass(frozen=True, slots=True)
class CriteriaProfile:
    id: UUID
    organization_id: UUID
    owner_user_id: UUID | None
    scope: Literal["ORGANIZATION", "PERSONAL"]
    name: str
    version: int
    values: Mapping[str, CriteriaValue]
    document_sha256: str
    change_reason: str
    created_by: UUID
    created_at: datetime

    def public_view(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "scope": self.scope,
            "name": self.name,
            "version": self.version,
            "values": {
                key: _json_value(value) for key, value in self.values.items()
            },
            "document_sha256": self.document_sha256,
            "change_reason": self.change_reason,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class CriteriaSelection:
    id: UUID
    organization_id: UUID
    user_id: UUID
    selection_kind: CriteriaSelectionKind
    personal_profile_id: UUID | None
    criteria_sha256: str
    selected_at: datetime
    source: CriteriaSelectionSource

    def public_view(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "selection_kind": self.selection_kind,
            "personal_profile_id": (
                str(self.personal_profile_id)
                if self.personal_profile_id is not None
                else None
            ),
            "criteria_sha256": self.criteria_sha256,
            "selected_at": self.selected_at.isoformat(),
            "source": self.source,
        }


class CriteriaProfileRepository(Protocol):
    def append(
        self,
        *,
        organization_id: UUID,
        owner_user_id: UUID | None,
        scope: Literal["ORGANIZATION", "PERSONAL"],
        name: str,
        values: Mapping[str, CriteriaValue],
        document_sha256: str,
        change_reason: str,
        created_by: UUID,
        is_administrator: bool,
    ) -> CriteriaProfile: ...

    def latest_organization(self, organization_id: UUID) -> CriteriaProfile | None: ...

    def latest_personal(
        self,
        organization_id: UUID,
        owner_user_id: UUID,
    ) -> tuple[CriteriaProfile, ...]: ...

    def get_personal(
        self,
        organization_id: UUID,
        owner_user_id: UUID,
        profile_id: UUID,
    ) -> CriteriaProfile | None: ...

    def append_selection(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        selection_kind: CriteriaSelectionKind,
        personal_profile_id: UUID | None,
        criteria_sha256: str,
        source: CriteriaSelectionSource,
        is_administrator: bool,
    ) -> CriteriaSelection: ...

    def latest_selection(
        self,
        organization_id: UUID,
        user_id: UUID,
    ) -> CriteriaSelection | None: ...

    def selection_history(
        self,
        organization_id: UUID,
        user_id: UUID,
        *,
        limit: int = 20,
    ) -> tuple[CriteriaSelection, ...]: ...


def _profile_name(value: str) -> str:
    normalized = " ".join(value.strip().split())
    if not normalized or len(normalized) > 80:
        raise CriteriaContractError("기준 이름은 1자 이상 80자 이하로 입력해 주세요.")
    return normalized


def _change_reason(value: str) -> str:
    normalized = " ".join(value.strip().split())
    if not normalized or len(normalized) > 256:
        raise CriteriaContractError("변경 이유는 1자 이상 256자 이하로 입력해 주세요.")
    return normalized


class AssessmentCriteriaService:
    """공식 기준을 보존하며 조직·개인 기준 버전을 합성합니다."""

    def __init__(self, repository: CriteriaProfileRepository) -> None:
        self._repository = repository

    def save_personal(
        self,
        principal: AuthenticatedPrincipal,
        *,
        name: str,
        values: object,
        change_reason: str,
    ) -> CriteriaProfile:
        normalized = validate_criteria_values(values)
        return self._repository.append(
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
            scope="PERSONAL",
            name=_profile_name(name),
            values=normalized,
            document_sha256=canonical_criteria_sha256(normalized),
            change_reason=_change_reason(change_reason),
            created_by=principal.user_id,
            is_administrator=HumanRole.ADMIN in principal.roles,
        )

    def save_organization_default(
        self,
        principal: AuthenticatedPrincipal,
        *,
        values: object,
        change_reason: str,
    ) -> CriteriaProfile:
        if HumanRole.ADMIN not in principal.roles:
            raise CriteriaContractError("조직 기본 기준은 관리자만 변경할 수 있습니다.")
        normalized = validate_criteria_values(values)
        return self._repository.append(
            organization_id=principal.organization_id,
            owner_user_id=None,
            scope="ORGANIZATION",
            name="조직 기본 기준",
            values=normalized,
            document_sha256=canonical_criteria_sha256(normalized),
            change_reason=_change_reason(change_reason),
            created_by=principal.user_id,
            is_administrator=True,
        )

    def options(
        self,
        principal: AuthenticatedPrincipal,
        *,
        personal_profile_id: UUID | None = None,
        selection_kind: CriteriaSelectionKind | None = None,
    ) -> dict[str, object]:
        organization = self._repository.latest_organization(principal.organization_id)
        personal_profiles = self._repository.latest_personal(
            principal.organization_id,
            principal.user_id,
        )
        selection = self._repository.latest_selection(
            principal.organization_id,
            principal.user_id,
        )
        resolved_selection_kind: CriteriaSelectionKind = (
            selection_kind
            if selection_kind is not None
            else (
                selection.selection_kind
                if selection is not None
                else ("ORGANIZATION" if organization is not None else "KISA_DEFAULT")
            )
        )
        selected = None
        if personal_profile_id is not None:
            if selection_kind not in (None, "PERSONAL"):
                raise CriteriaContractError(
                    "KISA·조직 기준에는 개인 기준 번호를 사용할 수 없습니다."
                )
            selected = self._repository.get_personal(
                principal.organization_id,
                principal.user_id,
                personal_profile_id,
            )
            if selected is None:
                raise CriteriaContractError("선택한 개인 기준을 찾을 수 없습니다.")
            resolved_selection_kind = "PERSONAL"
        elif selection_kind == "PERSONAL":
            raise CriteriaContractError("선택할 개인 기준이 필요합니다.")
        elif (
            selection_kind is None
            and selection is not None
            and selection.selection_kind == "PERSONAL"
        ):
            if selection.personal_profile_id is None:
                raise CriteriaContractError("저장된 개인 기준 선택 이력이 올바르지 않습니다.")
            selected = self._repository.get_personal(
                principal.organization_id,
                principal.user_id,
                selection.personal_profile_id,
            )
            if selected is None:
                raise CriteriaContractError("저장된 개인 기준을 찾을 수 없습니다.")
        organization_values = (
            organization.values
            if organization is not None and resolved_selection_kind != "KISA_DEFAULT"
            else None
        )
        effective = build_effective_criteria(
            organization_values=organization_values,
            personal_values=selected.values if selected else None,
        )
        return {
            "official_reference": "KISA PC 보안 가이드 2026",
            "official_is_immutable": True,
            "organization_default": organization.public_view() if organization else None,
            "personal_profiles": [item.public_view() for item in personal_profiles],
            "selected_personal_profile": selected.public_view() if selected else None,
            "selected_kind": resolved_selection_kind,
            "latest_selection": selection.public_view() if selection else None,
            "selection_history": [
                item.public_view()
                for item in self._repository.selection_history(
                    principal.organization_id,
                    principal.user_id,
                    limit=20,
                )
            ],
            "effective": list(effective.values()),
            "effective_sha256": canonical_criteria_sha256(
                {key: cast(CriteriaValue, item["value"]) for key, item in effective.items()}
            ),
            "collection_errors_remain_errors": True,
        }

    def select(
        self,
        principal: AuthenticatedPrincipal,
        *,
        selection_kind: CriteriaSelectionKind,
        personal_profile_id: UUID | None = None,
        source: CriteriaSelectionSource = "CRITERIA_PAGE",
        expected_criteria_sha256: str | None = None,
    ) -> CriteriaSelection:
        organization = self._repository.latest_organization(principal.organization_id)
        selected: CriteriaProfile | None = None
        if selection_kind == "PERSONAL":
            if personal_profile_id is None:
                raise CriteriaContractError("선택할 개인 기준이 필요합니다.")
            selected = self._repository.get_personal(
                principal.organization_id,
                principal.user_id,
                personal_profile_id,
            )
            if selected is None:
                raise CriteriaContractError("선택한 개인 기준을 찾을 수 없습니다.")
        elif personal_profile_id is not None:
            raise CriteriaContractError("공식·조직 기준에는 개인 기준 번호를 사용할 수 없습니다.")
        effective = build_effective_criteria(
            organization_values=(
                organization.values
                if organization is not None and selection_kind != "KISA_DEFAULT"
                else None
            ),
            personal_values=selected.values if selected is not None else None,
        )
        values = {
            key: cast(CriteriaValue, item["value"])
            for key, item in effective.items()
        }
        criteria_sha256 = canonical_criteria_sha256(values)
        if expected_criteria_sha256 is not None and not hmac.compare_digest(
            criteria_sha256,
            expected_criteria_sha256,
        ):
            raise CriteriaContractError(
                "점검 기준이 변경되었습니다. 기준을 다시 확인해 주세요."
            )
        return self._repository.append_selection(
            organization_id=principal.organization_id,
            user_id=principal.user_id,
            selection_kind=selection_kind,
            personal_profile_id=selected.id if selected is not None else None,
            criteria_sha256=criteria_sha256,
            source=source,
            is_administrator=HumanRole.ADMIN in principal.roles,
        )
