"""세부 장비를 추측하지 않고 정확히 일치하는 읽기 Adapter를 선택합니다.

Discovery는 장비 정체만 표현하며 네트워크나 명령을 직접 실행하지 않습니다. 실제
읽기 전용 사전 확인은 플랫폼 Collector가 수행하고, 이 모듈은 검증·정규화·선택만
결정론적으로 처리합니다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, cast

from security_audit.common.canonical_json import JsonValue, canonical_sha256

from .contracts import AssetType, PlatformFamily

Architecture = Literal["X86_64", "AARCH64", "X86", "UNKNOWN"]
DiscoveryConfidence = Literal["EXACT", "PARTIAL", "CONFLICT", "UNKNOWN"]
SupportLevel = Literal["SUPPORTED", "PARTIAL", "PILOT", "BLOCKED", "EOL"]
MatchKind = Literal["EXACT"]

_SAFE_CODE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,79}$")
_SAFE_ADAPTER_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_OS_RELEASE_LINE = re.compile(
    r'(?m)^(?P<name>ID|VERSION_ID)=(?:"(?P<quoted>[^"\n]+)"|(?P<plain>[^\n]+))$'
)


class AdapterResolutionErrorCode(StrEnum):
    """외부에 원문 장비 정보를 노출하지 않는 자동 선택 오류 코드입니다."""

    IDENTITY_NOT_EXACT = "IDENTITY_NOT_EXACT"
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    AMBIGUOUS_ADAPTER = "AMBIGUOUS_ADAPTER"
    SUPPORT_BLOCKED = "SUPPORT_BLOCKED"
    DISCOVERY_INPUT_INVALID = "DISCOVERY_INPUT_INVALID"


class AdapterResolutionError(ValueError):
    def __init__(self, code: AdapterResolutionErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


def _code(value: str, *, label: str) -> str:
    normalized = value.strip().upper()
    if _SAFE_CODE.fullmatch(normalized) is None:
        raise AdapterResolutionError(
            AdapterResolutionErrorCode.DISCOVERY_INPUT_INVALID,
            f"{label} 식별값이 올바르지 않습니다.",
        )
    return normalized


def _version(value: str) -> str:
    normalized = value.strip()
    if _SAFE_VERSION.fullmatch(normalized) is None:
        raise AdapterResolutionError(
            AdapterResolutionErrorCode.DISCOVERY_INPUT_INVALID,
            "플랫폼 버전 식별값이 올바르지 않습니다.",
        )
    return normalized


def _adapter_id(value: str) -> str:
    normalized = value.strip().casefold()
    if _SAFE_ADAPTER_ID.fullmatch(normalized) is None:
        raise AdapterResolutionError(
            AdapterResolutionErrorCode.DISCOVERY_INPUT_INVALID,
            "Discovery Adapter 식별값이 올바르지 않습니다.",
        )
    return normalized


def _unique_codes(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    return tuple(sorted({_code(value, label=label) for value in values}))


@dataclass(frozen=True, slots=True)
class PlatformFingerprint:
    schema_version: str
    asset_type: AssetType
    platform: PlatformFamily
    vendor: str
    product_family: str
    version: str
    architecture: Architecture
    role_hints: tuple[str, ...]
    capabilities: tuple[str, ...]
    discovery_adapter_id: str
    confidence: DiscoveryConfidence
    limitations: tuple[str, ...]

    @classmethod
    def build(
        cls,
        *,
        asset_type: AssetType,
        platform: PlatformFamily,
        vendor: str,
        product_family: str,
        version: str,
        architecture: Architecture,
        role_hints: tuple[str, ...] = (),
        capabilities: tuple[str, ...] = (),
        discovery_adapter_id: str,
        confidence: DiscoveryConfidence = "EXACT",
        limitations: tuple[str, ...] = (),
    ) -> PlatformFingerprint:
        if architecture not in {"X86_64", "AARCH64", "X86", "UNKNOWN"}:
            raise AdapterResolutionError(
                AdapterResolutionErrorCode.DISCOVERY_INPUT_INVALID,
                "CPU 구조 식별값이 올바르지 않습니다.",
            )
        return cls(
            schema_version="1.0.0",
            asset_type=asset_type,
            platform=platform,
            vendor=_code(vendor, label="제조사"),
            product_family=_code(product_family, label="제품군"),
            version=_version(version),
            architecture=architecture,
            role_hints=_unique_codes(role_hints, label="장비 역할"),
            capabilities=_unique_codes(capabilities, label="장비 기능"),
            discovery_adapter_id=_adapter_id(discovery_adapter_id),
            confidence=confidence,
            limitations=_unique_codes(limitations, label="식별 제한"),
        )

    def _hash_body(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "asset_type": self.asset_type,
            "platform": self.platform,
            "vendor": self.vendor,
            "product_family": self.product_family,
            "version": self.version,
            "architecture": self.architecture,
            "role_hints": list(self.role_hints),
            "capabilities": list(self.capabilities),
            "discovery_adapter_id": self.discovery_adapter_id,
            "confidence": self.confidence,
            "limitations": list(self.limitations),
        }

    @property
    def fingerprint_sha256(self) -> str:
        return canonical_sha256(self._hash_body())

    def to_json(self) -> dict[str, JsonValue]:
        body = self._hash_body()
        body["fingerprint_sha256"] = self.fingerprint_sha256
        return body


@dataclass(frozen=True, slots=True)
class SupportCatalogEntry:
    entry_id: str
    asset_type: AssetType
    platform: PlatformFamily
    vendor: str
    product_family: str
    version_prefixes: tuple[str, ...]
    architectures: tuple[Architecture, ...]
    required_capabilities: tuple[str, ...]
    adapter_id: str
    adapter_version: str
    support_level: SupportLevel
    audit_pack_id: str
    audit_pack_version: str

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "entry_id": _code(self.entry_id, label="Catalog 항목"),
            "asset_type": self.asset_type,
            "platform": self.platform,
            "vendor": _code(self.vendor, label="제조사"),
            "product_family": _code(self.product_family, label="제품군"),
            "version_prefixes": cast(
                list[JsonValue],
                sorted(_version(item) for item in self.version_prefixes),
            ),
            "architectures": cast(
                list[JsonValue],
                sorted(self.architectures),
            ),
            "required_capabilities": list(
                _unique_codes(self.required_capabilities, label="필수 기능")
            ),
            "adapter_id": _adapter_id(self.adapter_id),
            "adapter_version": _version(self.adapter_version),
            "support_level": self.support_level,
            "audit_pack_id": _code(self.audit_pack_id, label="Audit Pack"),
            "audit_pack_version": _version(self.audit_pack_version),
        }

    def matches(self, fingerprint: PlatformFingerprint) -> bool:
        if (
            self.asset_type != fingerprint.asset_type
            or self.platform != fingerprint.platform
            or _code(self.vendor, label="제조사") != fingerprint.vendor
            or _code(self.product_family, label="제품군")
            != fingerprint.product_family
            or fingerprint.architecture not in self.architectures
        ):
            return False
        if not any(
            fingerprint.version == prefix
            or fingerprint.version.startswith(f"{prefix}.")
            for prefix in self.version_prefixes
        ):
            return False
        required = frozenset(
            _unique_codes(self.required_capabilities, label="필수 기능")
        )
        return required.issubset(fingerprint.capabilities)


@dataclass(frozen=True, slots=True)
class AdapterSelection:
    adapter_id: str
    adapter_version: str
    match_kind: MatchKind
    matched_on: tuple[str, ...]
    support_level: SupportLevel
    audit_pack_id: str
    audit_pack_version: str
    catalog_sha256: str
    fingerprint_sha256: str

    def _hash_body(self) -> dict[str, JsonValue]:
        return {
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "match_kind": self.match_kind,
            "matched_on": list(self.matched_on),
            "support_level": self.support_level,
            "audit_pack_id": self.audit_pack_id,
            "audit_pack_version": self.audit_pack_version,
            "catalog_sha256": self.catalog_sha256,
            "fingerprint_sha256": self.fingerprint_sha256,
        }

    @property
    def selection_sha256(self) -> str:
        return canonical_sha256(self._hash_body())

    def to_json(self) -> dict[str, JsonValue]:
        body = self._hash_body()
        body["selection_sha256"] = self.selection_sha256
        return body


class PlatformSupportCatalog:
    def __init__(self, entries: tuple[SupportCatalogEntry, ...]) -> None:
        if not entries:
            raise ValueError("지원 Catalog에는 항목이 필요합니다.")
        self._entries = tuple(entries)
        self._catalog_sha256 = canonical_sha256(
            cast(
                JsonValue,
                {
                    "schema_version": "1.0.0",
                    "entries": [
                        item.to_json()
                        for item in sorted(entries, key=lambda entry: entry.entry_id)
                    ],
                },
            )
        )

    @property
    def catalog_sha256(self) -> str:
        return self._catalog_sha256

    def resolve(self, fingerprint: PlatformFingerprint) -> AdapterSelection:
        if fingerprint.confidence != "EXACT":
            raise AdapterResolutionError(
                AdapterResolutionErrorCode.IDENTITY_NOT_EXACT,
                "장비를 정확히 식별하지 못해 점검기를 선택하지 않았습니다.",
            )
        candidates = [item for item in self._entries if item.matches(fingerprint)]
        if not candidates:
            raise AdapterResolutionError(
                AdapterResolutionErrorCode.UNSUPPORTED_PLATFORM,
                "감지된 제품과 버전은 현재 지원하지 않습니다.",
            )
        if len(candidates) != 1:
            raise AdapterResolutionError(
                AdapterResolutionErrorCode.AMBIGUOUS_ADAPTER,
                "안전하게 한 개의 점검기를 선택할 수 없습니다.",
            )
        selected = candidates[0]
        if selected.support_level in {"BLOCKED", "EOL"}:
            raise AdapterResolutionError(
                AdapterResolutionErrorCode.SUPPORT_BLOCKED,
                "차단 또는 지원 종료된 제품에서는 점검을 시작하지 않습니다.",
            )
        return AdapterSelection(
            adapter_id=_adapter_id(selected.adapter_id),
            adapter_version=_version(selected.adapter_version),
            match_kind="EXACT",
            matched_on=(
                "ASSET_TYPE",
                "PLATFORM",
                "VENDOR",
                "PRODUCT_FAMILY",
                "VERSION",
                "ARCHITECTURE",
                "CAPABILITIES",
            ),
            support_level=selected.support_level,
            audit_pack_id=_code(selected.audit_pack_id, label="Audit Pack"),
            audit_pack_version=_version(selected.audit_pack_version),
            catalog_sha256=self.catalog_sha256,
            fingerprint_sha256=fingerprint.fingerprint_sha256,
        )


def _architecture(machine: str) -> Architecture:
    normalized = machine.strip().casefold()
    if normalized in {"x86_64", "amd64"}:
        return "X86_64"
    if normalized in {"aarch64", "arm64"}:
        return "AARCH64"
    if normalized in {"x86", "i386", "i686"}:
        return "X86"
    return "UNKNOWN"


def _os_release_values(os_release: bytes) -> tuple[str, str]:
    if not os_release or len(os_release) > 8192 or b"\x00" in os_release:
        raise AdapterResolutionError(
            AdapterResolutionErrorCode.DISCOVERY_INPUT_INVALID,
            "Linux 배포판 정보를 안전하게 읽을 수 없습니다.",
        )
    try:
        text = os_release.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AdapterResolutionError(
            AdapterResolutionErrorCode.DISCOVERY_INPUT_INVALID,
            "Linux 배포판 정보의 문자 형식이 올바르지 않습니다.",
        ) from exc
    values: dict[str, str] = {}
    for match in _OS_RELEASE_LINE.finditer(text):
        name = match.group("name")
        if name in values:
            raise AdapterResolutionError(
                AdapterResolutionErrorCode.DISCOVERY_INPUT_INVALID,
                "Linux 배포판 정보에 중복 식별값이 있습니다.",
            )
        values[name] = (match.group("quoted") or match.group("plain")).strip()
    distro_id = values.get("ID", "").casefold()
    version = values.get("VERSION_ID", "")
    if not distro_id or _SAFE_VERSION.fullmatch(version) is None:
        raise AdapterResolutionError(
            AdapterResolutionErrorCode.DISCOVERY_INPUT_INVALID,
            "Linux 배포판 식별값이 올바르지 않습니다.",
        )
    return distro_id, version


def discover_linux_platform(
    os_release: bytes,
    *,
    machine: str,
    capabilities: tuple[str, ...] = (),
) -> PlatformFingerprint:
    distro_id, version = _os_release_values(os_release)
    identity = {
        "ubuntu": ("CANONICAL", "UBUNTU_LINUX"),
        "debian": ("DEBIAN_PROJECT", "DEBIAN_LINUX"),
        "rocky": ("ROCKY_ENTERPRISE_SOFTWARE_FOUNDATION", "ROCKY_LINUX"),
        "rhel": ("RED_HAT", "RHEL_LINUX"),
        "almalinux": ("ALMALINUX_OS_FOUNDATION", "ALMALINUX"),
    }.get(distro_id)
    if identity is None:
        raise AdapterResolutionError(
            AdapterResolutionErrorCode.UNSUPPORTED_PLATFORM,
            "감지된 Linux 배포판은 현재 지원하지 않습니다.",
        )
    vendor, product = identity
    return PlatformFingerprint.build(
        asset_type="LINUX_SERVER",
        platform="LINUX",
        vendor=vendor,
        product_family=product,
        version=version,
        architecture=_architecture(machine),
        role_hints=("SERVER",),
        capabilities=capabilities,
        discovery_adapter_id="secai.linux.discovery.v1",
    )


def discover_windows_platform(
    *,
    product_kind: Literal["CLIENT", "MEMBER_SERVER", "DOMAIN_CONTROLLER"],
    product_version: str,
    build: str,
    machine: str,
) -> PlatformFingerprint:
    family_by_kind = {
        "CLIENT": f"WINDOWS_CLIENT_{_version(product_version)}",
        "MEMBER_SERVER": "WINDOWS_MEMBER_SERVER",
        "DOMAIN_CONTROLLER": "WINDOWS_DOMAIN_CONTROLLER",
    }
    return PlatformFingerprint.build(
        asset_type="WINDOWS_PC",
        platform="WINDOWS",
        vendor="MICROSOFT",
        product_family=family_by_kind[product_kind],
        version=product_version,
        architecture=_architecture(machine),
        role_hints=(product_kind, f"BUILD_{_version(build)}"),
        discovery_adapter_id="secai.windows.discovery.v1",
    )


def discover_aruba_aoscx_platform(
    *,
    version: str,
    capabilities: tuple[str, ...] = (),
) -> PlatformFingerprint:
    return PlatformFingerprint.build(
        asset_type="NETWORK_SWITCH",
        platform="ARUBA_AOS_CX",
        vendor="HPE_ARUBA",
        product_family="AOS_CX",
        version=version,
        architecture="UNKNOWN",
        role_hints=("SWITCH",),
        capabilities=capabilities,
        discovery_adapter_id="secai.aruba-aos-cx.discovery.v1",
    )


def current_platform_support_catalog() -> PlatformSupportCatalog:
    """현재 개발·Pilot 정책으로 허용한 플랫폼만 지원 항목으로 노출합니다."""

    return PlatformSupportCatalog(
        (
            SupportCatalogEntry(
                entry_id="WINDOWS.CLIENT10.X86_64",
                asset_type="WINDOWS_PC",
                platform="WINDOWS",
                vendor="MICROSOFT",
                product_family="WINDOWS_CLIENT_10",
                version_prefixes=("10",),
                architectures=("X86_64",),
                required_capabilities=(),
                adapter_id="secai.windows.pc.readonly.v1",
                adapter_version="1.0.0",
                support_level="SUPPORTED",
                audit_pack_id="KISA-2026-PC01-PC18",
                audit_pack_version="1.0.0-DRAFT",
            ),
            SupportCatalogEntry(
                entry_id="WINDOWS.CLIENT11.X86_64",
                asset_type="WINDOWS_PC",
                platform="WINDOWS",
                vendor="MICROSOFT",
                product_family="WINDOWS_CLIENT_11",
                version_prefixes=("11",),
                architectures=("X86_64",),
                required_capabilities=(),
                adapter_id="secai.windows.pc.readonly.v1",
                adapter_version="1.0.0",
                support_level="SUPPORTED",
                audit_pack_id="KISA-2026-PC01-PC18",
                audit_pack_version="1.0.0-DRAFT",
            ),
            SupportCatalogEntry(
                entry_id="LINUX.UBUNTU22.X86_64",
                asset_type="LINUX_SERVER",
                platform="LINUX",
                vendor="CANONICAL",
                product_family="UBUNTU_LINUX",
                version_prefixes=("22.04",),
                architectures=("X86_64",),
                required_capabilities=(),
                adapter_id="secai.linux.ubuntu22.readonly.v1",
                adapter_version="1.0.0",
                support_level="SUPPORTED",
                audit_pack_id="KISA-2026-UNIX-U01-U67",
                audit_pack_version="2026-DRAFT",
            ),
            SupportCatalogEntry(
                entry_id="LINUX.UBUNTU24.X86_64",
                asset_type="LINUX_SERVER",
                platform="LINUX",
                vendor="CANONICAL",
                product_family="UBUNTU_LINUX",
                version_prefixes=("24.04",),
                architectures=("X86_64",),
                required_capabilities=(),
                adapter_id="secai.linux.ubuntu24.readonly.v1",
                adapter_version="1.0.0",
                support_level="SUPPORTED",
                audit_pack_id="KISA-2026-UNIX-U01-U67",
                audit_pack_version="2026-DRAFT",
            ),
            SupportCatalogEntry(
                entry_id="LINUX.DEBIAN12.X86_64",
                asset_type="LINUX_SERVER",
                platform="LINUX",
                vendor="DEBIAN_PROJECT",
                product_family="DEBIAN_LINUX",
                version_prefixes=("12",),
                architectures=("X86_64",),
                required_capabilities=(),
                adapter_id="secai.linux.debian12.readonly.v1",
                adapter_version="1.0.0",
                support_level="SUPPORTED",
                audit_pack_id="KISA-2026-UNIX-U01-U67",
                audit_pack_version="2026-DRAFT",
            ),
            SupportCatalogEntry(
                entry_id="LINUX.ROCKY9.X86_64",
                asset_type="LINUX_SERVER",
                platform="LINUX",
                vendor="ROCKY_ENTERPRISE_SOFTWARE_FOUNDATION",
                product_family="ROCKY_LINUX",
                version_prefixes=("9",),
                architectures=("X86_64",),
                required_capabilities=(),
                adapter_id="secai.linux.rocky9.readonly.v1",
                adapter_version="1.0.0",
                support_level="SUPPORTED",
                audit_pack_id="KISA-2026-UNIX-U01-U67",
                audit_pack_version="2026-DRAFT",
            ),
            SupportCatalogEntry(
                entry_id="LINUX.RHEL9.X86_64",
                asset_type="LINUX_SERVER",
                platform="LINUX",
                vendor="RED_HAT",
                product_family="RHEL_LINUX",
                version_prefixes=("9",),
                architectures=("X86_64",),
                required_capabilities=(),
                adapter_id="secai.linux.rhel9.readonly.v1",
                adapter_version="1.0.0",
                support_level="PILOT",
                audit_pack_id="KISA-2026-UNIX-U01-U67",
                audit_pack_version="2026-DRAFT",
            ),
            SupportCatalogEntry(
                entry_id="LINUX.ALMALINUX9.X86_64",
                asset_type="LINUX_SERVER",
                platform="LINUX",
                vendor="ALMALINUX_OS_FOUNDATION",
                product_family="ALMALINUX",
                version_prefixes=("9",),
                architectures=("X86_64",),
                required_capabilities=(),
                adapter_id="secai.linux.alma9.readonly.v1",
                adapter_version="1.0.0",
                support_level="SUPPORTED",
                audit_pack_id="KISA-2026-UNIX-U01-U67",
                audit_pack_version="2026-DRAFT",
            ),
            SupportCatalogEntry(
                entry_id="SWITCH.ARUBA.AOS_CX10_13",
                asset_type="NETWORK_SWITCH",
                platform="ARUBA_AOS_CX",
                vendor="HPE_ARUBA",
                product_family="AOS_CX",
                version_prefixes=("10.13",),
                architectures=("UNKNOWN",),
                required_capabilities=("HTTPS_REST",),
                adapter_id="secai.aruba-aos-cx.rest.v1",
                adapter_version="1.0.0",
                support_level="SUPPORTED",
                audit_pack_id="KISA-NETWORK-N01-N38",
                audit_pack_version="0.4.0-DRAFT",
            ),
        )
    )
