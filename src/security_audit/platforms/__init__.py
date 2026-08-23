"""다중 장비 점검의 공통 결과 계약과 장비별 읽기 전용 수집기."""

from .ai_context import (
    DeviceAIMessageContract,
    build_device_ai_context,
    build_device_ai_messages,
)
from .aruba_rest import (
    ArubaRestCollectionError,
    ArubaRestProjection,
    ArubaRestTarget,
    collect_aruba_rest_projection,
    evaluate_aruba_rest_baseline,
)
from .contracts import (
    AssetContext,
    DeviceAuditResult,
    DeviceControlResult,
    EvidenceTrace,
    PlatformContractError,
)
from .discovery import (
    AdapterResolutionError,
    AdapterResolutionErrorCode,
    AdapterSelection,
    PlatformFingerprint,
    PlatformSupportCatalog,
    SupportCatalogEntry,
    current_platform_support_catalog,
    discover_aruba_aoscx_platform,
    discover_linux_platform,
    discover_windows_platform,
)
from .linux import LINUX_PLAN, evaluate_linux_baseline
from .linux_adapters import (
    ALMALINUX_9,
    DEBIAN_12,
    RHEL_9,
    ROCKY_9,
    UBUNTU_22_04,
    UBUNTU_24_04,
    LinuxAdapter,
    LinuxDistribution,
    detect_linux_distribution,
    linux_adapter_for,
    linux_distribution_is_debian_family,
)
from .linux_kisa import (
    KISA_2026_UNIX_CONTROLS,
    KisaUnixAssessmentProfile,
    KisaUnixControl,
    evaluate_kisa_unix,
)
from .ssh_executor import (
    ReadOnlyCollectionBatch,
    SshReadOnlyTarget,
    collect_plan_over_ssh,
)
from .switch import ARUBA_AOS_CX, CISCO_IOS, evaluate_switch_baseline

__all__ = [
    "ARUBA_AOS_CX",
    "ArubaRestCollectionError",
    "ArubaRestProjection",
    "ArubaRestTarget",
    "CISCO_IOS",
    "LINUX_PLAN",
    "KISA_2026_UNIX_CONTROLS",
    "KisaUnixAssessmentProfile",
    "KisaUnixControl",
    "LinuxAdapter",
    "LinuxDistribution",
    "ALMALINUX_9",
    "DEBIAN_12",
    "ROCKY_9",
    "RHEL_9",
    "UBUNTU_22_04",
    "UBUNTU_24_04",
    "AssetContext",
    "AdapterResolutionError",
    "AdapterResolutionErrorCode",
    "AdapterSelection",
    "DeviceAuditResult",
    "DeviceControlResult",
    "EvidenceTrace",
    "PlatformContractError",
    "PlatformFingerprint",
    "PlatformSupportCatalog",
    "ReadOnlyCollectionBatch",
    "SshReadOnlyTarget",
    "SupportCatalogEntry",
    "build_device_ai_context",
    "build_device_ai_messages",
    "collect_plan_over_ssh",
    "current_platform_support_catalog",
    "collect_aruba_rest_projection",
    "detect_linux_distribution",
    "discover_aruba_aoscx_platform",
    "discover_linux_platform",
    "discover_windows_platform",
    "DeviceAIMessageContract",
    "evaluate_linux_baseline",
    "evaluate_kisa_unix",
    "evaluate_aruba_rest_baseline",
    "evaluate_switch_baseline",
    "linux_adapter_for",
    "linux_distribution_is_debian_family",
]
