from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from security_audit.platforms import (
    AdapterResolutionError,
    AdapterResolutionErrorCode,
    LinuxDistribution,
    PlatformFingerprint,
    PlatformSupportCatalog,
    SupportCatalogEntry,
    current_platform_support_catalog,
    detect_linux_distribution,
    discover_aruba_aoscx_platform,
    discover_linux_platform,
    discover_windows_platform,
    linux_adapter_for,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_linux_discovery_identifies_supported_distribution_without_user_choice() -> None:
    ubuntu = discover_linux_platform(
        b'ID=ubuntu\nVERSION_ID="24.04"\n',
        machine="x86_64",
        capabilities=("SYSTEMD", "PAM", "APPARMOR", "UFW"),
    )
    rocky = discover_linux_platform(
        b'ID=rocky\nVERSION_ID="9.4"\n',
        machine="amd64",
        capabilities=("SYSTEMD", "PAM", "SELINUX", "FIREWALLD"),
    )

    assert ubuntu.product_family == "UBUNTU_LINUX"
    assert ubuntu.version == "24.04"
    assert ubuntu.architecture == "X86_64"
    assert rocky.product_family == "ROCKY_LINUX"
    assert rocky.version == "9.4"
    assert ubuntu.to_json()["fingerprint_sha256"] == ubuntu.fingerprint_sha256


@pytest.mark.parametrize(
    ("os_release", "family", "version", "distribution", "adapter_id", "level"),
    (
        (
            b'ID=ubuntu\nVERSION_ID="22.04"\n',
            "UBUNTU_LINUX",
            "22.04",
            LinuxDistribution.UBUNTU_22_04,
            "secai.linux.ubuntu22.readonly.v1",
            "SUPPORTED",
        ),
        (
            b'ID=ubuntu\nVERSION_ID="24.04"\n',
            "UBUNTU_LINUX",
            "24.04",
            LinuxDistribution.UBUNTU_24_04,
            "secai.linux.ubuntu24.readonly.v1",
            "SUPPORTED",
        ),
        (
            b'ID=debian\nVERSION_ID="12"\n',
            "DEBIAN_LINUX",
            "12",
            LinuxDistribution.DEBIAN_12,
            "secai.linux.debian12.readonly.v1",
            "SUPPORTED",
        ),
        (
            b'ID=rocky\nVERSION_ID="9.5"\n',
            "ROCKY_LINUX",
            "9.5",
            LinuxDistribution.ROCKY_9,
            "secai.linux.rocky9.readonly.v1",
            "SUPPORTED",
        ),
        (
            b'ID=rhel\nVERSION_ID="9.4"\n',
            "RHEL_LINUX",
            "9.4",
            LinuxDistribution.RHEL_9,
            "secai.linux.rhel9.readonly.v1",
            "PILOT",
        ),
        (
            b'ID=almalinux\nVERSION_ID="9.4"\n',
            "ALMALINUX",
            "9.4",
            LinuxDistribution.ALMALINUX_9,
            "secai.linux.alma9.readonly.v1",
            "SUPPORTED",
        ),
    ),
)
def test_linux_supported_matrix_is_detected_and_resolved_without_user_choice(
    os_release: bytes,
    family: str,
    version: str,
    distribution: LinuxDistribution,
    adapter_id: str,
    level: str,
) -> None:
    fingerprint = discover_linux_platform(os_release, machine="x86_64")
    selection = current_platform_support_catalog().resolve(fingerprint)

    assert fingerprint.product_family == family
    assert fingerprint.version == version
    assert detect_linux_distribution(os_release) is distribution
    assert linux_adapter_for(distribution).distribution is distribution
    assert selection.adapter_id == adapter_id
    assert selection.support_level == level


def test_windows_10_and_11_clients_select_the_read_only_pc_adapter() -> None:
    catalog = current_platform_support_catalog()
    windows_10 = discover_windows_platform(
        product_kind="CLIENT",
        product_version="10",
        build="19045",
        machine="AMD64",
    )
    windows_11 = discover_windows_platform(
        product_kind="CLIENT",
        product_version="11",
        build="26100",
        machine="AMD64",
    )

    windows_10_selection = catalog.resolve(windows_10)
    windows_11_selection = catalog.resolve(windows_11)

    assert windows_10_selection.adapter_id == "secai.windows.pc.readonly.v1"
    assert windows_10_selection.support_level == "SUPPORTED"
    assert windows_11_selection.adapter_id == "secai.windows.pc.readonly.v1"
    assert windows_11_selection.support_level == "SUPPORTED"


def test_vmware_lab_scripts_prepare_verified_additional_linux_images() -> None:
    ubuntu_script = (
        PROJECT_ROOT / "deploy/vmware/ubuntu-lab.ps1"
    ).read_text(encoding="utf-8")
    enterprise_script = (
        PROJECT_ROOT / "deploy/vmware/rocky-lab.ps1"
    ).read_text(encoding="utf-8")

    for contract in (
        "[ValidateSet('22.04', '24.04')]",
        "cloud-images.ubuntu.com/releases/$releaseCode/release",
        "Get-FileHash",
    ):
        assert contract in ubuntu_script
    for contract in (
        "[ValidateSet('Ubuntu22', 'Rocky9', 'Debian12', 'RHEL9', 'AlmaLinux9')]",
        "cloud.debian.org/images/cloud/bookworm/latest",
        "repo.almalinux.org/almalinux/9/cloud/x86_64/images",
        "SourceImagePath",
        "Get-FileHash",
    ):
        assert contract in enterprise_script


@pytest.mark.parametrize(
    ("fingerprint", "adapter_id"),
    (
        (
            discover_linux_platform(
                b'ID=ubuntu\nVERSION_ID="24.04.3"\n', machine="x86_64"
            ),
            "secai.linux.ubuntu24.readonly.v1",
        ),
        (
            discover_linux_platform(
                b'ID=rocky\nVERSION_ID="9.8"\n', machine="x86_64"
            ),
            "secai.linux.rocky9.readonly.v1",
        ),
    ),
)
def test_current_catalog_selects_exact_supported_linux_adapter(
    fingerprint: PlatformFingerprint,
    adapter_id: str,
) -> None:
    selection = current_platform_support_catalog().resolve(fingerprint)

    assert selection.adapter_id == adapter_id
    assert selection.match_kind == "EXACT"
    assert selection.support_level == "SUPPORTED"
    assert selection.catalog_sha256


def test_current_windows_and_aruba_paths_use_the_same_exact_resolver() -> None:
    windows = discover_windows_platform(
        product_kind="CLIENT",
        product_version="11",
        build="26100",
        machine="AMD64",
    )
    aruba = discover_aruba_aoscx_platform(
        version="10.13.1170",
        capabilities=("HTTPS_REST",),
    )

    windows_selection = current_platform_support_catalog().resolve(windows)
    aruba_selection = current_platform_support_catalog().resolve(aruba)

    assert windows_selection.adapter_id == "secai.windows.pc.readonly.v1"
    assert windows_selection.audit_pack_id == "KISA-2026-PC01-PC18"
    assert aruba_selection.adapter_id == "secai.aruba-aos-cx.rest.v1"
    assert aruba_selection.audit_pack_id == "KISA-NETWORK-N01-N38"


def test_unknown_linux_version_is_not_downgraded_to_nearest_adapter() -> None:
    fingerprint = discover_linux_platform(
        b'ID=ubuntu\nVERSION_ID="26.04"\n',
        machine="x86_64",
    )

    with pytest.raises(AdapterResolutionError) as rejected:
        current_platform_support_catalog().resolve(fingerprint)

    assert rejected.value.code is AdapterResolutionErrorCode.UNSUPPORTED_PLATFORM


def test_partial_or_conflicting_identity_cannot_select_an_adapter() -> None:
    exact = discover_linux_platform(
        b'ID=ubuntu\nVERSION_ID="24.04"\n', machine="x86_64"
    )

    for confidence in ("PARTIAL", "CONFLICT", "UNKNOWN"):
        with pytest.raises(AdapterResolutionError) as rejected:
            current_platform_support_catalog().resolve(
                replace(exact, confidence=confidence)
            )
        assert rejected.value.code is AdapterResolutionErrorCode.IDENTITY_NOT_EXACT


def test_ambiguous_adapter_candidates_fail_closed() -> None:
    entry = SupportCatalogEntry(
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
    )
    catalog = PlatformSupportCatalog((entry, replace(entry, entry_id="DUPLICATE")))

    with pytest.raises(AdapterResolutionError) as rejected:
        catalog.resolve(
            discover_linux_platform(
                b'ID=ubuntu\nVERSION_ID="24.04"\n', machine="x86_64"
            )
        )

    assert rejected.value.code is AdapterResolutionErrorCode.AMBIGUOUS_ADAPTER


def test_adapter_selection_is_deterministic_for_same_catalog_and_fingerprint() -> None:
    catalog = current_platform_support_catalog()
    fingerprint = discover_linux_platform(
        b'ID=rocky\nVERSION_ID="9.4"\n', machine="x86_64"
    )

    selections = {catalog.resolve(fingerprint).selection_sha256 for _ in range(100)}

    assert len(selections) == 1


def test_platform_fingerprint_schema_accepts_valid_and_rejects_invalid_example() -> None:
    schema_root = PROJECT_ROOT / "database" / "schemas"
    schema = json.loads(
        (schema_root / "platform_fingerprint.schema.json").read_text(encoding="utf-8")
    )
    valid = json.loads(
        (schema_root / "examples" / "valid" / "platform_fingerprint.json").read_text(
            encoding="utf-8"
        )
    )
    invalid = json.loads(
        (
            schema_root / "examples" / "invalid" / "platform_fingerprint.json"
        ).read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)

    assert list(validator.iter_errors(valid)) == []
    assert list(validator.iter_errors(invalid))


def test_linux_manifest_schemas_and_new_migration_allow_the_supported_matrix() -> None:
    schema_root = PROJECT_ROOT / "database" / "schemas"
    expected = {
        "UBUNTU_22_04",
        "UBUNTU_24_04",
        "DEBIAN_12",
        "ROCKY_9",
        "RHEL_9",
        "ALMALINUX_9",
    }
    manifest_schema = json.loads(
        (schema_root / "linux_collector_manifest.schema.json").read_text(
            encoding="utf-8"
        )
    )
    package_schema = json.loads(
        (schema_root / "linux_audit_package.schema.json").read_text(encoding="utf-8")
    )
    manifest_distributions = manifest_schema["properties"]["target"]["properties"][
        "distribution"
    ]["enum"]
    package_distributions = package_schema["properties"]["host"]["properties"][
        "distribution"
    ]["enum"]
    assert set(manifest_distributions) == expected
    assert set(package_distributions) == expected

    migration = (
        PROJECT_ROOT
        / "database/alembic/versions/0035_windows_linux_platform_expansion.py"
    ).read_text(encoding="utf-8")
    assert 'down_revision: str | None = "0034_linux_managed_assets"' in migration
    assert "ck_linux_managed_asset_distribution" in migration
    assert "ALMALINUX_9" in migration
