from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security_audit.supply_chain.linux_collector_release import (
    LinuxReleaseError,
    build_linux_release_manifest,
    verify_linux_release_manifest,
)

NOW = datetime(2026, 8, 6, 2, 0, tzinfo=UTC)


def _artifacts(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path, Path]:
    automatic = tmp_path / "secai-linux-check-x86_64"
    ubuntu = tmp_path / "secai-linux-check-ubuntu24-x86_64"
    rocky = tmp_path / "secai-linux-check-rocky9-x86_64"
    sbom = tmp_path / "secai-linux-check-0.1.0.spdx.json"
    notice = tmp_path / "secai-linux-check-0.1.0-THIRD-PARTY-NOTICES.txt"
    vex = tmp_path / "secai-linux-check-0.1.0.openvex.json"
    automatic.write_bytes(b"automatic-linux-binary")
    ubuntu.write_bytes(b"ubuntu-linux-binary")
    rocky.write_bytes(b"rocky-linux-binary")
    sbom.write_text('{"spdxVersion":"SPDX-2.3"}', encoding="utf-8")
    notice.write_text("third-party package notice", encoding="utf-8")
    vex.write_text('{"@context":"https://openvex.dev/ns/v0.2.0"}', encoding="utf-8")
    return automatic, ubuntu, rocky, sbom, notice, vex


def test_signed_release_is_downloadable_only_after_every_supply_chain_gate(
    tmp_path: Path,
) -> None:
    automatic, ubuntu, rocky, sbom, notice, vex = _artifacts(tmp_path)
    key = Ed25519PrivateKey.generate()
    manifest = build_linux_release_manifest(
        artifacts={"AUTO_X86_64": automatic, "UBUNTU_24_04": ubuntu, "ROCKY_9": rocky},
        sbom_path=sbom,
        third_party_notice_path=notice,
        vex_path=vex,
        version="0.1.0",
        release_channel="SIGNED-PILOT",
        source_revision="test-revision",
        lock_sha256="a" * 64,
        build_image_digest="sha256:" + "b" * 64,
        created_at=NOW,
        sign=lambda payload: ("test-release-key", key.sign(payload)),
        dependency_scan="PASS",
        os_package_scan="PASS",
        malware_scan="CLEAN",
    )

    report = verify_linux_release_manifest(
        manifest,
        artifact_root=tmp_path,
        public_keys={"test-release-key": key.public_key()},
    )

    assert report.download_allowed is True
    assert report.artifact_count == 3
    assert report.errors == ()
    assert manifest["vex"] == {"filename": vex.name, "sha256": manifest["vex"]["sha256"]}


def test_dev_unsigned_release_can_never_be_an_operational_download(tmp_path: Path) -> None:
    automatic, ubuntu, rocky, sbom, notice, vex = _artifacts(tmp_path)
    manifest = build_linux_release_manifest(
        artifacts={"AUTO_X86_64": automatic, "UBUNTU_24_04": ubuntu, "ROCKY_9": rocky},
        sbom_path=sbom,
        third_party_notice_path=notice,
        vex_path=vex,
        version="0.1.0",
        release_channel="DEV-UNSIGNED",
        source_revision="WORKTREE-UNCOMMITTED",
        lock_sha256="a" * 64,
        build_image_digest="sha256:" + "b" * 64,
        created_at=NOW,
        sign=None,
        dependency_scan="PENDING",
        os_package_scan="PENDING",
        malware_scan="PENDING",
    )

    report = verify_linux_release_manifest(
        manifest,
        artifact_root=tmp_path,
        public_keys={},
    )

    assert report.download_allowed is False
    assert "RELEASE_CHANNEL_NOT_SIGNED" in report.errors
    assert all(item["signature"] is None for item in manifest["artifacts"])


def test_hash_or_signature_tamper_is_rejected(tmp_path: Path) -> None:
    automatic, ubuntu, rocky, sbom, notice, vex = _artifacts(tmp_path)
    key = Ed25519PrivateKey.generate()
    manifest = build_linux_release_manifest(
        artifacts={"AUTO_X86_64": automatic, "UBUNTU_24_04": ubuntu, "ROCKY_9": rocky},
        sbom_path=sbom,
        third_party_notice_path=notice,
        vex_path=vex,
        version="0.1.0",
        release_channel="SIGNED-PILOT",
        source_revision="test-revision",
        lock_sha256="a" * 64,
        build_image_digest="sha256:" + "b" * 64,
        created_at=NOW,
        sign=lambda payload: ("test-release-key", key.sign(payload)),
        dependency_scan="PASS",
        os_package_scan="PASS",
        malware_scan="CLEAN",
    )
    ubuntu.write_bytes(b"tampered")

    with pytest.raises(LinuxReleaseError):
        verify_linux_release_manifest(
            manifest,
            artifact_root=tmp_path,
            public_keys={"test-release-key": key.public_key()},
            fail_closed=True,
        )


def test_security_gate_tamper_breaks_the_signed_release_manifest(tmp_path: Path) -> None:
    automatic, ubuntu, rocky, sbom, notice, vex = _artifacts(tmp_path)
    key = Ed25519PrivateKey.generate()
    manifest = build_linux_release_manifest(
        artifacts={"AUTO_X86_64": automatic, "UBUNTU_24_04": ubuntu, "ROCKY_9": rocky},
        sbom_path=sbom,
        third_party_notice_path=notice,
        vex_path=vex,
        version="0.1.0",
        release_channel="SIGNED-PILOT",
        source_revision="test-revision",
        lock_sha256="a" * 64,
        build_image_digest="sha256:" + "b" * 64,
        created_at=NOW,
        sign=lambda payload: ("test-release-key", key.sign(payload)),
        dependency_scan="PASS",
        os_package_scan="PASS",
        malware_scan="CLEAN",
    )
    manifest["security_gates"]["dependency_scan"] = "FAIL"

    report = verify_linux_release_manifest(
        manifest,
        artifact_root=tmp_path,
        public_keys={"test-release-key": key.public_key()},
    )

    assert report.download_allowed is False
    assert "MANIFEST_SIGNATURE_INVALID" in report.errors


def test_vex_tamper_is_rejected_after_manifest_signing(tmp_path: Path) -> None:
    automatic, ubuntu, rocky, sbom, notice, vex = _artifacts(tmp_path)
    key = Ed25519PrivateKey.generate()
    manifest = build_linux_release_manifest(
        artifacts={"AUTO_X86_64": automatic, "UBUNTU_24_04": ubuntu, "ROCKY_9": rocky},
        sbom_path=sbom,
        third_party_notice_path=notice,
        vex_path=vex,
        version="0.1.0",
        release_channel="SIGNED-PILOT",
        source_revision="test-revision",
        lock_sha256="a" * 64,
        build_image_digest="sha256:" + "b" * 64,
        created_at=NOW,
        sign=lambda payload: ("test-release-key", key.sign(payload)),
        dependency_scan="PASS",
        os_package_scan="PASS",
        malware_scan="CLEAN",
    )
    vex.write_text("{}", encoding="utf-8")

    report = verify_linux_release_manifest(
        manifest,
        artifact_root=tmp_path,
        public_keys={"test-release-key": key.public_key()},
    )

    assert report.download_allowed is False
    assert "VEX_INVALID" in report.errors
