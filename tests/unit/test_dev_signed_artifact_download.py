from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security_audit.supply_chain.dev_signed_download import (
    DevArtifactPlatform,
    DevDownloadCodeError,
    DevDownloadCodeErrorCode,
    DevDownloadCodeService,
    InMemoryDevDownloadCodeStore,
    build_dev_signed_catalog,
    verify_dev_signed_catalog,
)

NOW = datetime(2026, 8, 6, 6, 0, tzinfo=UTC)


def _artifacts(root: Path) -> dict[DevArtifactPlatform, Path]:
    values = {
        DevArtifactPlatform.WINDOWS_X64: (
            "SecAI-Collector-Windows-x64.exe",
            b"windows-dev-collector",
        ),
        DevArtifactPlatform.LINUX_AUTO_X64: (
            "secai-linux-check-x86_64",
            b"automatic-linux-dev-collector",
        ),
        DevArtifactPlatform.UBUNTU_24_04_X64: (
            "secai-linux-check-ubuntu24-x86_64",
            b"ubuntu-dev-collector",
        ),
        DevArtifactPlatform.ROCKY_9_X64: (
            "secai-linux-check-rocky9-x86_64",
            b"rocky-dev-collector",
        ),
    }
    artifacts: dict[DevArtifactPlatform, Path] = {}
    for platform, (filename, content) in values.items():
        path = root / filename
        path.write_bytes(content)
        artifacts[platform] = path
    return artifacts


def _signed_catalog(
    root: Path,
    valid_days: int = 7,
) -> tuple[dict[str, object], Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    catalog = build_dev_signed_catalog(
        artifacts=_artifacts(root),
        created_at=NOW,
        expires_at=NOW + timedelta(days=valid_days),
        sign=lambda payload: ("secai-dev-download-test-key", key.sign(payload)),
        provenance={
            platform: {
                "source_profile": "TEST-SOURCE",
                "security_gates": "PASS",
            }
            for platform in DevArtifactPlatform
        },
    )
    return catalog, key


def test_dev_signed_catalog_requires_all_platforms_and_verifies_exact_files(
    tmp_path: Path,
) -> None:
    catalog, key = _signed_catalog(tmp_path)

    release = verify_dev_signed_catalog(
        catalog,
        artifact_root=tmp_path,
        public_keys={"secai-dev-download-test-key": key.public_key()},
        now=NOW + timedelta(minutes=1),
        fail_closed=True,
    )

    assert release.release_channel == "DEV-SIGNED-TEST"
    assert release.production_release is False
    assert release.key_id == "secai-dev-download-test-key"
    assert set(release.artifacts) == set(DevArtifactPlatform)
    assert all(item.path.parent == tmp_path for item in release.artifacts.values())


def test_dev_signed_catalog_rejects_tamper_expiry_and_wrong_key(tmp_path: Path) -> None:
    catalog, key = _signed_catalog(tmp_path)
    artifacts = catalog["artifacts"]
    assert isinstance(artifacts, list)
    first = artifacts[0]
    assert isinstance(first, dict)
    (tmp_path / str(first["filename"])).write_bytes(b"tampered")

    with pytest.raises(ValueError, match="verification failed"):
        verify_dev_signed_catalog(
            catalog,
            artifact_root=tmp_path,
            public_keys={"secai-dev-download-test-key": key.public_key()},
            now=NOW + timedelta(minutes=1),
            fail_closed=True,
        )

    clean_root = tmp_path / "clean"
    clean_root.mkdir()
    clean_catalog, _ = _signed_catalog(clean_root)
    with pytest.raises(ValueError, match="verification failed"):
        verify_dev_signed_catalog(
            clean_catalog,
            artifact_root=clean_root,
            public_keys={"wrong": Ed25519PrivateKey.generate().public_key()},
            now=NOW + timedelta(days=8),
            fail_closed=True,
        )


def test_dev_signed_catalog_allows_hundred_day_lifetime_and_rejects_longer(
    tmp_path: Path,
) -> None:
    catalog, key = _signed_catalog(tmp_path, valid_days=100)

    release = verify_dev_signed_catalog(
        catalog,
        artifact_root=tmp_path,
        public_keys={"secai-dev-download-test-key": key.public_key()},
        now=NOW + timedelta(days=99),
        fail_closed=True,
    )

    assert release.expires_at == NOW + timedelta(days=100)

    over_limit_root = tmp_path / "over-limit"
    over_limit_root.mkdir()
    with pytest.raises(ValueError, match="lifetime is invalid"):
        _signed_catalog(over_limit_root, valid_days=101)


def test_download_code_is_hmac_only_platform_scoped_expiring_and_one_time() -> None:
    store = InMemoryDevDownloadCodeStore()
    service = DevDownloadCodeService(
        store,
        hash_key=b"d" * 32,
        hash_key_version="test-v1",
    )
    issued = service.issue(
        platform=DevArtifactPlatform.UBUNTU_24_04_X64,
        subject_user_id="user-1",
        catalog_sha256="a" * 64,
        artifact_sha256="b" * 64,
        issued_at=NOW,
    )

    assert issued.code not in repr(store)
    with pytest.raises(DevDownloadCodeError) as wrong_platform:
        service.consume(
            issued.code,
            platform=DevArtifactPlatform.ROCKY_9_X64,
            catalog_sha256="a" * 64,
            artifact_sha256="b" * 64,
            received_at=NOW + timedelta(minutes=1),
        )
    assert wrong_platform.value.code is DevDownloadCodeErrorCode.SCOPE_MISMATCH

    consumed = service.consume(
        issued.code,
        platform=DevArtifactPlatform.UBUNTU_24_04_X64,
        catalog_sha256="a" * 64,
        artifact_sha256="b" * 64,
        received_at=NOW + timedelta(minutes=1),
    )
    assert consumed.subject_user_id == "user-1"

    with pytest.raises(DevDownloadCodeError) as reused:
        service.consume(
            issued.code,
            platform=DevArtifactPlatform.UBUNTU_24_04_X64,
            catalog_sha256="a" * 64,
            artifact_sha256="b" * 64,
            received_at=NOW + timedelta(minutes=2),
        )
    assert reused.value.code is DevDownloadCodeErrorCode.ALREADY_USED

    expired = service.issue(
        platform=DevArtifactPlatform.WINDOWS_X64,
        subject_user_id="user-1",
        catalog_sha256="c" * 64,
        artifact_sha256="d" * 64,
        issued_at=NOW,
        ttl=timedelta(minutes=1),
    )
    with pytest.raises(DevDownloadCodeError) as rejected:
        service.consume(
            expired.code,
            platform=DevArtifactPlatform.WINDOWS_X64,
            catalog_sha256="c" * 64,
            artifact_sha256="d" * 64,
            received_at=NOW + timedelta(minutes=2),
        )
    assert rejected.value.code is DevDownloadCodeErrorCode.EXPIRED


def test_download_code_rejects_catalog_or_artifact_replacement() -> None:
    service = DevDownloadCodeService(
        InMemoryDevDownloadCodeStore(),
        hash_key=b"e" * 32,
        hash_key_version="test-v1",
    )
    issued = service.issue(
        platform=DevArtifactPlatform.WINDOWS_X64,
        subject_user_id="user-1",
        catalog_sha256="a" * 64,
        artifact_sha256="b" * 64,
        issued_at=NOW,
    )

    with pytest.raises(DevDownloadCodeError) as replaced:
        service.consume(
            issued.code,
            platform=DevArtifactPlatform.WINDOWS_X64,
            catalog_sha256="f" * 64,
            artifact_sha256="b" * 64,
            received_at=NOW + timedelta(minutes=1),
        )
    assert replaced.value.code is DevDownloadCodeErrorCode.SCOPE_MISMATCH
