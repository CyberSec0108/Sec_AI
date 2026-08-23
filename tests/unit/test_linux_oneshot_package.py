from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest

from security_audit.analysis.package_validation import (
    DigestVerification,
    ExternalVerificationStatus,
    FullPackageValidator,
    MalwareScanStatus,
    MalwareScanVerification,
    NonceVerification,
    NonceVerificationStatus,
    PackageAuthenticationKind,
    PackageAuthenticationVerification,
    PackageGateVerifications,
    PackageValidationCode,
    PackageValidationContext,
    PackageValidationError,
    StagedObjectVerification,
)
from security_audit.collector.linux_local import LinuxProbeOutcome
from security_audit.collector.linux_manifest import build_linux_collector_manifest
from security_audit.collector.linux_package import build_linux_audit_package
from security_audit.platforms import LinuxDistribution

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
NOW = datetime(2026, 8, 6, 1, 0, tzinfo=UTC)


def _manifest() -> dict[str, Any]:
    return build_linux_collector_manifest(
        organization_id=UUID("71000000-0000-4000-8000-000000000001"),
        subject_user_id=UUID("71000000-0000-4000-8000-000000000002"),
        job_id=UUID("71000000-0000-4000-8000-000000000003"),
        asset_id=UUID("71000000-0000-4000-8000-000000000004"),
        manifest_id=UUID("71000000-0000-4000-8000-000000000005"),
        execution_attempt_id=UUID("71000000-0000-4000-8000-000000000006"),
        correlation_id=UUID("71000000-0000-4000-8000-000000000007"),
        distribution=LinuxDistribution.UBUNTU_24_04,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        nonce="LinuxOneShotPackageNonce000001",
        criteria_values={"password_maximum_age_days": 90},
        sign=lambda digest: ("linux-test-key", "A" * 43),
    )


def _outcome() -> LinuxProbeOutcome:
    return LinuxProbeOutcome(
        probe_id="linux.os-release",
        probe_version="1.0.0",
        control_ids=(),
        required_privilege="STANDARD_USER",
        executed_privilege="STANDARD_USER",
        collection_status="COLLECTED",
        error_code="NONE",
        exit_code=0,
        raw_output_sha256="a" * 64,
        normalized_sha256="b" * 64,
        redaction_applied=False,
        normalized_value='ID=ubuntu\nVERSION_ID="24.04"\n',
    )


def _verifications(
    manifest: dict[str, Any], descriptor: dict[str, Any]
) -> PackageGateVerifications:
    archive = descriptor["archive"]
    return PackageGateVerifications(
        manifest_signature=DigestVerification(
            ExternalVerificationStatus.VERIFIED,
            manifest["manifest_content_sha256"],
        ),
        nonce=NonceVerification(NonceVerificationStatus.FRESH_RESERVED, manifest["nonce"]),
        package_authentication=PackageAuthenticationVerification(
            ExternalVerificationStatus.VERIFIED,
            PackageAuthenticationKind.OFFLINE_SUBMITTER,
        ),
        malware_scan=MalwareScanVerification(
            MalwareScanStatus.CLEAN,
            archive["archive_sha256"],
        ),
        content_policy=DigestVerification(
            ExternalVerificationStatus.VERIFIED,
            archive["archive_sha256"],
        ),
        staged_object=StagedObjectVerification(
            ExternalVerificationStatus.VERIFIED,
            manifest["organization_id"],
            manifest["asset_id"],
            manifest["job_id"],
            archive["archive_sha256"],
            archive["compressed_bytes"],
        ),
    )


def test_linux_package_is_deterministic_and_reuses_full_validator(tmp_path: Path) -> None:
    manifest = _manifest()
    first = build_linux_audit_package(
        manifest=manifest,
        outcomes=(_outcome(),),
        archive_path=tmp_path / "first.zip",
        package_id=UUID("72000000-0000-4000-8000-000000000001"),
        collected_at=NOW + timedelta(minutes=5),
        build_sha256="c" * 64,
        host_version="24.04",
        authentication={
            "profile": "OFFLINE-USER-SUBMITTED",
            "assurance_level": "LOW",
        },
    )
    second = build_linux_audit_package(
        manifest=manifest,
        outcomes=(_outcome(),),
        archive_path=tmp_path / "second.zip",
        package_id=UUID("72000000-0000-4000-8000-000000000001"),
        collected_at=NOW + timedelta(minutes=5),
        build_sha256="c" * 64,
        host_version="24.04",
        authentication={
            "profile": "OFFLINE-USER-SUBMITTED",
            "assurance_level": "LOW",
        },
    )

    assert first.descriptor["archive"] == second.descriptor["archive"]
    assert first.archive_path.read_bytes() == second.archive_path.read_bytes()
    validator = FullPackageValidator(
        SCHEMA_ROOT,
        descriptor_schema="linux_audit_package.schema.json",
        manifest_schema="linux_collector_manifest.schema.json",
        evidence_control_field="control_ids",
        evidence_member_path_field="member_path",
    )
    result = validator.validate(
        first.archive_path,
        first.descriptor_bytes,
        manifest,
        PackageValidationContext(
            organization_id=manifest["organization_id"],
            asset_id=manifest["asset_id"],
            job_id=manifest["job_id"],
            endpoint_id=manifest["submission"]["endpoint_id"],
            received_at=NOW + timedelta(minutes=10),
        ),
        _verifications(manifest, first.descriptor),
    )
    assert result.eligible_for_original_promotion is True


def test_linux_package_never_overwrites_existing_output(tmp_path: Path) -> None:
    destination = tmp_path / "result.zip"
    destination.write_bytes(b"keep")

    with pytest.raises(FileExistsError):
        build_linux_audit_package(
            manifest=_manifest(),
            outcomes=(_outcome(),),
            archive_path=destination,
            package_id=UUID("72000000-0000-4000-8000-000000000001"),
            collected_at=NOW,
            build_sha256="c" * 64,
            host_version="24.04",
            authentication={
                "profile": "OFFLINE-USER-SUBMITTED",
                "assurance_level": "LOW",
            },
        )
    assert destination.read_bytes() == b"keep"


def test_linux_package_member_hash_tamper_is_rejected(tmp_path: Path) -> None:
    manifest = _manifest()
    package = build_linux_audit_package(
        manifest=manifest,
        outcomes=(_outcome(),),
        archive_path=tmp_path / "result.zip",
        package_id=UUID("72000000-0000-4000-8000-000000000001"),
        collected_at=NOW,
        build_sha256="c" * 64,
        host_version="24.04",
        authentication={
            "profile": "OFFLINE-USER-SUBMITTED",
            "assurance_level": "LOW",
        },
    )
    tampered = cast(dict[str, Any], json.loads(package.descriptor_bytes))
    tampered["file_inventory"][1]["sha256"] = "0" * 64
    validator = FullPackageValidator(
        SCHEMA_ROOT,
        descriptor_schema="linux_audit_package.schema.json",
        manifest_schema="linux_collector_manifest.schema.json",
        evidence_control_field="control_ids",
        evidence_member_path_field="member_path",
    )

    with pytest.raises(PackageValidationError) as captured:
        validator.validate(
            package.archive_path,
            json.dumps(tampered).encode(),
            manifest,
            PackageValidationContext(
                organization_id=manifest["organization_id"],
                asset_id=manifest["asset_id"],
                job_id=manifest["job_id"],
                endpoint_id=manifest["submission"]["endpoint_id"],
                received_at=NOW + timedelta(minutes=10),
            ),
            _verifications(manifest, package.descriptor),
        )
    assert captured.value.code is PackageValidationCode.HASH_MISMATCH
