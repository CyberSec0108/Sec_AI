from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from security_audit.analysis.package_validation import (
    DigestVerification,
    ExternalVerificationStatus,
    MalwareScanStatus,
    MalwareScanVerification,
    NonceVerification,
    NonceVerificationStatus,
    PackageAuthenticationKind,
    PackageAuthenticationVerification,
    PackageGateVerifications,
    PackageValidationContext,
    PackageValidationError,
    StagedObjectVerification,
)
from security_audit.application.linux_oneshot_processing import process_linux_oneshot_package
from security_audit.collector.linux_local import LinuxProbeOutcome, linux_probe_contracts
from security_audit.collector.linux_manifest import build_linux_collector_manifest
from security_audit.collector.linux_package import (
    BuiltLinuxAuditPackage,
    build_linux_audit_package,
)
from security_audit.platforms import LinuxDistribution

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
NOW = datetime(2026, 8, 6, 1, 0, tzinfo=UTC)


def _manifest() -> dict[str, Any]:
    return build_linux_collector_manifest(
        organization_id=UUID("91000000-0000-4000-8000-000000000001"),
        subject_user_id=UUID("91000000-0000-4000-8000-000000000002"),
        job_id=UUID("91000000-0000-4000-8000-000000000003"),
        asset_id=UUID("91000000-0000-4000-8000-000000000004"),
        manifest_id=UUID("91000000-0000-4000-8000-000000000005"),
        execution_attempt_id=UUID("91000000-0000-4000-8000-000000000006"),
        correlation_id=UUID("91000000-0000-4000-8000-000000000007"),
        distribution=LinuxDistribution.UBUNTU_24_04,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        nonce="LinuxProcessingNonce00000001",
        criteria_values={"password_maximum_age_days": 90},
        sign=lambda digest: ("linux-test-key", "A" * 43),
    )


def _outcomes() -> tuple[LinuxProbeOutcome, ...]:
    fixture = {
        "linux.login-defs": "PASS_MAX_DAYS 90\nPASS_MIN_LEN 12\n",
        "linux.sshd-effective": "permitrootlogin no\npasswordauthentication no\n",
        "linux.shadow-mode": "640:root:shadow\n",
        "linux.firewall-state": "active\n",
        "linux.time-sync": "yes\n",
        "linux.auditd-state": "active\n",
        "linux.os-release": 'ID=ubuntu\nVERSION_ID="24.04"\n',
    }
    outcomes: list[LinuxProbeOutcome] = []
    for contract in linux_probe_contracts(LinuxDistribution.UBUNTU_24_04):
        value = fixture.get(contract.probe_id)
        collected = value is not None
        encoded = value.encode() if value is not None else b""
        digest = hashlib.sha256(encoded).hexdigest()
        outcomes.append(
            LinuxProbeOutcome(
                probe_id=contract.probe_id,
                probe_version=contract.probe_version,
                control_ids=contract.control_ids,
                required_privilege=contract.required_privilege,
                executed_privilege=(contract.required_privilege if collected else "NOT_EXECUTED"),
                collection_status="COLLECTED" if collected else "ERROR",
                error_code="NONE" if collected else "COMMAND_FAILED",
                exit_code=0 if collected else 1,
                raw_output_sha256=digest,
                normalized_sha256=digest,
                redaction_applied=False,
                normalized_value=value or "",
            )
        )
    return tuple(outcomes)


def _case(
    tmp_path: Path,
    outcomes: tuple[LinuxProbeOutcome, ...] | None = None,
) -> tuple[
    dict[str, Any],
    BuiltLinuxAuditPackage,
    PackageValidationContext,
    PackageGateVerifications,
]:
    manifest = _manifest()
    package = build_linux_audit_package(
        manifest=manifest,
        outcomes=outcomes or _outcomes(),
        archive_path=tmp_path / "result.zip",
        package_id=UUID("92000000-0000-4000-8000-000000000001"),
        collected_at=NOW + timedelta(minutes=5),
        build_sha256="c" * 64,
        host_version="24.04",
        authentication={
            "profile": "OFFLINE-USER-SUBMITTED",
            "assurance_level": "LOW",
        },
    )
    archive = package.descriptor["archive"]
    context = PackageValidationContext(
        organization_id=manifest["organization_id"],
        asset_id=manifest["asset_id"],
        job_id=manifest["job_id"],
        endpoint_id=manifest["submission"]["endpoint_id"],
        received_at=NOW + timedelta(minutes=10),
    )
    verifications = PackageGateVerifications(
        manifest_signature=DigestVerification(
            ExternalVerificationStatus.VERIFIED, manifest["manifest_content_sha256"]
        ),
        nonce=NonceVerification(NonceVerificationStatus.FRESH_RESERVED, manifest["nonce"]),
        package_authentication=PackageAuthenticationVerification(
            ExternalVerificationStatus.VERIFIED,
            PackageAuthenticationKind.OFFLINE_SUBMITTER,
        ),
        malware_scan=MalwareScanVerification(
            MalwareScanStatus.CLEAN, archive["archive_sha256"]
        ),
        content_policy=DigestVerification(
            ExternalVerificationStatus.VERIFIED, archive["archive_sha256"]
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
    return manifest, package, context, verifications


def test_valid_complete_package_creates_exactly_67_draft_results(tmp_path: Path) -> None:
    manifest, package, context, verifications = _case(tmp_path)

    processed = process_linux_oneshot_package(
        archive_path=package.archive_path,
        descriptor_bytes=package.descriptor_bytes,
        expected_manifest=manifest,
        context=context,
        verifications=verifications,
        expected_subject_user_id=manifest["subject_user_id"],
        schema_root=SCHEMA_ROOT,
    )

    assert len(processed.result_json["controls"]) == 67
    assert processed.result_json["status_authority"] == "RULE_ENGINE"
    assert processed.result_json["raw_evidence_included"] is False
    assert processed.assurance_level == "LOW"
    assert len(processed.evidence) == 42


def test_missing_probe_is_rejected_before_rule_engine(tmp_path: Path) -> None:
    manifest, package, context, verifications = _case(tmp_path, _outcomes()[:-1])

    with pytest.raises(PackageValidationError):
        process_linux_oneshot_package(
            archive_path=package.archive_path,
            descriptor_bytes=package.descriptor_bytes,
            expected_manifest=manifest,
            context=context,
            verifications=verifications,
            expected_subject_user_id=manifest["subject_user_id"],
            schema_root=SCHEMA_ROOT,
        )


def test_same_package_processing_is_deterministic(tmp_path: Path) -> None:
    manifest, package, context, verifications = _case(tmp_path)
    hashes = {
        process_linux_oneshot_package(
            archive_path=package.archive_path,
            descriptor_bytes=package.descriptor_bytes,
            expected_manifest=manifest,
            context=context,
            verifications=verifications,
            expected_subject_user_id=manifest["subject_user_id"],
            schema_root=SCHEMA_ROOT,
        ).result_json["result_sha256"]
        for _ in range(10)
    }
    assert len(hashes) == 1
