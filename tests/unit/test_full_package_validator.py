from __future__ import annotations

import copy
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from zipfile import ZIP_DEFLATED, ZipFile

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
    inspect_package_archive,
)
from security_audit.common.canonical_json import canonical_sha256_without_fields

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
EXAMPLES = SCHEMA_ROOT / "examples" / "valid"
RECEIVED_AT = datetime(2026, 7, 21, 6, 20, tzinfo=UTC)


@dataclass(slots=True)
class PackageCase:
    archive_path: Path
    descriptor: dict[str, Any]
    manifest: dict[str, Any]
    context: PackageValidationContext
    verifications: PackageGateVerifications

    @property
    def descriptor_bytes(self) -> bytes:
        return json.dumps(self.descriptor, separators=(",", ":")).encode("utf-8")


def _load_example(name: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((EXAMPLES / name).read_text(encoding="utf-8")),
    )


def _build_case(
    tmp_path: Path,
    *,
    manifest_mutator: Callable[[dict[str, Any]], None] | None = None,
    embedded_manifest_mutator: Callable[[dict[str, Any]], None] | None = None,
    descriptor_mutator: Callable[[dict[str, Any]], None] | None = None,
    collection_error: bool = False,
) -> PackageCase:
    manifest = _load_example("collector_manifest.json")
    manifest["issued_at"] = "2026-07-21T06:00:00Z"
    manifest["expires_at"] = "2026-07-21T06:30:00Z"
    if manifest_mutator is not None:
        manifest_mutator(manifest)
    manifest_hash = canonical_sha256_without_fields(
        manifest,
        {"manifest_content_sha256", "authorization"},
    )
    manifest["manifest_content_sha256"] = manifest_hash
    manifest["authorization"]["signature"]["signed_sha256"] = manifest_hash

    embedded_manifest = copy.deepcopy(manifest)
    if embedded_manifest_mutator is not None:
        embedded_manifest_mutator(embedded_manifest)
    manifest_bytes = json.dumps(embedded_manifest, separators=(",", ":")).encode("utf-8")
    evidence_bytes = b'{"filesystem":"NTFS","synthetic":true}'
    evidence_hash = sha256(evidence_bytes).hexdigest()

    descriptor = _load_example("audit_package.json")
    descriptor["issued_at"] = "2026-07-21T06:10:00Z"
    descriptor["expires_at"] = "2026-07-21T06:25:00Z"
    descriptor["manifest_id"] = manifest["id"]
    descriptor["manifest_hash"] = manifest_hash
    descriptor["job_id"] = manifest["job_id"]
    descriptor["asset_id"] = manifest["asset_id"]
    descriptor["nonce"] = manifest["nonce"]
    evidence_record = descriptor["evidence_records"][0]
    if collection_error:
        evidence_record["collection_status"] = "ERROR"
        evidence_record["error_code"] = "PROBE_TIMEOUT"
        evidence_record.pop("raw_value", None)
    evidence_id = evidence_record["evidence_id"]
    member_directory = "errors" if collection_error else "evidence"
    evidence_path = f"{member_directory}/{evidence_id}.json"

    archive_path = tmp_path / "payload.zip"
    with ZipFile(archive_path, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("collector_manifest.json", manifest_bytes)
        archive.writestr(evidence_path, evidence_bytes)
    inspection = inspect_package_archive(archive_path)
    descriptor["archive"] = {
        "format": "ZIP-STORED-OR-DEFLATE",
        "archive_sha256": inspection.archive_sha256,
        "content_set_sha256": inspection.content_set_sha256,
        "compressed_bytes": inspection.compressed_bytes,
        "uncompressed_bytes": inspection.uncompressed_bytes,
        "file_count": inspection.file_count,
    }
    descriptor["file_inventory"] = [
        {
            "path": record.path,
            "media_type": "application/json",
            "size_bytes": record.size_bytes,
            "sha256": record.sha256,
        }
        for record in inspection.files
    ]
    descriptor["evidence_records"][0]["evidence_sha256"] = evidence_hash
    if descriptor_mutator is not None:
        descriptor_mutator(descriptor)

    context = PackageValidationContext(
        organization_id="30000000-0000-4000-8000-000000000001",
        asset_id=manifest["asset_id"],
        job_id=manifest["job_id"],
        endpoint_id=manifest["submission"]["endpoint_id"],
        received_at=RECEIVED_AT,
    )
    verifications = PackageGateVerifications(
        manifest_signature=DigestVerification(
            ExternalVerificationStatus.VERIFIED,
            manifest_hash,
        ),
        nonce=NonceVerification(
            NonceVerificationStatus.FRESH_RESERVED,
            manifest["nonce"],
        ),
        package_authentication=PackageAuthenticationVerification(
            ExternalVerificationStatus.VERIFIED,
            PackageAuthenticationKind.ONLINE_TRANSPORT,
        ),
        malware_scan=MalwareScanVerification(
            MalwareScanStatus.CLEAN,
            inspection.archive_sha256,
        ),
        content_policy=DigestVerification(
            ExternalVerificationStatus.VERIFIED,
            inspection.archive_sha256,
        ),
        staged_object=StagedObjectVerification(
            ExternalVerificationStatus.VERIFIED,
            context.organization_id,
            context.asset_id,
            context.job_id,
            inspection.archive_sha256,
            inspection.compressed_bytes,
        ),
    )
    return PackageCase(archive_path, descriptor, manifest, context, verifications)


@pytest.fixture
def validator() -> FullPackageValidator:
    return FullPackageValidator(SCHEMA_ROOT)


def _expect_code(
    validator: FullPackageValidator,
    case: PackageCase,
    expected: PackageValidationCode,
) -> None:
    with pytest.raises(PackageValidationError) as captured:
        validator.validate(
            case.archive_path,
            case.descriptor_bytes,
            case.manifest,
            case.context,
            case.verifications,
        )
    assert captured.value.code is expected


def test_valid_package_passes_every_gate_without_creating_a_finding(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(tmp_path)

    result = validator.validate(
        case.archive_path,
        case.descriptor_bytes,
        case.manifest,
        case.context,
        case.verifications,
    )

    assert result.eligible_for_original_promotion is True
    assert result.package_id == case.descriptor["id"]
    assert result.descriptor_sha256 == canonical_sha256_without_fields(case.descriptor, set())
    assert result.manifest_content_sha256 == case.manifest["manifest_content_sha256"]
    assert not hasattr(result, "finding")


def test_collection_error_member_is_validated_without_becoming_a_control_finding(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(tmp_path, collection_error=True)

    result = validator.validate(
        case.archive_path,
        case.descriptor_bytes,
        case.manifest,
        case.context,
        case.verifications,
    )

    assert result.eligible_for_original_promotion is True
    assert not hasattr(result, "finding")


def test_descriptor_schema_violation_is_rejected(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(tmp_path, descriptor_mutator=lambda value: value.update(extra=True))
    _expect_code(validator, case, PackageValidationCode.DESCRIPTOR_SCHEMA_INVALID)


def test_manifest_schema_violation_is_rejected(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(tmp_path, manifest_mutator=lambda value: value.update(extra=True))
    _expect_code(validator, case, PackageValidationCode.MANIFEST_SCHEMA_INVALID)


def test_manifest_content_hash_mismatch_is_rejected(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(tmp_path)
    case.manifest["manifest_content_sha256"] = "0" * 64
    _expect_code(validator, case, PackageValidationCode.MANIFEST_HASH_MISMATCH)


def test_embedded_manifest_must_match_server_manifest(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(
        tmp_path,
        embedded_manifest_mutator=lambda value: value.update(created_at="2026-07-21T05:59:59Z"),
    )
    _expect_code(validator, case, PackageValidationCode.MANIFEST_HASH_MISMATCH)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (
            ExternalVerificationStatus.FAILED,
            PackageValidationCode.MANIFEST_SIGNATURE_INVALID,
        ),
        (
            ExternalVerificationStatus.UNAVAILABLE,
            PackageValidationCode.MANIFEST_SIGNATURE_UNAVAILABLE,
        ),
    ],
)
def test_manifest_signature_gate_fails_closed(
    tmp_path: Path,
    validator: FullPackageValidator,
    status: ExternalVerificationStatus,
    expected: PackageValidationCode,
) -> None:
    case = _build_case(tmp_path)
    case.verifications = replace(
        case.verifications,
        manifest_signature=replace(case.verifications.manifest_signature, status=status),
    )
    _expect_code(validator, case, expected)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (NonceVerificationStatus.REPLAYED, PackageValidationCode.NONCE_REPLAYED),
        (
            NonceVerificationStatus.UNAVAILABLE,
            PackageValidationCode.NONCE_CHECK_UNAVAILABLE,
        ),
    ],
)
def test_nonce_gate_fails_closed(
    tmp_path: Path,
    validator: FullPackageValidator,
    status: NonceVerificationStatus,
    expected: PackageValidationCode,
) -> None:
    case = _build_case(tmp_path)
    case.verifications = replace(
        case.verifications,
        nonce=replace(case.verifications.nonce, status=status),
    )
    _expect_code(validator, case, expected)


def test_expired_manifest_is_rejected(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(tmp_path)
    case.context = replace(
        case.context,
        received_at=datetime(2026, 7, 21, 6, 31, tzinfo=UTC),
    )
    _expect_code(validator, case, PackageValidationCode.MANIFEST_EXPIRED)


def test_cross_asset_context_is_rejected(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(tmp_path)
    case.context = replace(case.context, asset_id="30000000-0000-4000-8000-000000000099")
    _expect_code(validator, case, PackageValidationCode.MANIFEST_SCOPE_MISMATCH)


def test_cross_organization_staging_receipt_is_rejected(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(tmp_path)
    case.verifications = replace(
        case.verifications,
        staged_object=replace(
            case.verifications.staged_object,
            organization_id="30000000-0000-4000-8000-000000000099",
        ),
    )
    _expect_code(validator, case, PackageValidationCode.ATTESTATION_BINDING_MISMATCH)


def test_unavailable_staging_verification_fails_closed(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(tmp_path)
    case.verifications = replace(
        case.verifications,
        staged_object=replace(
            case.verifications.staged_object,
            status=ExternalVerificationStatus.UNAVAILABLE,
        ),
    )
    _expect_code(validator, case, PackageValidationCode.STAGING_UNAVAILABLE)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (MalwareScanStatus.DETECTED, PackageValidationCode.MALWARE_DETECTED),
        (
            MalwareScanStatus.UNAVAILABLE,
            PackageValidationCode.MALWARE_SCAN_UNAVAILABLE,
        ),
    ],
)
def test_malware_gate_fails_closed(
    tmp_path: Path,
    validator: FullPackageValidator,
    status: MalwareScanStatus,
    expected: PackageValidationCode,
) -> None:
    case = _build_case(tmp_path)
    case.verifications = replace(
        case.verifications,
        malware_scan=replace(case.verifications.malware_scan, status=status),
    )
    _expect_code(validator, case, expected)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (ExternalVerificationStatus.FAILED, PackageValidationCode.CONTENT_POLICY_FAILED),
        (
            ExternalVerificationStatus.UNAVAILABLE,
            PackageValidationCode.CONTENT_POLICY_UNAVAILABLE,
        ),
    ],
)
def test_secret_and_overcollection_gate_fails_closed(
    tmp_path: Path,
    validator: FullPackageValidator,
    status: ExternalVerificationStatus,
    expected: PackageValidationCode,
) -> None:
    case = _build_case(tmp_path)
    case.verifications = replace(
        case.verifications,
        content_policy=replace(case.verifications.content_policy, status=status),
    )
    _expect_code(validator, case, expected)


def test_authentication_kind_must_match_submission_profile(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(tmp_path)
    case.verifications = replace(
        case.verifications,
        package_authentication=replace(
            case.verifications.package_authentication,
            kind=PackageAuthenticationKind.OFFLINE_SIGNATURE,
        ),
    )
    _expect_code(validator, case, PackageValidationCode.PACKAGE_AUTHENTICATION_INVALID)


def test_unavailable_package_authentication_fails_closed(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(tmp_path)
    case.verifications = replace(
        case.verifications,
        package_authentication=replace(
            case.verifications.package_authentication,
            status=ExternalVerificationStatus.UNAVAILABLE,
        ),
    )
    _expect_code(validator, case, PackageValidationCode.PACKAGE_AUTHENTICATION_UNAVAILABLE)


def test_profile_not_authorized_by_manifest_is_rejected(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(
        tmp_path,
        manifest_mutator=lambda value: value["submission"].update(
            allowed_profiles=["OFFLINE-SIGNED"]
        ),
    )
    _expect_code(validator, case, PackageValidationCode.SUBMISSION_PROFILE_NOT_ALLOWED)


def test_collector_version_outside_signed_range_is_rejected(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(
        tmp_path,
        descriptor_mutator=lambda value: value["collector"].update(version="2.0.0"),
    )
    _expect_code(validator, case, PackageValidationCode.COLLECTOR_CONSTRAINT_MISMATCH)


def test_evidence_outside_signed_probe_scope_is_rejected(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(
        tmp_path,
        manifest_mutator=lambda value: value["probes"][0].update(control_ids=["PC-08"]),
    )
    _expect_code(validator, case, PackageValidationCode.EVIDENCE_SCOPE_MISMATCH)


def test_external_scan_must_be_bound_to_exact_archive_digest(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(tmp_path)
    case.verifications = replace(
        case.verifications,
        malware_scan=replace(case.verifications.malware_scan, archive_sha256="0" * 64),
    )
    _expect_code(validator, case, PackageValidationCode.ATTESTATION_BINDING_MISMATCH)


def test_manifest_cannot_reduce_file_limit_below_required_layout(
    tmp_path: Path,
    validator: FullPackageValidator,
) -> None:
    case = _build_case(
        tmp_path,
        manifest_mutator=lambda value: value["submission"].update(max_files=1),
    )
    _expect_code(validator, case, PackageValidationCode.MANIFEST_SEMANTIC_INVALID)
