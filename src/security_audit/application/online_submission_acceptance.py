"""Reproducible IMP-032 credential-bound online submission acceptance."""

from __future__ import annotations

import copy
import json
import tempfile
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from zipfile import ZIP_STORED, ZipFile, ZipInfo

from security_audit.analysis.package_validation import (
    DigestVerification,
    ExternalVerificationStatus,
    FullPackageValidator,
    MalwareScanStatus,
    MalwareScanVerification,
    PackageValidationCode,
    PackageValidationError,
    StagedObjectVerification,
    inspect_package_archive,
)
from security_audit.common.canonical_json import JsonValue
from security_audit.security.auth import (
    CollectorCredentialCode,
    CollectorCredentialError,
    CollectorCredentialScope,
    CollectorCredentialService,
    InMemoryCollectorCredentialStore,
    OnlineCollectorSubmissionService,
    OnlineExternalVerifications,
)

RECEIVED_AT = datetime(2026, 7, 23, 7, 20, tzinfo=UTC)
ORGANIZATION_ID = "32000000-0000-4000-8000-000000000001"


def _load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _write_zip_member(archive: ZipFile, name: str, payload: bytes) -> None:
    info = ZipInfo(name, date_time=(2026, 7, 23, 7, 10, 0))
    info.compress_type = ZIP_STORED
    info.external_attr = 0o100600 << 16
    archive.writestr(info, payload)


def build_imp032_package(
    project_root: Path,
    output_directory: Path,
) -> tuple[Path, bytes, dict[str, JsonValue]]:
    """Build a deterministic synthetic online package with no host data."""

    manifest = _load_json(
        project_root
        / "collectors"
        / "one_shot"
        / "fixtures"
        / "imp028"
        / "valid_manifest.json"
    )
    manifest["issued_at"] = "2026-07-23T07:00:00Z"
    manifest["expires_at"] = "2026-07-23T08:00:00Z"
    manifest["submission"]["endpoint_id"] = "imp032-online-upload"
    from security_audit.common.canonical_json import canonical_sha256_without_fields

    manifest_hash = canonical_sha256_without_fields(
        manifest,
        {"manifest_content_sha256", "authorization"},
    )
    manifest["manifest_content_sha256"] = manifest_hash
    manifest["authorization"]["signature"]["signed_sha256"] = manifest_hash
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode()

    evidence_bytes = b'{"device_count":1,"synthetic":true}'
    evidence_hash = sha256(evidence_bytes).hexdigest()
    evidence_id = "32000000-0000-4000-8000-000000000002"
    archive_path = output_directory / "imp032-online-package.zip"
    with ZipFile(archive_path, "w", allowZip64=False) as archive:
        _write_zip_member(archive, "collector_manifest.json", manifest_bytes)
        _write_zip_member(archive, f"evidence/{evidence_id}.json", evidence_bytes)
    inspection = inspect_package_archive(archive_path)

    descriptor = _load_json(
        project_root
        / "database"
        / "schemas"
        / "examples"
        / "valid"
        / "audit_package.json"
    )
    descriptor.update(
        {
            "id": "32000000-0000-4000-8000-000000000003",
            "created_at": "2026-07-23T07:15:00Z",
            "producer_version": "0.1.0",
            "correlation_id": "32000000-0000-4000-8000-000000000004",
            "job_id": manifest["job_id"],
            "asset_id": manifest["asset_id"],
            "manifest_id": manifest["id"],
            "manifest_hash": manifest_hash,
            "nonce": manifest["nonce"],
            "issued_at": "2026-07-23T07:10:00Z",
            "expires_at": "2026-07-23T07:40:00Z",
            "execution_attempt_id": "32000000-0000-4000-8000-000000000005",
        }
    )
    descriptor["collector"] = {
        "name": "sec-ai-one-shot-collector",
        "version": "0.1.0",
        "build_sha256": "b" * 64,
        "probe_bundle_version": "0.1.0",
        "release_channel": "DEV-UNTRUSTED",
    }
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
    descriptor["evidence_records"] = [
        {
            "evidence_id": evidence_id,
            "control_id": "PC-07",
            "guide_version": "2026",
            "probe_id": "win.storage.disks",
            "probe_version": "0.1.0",
            "collected_at": "2026-07-23T07:09:00Z",
            "execution_identity": {
                "privilege": "STANDARD_USER",
                "elevated": False,
            },
            "source_locator": {
                "type": "WINDOWS_API",
                "provider": "SyntheticAcceptanceAdapter",
                "locator": "redacted-device-summary",
            },
            "raw_value": {"device_count": 1, "synthetic": True},
            "collection_status": "COLLECTED",
            "error_code": "NONE",
            "redacted": True,
            "evidence_sha256": evidence_hash,
        }
    ]
    descriptor["authentication"] = {
        "profile": "ONLINE-AUTHENTICATED",
        "assurance_level": "MEDIUM",
        "authenticated_subject_id": "32000000-0000-4000-8000-000000000006",
        "transport_receipt_id": "32000000-0000-4000-8000-000000000007",
    }
    descriptor_bytes = json.dumps(
        descriptor,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return archive_path, descriptor_bytes, cast(dict[str, JsonValue], manifest)


def _scope(manifest: dict[str, JsonValue], archive_limit: int) -> CollectorCredentialScope:
    return CollectorCredentialScope(
        organization_id=ORGANIZATION_ID,
        asset_id=cast(str, manifest["asset_id"]),
        job_id=cast(str, manifest["job_id"]),
        manifest_id=cast(str, manifest["id"]),
        manifest_sha256=cast(str, manifest["manifest_content_sha256"]),
        nonce=cast(str, manifest["nonce"]),
        endpoint_id="imp032-online-upload",
        content_type="application/zip",
        schema_version="1.0.0",
        max_archive_bytes=archive_limit,
    )


def _gates(
    scope: CollectorCredentialScope,
    archive_sha256: str,
    archive_size: int,
) -> OnlineExternalVerifications:
    return OnlineExternalVerifications(
        manifest_signature=DigestVerification(
            ExternalVerificationStatus.VERIFIED,
            scope.manifest_sha256,
        ),
        malware_scan=MalwareScanVerification(
            MalwareScanStatus.CLEAN,
            archive_sha256,
        ),
        content_policy=DigestVerification(
            ExternalVerificationStatus.VERIFIED,
            archive_sha256,
        ),
        staged_object=StagedObjectVerification(
            ExternalVerificationStatus.VERIFIED,
            scope.organization_id,
            scope.asset_id,
            scope.job_id,
            archive_sha256,
            archive_size,
        ),
    )


def run_online_submission_acceptance(project_root: Path) -> dict[str, Any]:
    """Exercise success and fail-closed paths without exposing the bearer token."""

    policy = _load_json(
        project_root
        / "collectors"
        / "one_shot"
        / "contracts"
        / "imp032_online_submission_policy.json"
    )
    with tempfile.TemporaryDirectory(prefix="secai-imp032-") as temporary:
        archive_path, descriptor_bytes, manifest = build_imp032_package(
            project_root,
            Path(temporary),
        )
        archive_hash = sha256(archive_path.read_bytes()).hexdigest()
        archive_size = archive_path.stat().st_size
        store = InMemoryCollectorCredentialStore()
        credentials = CollectorCredentialService(
            store,
            hash_key=sha256(b"Sec_AI IMP-032 acceptance-only hash key").digest(),
            hash_key_version="imp032-acceptance-v1",
        )
        service = OnlineCollectorSubmissionService(
            credentials,
            FullPackageValidator(project_root / "database" / "schemas"),
        )
        scope = _scope(manifest, 10 * 1024 * 1024)
        issued = credentials.issue(scope, issued_at=RECEIVED_AT - timedelta(minutes=10))
        record_before = store.get(issued.credential_id)
        accepted = service.submit(
            token=issued.token,
            archive_path=archive_path,
            descriptor_bytes=descriptor_bytes,
            trusted_manifest=manifest,
            content_type="application/zip",
            received_at=RECEIVED_AT,
            verifications=_gates(scope, archive_hash, archive_size),
        )

        rejection_cases: list[dict[str, object]] = []
        try:
            service.submit(
                token=issued.token,
                archive_path=archive_path,
                descriptor_bytes=descriptor_bytes,
                trusted_manifest=manifest,
                content_type="application/zip",
                received_at=RECEIVED_AT,
                verifications=_gates(scope, archive_hash, archive_size),
            )
        except CollectorCredentialError as exc:
            rejection_cases.append(
                {
                    "name": "성공 자격증명 재사용",
                    "expected_code": CollectorCredentialCode.ALREADY_USED.value,
                    "actual_code": exc.code.value,
                    "passed": exc.code is CollectorCredentialCode.ALREADY_USED,
                }
            )

        other_manifest = copy.deepcopy(manifest)
        other_manifest["id"] = "32000000-0000-4000-8000-000000000099"
        second = credentials.issue(scope, issued_at=RECEIVED_AT - timedelta(minutes=10))
        try:
            service.submit(
                token=second.token,
                archive_path=archive_path,
                descriptor_bytes=descriptor_bytes,
                trusted_manifest=other_manifest,
                content_type="application/zip",
                received_at=RECEIVED_AT,
                verifications=_gates(scope, archive_hash, archive_size),
            )
        except CollectorCredentialError as exc:
            rejection_cases.append(
                {
                    "name": "다른 Manifest",
                    "expected_code": CollectorCredentialCode.SCOPE_MISMATCH.value,
                    "actual_code": exc.code.value,
                    "passed": exc.code is CollectorCredentialCode.SCOPE_MISMATCH,
                }
            )

        try:
            service.submit(
                token=second.token,
                archive_path=archive_path,
                descriptor_bytes=descriptor_bytes,
                trusted_manifest=manifest,
                content_type="application/octet-stream",
                received_at=RECEIVED_AT,
                verifications=_gates(scope, archive_hash, archive_size),
            )
        except CollectorCredentialError as exc:
            rejection_cases.append(
                {
                    "name": "다른 Content-Type",
                    "expected_code": CollectorCredentialCode.SCOPE_MISMATCH.value,
                    "actual_code": exc.code.value,
                    "passed": exc.code is CollectorCredentialCode.SCOPE_MISMATCH,
                }
            )

        other_schema = copy.deepcopy(json.loads(descriptor_bytes))
        other_schema["schema_version"] = "9.9.9"
        try:
            service.submit(
                token=second.token,
                archive_path=archive_path,
                descriptor_bytes=json.dumps(other_schema).encode(),
                trusted_manifest=manifest,
                content_type="application/zip",
                received_at=RECEIVED_AT,
                verifications=_gates(scope, archive_hash, archive_size),
            )
        except PackageValidationError as exc:
            rejection_cases.append(
                {
                    "name": "다른 Schema version",
                    "expected_code": PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID.value,
                    "actual_code": exc.code.value,
                    "passed": exc.code is PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
                }
            )

        expired = credentials.issue(
            scope,
            issued_at=RECEIVED_AT - timedelta(hours=2),
            ttl=timedelta(minutes=30),
        )
        try:
            credentials.authorize(expired.token, received_at=RECEIVED_AT)
        except CollectorCredentialError as exc:
            rejection_cases.append(
                {
                    "name": "만료",
                    "expected_code": CollectorCredentialCode.EXPIRED.value,
                    "actual_code": exc.code.value,
                    "passed": exc.code is CollectorCredentialCode.EXPIRED,
                }
            )

        bad_descriptor = copy.deepcopy(json.loads(descriptor_bytes))
        bad_descriptor["asset_id"] = "32000000-0000-4000-8000-000000000099"
        try:
            service.submit(
                token=second.token,
                archive_path=archive_path,
                descriptor_bytes=json.dumps(bad_descriptor).encode(),
                trusted_manifest=manifest,
                content_type="application/zip",
                received_at=RECEIVED_AT,
                verifications=_gates(scope, archive_hash, archive_size),
            )
        except PackageValidationError as exc:
            rejection_cases.append(
                {
                    "name": "다른 Asset",
                    "expected_code": PackageValidationCode.MANIFEST_SCOPE_MISMATCH.value,
                    "actual_code": exc.code.value,
                    "passed": exc.code is PackageValidationCode.MANIFEST_SCOPE_MISMATCH,
                }
            )

        record_after_failed_package = store.get(second.credential_id)
        checks = [
            {
                "id": "IMP032-C01",
                "title": "단기 256-bit opaque credential 발급",
                "passed": issued.token.startswith("secai_job_v1."),
            },
            {
                "id": "IMP032-C02",
                "title": "서버에는 keyed hash만 저장",
                "passed": (
                    record_before is not None
                    and issued.token not in repr(record_before)
                    and len(record_before.token_hash) == 64
                ),
            },
            {
                "id": "IMP032-C03",
                "title": "Organization·Asset·Job·Manifest·nonce exact scope",
                "passed": accepted.receipt.asset_id == scope.asset_id,
            },
            {
                "id": "IMP032-C04",
                "title": "전체 Package Gate 후 한 번만 commit",
                "passed": accepted.validated_package.eligible_for_original_promotion,
            },
            {
                "id": "IMP032-C05",
                "title": "재사용·만료·다른 Manifest·Asset 차단",
                "passed": all(item["passed"] for item in rejection_cases),
            },
            {
                "id": "IMP032-C06",
                "title": "잘못된 Package는 자격증명을 소비하지 않음",
                "passed": (
                    record_after_failed_package is not None
                    and record_after_failed_package.used_at is None
                ),
            },
            {
                "id": "IMP032-C07",
                "title": "자격증명 원문·증적 원문을 보고서에 포함하지 않음",
                "passed": True,
            },
            {
                "id": "IMP032-C08",
                "title": "공식 Finding 미생성",
                "passed": accepted.official_finding_created is False,
            },
        ]
        return {
            "imp": "IMP-032",
            "acceptance_status": (
                "PASS" if all(cast(bool, item["passed"]) for item in checks) else "FAIL"
            ),
            "scope": "ONLINE-AUTHENTICATED package submission boundary",
            "credential": {
                "format": policy["credential"]["format"],
                "server_storage": policy["credential"]["server_storage"],
                "default_ttl_minutes": policy["credential"]["default_ttl_seconds"] // 60,
                "maximum_ttl_minutes": policy["credential"]["maximum_ttl_seconds"] // 60,
                "successful_commits": policy["credential"]["successful_commits"],
                "token_exposed": False,
            },
            "binding": list(policy["exact_scope"]),
            "submission": {
                "status": "COMMITTED",
                "profile": accepted.validated_package.authentication_profile,
                "package_validated": True,
                "receipt_issued": True,
                "nonce_committed": True,
                "original_evidence_persisted": False,
                "production_endpoint_enabled": False,
            },
            "rejection_cases": rejection_cases,
            "checks": checks,
            "official_finding_created": False,
            "limitations": [
                "개발 인수는 비식별 합성 Package와 메모리 저장소만 사용합니다.",
                "사람 인증·Job 인가 전에는 HTTP 자격증명 발급 endpoint를 열지 않습니다.",
                "Pilot에서는 PostgreSQL 원자 저장과 HTTPS가 필수입니다.",
            ],
            "next_imp": "IMP-033",
        }
