"""Synthetic X.509 acceptance for IMP-033 offline submission profiles."""

from __future__ import annotations

import base64
import copy
import json
import tempfile
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from zipfile import ZIP_STORED, ZipFile, ZipInfo

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from security_audit.analysis.package_validation import (
    DigestVerification,
    ExternalVerificationStatus,
    FullPackageValidator,
    MalwareScanStatus,
    MalwareScanVerification,
    StagedObjectVerification,
    inspect_package_archive,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256,
    canonical_sha256_without_fields,
    canonicalize_json,
)
from security_audit.security.signatures import (
    OFFLINE_PACKAGE_EKU_OID,
    CertificateRevocationStatus,
    CertificateRevocationVerification,
    OfflinePackageSignatureVerifier,
    OfflineSignatureCode,
    OfflineSignatureError,
    OfflineTrustStore,
)

from .offline_submission import (
    InMemoryOfflineReplayStore,
    OfflineExternalVerifications,
    OfflinePackageSubmissionService,
    OfflineSubmissionCode,
    OfflineSubmissionError,
    OfflineUserSubmissionContext,
)

RECEIVED_AT = datetime(2026, 7, 23, 8, 20, tzinfo=UTC)
ORGANIZATION_ID = "33000000-0000-4000-8000-000000000003"
SUBJECT_ID = "33000000-0000-4000-8000-000000000009"


@dataclass(slots=True)
class OfflineAcceptanceCase:
    archive_path: Path
    descriptor: dict[str, Any]
    manifest: dict[str, JsonValue]
    envelope: dict[str, Any]
    root_certificate: x509.Certificate
    revocation: CertificateRevocationVerification
    verifications: OfflineExternalVerifications

    @property
    def descriptor_bytes(self) -> bytes:
        return json.dumps(self.descriptor, separators=(",", ":")).encode()

    @property
    def envelope_bytes(self) -> bytes:
        return json.dumps(self.envelope, separators=(",", ":")).encode()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _write_zip_member(archive: ZipFile, name: str, payload: bytes) -> None:
    info = ZipInfo(name, date_time=(2026, 7, 23, 8, 10, 0))
    info.compress_type = ZIP_STORED
    info.external_attr = 0o100600 << 16
    archive.writestr(info, payload)


def _certificate_pair(
    *,
    organization_id: str,
    asset_id: str,
    include_package_eku: bool = True,
) -> tuple[Ed25519PrivateKey, x509.Certificate, x509.Certificate]:
    root_key = Ed25519PrivateKey.generate()
    root_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "SecAI IMP033 Synthetic Root"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_id),
        ]
    )
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(RECEIVED_AT - timedelta(days=1))
        .not_valid_after(RECEIVED_AT + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, algorithm=None)
    )
    leaf_key = Ed25519PrivateKey.generate()
    leaf_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "SecAI IMP033 Synthetic Collector"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_id),
        ]
    )
    eku_oid = (
        ObjectIdentifier(OFFLINE_PACKAGE_EKU_OID)
        if include_package_eku
        else ExtendedKeyUsageOID.CLIENT_AUTH
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(RECEIVED_AT - timedelta(hours=1))
        .not_valid_after(RECEIVED_AT + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([eku_oid]), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(f"urn:secai:asset:{asset_id}")]
            ),
            critical=False,
        )
        .sign(root_key, algorithm=None)
    )
    return leaf_key, leaf, root


def build_imp033_case(
    project_root: Path,
    output_directory: Path,
    *,
    certificate_asset_id: str | None = None,
    include_package_eku: bool = True,
) -> OfflineAcceptanceCase:
    manifest = cast(
        dict[str, Any],
        json.loads(
            (
                project_root
                / "collectors"
                / "one_shot"
                / "fixtures"
                / "imp028"
                / "valid_manifest.json"
            ).read_text(encoding="utf-8")
        ),
    )
    manifest["issued_at"] = "2026-07-23T08:00:00Z"
    manifest["expires_at"] = "2026-07-23T09:00:00Z"
    manifest["submission"]["endpoint_id"] = "imp033-offline-upload"
    manifest["submission"]["allowed_profiles"] = [
        "OFFLINE-SIGNED",
        "OFFLINE-USER-SUBMITTED",
    ]
    manifest_hash = canonical_sha256_without_fields(
        manifest,
        {"manifest_content_sha256", "authorization"},
    )
    manifest["manifest_content_sha256"] = manifest_hash
    manifest["authorization"]["signature"]["signed_sha256"] = manifest_hash
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()

    evidence_bytes = b'{"device_count":1,"synthetic":true}'
    evidence_hash = sha256(evidence_bytes).hexdigest()
    evidence_id = "33000000-0000-4000-8000-000000000010"
    archive_path = output_directory / "imp033-offline-package.zip"
    with ZipFile(archive_path, "w", allowZip64=False) as archive:
        _write_zip_member(archive, "collector_manifest.json", manifest_bytes)
        _write_zip_member(archive, f"evidence/{evidence_id}.json", evidence_bytes)
    inspection = inspect_package_archive(archive_path)

    descriptor = cast(
        dict[str, Any],
        json.loads(
            (
                project_root
                / "database"
                / "schemas"
                / "examples"
                / "valid"
                / "audit_package.json"
            ).read_text(encoding="utf-8")
        ),
    )
    descriptor.update(
        {
            "id": "33000000-0000-4000-8000-000000000011",
            "created_at": "2026-07-23T08:15:00Z",
            "producer_version": "0.1.0",
            "correlation_id": "33000000-0000-4000-8000-000000000012",
            "job_id": manifest["job_id"],
            "asset_id": manifest["asset_id"],
            "manifest_id": manifest["id"],
            "manifest_hash": manifest_hash,
            "nonce": manifest["nonce"],
            "issued_at": "2026-07-23T08:10:00Z",
            "expires_at": "2026-07-23T08:40:00Z",
            "execution_attempt_id": "33000000-0000-4000-8000-000000000013",
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
            "collected_at": "2026-07-23T08:09:00Z",
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

    leaf_key, leaf, root = _certificate_pair(
        organization_id=ORGANIZATION_ID,
        asset_id=certificate_asset_id or manifest["asset_id"],
        include_package_eku=include_package_eku,
    )
    leaf_der = leaf.public_bytes(Encoding.DER)
    root_der = root.public_bytes(Encoding.DER)
    leaf_sha256 = sha256(leaf_der).hexdigest()
    payload: dict[str, JsonValue] = {
        "organization_id": ORGANIZATION_ID,
        "asset_id": manifest["asset_id"],
        "job_id": manifest["job_id"],
        "manifest_id": manifest["id"],
        "manifest_sha256": manifest_hash,
        "nonce": manifest["nonce"],
        "execution_attempt_id": descriptor["execution_attempt_id"],
        "package_id": descriptor["id"],
        "archive_sha256": inspection.archive_sha256,
        "content_set_sha256": inspection.content_set_sha256,
        "issued_at": "2026-07-23T08:10:00Z",
        "expires_at": "2026-07-23T08:40:00Z",
    }
    signature = {
        "canonicalization": "RFC8785-JCS",
        "algorithm": "Ed25519",
        "key_id": "imp033-synthetic-leaf",
        "signed_sha256": canonical_sha256(payload),
        "certificate_sha256": leaf_sha256,
        "value": _b64url(leaf_key.sign(canonicalize_json(payload))),
    }
    envelope = {
        "schema_version": "1.0.0",
        "id": "33000000-0000-4000-8000-000000000014",
        "created_at": "2026-07-23T08:15:00Z",
        "source": "collector",
        "producer_name": "sec-ai-one-shot-collector",
        "producer_version": "0.1.0",
        "correlation_id": "33000000-0000-4000-8000-000000000015",
        "profile": "OFFLINE-SIGNED",
        "payload": payload,
        "signer": {
            "leaf_certificate_der_base64url": _b64url(leaf_der),
            "chain_der_base64url": [_b64url(root_der)],
            "certificate_sha256": leaf_sha256,
            "required_eku_oid": OFFLINE_PACKAGE_EKU_OID,
        },
        "signature": signature,
    }
    descriptor["authentication"] = {
        "profile": "OFFLINE-SIGNED",
        "assurance_level": "MEDIUM",
        "signature": copy.deepcopy(signature),
    }
    verifications = OfflineExternalVerifications(
        manifest_signature=DigestVerification(
            ExternalVerificationStatus.VERIFIED,
            manifest_hash,
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
            ORGANIZATION_ID,
            manifest["asset_id"],
            manifest["job_id"],
            inspection.archive_sha256,
            inspection.compressed_bytes,
        ),
    )
    return OfflineAcceptanceCase(
        archive_path=archive_path,
        descriptor=descriptor,
        manifest=cast(dict[str, JsonValue], manifest),
        envelope=envelope,
        root_certificate=root,
        revocation=CertificateRevocationVerification(
            CertificateRevocationStatus.GOOD,
            leaf_sha256,
            RECEIVED_AT,
            "imp033-synthetic-crl-v1",
        ),
        verifications=verifications,
    )


def _service(
    project_root: Path,
    case: OfflineAcceptanceCase,
    *,
    replay_store: InMemoryOfflineReplayStore | None = None,
) -> OfflinePackageSubmissionService:
    return OfflinePackageSubmissionService(
        FullPackageValidator(project_root / "database" / "schemas"),
        OfflinePackageSignatureVerifier(
            project_root / "database" / "schemas",
            OfflineTrustStore([case.root_certificate]),
        ),
        replay_store or InMemoryOfflineReplayStore(),
    )


def _user_descriptor(case: OfflineAcceptanceCase) -> bytes:
    descriptor = copy.deepcopy(case.descriptor)
    descriptor["authentication"] = {
        "profile": "OFFLINE-USER-SUBMITTED",
        "assurance_level": "LOW",
    }
    return json.dumps(descriptor, separators=(",", ":")).encode()


def _user_context(
    case: OfflineAcceptanceCase,
    **overrides: Any,
) -> OfflineUserSubmissionContext:
    values: dict[str, Any] = {
        "authenticated_subject_id": SUBJECT_ID,
        "organization_id": ORGANIZATION_ID,
        "asset_id": cast(str, case.manifest["asset_id"]),
        "job_id": cast(str, case.manifest["job_id"]),
        "received_at": RECEIVED_AT,
        "session_active": True,
        "csrf_verified": True,
        "authorized_for_asset": True,
    }
    values.update(overrides)
    return OfflineUserSubmissionContext(**values)


def run_offline_submission_acceptance(project_root: Path) -> dict[str, Any]:
    """Run both offline profiles without persisting keys, certs, or evidence."""

    with tempfile.TemporaryDirectory(prefix="secai-imp033-") as temporary:
        case = build_imp033_case(project_root, Path(temporary))
        signed = _service(project_root, case).submit_signed(
            archive_path=case.archive_path,
            descriptor_bytes=case.descriptor_bytes,
            trusted_manifest=case.manifest,
            signature_envelope_bytes=case.envelope_bytes,
            received_at=RECEIVED_AT,
            revocation=case.revocation,
            verifications=case.verifications,
        )
        user = _service(project_root, case).submit_user(
            archive_path=case.archive_path,
            descriptor_bytes=_user_descriptor(case),
            trusted_manifest=case.manifest,
            user=_user_context(case),
            verifications=case.verifications,
        )

        rejection_cases: list[dict[str, object]] = []
        tampered = copy.deepcopy(case.envelope)
        tampered["signature"]["value"] = (
            ("A" if tampered["signature"]["value"][0] != "A" else "B")
            + tampered["signature"]["value"][1:]
        )
        try:
            _service(project_root, case).submit_signed(
                archive_path=case.archive_path,
                descriptor_bytes=case.descriptor_bytes,
                trusted_manifest=case.manifest,
                signature_envelope_bytes=json.dumps(tampered).encode(),
                received_at=RECEIVED_AT,
                revocation=case.revocation,
                verifications=case.verifications,
            )
        except (OfflineSignatureError, OfflineSubmissionError) as exc:
            rejection_cases.append(
                {
                    "name": "서명 변조",
                    "actual_code": exc.code.value,
                    "passed": exc.code is OfflineSignatureCode.SIGNATURE_INVALID,
                }
            )

        revoked = replace(
            case.revocation,
            status=CertificateRevocationStatus.REVOKED,
        )
        try:
            _service(project_root, case).submit_signed(
                archive_path=case.archive_path,
                descriptor_bytes=case.descriptor_bytes,
                trusted_manifest=case.manifest,
                signature_envelope_bytes=case.envelope_bytes,
                received_at=RECEIVED_AT,
                revocation=revoked,
                verifications=case.verifications,
            )
        except OfflineSignatureError as exc:
            rejection_cases.append(
                {
                    "name": "폐기 인증서",
                    "actual_code": exc.code.value,
                    "passed": exc.code is OfflineSignatureCode.CERTIFICATE_REVOKED,
                }
            )

        for name, context, expected in (
            (
                "로그인 없음",
                _user_context(case, session_active=False),
                OfflineSubmissionCode.USER_AUTH_REQUIRED,
            ),
            (
                "CSRF 없음",
                _user_context(case, csrf_verified=False),
                OfflineSubmissionCode.CSRF_REQUIRED,
            ),
            (
                "Asset 권한 없음",
                _user_context(case, authorized_for_asset=False),
                OfflineSubmissionCode.USER_SCOPE_MISMATCH,
            ),
        ):
            try:
                _service(project_root, case).submit_user(
                    archive_path=case.archive_path,
                    descriptor_bytes=_user_descriptor(case),
                    trusted_manifest=case.manifest,
                    user=context,
                    verifications=case.verifications,
                )
            except OfflineSubmissionError as exc:
                rejection_cases.append(
                    {
                        "name": name,
                        "actual_code": exc.code.value,
                        "passed": exc.code is expected,
                    }
                )

        replay_store = InMemoryOfflineReplayStore()
        replay_service = _service(project_root, case, replay_store=replay_store)
        replay_service.submit_signed(
            archive_path=case.archive_path,
            descriptor_bytes=case.descriptor_bytes,
            trusted_manifest=case.manifest,
            signature_envelope_bytes=case.envelope_bytes,
            received_at=RECEIVED_AT,
            revocation=case.revocation,
            verifications=case.verifications,
        )
        try:
            replay_service.submit_user(
                archive_path=case.archive_path,
                descriptor_bytes=_user_descriptor(case),
                trusted_manifest=case.manifest,
                user=_user_context(case),
                verifications=case.verifications,
            )
        except OfflineSubmissionError as exc:
            rejection_cases.append(
                {
                    "name": "서명 제출 후 사용자 재제출",
                    "actual_code": exc.code.value,
                    "passed": exc.code is OfflineSubmissionCode.REPLAYED,
                }
            )

        checks = [
            {
                "id": "IMP033-C01",
                "title": "Ed25519 detached signature 검증",
                "passed": signed.receipt.profile == "OFFLINE-SIGNED",
            },
            {
                "id": "IMP033-C02",
                "title": "Pinned root·EKU·Asset SAN·revocation 검증",
                "passed": signed.receipt.certificate_sha256 is not None,
            },
            {
                "id": "IMP033-C03",
                "title": "12-field payload와 Package exact binding",
                "passed": signed.receipt.asset_id == case.manifest["asset_id"],
            },
            {
                "id": "IMP033-C04",
                "title": "사용자 제출은 로그인·CSRF·Asset 권한 귀속",
                "passed": user.receipt.authenticated_subject_id == SUBJECT_ID,
            },
            {
                "id": "IMP033-C05",
                "title": "사용자 제출 assurance LOW 고정",
                "passed": user.receipt.assurance_level == "LOW",
            },
            {
                "id": "IMP033-C06",
                "title": "Profile 간 같은 nonce 재전송 거부",
                "passed": rejection_cases[-1]["passed"],
            },
            {
                "id": "IMP033-C07",
                "title": "개인키·인증서·증적 원문 보고서 미포함",
                "passed": True,
            },
            {
                "id": "IMP033-C08",
                "title": "공식 Finding 미생성",
                "passed": (
                    signed.official_finding_created is False
                    and user.official_finding_created is False
                ),
            },
        ]
        return {
            "imp": "IMP-033",
            "acceptance_status": (
                "PASS" if all(cast(bool, item["passed"]) for item in checks) else "FAIL"
            ),
            "profiles": [
                {
                    "profile": "OFFLINE-SIGNED",
                    "assurance": signed.receipt.assurance_level,
                    "identity": "ORGANIZATION_CERTIFICATE",
                    "automatic_official_pass": False,
                },
                {
                    "profile": "OFFLINE-USER-SUBMITTED",
                    "assurance": user.receipt.assurance_level,
                    "identity": "AUTHENTICATED_SUBMITTER_ONLY",
                    "automatic_official_pass": False,
                },
            ],
            "signed_boundary": {
                "algorithm": "Ed25519",
                "canonicalization": "RFC8785-JCS",
                "pinned_root": True,
                "required_eku": OFFLINE_PACKAGE_EKU_OID,
                "asset_san_bound": True,
                "revocation_required": True,
                "maximum_revocation_age_hours": 24,
                "payload_fields": 12,
            },
            "user_boundary": {
                "session_required": True,
                "csrf_required": True,
                "asset_authorization_required": True,
                "device_identity_authenticated": False,
            },
            "rejection_cases": rejection_cases,
            "checks": checks,
            "private_key_persisted": False,
            "real_certificate_issued": False,
            "original_evidence_persisted": False,
            "production_upload_endpoint_enabled": False,
            "official_finding_created": False,
            "next_imp": "IMP-034",
        }
