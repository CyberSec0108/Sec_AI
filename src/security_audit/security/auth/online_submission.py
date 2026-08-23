"""Credential-bound online package validation and atomic commit."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from security_audit.analysis.package_validation import (
    DigestVerification,
    ExternalVerificationStatus,
    FullPackageValidator,
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
    ValidatedPackage,
    load_strict_json,
)
from security_audit.common.canonical_json import JsonValue

from .collector_credentials import (
    CollectorCredentialCode,
    CollectorCredentialError,
    CollectorCredentialService,
    CollectorSubmissionReceipt,
)


@dataclass(frozen=True, slots=True)
class OnlineExternalVerifications:
    """External gates bound to the exact archive; transport auth is internal."""

    manifest_signature: DigestVerification
    malware_scan: MalwareScanVerification
    content_policy: DigestVerification
    staged_object: StagedObjectVerification


@dataclass(frozen=True, slots=True)
class AcceptedOnlineSubmission:
    validated_package: ValidatedPackage
    receipt: CollectorSubmissionReceipt
    official_finding_created: bool = False


class OnlineCollectorSubmissionService:
    """Validate the package before consuming a single-success credential."""

    def __init__(
        self,
        credential_service: CollectorCredentialService,
        validator: FullPackageValidator,
    ) -> None:
        self._credentials = credential_service
        self._validator = validator

    def submit(
        self,
        *,
        token: str,
        archive_path: Path,
        descriptor_bytes: bytes,
        trusted_manifest: dict[str, JsonValue],
        content_type: str,
        received_at: datetime,
        verifications: OnlineExternalVerifications,
    ) -> AcceptedOnlineSubmission:
        authorization = self._credentials.authorize(token, received_at=received_at)
        scope = authorization.scope
        if content_type != scope.content_type:
            raise CollectorCredentialError(
                CollectorCredentialCode.SCOPE_MISMATCH,
                "Collector credential is not scoped to this content type.",
            )
        descriptor = load_strict_json(descriptor_bytes)
        if (
            not isinstance(descriptor, dict)
            or descriptor.get("schema_version") != scope.schema_version
        ):
            raise PackageValidationError(
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
                "Package schema version differs from the credential scope.",
            )
        manifest_id = trusted_manifest.get("id")
        manifest_sha256 = trusted_manifest.get("manifest_content_sha256")
        manifest_nonce = trusted_manifest.get("nonce")
        if (
            not isinstance(manifest_id, str)
            or not isinstance(manifest_sha256, str)
            or not isinstance(manifest_nonce, str)
            or manifest_id != scope.manifest_id
            or not hmac.compare_digest(manifest_sha256, scope.manifest_sha256)
            or manifest_nonce != scope.nonce
        ):
            raise CollectorCredentialError(
                CollectorCredentialCode.SCOPE_MISMATCH,
                "Collector credential is not scoped to this Manifest.",
            )
        if archive_path.stat().st_size > scope.max_archive_bytes:
            raise PackageValidationError(
                PackageValidationCode.ARCHIVE_TOO_LARGE,
                "Package archive exceeds the credential scope.",
            )
        context = PackageValidationContext(
            organization_id=scope.organization_id,
            asset_id=scope.asset_id,
            job_id=scope.job_id,
            endpoint_id=scope.endpoint_id,
            received_at=received_at,
        )
        gates = PackageGateVerifications(
            manifest_signature=verifications.manifest_signature,
            nonce=NonceVerification(
                NonceVerificationStatus.FRESH_RESERVED,
                scope.nonce,
            ),
            package_authentication=PackageAuthenticationVerification(
                ExternalVerificationStatus.VERIFIED,
                PackageAuthenticationKind.ONLINE_TRANSPORT,
            ),
            malware_scan=verifications.malware_scan,
            content_policy=verifications.content_policy,
            staged_object=verifications.staged_object,
        )
        validated = self._validator.validate(
            archive_path,
            descriptor_bytes,
            trusted_manifest,
            context,
            gates,
        )
        if validated.authentication_profile != "ONLINE-AUTHENTICATED":
            raise PackageValidationError(
                PackageValidationCode.PACKAGE_AUTHENTICATION_INVALID,
                "Online endpoint accepts only ONLINE-AUTHENTICATED packages.",
            )
        receipt = self._credentials.commit(
            token,
            received_at=received_at,
            package_id=validated.package_id,
            archive_sha256=validated.inspection.archive_sha256,
        )
        return AcceptedOnlineSubmission(validated, receipt)
