"""Offline signed and authenticated-user Package submission for IMP-033."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import cast
from uuid import UUID, uuid4

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
from security_audit.security.signatures import (
    CertificateRevocationVerification,
    OfflinePackageSignatureVerifier,
    VerifiedOfflineSigner,
)


class OfflineSubmissionCode(StrEnum):
    USER_AUTH_REQUIRED = "OFFLINE_USER_AUTH_REQUIRED"
    CSRF_REQUIRED = "OFFLINE_CSRF_REQUIRED"
    USER_SCOPE_MISMATCH = "OFFLINE_USER_SCOPE_MISMATCH"
    PROFILE_MISMATCH = "OFFLINE_PROFILE_MISMATCH"
    SIGNED_SCOPE_MISMATCH = "OFFLINE_SIGNED_SCOPE_MISMATCH"
    REPLAYED = "OFFLINE_NONCE_REPLAYED"


class OfflineSubmissionError(ValueError):
    def __init__(self, code: OfflineSubmissionCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class OfflineExternalVerifications:
    manifest_signature: DigestVerification
    malware_scan: MalwareScanVerification
    content_policy: DigestVerification
    staged_object: StagedObjectVerification


@dataclass(frozen=True, slots=True)
class OfflineUserSubmissionContext:
    authenticated_subject_id: str
    organization_id: str
    asset_id: str
    job_id: str
    received_at: datetime
    session_active: bool
    csrf_verified: bool
    authorized_for_asset: bool

    def __post_init__(self) -> None:
        for value in (
            self.authenticated_subject_id,
            self.organization_id,
            self.asset_id,
            self.job_id,
        ):
            UUID(value)
        if self.received_at.tzinfo is None or self.received_at.utcoffset() is None:
            raise ValueError("received_at must be timezone-aware.")


@dataclass(frozen=True, slots=True)
class OfflineSubmissionReceipt:
    receipt_id: str
    profile: str
    assurance_level: str
    organization_id: str
    asset_id: str
    job_id: str
    package_id: str
    archive_sha256: str
    committed_at: datetime
    authenticated_subject_id: str | None
    certificate_sha256: str | None


@dataclass(frozen=True, slots=True)
class AcceptedOfflineSubmission:
    validated_package: ValidatedPackage
    receipt: OfflineSubmissionReceipt
    official_finding_created: bool = False


class InMemoryOfflineReplayStore:
    """Atomic profile-independent nonce commit used by pure acceptance tests."""

    def __init__(self) -> None:
        self._used: set[tuple[str, str, str, str]] = set()
        self._lock = RLock()

    def commit(
        self,
        *,
        profile: str,
        assurance_level: str,
        organization_id: str,
        asset_id: str,
        job_id: str,
        nonce: str,
        package_id: str,
        archive_sha256: str,
        committed_at: datetime,
        authenticated_subject_id: str | None,
        certificate_sha256: str | None,
    ) -> OfflineSubmissionReceipt:
        key = (organization_id, asset_id, job_id, nonce)
        with self._lock:
            if key in self._used:
                raise OfflineSubmissionError(
                    OfflineSubmissionCode.REPLAYED,
                    "Offline submission nonce was already committed.",
                )
            self._used.add(key)
        return OfflineSubmissionReceipt(
            receipt_id=str(uuid4()),
            profile=profile,
            assurance_level=assurance_level,
            organization_id=organization_id,
            asset_id=asset_id,
            job_id=job_id,
            package_id=package_id,
            archive_sha256=archive_sha256,
            committed_at=committed_at,
            authenticated_subject_id=authenticated_subject_id,
            certificate_sha256=certificate_sha256,
        )


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PackageValidationError(
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
            "Offline package object is invalid.",
        )
    return cast(Mapping[str, object], value)


def _string(value: Mapping[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise PackageValidationError(
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
            "Offline package field is invalid.",
        )
    return item


class OfflinePackageSubmissionService:
    """Run authentication-specific gates before atomic offline replay commit."""

    def __init__(
        self,
        validator: FullPackageValidator,
        signature_verifier: OfflinePackageSignatureVerifier,
        replay_store: InMemoryOfflineReplayStore,
    ) -> None:
        self._validator = validator
        self._signatures = signature_verifier
        self._replay = replay_store

    def submit_signed(
        self,
        *,
        archive_path: Path,
        descriptor_bytes: bytes,
        trusted_manifest: dict[str, JsonValue],
        signature_envelope_bytes: bytes,
        received_at: datetime,
        revocation: CertificateRevocationVerification,
        verifications: OfflineExternalVerifications,
    ) -> AcceptedOfflineSubmission:
        payload, signer = self._signatures.verify(
            signature_envelope_bytes,
            received_at=received_at,
            revocation=revocation,
        )
        descriptor = self._descriptor(descriptor_bytes)
        manifest = cast(Mapping[str, object], trusted_manifest)
        self._verify_signed_binding(
            payload,
            signer,
            descriptor,
            manifest,
            signature_envelope_bytes,
        )
        return self._validate_and_commit(
            archive_path=archive_path,
            descriptor_bytes=descriptor_bytes,
            trusted_manifest=trusted_manifest,
            organization_id=signer.organization_id,
            asset_id=signer.asset_id,
            job_id=_string(cast(Mapping[str, object], payload), "job_id"),
            endpoint_id=_string(
                _mapping(manifest.get("submission")),
                "endpoint_id",
            ),
            nonce=_string(cast(Mapping[str, object], payload), "nonce"),
            received_at=received_at,
            profile="OFFLINE-SIGNED",
            assurance_level=signer.assurance_level,
            authentication_kind=PackageAuthenticationKind.OFFLINE_SIGNATURE,
            authenticated_subject_id=None,
            certificate_sha256=signer.certificate_sha256,
            verifications=verifications,
        )

    def submit_user(
        self,
        *,
        archive_path: Path,
        descriptor_bytes: bytes,
        trusted_manifest: dict[str, JsonValue],
        user: OfflineUserSubmissionContext,
        verifications: OfflineExternalVerifications,
    ) -> AcceptedOfflineSubmission:
        if not user.session_active:
            raise OfflineSubmissionError(
                OfflineSubmissionCode.USER_AUTH_REQUIRED,
                "An active authenticated session is required.",
            )
        if not user.csrf_verified:
            raise OfflineSubmissionError(
                OfflineSubmissionCode.CSRF_REQUIRED,
                "CSRF verification is required.",
            )
        descriptor = self._descriptor(descriptor_bytes)
        manifest = cast(Mapping[str, object], trusted_manifest)
        descriptor_auth = _mapping(descriptor.get("authentication"))
        if (
            _string(descriptor_auth, "profile") != "OFFLINE-USER-SUBMITTED"
            or _string(descriptor_auth, "assurance_level") != "LOW"
        ):
            raise OfflineSubmissionError(
                OfflineSubmissionCode.PROFILE_MISMATCH,
                "User-submitted package profile is invalid.",
            )
        if not user.authorized_for_asset or (
            _string(descriptor, "asset_id") != user.asset_id
            or _string(descriptor, "job_id") != user.job_id
            or _string(manifest, "asset_id") != user.asset_id
            or _string(manifest, "job_id") != user.job_id
        ):
            raise OfflineSubmissionError(
                OfflineSubmissionCode.USER_SCOPE_MISMATCH,
                "Authenticated user is not authorized for this Asset and Job.",
            )
        return self._validate_and_commit(
            archive_path=archive_path,
            descriptor_bytes=descriptor_bytes,
            trusted_manifest=trusted_manifest,
            organization_id=user.organization_id,
            asset_id=user.asset_id,
            job_id=user.job_id,
            endpoint_id=_string(_mapping(manifest.get("submission")), "endpoint_id"),
            nonce=_string(descriptor, "nonce"),
            received_at=user.received_at,
            profile="OFFLINE-USER-SUBMITTED",
            assurance_level="LOW",
            authentication_kind=PackageAuthenticationKind.OFFLINE_SUBMITTER,
            authenticated_subject_id=user.authenticated_subject_id,
            certificate_sha256=None,
            verifications=verifications,
        )

    def _descriptor(self, descriptor_bytes: bytes) -> Mapping[str, object]:
        value = load_strict_json(descriptor_bytes)
        return _mapping(value)

    def _verify_signed_binding(
        self,
        payload: dict[str, JsonValue],
        signer: VerifiedOfflineSigner,
        descriptor: Mapping[str, object],
        manifest: Mapping[str, object],
        envelope_bytes: bytes,
    ) -> None:
        envelope = _mapping(load_strict_json(envelope_bytes))
        descriptor_auth = _mapping(descriptor.get("authentication"))
        envelope_signature = _mapping(envelope.get("signature"))
        descriptor_signature = _mapping(descriptor_auth.get("signature"))
        if (
            _string(descriptor_auth, "profile") != "OFFLINE-SIGNED"
            or _string(descriptor_auth, "assurance_level") not in {"HIGH", "MEDIUM"}
            or dict(descriptor_signature) != dict(envelope_signature)
        ):
            raise OfflineSubmissionError(
                OfflineSubmissionCode.PROFILE_MISMATCH,
                "Signed package authentication envelope is inconsistent.",
            )
        payload_object = cast(Mapping[str, object], payload)
        archive = _mapping(descriptor.get("archive"))
        expected_pairs = (
            ("asset_id", _string(descriptor, "asset_id")),
            ("job_id", _string(descriptor, "job_id")),
            ("manifest_id", _string(descriptor, "manifest_id")),
            ("manifest_sha256", _string(descriptor, "manifest_hash")),
            ("nonce", _string(descriptor, "nonce")),
            ("execution_attempt_id", _string(descriptor, "execution_attempt_id")),
            ("package_id", _string(descriptor, "id")),
            ("archive_sha256", _string(archive, "archive_sha256")),
            ("content_set_sha256", _string(archive, "content_set_sha256")),
        )
        if any(_string(payload_object, key) != expected for key, expected in expected_pairs):
            raise OfflineSubmissionError(
                OfflineSubmissionCode.SIGNED_SCOPE_MISMATCH,
                "Offline signature payload is not bound to this Package.",
            )
        if (
            _string(manifest, "id") != _string(payload_object, "manifest_id")
            or not hmac.compare_digest(
                _string(manifest, "manifest_content_sha256"),
                _string(payload_object, "manifest_sha256"),
            )
            or _string(manifest, "asset_id") != signer.asset_id
            or _string(manifest, "job_id") != _string(payload_object, "job_id")
        ):
            raise OfflineSubmissionError(
                OfflineSubmissionCode.SIGNED_SCOPE_MISMATCH,
                "Offline signature payload is not bound to the trusted Manifest.",
            )

    def _validate_and_commit(
        self,
        *,
        archive_path: Path,
        descriptor_bytes: bytes,
        trusted_manifest: dict[str, JsonValue],
        organization_id: str,
        asset_id: str,
        job_id: str,
        endpoint_id: str,
        nonce: str,
        received_at: datetime,
        profile: str,
        assurance_level: str,
        authentication_kind: PackageAuthenticationKind,
        authenticated_subject_id: str | None,
        certificate_sha256: str | None,
        verifications: OfflineExternalVerifications,
    ) -> AcceptedOfflineSubmission:
        gates = PackageGateVerifications(
            manifest_signature=verifications.manifest_signature,
            nonce=NonceVerification(NonceVerificationStatus.FRESH_RESERVED, nonce),
            package_authentication=PackageAuthenticationVerification(
                ExternalVerificationStatus.VERIFIED,
                authentication_kind,
            ),
            malware_scan=verifications.malware_scan,
            content_policy=verifications.content_policy,
            staged_object=verifications.staged_object,
        )
        validated = self._validator.validate(
            archive_path,
            descriptor_bytes,
            trusted_manifest,
            PackageValidationContext(
                organization_id=organization_id,
                asset_id=asset_id,
                job_id=job_id,
                endpoint_id=endpoint_id,
                received_at=received_at,
            ),
            gates,
        )
        if validated.authentication_profile != profile:
            raise OfflineSubmissionError(
                OfflineSubmissionCode.PROFILE_MISMATCH,
                "Validated Package profile differs from the submission path.",
            )
        receipt = self._replay.commit(
            profile=profile,
            assurance_level=assurance_level,
            organization_id=organization_id,
            asset_id=asset_id,
            job_id=job_id,
            nonce=nonce,
            package_id=validated.package_id,
            archive_sha256=validated.inspection.archive_sha256,
            committed_at=received_at,
            authenticated_subject_id=authenticated_subject_id,
            certificate_sha256=certificate_sha256,
        )
        return AcceptedOfflineSubmission(validated, receipt)

