"""Fail-closed orchestration of every pre-Finding audit package gate."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Never, cast
from zipfile import BadZipFile, ZipFile

from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256,
    canonical_sha256_without_fields,
)

from .archive_contract import validate_package_contract
from .contracts import (
    DigestVerification,
    ExternalVerificationStatus,
    MalwareScanStatus,
    NonceVerificationStatus,
    PackageAuthenticationKind,
    PackageGateVerifications,
    PackageInspection,
    PackageLimits,
    PackageValidationCode,
    PackageValidationContext,
    PackageValidationError,
    ValidatedPackage,
)
from .schema_contract import PackageSchemaCatalog
from .strict_json import load_strict_json

_CHUNK_SIZE = 64 * 1024
_MANIFEST_PATH = "collector_manifest.json"
_SEMVER_PATTERN = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z.-]+))?"
    r"(?:\+[0-9A-Za-z.-]+)?$"
)


def _reject(code: PackageValidationCode, message: str) -> Never:
    raise PackageValidationError(code, message)


def _mapping(value: object, code: PackageValidationCode) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(code, "A required package object is invalid.")
    return cast(Mapping[str, object], value)


def _sequence(value: object, code: PackageValidationCode) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _reject(code, "A required package array is invalid.")
    return cast(Sequence[object], value)


def _string(mapping: Mapping[str, object], key: str, code: PackageValidationCode) -> str:
    value = mapping.get(key)
    if not isinstance(value, str):
        _reject(code, "A required package string is invalid.")
    return value


def _integer(mapping: Mapping[str, object], key: str, code: PackageValidationCode) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        _reject(code, "A required package integer is invalid.")
    return value


def _timestamp(mapping: Mapping[str, object], key: str, code: PackageValidationCode) -> datetime:
    value = _string(mapping, key, code)
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise PackageValidationError(code, "A package timestamp is invalid.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _reject(code, "A package timestamp must include a timezone.")
    return parsed


def _manifest_content_hash(manifest: Mapping[str, JsonValue]) -> str:
    return canonical_sha256_without_fields(
        manifest,
        {"manifest_content_sha256", "authorization"},
    )


def _measure_file(path: Path, maximum_bytes: int) -> tuple[int, str]:
    if not path.is_file():
        _reject(PackageValidationCode.ARCHIVE_NOT_FILE, "Package archive is not a file.")
    measured = 0
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK_SIZE):
            measured += len(chunk)
            if measured > maximum_bytes:
                _reject(PackageValidationCode.ARCHIVE_TOO_LARGE, "Package archive is too large.")
            digest.update(chunk)
    if measured == 0:
        _reject(PackageValidationCode.ARCHIVE_EMPTY, "Package archive is empty.")
    return measured, digest.hexdigest()


def _verified_digest(
    verification: DigestVerification,
    expected_sha256: str,
    *,
    failed_code: PackageValidationCode,
    unavailable_code: PackageValidationCode,
) -> None:
    if verification.status is ExternalVerificationStatus.UNAVAILABLE:
        _reject(unavailable_code, "A required external verification is unavailable.")
    if verification.status is ExternalVerificationStatus.FAILED:
        _reject(failed_code, "A required external verification failed.")
    if verification.sha256 != expected_sha256:
        _reject(
            PackageValidationCode.ATTESTATION_BINDING_MISMATCH,
            "An external verification is bound to a different digest.",
        )


def _semver_parts(version: str) -> tuple[tuple[int, int, int], tuple[str, ...] | None]:
    matched = _SEMVER_PATTERN.fullmatch(version)
    if matched is None:
        _reject(
            PackageValidationCode.COLLECTOR_CONSTRAINT_MISMATCH, "Collector version is invalid."
        )
    core = (
        int(matched.group("major")),
        int(matched.group("minor")),
        int(matched.group("patch")),
    )
    prerelease = matched.group("prerelease")
    return core, None if prerelease is None else tuple(prerelease.split("."))


def _compare_prerelease(left: tuple[str, ...] | None, right: tuple[str, ...] | None) -> int:
    if left is None or right is None:
        if left is right:
            return 0
        return 1 if left is None else -1
    for left_part, right_part in zip(left, right, strict=False):
        if left_part == right_part:
            continue
        left_numeric = left_part.isdigit()
        right_numeric = right_part.isdigit()
        if left_numeric and right_numeric:
            return -1 if int(left_part) < int(right_part) else 1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return -1 if left_part < right_part else 1
    return (len(left) > len(right)) - (len(left) < len(right))


def _compare_semver(left: str, right: str) -> int:
    left_core, left_pre = _semver_parts(left)
    right_core, right_pre = _semver_parts(right)
    if left_core != right_core:
        return -1 if left_core < right_core else 1
    return _compare_prerelease(left_pre, right_pre)


class FullPackageValidator:
    """Compose Schema, scope, authentication, scan, storage, and hash gates."""

    def __init__(
        self,
        schema_root: Path,
        *,
        descriptor_schema: str = "audit_package.schema.json",
        manifest_schema: str = "collector_manifest.schema.json",
        evidence_control_field: str = "control_id",
        evidence_member_path_field: str | None = None,
    ) -> None:
        self._schemas = PackageSchemaCatalog(schema_root)
        self._descriptor_schema = descriptor_schema
        self._manifest_schema = manifest_schema
        self._evidence_control_field = evidence_control_field
        self._evidence_member_path_field = evidence_member_path_field

    def validate(
        self,
        archive_path: Path,
        descriptor_bytes: bytes,
        expected_manifest: Mapping[str, object],
        context: PackageValidationContext,
        verifications: PackageGateVerifications,
    ) -> ValidatedPackage:
        descriptor_value = load_strict_json(descriptor_bytes)
        descriptor = cast(dict[str, JsonValue], descriptor_value)
        self._schemas.validate(
            descriptor,
            self._descriptor_schema,
            PackageValidationCode.DESCRIPTOR_SCHEMA_INVALID,
        )

        trusted_manifest = cast(dict[str, JsonValue], dict(expected_manifest))
        self._schemas.validate(
            trusted_manifest,
            self._manifest_schema,
            PackageValidationCode.MANIFEST_SCHEMA_INVALID,
        )
        manifest_mapping = cast(Mapping[str, object], trusted_manifest)
        manifest_hash = _manifest_content_hash(trusted_manifest)
        if (
            _string(
                manifest_mapping,
                "manifest_content_sha256",
                PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
            )
            != manifest_hash
        ):
            _reject(PackageValidationCode.MANIFEST_HASH_MISMATCH, "Manifest hash is invalid.")
        authorization = _mapping(
            manifest_mapping.get("authorization"),
            PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
        )
        signature = _mapping(
            authorization.get("signature"),
            PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
        )
        if (
            _string(
                signature,
                "signed_sha256",
                PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
            )
            != manifest_hash
        ):
            _reject(
                PackageValidationCode.MANIFEST_HASH_MISMATCH, "Manifest signature hash is invalid."
            )
        _verified_digest(
            verifications.manifest_signature,
            manifest_hash,
            failed_code=PackageValidationCode.MANIFEST_SIGNATURE_INVALID,
            unavailable_code=PackageValidationCode.MANIFEST_SIGNATURE_UNAVAILABLE,
        )

        self._validate_manifest_context(manifest_mapping, context, verifications)
        limits = self._manifest_limits(manifest_mapping)

        descriptor_mapping = cast(Mapping[str, object], descriptor)
        descriptor_archive = _mapping(
            descriptor_mapping.get("archive"),
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
        )
        declared_archive_hash = _string(
            descriptor_archive,
            "archive_sha256",
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
        )
        declared_size = _integer(
            descriptor_archive,
            "compressed_bytes",
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
        )
        measured_size, measured_hash = _measure_file(archive_path, limits.max_archive_bytes)
        if measured_hash != declared_archive_hash:
            _reject(PackageValidationCode.ARCHIVE_HASH_MISMATCH, "Archive digest is invalid.")
        if measured_size != declared_size:
            _reject(PackageValidationCode.ARCHIVE_SIZE_MISMATCH, "Archive size is invalid.")

        self._validate_external_archive_gates(
            measured_hash,
            measured_size,
            context,
            verifications,
        )
        inspection = validate_package_contract(archive_path, descriptor_mapping, limits=limits)
        embedded_manifest = self._load_embedded_manifest(archive_path, inspection, limits)
        self._schemas.validate(
            embedded_manifest,
            self._manifest_schema,
            PackageValidationCode.MANIFEST_SCHEMA_INVALID,
        )
        if (
            _manifest_content_hash(embedded_manifest) != manifest_hash
            or canonical_sha256(embedded_manifest) != canonical_sha256(trusted_manifest)
        ):
            _reject(PackageValidationCode.MANIFEST_HASH_MISMATCH, "Embedded Manifest differs.")

        self._validate_descriptor_semantics(
            descriptor_mapping,
            manifest_mapping,
            context,
            verifications,
        )
        return ValidatedPackage(
            package_id=_string(
                descriptor_mapping,
                "id",
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
            ),
            manifest_id=_string(
                descriptor_mapping,
                "manifest_id",
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
            ),
            job_id=context.job_id,
            asset_id=context.asset_id,
            descriptor_sha256=canonical_sha256(descriptor),
            manifest_content_sha256=manifest_hash,
            authentication_profile=_string(
                _mapping(
                    descriptor_mapping.get("authentication"),
                    PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
                ),
                "profile",
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
            ),
            inspection=inspection,
        )

    def _validate_manifest_context(
        self,
        manifest: Mapping[str, object],
        context: PackageValidationContext,
        verifications: PackageGateVerifications,
    ) -> None:
        issued_at = _timestamp(
            manifest, "issued_at", PackageValidationCode.MANIFEST_SEMANTIC_INVALID
        )
        expires_at = _timestamp(
            manifest,
            "expires_at",
            PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
        )
        if expires_at <= issued_at:
            _reject(
                PackageValidationCode.MANIFEST_SEMANTIC_INVALID, "Manifest time range is invalid."
            )
        if context.received_at < issued_at:
            _reject(PackageValidationCode.MANIFEST_NOT_YET_VALID, "Manifest is not yet valid.")
        if context.received_at > expires_at:
            _reject(PackageValidationCode.MANIFEST_EXPIRED, "Manifest has expired.")
        submission = _mapping(
            manifest.get("submission"),
            PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
        )
        scope_values = (
            (
                _string(manifest, "job_id", PackageValidationCode.MANIFEST_SEMANTIC_INVALID),
                context.job_id,
            ),
            (
                _string(manifest, "asset_id", PackageValidationCode.MANIFEST_SEMANTIC_INVALID),
                context.asset_id,
            ),
            (
                _string(submission, "endpoint_id", PackageValidationCode.MANIFEST_SEMANTIC_INVALID),
                context.endpoint_id,
            ),
        )
        if any(actual != expected for actual, expected in scope_values):
            _reject(PackageValidationCode.MANIFEST_SCOPE_MISMATCH, "Manifest scope is invalid.")
        manifest_nonce = _string(
            manifest,
            "nonce",
            PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
        )
        if verifications.nonce.nonce != manifest_nonce:
            _reject(
                PackageValidationCode.ATTESTATION_BINDING_MISMATCH, "Nonce proof is mismatched."
            )
        if verifications.nonce.status is NonceVerificationStatus.UNAVAILABLE:
            _reject(PackageValidationCode.NONCE_CHECK_UNAVAILABLE, "Nonce check is unavailable.")
        if verifications.nonce.status is NonceVerificationStatus.REPLAYED:
            _reject(PackageValidationCode.NONCE_REPLAYED, "Manifest nonce has already been used.")

    def _manifest_limits(self, manifest: Mapping[str, object]) -> PackageLimits:
        submission = _mapping(
            manifest.get("submission"),
            PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
        )
        try:
            return PackageLimits(
                max_archive_bytes=_integer(
                    submission,
                    "max_archive_bytes",
                    PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
                ),
                max_uncompressed_bytes=_integer(
                    submission,
                    "max_uncompressed_bytes",
                    PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
                ),
                max_files=_integer(
                    submission,
                    "max_files",
                    PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
                ),
            )
        except ValueError as exc:
            raise PackageValidationError(
                PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
                "Manifest package limits are incompatible with the package layout.",
            ) from exc

    def _validate_external_archive_gates(
        self,
        archive_hash: str,
        archive_size: int,
        context: PackageValidationContext,
        verifications: PackageGateVerifications,
    ) -> None:
        staged = verifications.staged_object
        if staged.status is ExternalVerificationStatus.UNAVAILABLE:
            _reject(
                PackageValidationCode.STAGING_UNAVAILABLE, "Staging verification is unavailable."
            )
        if staged.status is ExternalVerificationStatus.FAILED:
            _reject(
                PackageValidationCode.STAGING_VERIFICATION_FAILED, "Staging verification failed."
            )
        if (
            staged.organization_id != context.organization_id
            or staged.asset_id != context.asset_id
            or staged.job_id != context.job_id
            or staged.archive_sha256 != archive_hash
            or staged.size_bytes != archive_size
        ):
            _reject(
                PackageValidationCode.ATTESTATION_BINDING_MISMATCH,
                "Staging proof is bound to a different object or scope.",
            )
        malware = verifications.malware_scan
        if malware.archive_sha256 != archive_hash:
            _reject(
                PackageValidationCode.ATTESTATION_BINDING_MISMATCH, "Scan digest is mismatched."
            )
        if malware.status is MalwareScanStatus.UNAVAILABLE:
            _reject(PackageValidationCode.MALWARE_SCAN_UNAVAILABLE, "Malware scan is unavailable.")
        if malware.status is MalwareScanStatus.DETECTED:
            _reject(PackageValidationCode.MALWARE_DETECTED, "Malware scan rejected the package.")
        _verified_digest(
            verifications.content_policy,
            archive_hash,
            failed_code=PackageValidationCode.CONTENT_POLICY_FAILED,
            unavailable_code=PackageValidationCode.CONTENT_POLICY_UNAVAILABLE,
        )

    def _load_embedded_manifest(
        self,
        archive_path: Path,
        inspection: PackageInspection,
        limits: PackageLimits,
    ) -> dict[str, JsonValue]:
        record = next((item for item in inspection.files if item.path == _MANIFEST_PATH), None)
        if record is None:
            _reject(PackageValidationCode.REQUIRED_MANIFEST_MISSING, "Manifest is missing.")
        try:
            with ZipFile(archive_path, "r", allowZip64=False) as archive:
                info = archive.getinfo(_MANIFEST_PATH)
                if info.file_size > limits.max_member_bytes:
                    _reject(PackageValidationCode.FILE_TOO_LARGE, "Manifest is too large.")
                data = archive.read(info)
        except (BadZipFile, KeyError, OSError, RuntimeError) as exc:
            raise PackageValidationError(
                PackageValidationCode.MEMBER_READ_ERROR,
                "Manifest could not be read safely.",
            ) from exc
        if len(data) != record.size_bytes or sha256(data).hexdigest() != record.sha256:
            _reject(PackageValidationCode.HASH_MISMATCH, "Manifest changed during validation.")
        return cast(dict[str, JsonValue], load_strict_json(data))

    def _validate_descriptor_semantics(
        self,
        descriptor: Mapping[str, object],
        manifest: Mapping[str, object],
        context: PackageValidationContext,
        verifications: PackageGateVerifications,
    ) -> None:
        issued_at = _timestamp(
            descriptor,
            "issued_at",
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
        )
        expires_at = _timestamp(
            descriptor,
            "expires_at",
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
        )
        manifest_issued = _timestamp(
            manifest,
            "issued_at",
            PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
        )
        manifest_expires = _timestamp(
            manifest,
            "expires_at",
            PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
        )
        if (
            expires_at <= issued_at
            or issued_at < manifest_issued
            or expires_at > manifest_expires
            or context.received_at < issued_at
            or context.received_at > expires_at
        ):
            _reject(
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID, "Package time range is invalid."
            )
        expected_pairs = (
            ("job_id", context.job_id),
            ("asset_id", context.asset_id),
            (
                "manifest_id",
                _string(manifest, "id", PackageValidationCode.MANIFEST_SEMANTIC_INVALID),
            ),
            ("nonce", _string(manifest, "nonce", PackageValidationCode.MANIFEST_SEMANTIC_INVALID)),
            (
                "manifest_hash",
                _string(
                    manifest,
                    "manifest_content_sha256",
                    PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
                ),
            ),
        )
        if any(
            _string(descriptor, key, PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID) != expected
            for key, expected in expected_pairs
        ):
            _reject(PackageValidationCode.MANIFEST_SCOPE_MISMATCH, "Package scope is invalid.")

        authentication = _mapping(
            descriptor.get("authentication"),
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
        )
        profile = _string(
            authentication,
            "profile",
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
        )
        submission = _mapping(
            manifest.get("submission"),
            PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
        )
        allowed_profiles = _sequence(
            submission.get("allowed_profiles"),
            PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
        )
        if profile not in allowed_profiles:
            _reject(
                PackageValidationCode.SUBMISSION_PROFILE_NOT_ALLOWED,
                "Package authentication profile is not authorized.",
            )
        expected_kind = {
            "ONLINE-AUTHENTICATED": PackageAuthenticationKind.ONLINE_TRANSPORT,
            "OFFLINE-SIGNED": PackageAuthenticationKind.OFFLINE_SIGNATURE,
            "OFFLINE-USER-SUBMITTED": PackageAuthenticationKind.OFFLINE_SUBMITTER,
        }[profile]
        package_auth = verifications.package_authentication
        if package_auth.kind is not expected_kind:
            _reject(
                PackageValidationCode.PACKAGE_AUTHENTICATION_INVALID,
                "Package authentication proof has the wrong type.",
            )
        if package_auth.status is ExternalVerificationStatus.UNAVAILABLE:
            _reject(
                PackageValidationCode.PACKAGE_AUTHENTICATION_UNAVAILABLE,
                "Package authentication is unavailable.",
            )
        if package_auth.status is ExternalVerificationStatus.FAILED:
            _reject(
                PackageValidationCode.PACKAGE_AUTHENTICATION_INVALID,
                "Package authentication failed.",
            )
        self._validate_collector_and_evidence(descriptor, manifest)

    def _validate_collector_and_evidence(
        self,
        descriptor: Mapping[str, object],
        manifest: Mapping[str, object],
    ) -> None:
        collector = _mapping(
            descriptor.get("collector"),
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
        )
        constraint = _mapping(
            manifest.get("collector_constraint"),
            PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
        )
        collector_version = _string(
            collector,
            "version",
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
        )
        if (
            _string(collector, "name", PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID)
            != _string(constraint, "name", PackageValidationCode.MANIFEST_SEMANTIC_INVALID)
            or _string(
                collector,
                "release_channel",
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
            )
            != _string(
                constraint,
                "release_channel",
                PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
            )
            or _compare_semver(
                collector_version,
                _string(
                    constraint,
                    "min_version",
                    PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
                ),
            )
            < 0
            or _compare_semver(
                collector_version,
                _string(
                    constraint,
                    "max_version_exclusive",
                    PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
                ),
            )
            >= 0
        ):
            _reject(
                PackageValidationCode.COLLECTOR_CONSTRAINT_MISMATCH,
                "Collector build is outside the signed Manifest constraint.",
            )

        probes = _sequence(
            manifest.get("probes"),
            PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
        )
        authorized: dict[str, tuple[str, frozenset[object]]] = {}
        for item in probes:
            probe = _mapping(item, PackageValidationCode.MANIFEST_SEMANTIC_INVALID)
            probe_id = _string(
                probe,
                "probe_id",
                PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
            )
            if probe_id in authorized:
                _reject(PackageValidationCode.MANIFEST_SEMANTIC_INVALID, "Probe is duplicated.")
            authorized[probe_id] = (
                _string(
                    probe,
                    "probe_version",
                    PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
                ),
                frozenset(
                    _sequence(
                        probe.get("control_ids"),
                        PackageValidationCode.MANIFEST_SEMANTIC_INVALID,
                    )
                ),
            )
        inventory = _sequence(
            descriptor.get("file_inventory"),
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
        )
        inventory_hashes = {
            _string(
                _mapping(item, PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID),
                "path",
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
            ): _string(
                _mapping(item, PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID),
                "sha256",
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
            )
            for item in inventory
        }
        evidence_records = _sequence(
            descriptor.get("evidence_records"),
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
        )
        evidence_ids: set[str] = set()
        for item in evidence_records:
            evidence = _mapping(item, PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID)
            evidence_id = _string(
                evidence,
                "evidence_id",
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
            )
            if evidence_id in evidence_ids:
                _reject(
                    PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID, "Evidence is duplicated."
                )
            evidence_ids.add(evidence_id)
            probe_id = _string(
                evidence,
                "probe_id",
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
            )
            authorized_probe = authorized.get(probe_id)
            if self._evidence_control_field == "control_id":
                evidence_controls = frozenset(
                    {
                        _string(
                            evidence,
                            "control_id",
                            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
                        )
                    }
                )
            else:
                raw_controls = _sequence(
                    evidence.get(self._evidence_control_field),
                    PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
                )
                if any(not isinstance(item, str) for item in raw_controls):
                    _reject(
                        PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
                        "Evidence control identifiers must be strings.",
                    )
                evidence_controls = frozenset(cast(str, item) for item in raw_controls)
            if authorized_probe is None or (
                _string(
                    evidence,
                    "probe_version",
                    PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
                )
                != authorized_probe[0]
                or evidence_controls != authorized_probe[1]
            ):
                _reject(
                    PackageValidationCode.EVIDENCE_SCOPE_MISMATCH,
                    "Evidence was not authorized by the signed Manifest.",
                )
            collection_status = _string(
                evidence,
                "collection_status",
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
            )
            member_directory = "evidence" if collection_status == "COLLECTED" else "errors"
            expected_evidence_path = f"{member_directory}/{evidence_id}.json"
            evidence_path = (
                expected_evidence_path
                if self._evidence_member_path_field is None
                else _string(
                    evidence,
                    self._evidence_member_path_field,
                    PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
                )
            )
            if evidence_path != expected_evidence_path:
                _reject(
                    PackageValidationCode.EVIDENCE_SCOPE_MISMATCH,
                    "Evidence member path does not match its collection status.",
                )
            evidence_hash = _string(
                evidence,
                "evidence_sha256",
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
            )
            if inventory_hashes.get(evidence_path) != evidence_hash:
                _reject(
                    PackageValidationCode.EVIDENCE_SCOPE_MISMATCH,
                    "Evidence record does not match the archive inventory.",
                )
        if _integer(
            _mapping(
                descriptor.get("archive"),
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
            ),
            "file_count",
            PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID,
        ) != len(inventory):
            _reject(
                PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID, "Inventory count is invalid."
            )
