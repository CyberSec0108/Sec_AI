"""Data contracts for deterministic Sec_AI audit package validation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024
MAX_FILES = 1024
MAX_MEMBER_BYTES = 1024 * 1024
MAX_PATH_LENGTH = 240
MAX_COMPRESSION_RATIO = 100.0
MIN_FILES = 2


class PackageValidationCode(StrEnum):
    """Stable machine-readable rejection codes for package preflight."""

    ARCHIVE_NOT_FILE = "ARCHIVE_NOT_FILE"
    ARCHIVE_EMPTY = "ARCHIVE_EMPTY"
    ARCHIVE_TOO_LARGE = "ARCHIVE_TOO_LARGE"
    ARCHIVE_INVALID = "ARCHIVE_INVALID"
    ARCHIVE_HASH_MISMATCH = "ARCHIVE_HASH_MISMATCH"
    ARCHIVE_SIZE_MISMATCH = "ARCHIVE_SIZE_MISMATCH"
    FILE_COUNT_OUT_OF_RANGE = "FILE_COUNT_OUT_OF_RANGE"
    FILE_COUNT_MISMATCH = "FILE_COUNT_MISMATCH"
    DIRECTORY_ENTRY = "DIRECTORY_ENTRY"
    SYMLINK_ENTRY = "SYMLINK_ENTRY"
    REPARSE_POINT = "REPARSE_POINT"
    SPECIAL_FILE_ENTRY = "SPECIAL_FILE_ENTRY"
    OVERLAPPING_ENTRY = "OVERLAPPING_ENTRY"
    ENCRYPTED_ENTRY = "ENCRYPTED_ENTRY"
    UNSUPPORTED_COMPRESSION = "UNSUPPORTED_COMPRESSION"
    NESTED_ARCHIVE = "NESTED_ARCHIVE"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    PATH_INVALID = "PATH_INVALID"
    DUPLICATE_PATH = "DUPLICATE_PATH"
    CASE_COLLISION = "CASE_COLLISION"
    REQUIRED_MANIFEST_MISSING = "REQUIRED_MANIFEST_MISSING"
    FILE_TOO_SMALL = "FILE_TOO_SMALL"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    TOTAL_SIZE_EXCEEDED = "TOTAL_SIZE_EXCEEDED"
    UNCOMPRESSED_SIZE_MISMATCH = "UNCOMPRESSED_SIZE_MISMATCH"
    COMPRESSION_RATIO_EXCEEDED = "COMPRESSION_RATIO_EXCEEDED"
    MEMBER_SIZE_MISMATCH = "MEMBER_SIZE_MISMATCH"
    MEMBER_READ_ERROR = "MEMBER_READ_ERROR"
    JSON_BOM_NOT_ALLOWED = "JSON_BOM_NOT_ALLOWED"
    JSON_ENCODING_INVALID = "JSON_ENCODING_INVALID"
    DUPLICATE_JSON_KEY = "DUPLICATE_JSON_KEY"
    JSON_NUMBER_INVALID = "JSON_NUMBER_INVALID"
    INVALID_JSON = "INVALID_JSON"
    JSON_TOP_LEVEL_INVALID = "JSON_TOP_LEVEL_INVALID"
    INVENTORY_INVALID = "INVENTORY_INVALID"
    FILE_MISSING = "FILE_MISSING"
    UNDECLARED_FILE = "UNDECLARED_FILE"
    SIZE_MISMATCH = "SIZE_MISMATCH"
    HASH_MISMATCH = "HASH_MISMATCH"
    CONTENT_SET_HASH_MISMATCH = "CONTENT_SET_HASH_MISMATCH"
    DESCRIPTOR_SCHEMA_INVALID = "DESCRIPTOR_SCHEMA_INVALID"
    MANIFEST_SCHEMA_INVALID = "MANIFEST_SCHEMA_INVALID"
    SCHEMA_CATALOG_INVALID = "SCHEMA_CATALOG_INVALID"
    MANIFEST_HASH_MISMATCH = "MANIFEST_HASH_MISMATCH"
    MANIFEST_SIGNATURE_INVALID = "MANIFEST_SIGNATURE_INVALID"
    MANIFEST_SIGNATURE_UNAVAILABLE = "MANIFEST_SIGNATURE_UNAVAILABLE"
    MANIFEST_NOT_YET_VALID = "MANIFEST_NOT_YET_VALID"
    MANIFEST_EXPIRED = "MANIFEST_EXPIRED"
    MANIFEST_SCOPE_MISMATCH = "MANIFEST_SCOPE_MISMATCH"
    NONCE_REPLAYED = "NONCE_REPLAYED"
    NONCE_CHECK_UNAVAILABLE = "NONCE_CHECK_UNAVAILABLE"
    SUBMISSION_PROFILE_NOT_ALLOWED = "SUBMISSION_PROFILE_NOT_ALLOWED"
    PACKAGE_AUTHENTICATION_INVALID = "PACKAGE_AUTHENTICATION_INVALID"
    PACKAGE_AUTHENTICATION_UNAVAILABLE = "PACKAGE_AUTHENTICATION_UNAVAILABLE"
    COLLECTOR_CONSTRAINT_MISMATCH = "COLLECTOR_CONSTRAINT_MISMATCH"
    EVIDENCE_SCOPE_MISMATCH = "EVIDENCE_SCOPE_MISMATCH"
    STAGING_VERIFICATION_FAILED = "STAGING_VERIFICATION_FAILED"
    STAGING_UNAVAILABLE = "STAGING_UNAVAILABLE"
    MALWARE_DETECTED = "MALWARE_DETECTED"
    MALWARE_SCAN_UNAVAILABLE = "MALWARE_SCAN_UNAVAILABLE"
    CONTENT_POLICY_FAILED = "CONTENT_POLICY_FAILED"
    CONTENT_POLICY_UNAVAILABLE = "CONTENT_POLICY_UNAVAILABLE"
    ATTESTATION_BINDING_MISMATCH = "ATTESTATION_BINDING_MISMATCH"
    MANIFEST_SEMANTIC_INVALID = "MANIFEST_SEMANTIC_INVALID"
    DESCRIPTOR_SEMANTIC_INVALID = "DESCRIPTOR_SEMANTIC_INVALID"


class PackageValidationError(ValueError):
    """Fail-closed package rejection with a stable public error code."""

    def __init__(
        self,
        code: PackageValidationCode,
        message: str,
        *,
        member_path: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.member_path = member_path


@dataclass(frozen=True, slots=True)
class PackageLimits:
    """Absolute server-side limits; a signed manifest may only reduce them."""

    max_archive_bytes: int = MAX_ARCHIVE_BYTES
    max_uncompressed_bytes: int = MAX_UNCOMPRESSED_BYTES
    max_files: int = MAX_FILES
    max_member_bytes: int = MAX_MEMBER_BYTES
    max_path_length: int = MAX_PATH_LENGTH
    max_compression_ratio: float = MAX_COMPRESSION_RATIO
    min_files: int = MIN_FILES

    def __post_init__(self) -> None:
        integer_limits = (
            self.max_archive_bytes,
            self.max_uncompressed_bytes,
            self.max_files,
            self.max_member_bytes,
            self.max_path_length,
            self.min_files,
        )
        if any(value <= 0 for value in integer_limits):
            raise ValueError("Package limits must be positive.")
        if self.min_files > self.max_files:
            raise ValueError("min_files cannot exceed max_files.")
        if self.max_compression_ratio < 1.0:
            raise ValueError("max_compression_ratio must be at least 1.0.")
        absolute_caps = (
            (self.max_archive_bytes, MAX_ARCHIVE_BYTES, "max_archive_bytes"),
            (self.max_uncompressed_bytes, MAX_UNCOMPRESSED_BYTES, "max_uncompressed_bytes"),
            (self.max_files, MAX_FILES, "max_files"),
            (self.max_member_bytes, MAX_MEMBER_BYTES, "max_member_bytes"),
            (self.max_path_length, MAX_PATH_LENGTH, "max_path_length"),
            (
                self.max_compression_ratio,
                MAX_COMPRESSION_RATIO,
                "max_compression_ratio",
            ),
        )
        for value, absolute_cap, field_name in absolute_caps:
            if value > absolute_cap:
                raise ValueError(f"{field_name} cannot expand the server-side absolute cap.")
        if self.min_files != MIN_FILES:
            raise ValueError("min_files is fixed by the package layout contract.")


@dataclass(frozen=True, slots=True)
class PackageFileRecord:
    """Measured immutable facts about one archive member."""

    path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class PackageInspection:
    """Measured package facts safe to compare with an untrusted descriptor."""

    archive_sha256: str
    content_set_sha256: str
    compressed_bytes: int
    uncompressed_bytes: int
    file_count: int
    files: tuple[PackageFileRecord, ...]


class ExternalVerificationStatus(StrEnum):
    """Result vocabulary for an external security check bound by a digest."""

    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"


class NonceVerificationStatus(StrEnum):
    """Atomic nonce reservation outcome supplied by the application layer."""

    FRESH_RESERVED = "FRESH_RESERVED"
    REPLAYED = "REPLAYED"
    UNAVAILABLE = "UNAVAILABLE"


class MalwareScanStatus(StrEnum):
    """Malware scan outcome for the exact staged archive digest."""

    CLEAN = "CLEAN"
    DETECTED = "DETECTED"
    UNAVAILABLE = "UNAVAILABLE"


class PackageAuthenticationKind(StrEnum):
    """External authentication proof expected for each submission profile."""

    ONLINE_TRANSPORT = "ONLINE_TRANSPORT"
    OFFLINE_SIGNATURE = "OFFLINE_SIGNATURE"
    OFFLINE_SUBMITTER = "OFFLINE_SUBMITTER"


@dataclass(frozen=True, slots=True)
class DigestVerification:
    status: ExternalVerificationStatus
    sha256: str


@dataclass(frozen=True, slots=True)
class NonceVerification:
    status: NonceVerificationStatus
    nonce: str


@dataclass(frozen=True, slots=True)
class MalwareScanVerification:
    status: MalwareScanStatus
    archive_sha256: str


@dataclass(frozen=True, slots=True)
class PackageAuthenticationVerification:
    status: ExternalVerificationStatus
    kind: PackageAuthenticationKind


@dataclass(frozen=True, slots=True)
class StagedObjectVerification:
    status: ExternalVerificationStatus
    organization_id: str
    asset_id: str
    job_id: str
    archive_sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class PackageGateVerifications:
    manifest_signature: DigestVerification
    nonce: NonceVerification
    package_authentication: PackageAuthenticationVerification
    malware_scan: MalwareScanVerification
    content_policy: DigestVerification
    staged_object: StagedObjectVerification


@dataclass(frozen=True, slots=True)
class PackageValidationContext:
    organization_id: str
    asset_id: str
    job_id: str
    endpoint_id: str
    received_at: datetime

    def __post_init__(self) -> None:
        if self.received_at.tzinfo is None or self.received_at.utcoffset() is None:
            raise ValueError("received_at must be timezone-aware.")


@dataclass(frozen=True, slots=True)
class ValidatedPackage:
    """A package eligible for promotion; this is never an official Finding."""

    package_id: str
    manifest_id: str
    job_id: str
    asset_id: str
    descriptor_sha256: str
    manifest_content_sha256: str
    authentication_profile: str
    inspection: PackageInspection
    eligible_for_original_promotion: bool = True
