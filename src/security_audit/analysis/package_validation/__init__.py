"""Public package-validation contract for Sec_AI collector archives."""

from .archive_contract import inspect_package_archive, validate_package_contract
from .contracts import (
    DigestVerification,
    ExternalVerificationStatus,
    MalwareScanStatus,
    MalwareScanVerification,
    NonceVerification,
    NonceVerificationStatus,
    PackageAuthenticationKind,
    PackageAuthenticationVerification,
    PackageFileRecord,
    PackageGateVerifications,
    PackageInspection,
    PackageLimits,
    PackageValidationCode,
    PackageValidationContext,
    PackageValidationError,
    StagedObjectVerification,
    ValidatedPackage,
)
from .full_validator import FullPackageValidator
from .schema_contract import PackageSchemaCatalog
from .strict_json import load_strict_json

__all__ = [
    "DigestVerification",
    "ExternalVerificationStatus",
    "FullPackageValidator",
    "MalwareScanStatus",
    "MalwareScanVerification",
    "NonceVerification",
    "NonceVerificationStatus",
    "PackageAuthenticationKind",
    "PackageAuthenticationVerification",
    "PackageFileRecord",
    "PackageGateVerifications",
    "PackageInspection",
    "PackageLimits",
    "PackageSchemaCatalog",
    "PackageValidationCode",
    "PackageValidationContext",
    "PackageValidationError",
    "StagedObjectVerification",
    "ValidatedPackage",
    "inspect_package_archive",
    "load_strict_json",
    "validate_package_contract",
]
