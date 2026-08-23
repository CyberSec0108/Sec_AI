"""Typed contracts for the IMP-028 one-shot Collector boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType

from security_audit.common.canonical_json import JsonScalar, JsonValue

type ParameterValue = JsonScalar


class ManifestVerificationCode(StrEnum):
    """Stable fail-closed outcomes produced before any Probe can run."""

    INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    JSON_INVALID = "JSON_INVALID"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    HASH_MISMATCH = "HASH_MISMATCH"
    SIGNATURE_HASH_MISMATCH = "SIGNATURE_HASH_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    SIGNATURE_UNAVAILABLE = "SIGNATURE_UNAVAILABLE"
    MANIFEST_NOT_YET_VALID = "MANIFEST_NOT_YET_VALID"
    MANIFEST_EXPIRED = "MANIFEST_EXPIRED"
    MANIFEST_SCOPE_MISMATCH = "MANIFEST_SCOPE_MISMATCH"
    NONCE_REPLAYED = "NONCE_REPLAYED"
    NONCE_CHECK_UNAVAILABLE = "NONCE_CHECK_UNAVAILABLE"
    TARGET_MISMATCH = "TARGET_MISMATCH"
    COLLECTOR_CONSTRAINT_MISMATCH = "COLLECTOR_CONSTRAINT_MISMATCH"
    PROBE_DUPLICATED = "PROBE_DUPLICATED"
    PROBE_NOT_ALLOWED = "PROBE_NOT_ALLOWED"
    PROBE_CONTRACT_MISMATCH = "PROBE_CONTRACT_MISMATCH"
    MANIFEST_SEMANTIC_INVALID = "MANIFEST_SEMANTIC_INVALID"


class ManifestVerificationError(ValueError):
    """A public code without untrusted Manifest values in the message."""

    def __init__(self, code: ManifestVerificationCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class ExternalSignatureStatus(StrEnum):
    """Result from the trusted-key signature adapter."""

    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"


class NonceStatus(StrEnum):
    """Result from the local/server nonce freshness boundary."""

    FRESH = "FRESH"
    REPLAYED = "REPLAYED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class ManifestSignatureProof:
    """Signature result bound to one exact Manifest digest and key ID."""

    status: ExternalSignatureStatus
    manifest_sha256: str
    key_id: str


@dataclass(frozen=True, slots=True)
class ManifestVerificationContext:
    """Facts supplied independently of the untrusted Manifest."""

    expected_job_id: str
    expected_asset_id: str
    expected_endpoint_id: str
    expected_nonce: str
    checked_at: datetime
    nonce_status: NonceStatus

    def __post_init__(self) -> None:
        if self.checked_at.tzinfo is None or self.checked_at.utcoffset() is None:
            raise ValueError("checked_at must be timezone-aware.")


@dataclass(frozen=True, slots=True)
class ProbeContract:
    """One immutable entry in the Collector release allowlist."""

    probe_id: str
    probe_version: str
    control_ids: frozenset[str]
    required_privilege: str
    max_timeout_seconds: int
    max_output_bytes: int
    parameters: MappingProxyType[str, ParameterValue]


@dataclass(frozen=True, slots=True)
class VerifiedProbeRequest:
    """A Manifest request narrowed to an exact built-in Probe contract."""

    probe_id: str
    probe_version: str
    control_ids: tuple[str, ...]
    required_privilege: str
    timeout_seconds: int
    max_output_bytes: int
    parameters: MappingProxyType[str, ParameterValue]


@dataclass(frozen=True, slots=True)
class VerifiedExecutionPlan:
    """Capability object emitted only after every Manifest gate passes."""

    manifest_id: str
    manifest_sha256: str
    job_id: str
    asset_id: str
    nonce: str
    verified_at: datetime
    probes: tuple[VerifiedProbeRequest, ...]


class MockCollectionCode(StrEnum):
    """Mock-only execution outcomes; none are official Finding states."""

    COLLECTED = "COLLECTED"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    PLAN_INVALID = "PLAN_INVALID"


class MockCollectionError(ValueError):
    def __init__(self, code: MockCollectionCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class MockProbeResult:
    probe_id: str
    probe_version: str
    control_ids: tuple[str, ...]
    collection_status: MockCollectionCode
    synthetic: bool
    payload: JsonValue


@dataclass(frozen=True, slots=True)
class MockCollectionRun:
    manifest_id: str
    manifest_sha256: str
    job_id: str
    asset_id: str
    execution_mode: str
    real_os_access: bool
    results: tuple[MockProbeResult, ...]
