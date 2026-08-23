"""Linux 원샷 실행 범위를 서버가 서명하는 Manifest v2 생성·검증."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from security_audit.analysis.package_validation import (
    PackageSchemaCatalog,
    PackageValidationCode,
    PackageValidationError,
)
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256,
    canonical_sha256_without_fields,
)
from security_audit.platforms import LinuxDistribution
from security_audit.platforms.linux_kisa import KisaUnixAssessmentProfile

from .linux_local import linux_probe_contracts

ManifestSigner = Callable[[bytes], tuple[str, str]]
ManifestSignatureVerifier = Callable[[str, bytes, str], bool]
COLLECTOR_VERSION = "0.1.0"
ENDPOINT_ID = "linux.oneshot.submit.v1"


def _utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Manifest timestamps must be timezone-aware.")
    return value.isoformat().replace("+00:00", "Z")


def _probe_documents(distribution: LinuxDistribution) -> list[dict[str, JsonValue]]:
    return [
        {
            "probe_id": item.probe_id,
            "probe_version": item.probe_version,
            "control_ids": list(item.control_ids),
            "required_privilege": item.required_privilege,
            "exact_argv": list(item.exact_argv),
            "timeout_seconds": item.timeout_seconds,
            "max_output_bytes": item.max_output_bytes,
            "accepted_exit_codes": list(item.accepted_exit_codes),
        }
        for item in linux_probe_contracts(distribution)
    ]


def build_linux_collector_manifest(
    *,
    organization_id: UUID,
    subject_user_id: UUID,
    job_id: UUID,
    asset_id: UUID,
    manifest_id: UUID,
    execution_attempt_id: UUID,
    correlation_id: UUID,
    distribution: LinuxDistribution,
    issued_at: datetime,
    expires_at: datetime,
    nonce: str,
    criteria_values: Mapping[str, object],
    sign: ManifestSigner,
    release_channel: str = "DEV-UNTRUSTED",
) -> dict[str, Any]:
    if expires_at <= issued_at:
        raise ValueError("Manifest expiry must be later than issuance.")
    probes = _probe_documents(distribution)
    probe_bundle_sha256 = canonical_sha256(cast(JsonValue, probes))
    merged_criteria = KisaUnixAssessmentProfile().public_values()
    merged_criteria.update(cast(Mapping[str, JsonValue], criteria_values))
    normalized_criteria = KisaUnixAssessmentProfile.from_values(merged_criteria).public_values()
    criteria_body: dict[str, JsonValue] = {
        "benchmark_id": "KISA-2026-UNIX-U01-U67",
        "benchmark_version": "2026-DRAFT",
        "values": normalized_criteria,
    }
    criteria_sha256 = canonical_sha256(criteria_body)
    document: dict[str, JsonValue] = {
        "schema_version": "2.0.0",
        "profile": "LINUX-ONESHOT-MANIFEST-V2",
        "id": str(manifest_id),
        "created_at": _utc(issued_at),
        "source": "api",
        "producer_name": "sec-ai-api",
        "producer_version": "0.7.0",
        "correlation_id": str(correlation_id),
        "organization_id": str(organization_id),
        "subject_user_id": str(subject_user_id),
        "job_id": str(job_id),
        "asset_id": str(asset_id),
        "execution_attempt_id": str(execution_attempt_id),
        "guide_version": "2026",
        "nonce": nonce,
        "issued_at": _utc(issued_at),
        "expires_at": _utc(expires_at),
        "manifest_content_sha256": "0" * 64,
        "target": {
            "os_family": "LINUX",
            "distribution": distribution.value,
            "architecture": "x86_64",
        },
        "collector_constraint": {
            "name": "sec-ai-linux-one-shot",
            "min_version": COLLECTOR_VERSION,
            "max_version_exclusive": "1.0.0",
            "release_channel": release_channel,
            "probe_bundle_sha256": probe_bundle_sha256,
        },
        "criteria_snapshot": {**criteria_body, "sha256": criteria_sha256},
        "probes": cast(list[JsonValue], probes),
        "submission": {
            "allowed_profiles": [
                "ONLINE-AUTHENTICATED",
                "OFFLINE-USER-SUBMITTED",
            ],
            "endpoint_id": ENDPOINT_ID,
            "max_archive_bytes": 10 * 1024 * 1024,
            "max_uncompressed_bytes": 50 * 1024 * 1024,
            "max_files": 64,
        },
    }
    content_sha256 = canonical_sha256_without_fields(
        document,
        {"manifest_content_sha256", "authorization"},
    )
    document["manifest_content_sha256"] = content_sha256
    key_id, signature = sign(bytes.fromhex(content_sha256))
    document["authorization"] = {
        "profile": "MANIFEST-SIGNED-V1",
        "signature": {
            "canonicalization": "RFC8785-JCS",
            "algorithm": "Ed25519",
            "key_id": key_id,
            "signed_sha256": content_sha256,
            "value": signature,
        },
    }
    return cast(dict[str, Any], document)


def verify_linux_collector_manifest(
    manifest: Mapping[str, object],
    *,
    schema_root: Path,
    expected_distribution: LinuxDistribution,
    now: datetime,
    verify_signature: ManifestSignatureVerifier,
) -> dict[str, Any]:
    """Schema, hash, time, distribution, exact argv and Ed25519 proof를 검증합니다."""

    document = cast(dict[str, JsonValue], dict(manifest))
    PackageSchemaCatalog(schema_root).validate(
        document,
        "linux_collector_manifest.schema.json",
        PackageValidationCode.MANIFEST_SCHEMA_INVALID,
    )
    content_hash = canonical_sha256_without_fields(
        document,
        {"manifest_content_sha256", "authorization"},
    )
    if document.get("manifest_content_sha256") != content_hash:
        raise PackageValidationError(
            PackageValidationCode.MANIFEST_HASH_MISMATCH,
            "Linux Collector Manifest hash is invalid.",
        )
    issued = datetime.fromisoformat(str(document["issued_at"]).replace("Z", "+00:00"))
    expires = datetime.fromisoformat(str(document["expires_at"]).replace("Z", "+00:00"))
    if now.tzinfo is None or now.utcoffset() is None or now < issued or now > expires:
        raise PackageValidationError(
            PackageValidationCode.MANIFEST_EXPIRED,
            "Linux Collector Manifest is outside its validity window.",
        )
    target = cast(dict[str, object], document["target"])
    if target.get("distribution") != expected_distribution.value:
        raise PackageValidationError(
            PackageValidationCode.MANIFEST_SCOPE_MISMATCH,
            "Linux Collector Manifest distribution is mismatched.",
        )
    expected_probes = _probe_documents(expected_distribution)
    if document.get("probes") != expected_probes:
        raise PackageValidationError(
            PackageValidationCode.EVIDENCE_SCOPE_MISMATCH,
            "Linux Collector Manifest Probe scope is not the embedded allowlist.",
        )
    authorization = cast(dict[str, object], document["authorization"])
    signature = cast(dict[str, object], authorization["signature"])
    if signature.get("signed_sha256") != content_hash or not verify_signature(
        str(signature["key_id"]),
        bytes.fromhex(content_hash),
        str(signature["value"]),
    ):
        raise PackageValidationError(
            PackageValidationCode.MANIFEST_SIGNATURE_INVALID,
            "Linux Collector Manifest signature is invalid.",
        )
    return cast(dict[str, Any], document)
