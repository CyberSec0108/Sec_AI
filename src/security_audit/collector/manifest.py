"""Fail-closed Collector-side Manifest verification."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Never, cast

from security_audit.analysis.package_validation import (
    PackageSchemaCatalog,
    PackageValidationCode,
    PackageValidationError,
    load_strict_json,
)
from security_audit.common.canonical_json import (
    JsonScalar,
    JsonValue,
    canonical_sha256_without_fields,
)

from .allowlist import ProbeAllowlist
from .contracts import (
    ExternalSignatureStatus,
    ManifestSignatureProof,
    ManifestVerificationCode,
    ManifestVerificationContext,
    ManifestVerificationError,
    NonceStatus,
    VerifiedExecutionPlan,
    VerifiedProbeRequest,
)

MAX_MANIFEST_BYTES = 256 * 1024
_SEMVER_PATTERN = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z.-]+))?"
    r"(?:\+[0-9A-Za-z.-]+)?$"
)


def _reject(code: ManifestVerificationCode, message: str) -> Never:
    raise ManifestVerificationError(code, message)


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(
            ManifestVerificationCode.MANIFEST_SEMANTIC_INVALID,
            "A required Manifest object is invalid.",
        )
    return cast(Mapping[str, object], value)


def _sequence(value: object) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _reject(
            ManifestVerificationCode.MANIFEST_SEMANTIC_INVALID,
            "A required Manifest array is invalid.",
        )
    return cast(Sequence[object], value)


def _string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str):
        _reject(
            ManifestVerificationCode.MANIFEST_SEMANTIC_INVALID,
            "A required Manifest string is invalid.",
        )
    return value


def _integer(mapping: Mapping[str, object], key: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        _reject(
            ManifestVerificationCode.MANIFEST_SEMANTIC_INVALID,
            "A required Manifest integer is invalid.",
        )
    return value


def _timestamp(mapping: Mapping[str, object], key: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(_string(mapping, key).removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ManifestVerificationError(
            ManifestVerificationCode.MANIFEST_SEMANTIC_INVALID,
            "A Manifest timestamp is invalid.",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _reject(
            ManifestVerificationCode.MANIFEST_SEMANTIC_INVALID,
            "A Manifest timestamp must include a timezone.",
        )
    return parsed


def _semver_parts(version: str) -> tuple[tuple[int, int, int], tuple[str, ...] | None]:
    matched = _SEMVER_PATTERN.fullmatch(version)
    if matched is None:
        _reject(
            ManifestVerificationCode.COLLECTOR_CONSTRAINT_MISMATCH,
            "A Collector version is invalid.",
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


def _parameters(value: object) -> MappingProxyType[str, JsonScalar]:
    mapping = _mapping(value)
    result: dict[str, JsonScalar] = {}
    for key, raw_value in mapping.items():
        if not isinstance(raw_value, (str, int, float, bool, type(None))):
            _reject(
                ManifestVerificationCode.PROBE_CONTRACT_MISMATCH,
                "Probe parameters do not match the built-in contract.",
            )
        result[key] = raw_value
    return MappingProxyType(result)


class CollectorManifestVerifier:
    """Turn untrusted bytes into a narrow execution capability."""

    def __init__(self, schema_root: Path, allowlist: ProbeAllowlist) -> None:
        self._schemas = PackageSchemaCatalog(schema_root)
        self._allowlist = allowlist

    def verify_bytes(
        self,
        manifest_bytes: bytes,
        context: ManifestVerificationContext,
        signature: ManifestSignatureProof,
    ) -> VerifiedExecutionPlan:
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            _reject(ManifestVerificationCode.INPUT_TOO_LARGE, "Manifest is too large.")
        try:
            raw = load_strict_json(manifest_bytes)
        except PackageValidationError as exc:
            raise ManifestVerificationError(
                ManifestVerificationCode.JSON_INVALID,
                "Manifest is not strict UTF-8 JSON.",
            ) from exc
        if not isinstance(raw, dict):
            _reject(ManifestVerificationCode.JSON_INVALID, "Manifest must be a JSON object.")
        return self.verify(raw, context, signature)

    def verify(
        self,
        manifest: Mapping[str, JsonValue],
        context: ManifestVerificationContext,
        signature: ManifestSignatureProof,
    ) -> VerifiedExecutionPlan:
        document = dict(manifest)
        try:
            self._schemas.validate(
                document,
                "collector_manifest.schema.json",
                PackageValidationCode.MANIFEST_SCHEMA_INVALID,
            )
        except PackageValidationError as exc:
            raise ManifestVerificationError(
                ManifestVerificationCode.SCHEMA_INVALID,
                "Manifest failed the closed local JSON Schema.",
            ) from exc
        manifest_mapping = cast(Mapping[str, object], document)
        manifest_hash = canonical_sha256_without_fields(
            document,
            {"manifest_content_sha256", "authorization"},
        )
        if _string(manifest_mapping, "manifest_content_sha256") != manifest_hash:
            _reject(ManifestVerificationCode.HASH_MISMATCH, "Manifest content hash is invalid.")
        authorization = _mapping(manifest_mapping.get("authorization"))
        signature_fields = _mapping(authorization.get("signature"))
        if _string(signature_fields, "signed_sha256") != manifest_hash:
            _reject(
                ManifestVerificationCode.SIGNATURE_HASH_MISMATCH,
                "Manifest signature is bound to another digest.",
            )
        if signature.status is ExternalSignatureStatus.UNAVAILABLE:
            _reject(
                ManifestVerificationCode.SIGNATURE_UNAVAILABLE,
                "Manifest signature verification is unavailable.",
            )
        if signature.status is ExternalSignatureStatus.FAILED:
            _reject(
                ManifestVerificationCode.SIGNATURE_INVALID,
                "Manifest signature verification failed.",
            )
        if (
            signature.manifest_sha256 != manifest_hash
            or signature.key_id != _string(signature_fields, "key_id")
        ):
            _reject(
                ManifestVerificationCode.SIGNATURE_INVALID,
                "Manifest signature proof is not bound to this Manifest.",
            )
        self._verify_time_and_scope(manifest_mapping, context)
        self._verify_collector_constraint(manifest_mapping)
        verified_probes = self._verify_probes(manifest_mapping)
        return VerifiedExecutionPlan(
            manifest_id=_string(manifest_mapping, "id"),
            manifest_sha256=manifest_hash,
            job_id=context.expected_job_id,
            asset_id=context.expected_asset_id,
            nonce=context.expected_nonce,
            verified_at=context.checked_at,
            probes=verified_probes,
        )

    def _verify_time_and_scope(
        self,
        manifest: Mapping[str, object],
        context: ManifestVerificationContext,
    ) -> None:
        issued_at = _timestamp(manifest, "issued_at")
        expires_at = _timestamp(manifest, "expires_at")
        if expires_at <= issued_at:
            _reject(
                ManifestVerificationCode.MANIFEST_SEMANTIC_INVALID,
                "Manifest time range is invalid.",
            )
        if context.checked_at < issued_at:
            _reject(
                ManifestVerificationCode.MANIFEST_NOT_YET_VALID,
                "Manifest is not yet valid.",
            )
        if context.checked_at > expires_at:
            _reject(ManifestVerificationCode.MANIFEST_EXPIRED, "Manifest has expired.")
        submission = _mapping(manifest.get("submission"))
        if (
            _string(manifest, "job_id") != context.expected_job_id
            or _string(manifest, "asset_id") != context.expected_asset_id
            or _string(submission, "endpoint_id") != context.expected_endpoint_id
            or _string(manifest, "nonce") != context.expected_nonce
        ):
            _reject(
                ManifestVerificationCode.MANIFEST_SCOPE_MISMATCH,
                "Manifest is not authorized for this Job, Asset, endpoint, and nonce.",
            )
        if context.nonce_status is NonceStatus.UNAVAILABLE:
            _reject(
                ManifestVerificationCode.NONCE_CHECK_UNAVAILABLE,
                "Nonce freshness verification is unavailable.",
            )
        if context.nonce_status is NonceStatus.REPLAYED:
            _reject(ManifestVerificationCode.NONCE_REPLAYED, "Manifest nonce was already used.")
        target = _mapping(manifest.get("target"))
        if (
            _string(target, "os_family") != "WINDOWS"
            or _string(target, "os_version") not in {"10", "11"}
            or _string(target, "architecture") != "x86_64"
        ):
            _reject(
                ManifestVerificationCode.TARGET_MISMATCH,
                "Manifest target is not supported by this Collector.",
            )

    def _verify_collector_constraint(self, manifest: Mapping[str, object]) -> None:
        constraint = _mapping(manifest.get("collector_constraint"))
        collector_version = self._allowlist.collector_version
        if (
            _string(constraint, "name") != self._allowlist.collector_name
            or _string(constraint, "release_channel") != self._allowlist.release_channel
            or _compare_semver(collector_version, _string(constraint, "min_version")) < 0
            or _compare_semver(
                collector_version,
                _string(constraint, "max_version_exclusive"),
            )
            >= 0
        ):
            _reject(
                ManifestVerificationCode.COLLECTOR_CONSTRAINT_MISMATCH,
                "Collector release is outside the signed Manifest constraint.",
            )

    def _verify_probes(
        self,
        manifest: Mapping[str, object],
    ) -> tuple[VerifiedProbeRequest, ...]:
        result: list[VerifiedProbeRequest] = []
        seen: set[str] = set()
        for raw_request in _sequence(manifest.get("probes")):
            request = _mapping(raw_request)
            probe_id = _string(request, "probe_id")
            if probe_id in seen:
                _reject(
                    ManifestVerificationCode.PROBE_DUPLICATED,
                    "Manifest contains a duplicate Probe.",
                )
            seen.add(probe_id)
            contract = self._allowlist.get(probe_id)
            if contract is None:
                _reject(
                    ManifestVerificationCode.PROBE_NOT_ALLOWED,
                    "Manifest requested a Probe not built into this release.",
                )
            control_ids = tuple(sorted(_string({"value": item}, "value") for item in _sequence(
                request.get("control_ids")
            )))
            parameters = _parameters(request.get("parameters"))
            if (
                _string(request, "probe_version") != contract.probe_version
                or frozenset(control_ids) != contract.control_ids
                or _string(request, "required_privilege") != contract.required_privilege
                or _integer(request, "timeout_seconds") > contract.max_timeout_seconds
                or _integer(request, "max_output_bytes") > contract.max_output_bytes
                or dict(parameters) != dict(contract.parameters)
            ):
                _reject(
                    ManifestVerificationCode.PROBE_CONTRACT_MISMATCH,
                    "Probe request exceeds or differs from the built-in contract.",
                )
            result.append(
                VerifiedProbeRequest(
                    probe_id=probe_id,
                    probe_version=contract.probe_version,
                    control_ids=control_ids,
                    required_privilege=contract.required_privilege,
                    timeout_seconds=_integer(request, "timeout_seconds"),
                    max_output_bytes=_integer(request, "max_output_bytes"),
                    parameters=parameters,
                )
            )
        return tuple(result)
