"""검증된 Linux 원샷 Package를 U-01~U-67 DRAFT 결과로 변환합니다."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID
from zipfile import ZipFile

from security_audit.analysis.package_validation import (
    FullPackageValidator,
    PackageGateVerifications,
    PackageSchemaCatalog,
    PackageValidationCode,
    PackageValidationContext,
    PackageValidationError,
    ValidatedPackage,
    inspect_package_archive,
    load_strict_json,
)
from security_audit.application.device_ai_token_stream import (
    enrich_linux_audit_history_result,
)
from security_audit.common.canonical_json import JsonValue, canonical_sha256
from security_audit.platforms import (
    AssetContext,
    DeviceAuditResult,
    LinuxDistribution,
    evaluate_kisa_unix,
    linux_adapter_for,
)
from security_audit.platforms.linux_kisa import KisaUnixAssessmentProfile

_SECRET_VALUE = re.compile(
    r"(?im)(?:token|cookie|private[_ -]?key)\s*[:=]\s*(?!<redacted>)\S+"
)
_COMMUNITY_VALUE = re.compile(r"(?im)^\s*(?:ro|rw)community\s+(?!<redacted>)\S+")


@dataclass(frozen=True, slots=True)
class ProcessedLinuxOneShotPackage:
    validated_package: ValidatedPackage
    result_json: dict[str, Any]
    evidence: tuple[dict[str, Any], ...]
    assurance_level: str
    submission_profile: str


def _reject(code: PackageValidationCode, message: str) -> None:
    raise PackageValidationError(code, message)


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID, "Package object is invalid.")
    return cast(Mapping[str, object], value)


def _validate_scope(
    descriptor: Mapping[str, object],
    manifest: Mapping[str, object],
    *,
    context: PackageValidationContext,
    expected_subject_user_id: str,
) -> None:
    expected = {
        "organization_id": context.organization_id,
        "subject_user_id": expected_subject_user_id,
        "job_id": context.job_id,
        "asset_id": context.asset_id,
        "execution_attempt_id": str(manifest["execution_attempt_id"]),
    }
    if any(str(descriptor.get(key)) != value for key, value in expected.items()):
        _reject(
            PackageValidationCode.MANIFEST_SCOPE_MISMATCH,
            "Linux one-shot user, asset, Job, or attempt scope is mismatched.",
        )
    if str(manifest.get("organization_id")) != context.organization_id or str(
        manifest.get("subject_user_id")
    ) != expected_subject_user_id:
        _reject(
            PackageValidationCode.MANIFEST_SCOPE_MISMATCH,
            "Linux one-shot Manifest owner scope is mismatched.",
        )


def _load_evidence(
    *,
    archive_path: Path,
    descriptor: Mapping[str, object],
    manifest: Mapping[str, object],
    schema_root: Path,
) -> tuple[dict[str, bytes], tuple[dict[str, Any], ...]]:
    schema = PackageSchemaCatalog(schema_root)
    manifest_probes = {
        str(_mapping(item)["probe_id"]): _mapping(item)
        for item in cast(list[object], manifest["probes"])
    }
    records = cast(list[object], descriptor["evidence_records"])
    descriptor_probes = {str(_mapping(item)["probe_id"]) for item in records}
    if descriptor_probes != set(manifest_probes) or len(records) != len(manifest_probes):
        _reject(
            PackageValidationCode.EVIDENCE_SCOPE_MISMATCH,
            "Every signed Linux Probe must have exactly one Evidence record.",
        )

    outputs: dict[str, bytes] = {}
    evidence: list[dict[str, Any]] = []
    with ZipFile(archive_path, "r") as archive:
        for raw_record in records:
            record = _mapping(raw_record)
            member_path = str(record["member_path"])
            member_value = load_strict_json(archive.read(member_path))
            schema.validate(
                member_value,
                "linux_collector_evidence.schema.json",
                PackageValidationCode.DESCRIPTOR_SCHEMA_INVALID,
            )
            member = cast(dict[str, Any], member_value)
            fields = (
                "evidence_id",
                "probe_id",
                "probe_version",
                "control_ids",
                "required_privilege",
                "collection_status",
                "error_code",
            )
            if any(member[field] != record[field] for field in fields):
                _reject(
                    PackageValidationCode.EVIDENCE_SCOPE_MISMATCH,
                    "Linux Evidence member differs from its descriptor record.",
                )
            normalized = str(member["normalized_value"])
            normalized_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            if normalized_hash != member["normalized_sha256"]:
                _reject(
                    PackageValidationCode.HASH_MISMATCH,
                    "Linux normalized Evidence hash is invalid.",
                )
            if not member["redaction_applied"] and (
                member["raw_output_sha256"] != member["normalized_sha256"]
            ):
                _reject(
                    PackageValidationCode.HASH_MISMATCH,
                    "Unredacted Linux Evidence hashes must match.",
                )
            if "-----BEGIN " in normalized or _SECRET_VALUE.search(
                normalized
            ) or _COMMUNITY_VALUE.search(normalized):
                _reject(
                    PackageValidationCode.CONTENT_POLICY_FAILED,
                    "Linux Evidence contains prohibited secret material.",
                )
            probe_id = str(member["probe_id"])
            if member["collection_status"] == "COLLECTED":
                outputs[probe_id] = normalized.encode("utf-8")
            evidence.append(member)
    return outputs, tuple(evidence)


def inspect_linux_package_content_policy(
    archive_path: Path,
    *,
    schema_root: Path,
) -> str:
    """전체 Validator 전에 exact archive에 secret·비계약 member가 없는지 확인합니다."""

    inspection = inspect_package_archive(archive_path)
    schema = PackageSchemaCatalog(schema_root)
    with ZipFile(archive_path, "r") as archive:
        for record in inspection.files:
            if record.path == "collector_manifest.json":
                continue
            member_value = load_strict_json(archive.read(record.path))
            schema.validate(
                member_value,
                "linux_collector_evidence.schema.json",
                PackageValidationCode.DESCRIPTOR_SCHEMA_INVALID,
            )
            member = cast(dict[str, object], member_value)
            normalized = str(member["normalized_value"])
            if "-----BEGIN " in normalized or _SECRET_VALUE.search(
                normalized
            ) or _COMMUNITY_VALUE.search(normalized):
                _reject(
                    PackageValidationCode.CONTENT_POLICY_FAILED,
                    "Linux Evidence contains prohibited secret material.",
                )
    return inspection.archive_sha256


def process_linux_oneshot_package(
    *,
    archive_path: Path,
    descriptor_bytes: bytes,
    expected_manifest: Mapping[str, object],
    context: PackageValidationContext,
    verifications: PackageGateVerifications,
    expected_subject_user_id: str,
    schema_root: Path,
) -> ProcessedLinuxOneShotPackage:
    """전체 Package Gate 성공 뒤에만 기존 결정론 규칙 엔진을 호출합니다."""

    validator = FullPackageValidator(
        schema_root,
        descriptor_schema="linux_audit_package.schema.json",
        manifest_schema="linux_collector_manifest.schema.json",
        evidence_control_field="control_ids",
        evidence_member_path_field="member_path",
    )
    validated = validator.validate(
        archive_path,
        descriptor_bytes,
        expected_manifest,
        context,
        verifications,
    )
    descriptor_value = load_strict_json(descriptor_bytes)
    descriptor = cast(dict[str, Any], descriptor_value)
    _validate_scope(
        descriptor,
        expected_manifest,
        context=context,
        expected_subject_user_id=expected_subject_user_id,
    )
    outputs, evidence = _load_evidence(
        archive_path=archive_path,
        descriptor=descriptor,
        manifest=expected_manifest,
        schema_root=schema_root,
    )
    target = _mapping(expected_manifest["target"])
    distribution = LinuxDistribution(str(target["distribution"]))
    adapter = linux_adapter_for(distribution)
    criteria_snapshot = _mapping(expected_manifest["criteria_snapshot"])
    values = _mapping(criteria_snapshot["values"])
    criteria_body: dict[str, JsonValue] = {
        "benchmark_id": str(criteria_snapshot["benchmark_id"]),
        "benchmark_version": str(criteria_snapshot["benchmark_version"]),
        "values": cast(dict[str, JsonValue], dict(values)),
    }
    criteria_sha256 = canonical_sha256(criteria_body)
    if criteria_sha256 != criteria_snapshot["sha256"]:
        _reject(
            PackageValidationCode.MANIFEST_HASH_MISMATCH,
            "Linux criteria snapshot hash is invalid.",
        )
    profile = KisaUnixAssessmentProfile.from_values(dict(values))
    controls = evaluate_kisa_unix(
        outputs,
        captured_at=context.received_at,
        distribution=distribution,
        profile=profile,
    )
    host = _mapping(descriptor["host"])
    result = enrich_linux_audit_history_result(
        DeviceAuditResult(
            schema_version="1.0.0",
            run_id=UUID(context.job_id),
            asset=AssetContext(
                asset_id=UUID(context.asset_id),
                asset_type="LINUX_SERVER",
                platform="LINUX",
                platform_version=str(host["version_id"]),
                vendor=adapter.vendor,
                product_family=adapter.display_name,
            ),
            benchmark_id="KISA-2026-UNIX-U01-U67",
            benchmark_version="2026-DRAFT",
            criteria_profile_id=None,
            criteria_sha256=criteria_sha256,
            started_at=datetime.fromisoformat(
                str(expected_manifest["issued_at"]).replace("Z", "+00:00")
            ),
            completed_at=context.received_at,
            controls=controls,
            criteria_summary={
                "name": "KISA·SecAI Linux 자가 점검 기준",
                "source": "SELF_SCAN_DRAFT",
                "values": cast(JsonValue, dict(values)),
                "review_display": "CHECK_REQUIRED",
                "official_certification": False,
            },
        ).to_json()
    )
    authentication = _mapping(descriptor["authentication"])
    return ProcessedLinuxOneShotPackage(
        validated_package=validated,
        result_json=result,
        evidence=evidence,
        assurance_level=str(authentication["assurance_level"]),
        submission_profile=str(authentication["profile"]),
    )
