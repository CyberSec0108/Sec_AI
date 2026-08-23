"""IMP-019 localhost-only synthetic Package to Finding application pipeline."""

from __future__ import annotations

import base64
import copy
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast
from uuid import UUID, uuid5
from zipfile import ZIP_DEFLATED, ZipFile

from security_audit.analysis.finding import FindingBuildContext, FindingBuilder
from security_audit.analysis.normalization import EvidenceNormalizer
from security_audit.analysis.package_validation import (
    DigestVerification,
    ExternalVerificationStatus,
    FullPackageValidator,
    MalwareScanStatus,
    MalwareScanVerification,
    NonceVerification,
    NonceVerificationStatus,
    PackageAuthenticationKind,
    PackageAuthenticationVerification,
    PackageGateVerifications,
    PackageSchemaCatalog,
    PackageValidationCode,
    PackageValidationContext,
    PackageValidationError,
    StagedObjectVerification,
    inspect_package_archive,
    load_strict_json,
)
from security_audit.analysis.rule_engine import RuleRegistry
from security_audit.common.canonical_json import JsonValue, canonical_sha256_without_fields

DEMO_ORGANIZATION_ID = "70000000-0000-4000-8000-000000000001"
DEMO_EVALUATION_AS_OF = "2026-07-22T08:00:00Z"
DEMO_EVALUATED_AT = "2026-07-22T09:00:00Z"
DEMO_ENGINE_ARTIFACT_SHA256 = "a" * 64
_RECEIVED_AT = datetime(2026, 7, 22, 8, 0, 30, tzinfo=UTC)
_NORMALIZED_AT = datetime(2026, 7, 22, 8, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class DemoCase:
    id: str
    label: str
    description: str
    expected_status: str


DEMO_CASES = (
    DemoCase(
        "pc07-pass",
        "양호 상태 점검",
        "모든 점검 대상 저장 장치가 NTFS인 경우입니다.",
        "PASS",
    ),
    DemoCase(
        "pc07-fail-fat32",
        "취약 상태 점검",
        "데이터 저장 장치에 FAT32가 포함된 경우입니다.",
        "FAIL",
    ),
    DemoCase(
        "pc07-error-collection",
        "정보 수집 오류 점검",
        "필수 저장 장치 정보를 가져오지 못한 경우입니다.",
        "ERROR",
    ),
)
_CASE_BY_ID = {item.id: item for item in DEMO_CASES}


@dataclass(frozen=True, slots=True)
class DemoEvaluation:
    case_id: str
    organization_id: str
    package_id: str
    job_id: str
    asset_id: str
    package_validated: bool
    normalized_evidence_count: int
    finding: dict[str, JsonValue]


def _load_object(path: Path) -> dict[str, Any]:
    value = load_strict_json(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object.")
    return cast(dict[str, Any], value)


def _compact_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _nonce(case_id: str) -> str:
    digest = sha256(case_id.encode("utf-8")).digest()[:16]
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _uuid_child(parent: str, name: str) -> str:
    return str(uuid5(UUID(parent), name))


@dataclass(frozen=True, slots=True)
class _SyntheticPackage:
    archive_path: Path
    descriptor: dict[str, Any]
    manifest: dict[str, Any]
    context: PackageValidationContext
    verifications: PackageGateVerifications

    @property
    def descriptor_bytes(self) -> bytes:
        return _compact_bytes(self.descriptor)


class SyntheticPc07Pipeline:
    """Run three fixed non-identifying fixtures through the real pure pipeline."""

    def __init__(self, project_root: Path) -> None:
        self._root = project_root
        self._schema_root = project_root / "database" / "schemas"
        self._fixture_root = project_root / "audit_packs" / "kisa_2026_pc" / "fixtures"
        self._pack_path = project_root / "audit_packs" / "kisa_2026_pc" / "src" / "pack.json"

    def evaluate(self, case_id: str) -> DemoEvaluation:
        if case_id not in _CASE_BY_ID:
            raise ValueError("Synthetic demo case is not allowlisted.")
        input_document = _load_object(
            self._fixture_root / "pc07" / "input" / f"{case_id}.json"
        )
        expected = _load_object(
            self._fixture_root / "pc07" / "expected" / f"{case_id}.json"
        )
        with TemporaryDirectory(prefix="secai-imp019-") as temp_directory:
            package = self._build_package(
                case_id,
                input_document,
                Path(temp_directory),
            )
            validated = FullPackageValidator(self._schema_root).validate(
                package.archive_path,
                package.descriptor_bytes,
                package.manifest,
                package.context,
                package.verifications,
            )
            evidence = EvidenceNormalizer(self._schema_root).normalize(
                validated,
                package.descriptor_bytes,
                normalized_at=_NORMALIZED_AT,
            )

        pack = _load_object(self._pack_path)
        controls = cast(list[dict[str, Any]], pack["controls"])
        if len(controls) != 1:
            raise ValueError("PC-07 demo Pack must contain exactly one Control.")
        control = controls[0]
        decision = RuleRegistry().evaluate(
            control_id="PC-07",
            applicability_rule=cast(dict[str, Any], control["applicability_rule"]),
            evaluation_rule=cast(dict[str, Any], control["evaluation_rule"]),
            evidence=cast(tuple[Mapping[str, object], ...], evidence),
        )
        finding = FindingBuilder(PackageSchemaCatalog(self._schema_root)).build(
            pack=pack,
            control_id="PC-07",
            evidence=evidence,
            decision=decision,
            context=FindingBuildContext(
                organization_id=DEMO_ORGANIZATION_ID,
                evaluation_as_of=DEMO_EVALUATION_AS_OF,
                evaluated_at=DEMO_EVALUATED_AT,
                engine_version="0.1.0",
                engine_artifact_sha256=DEMO_ENGINE_ARTIFACT_SHA256,
            ),
            allow_draft=True,
        )
        if finding["status"] != expected["expected_status"]:
            raise ValueError("Synthetic Package result differs from the approved fixture oracle.")
        return DemoEvaluation(
            case_id=case_id,
            organization_id=DEMO_ORGANIZATION_ID,
            package_id=validated.package_id,
            job_id=validated.job_id,
            asset_id=validated.asset_id,
            package_validated=validated.eligible_for_original_promotion,
            normalized_evidence_count=len(evidence),
            finding=finding,
        )

    def verify_archive_tamper_rejected(self, case_id: str) -> PackageValidationCode:
        """Prove that a fixed demo archive hash change is rejected before evaluation."""
        if case_id not in _CASE_BY_ID:
            raise ValueError("Synthetic demo case is not allowlisted.")
        input_document = _load_object(
            self._fixture_root / "pc07" / "input" / f"{case_id}.json"
        )
        with TemporaryDirectory(prefix="secai-imp020-tamper-") as temp_directory:
            package = self._build_package(
                case_id,
                input_document,
                Path(temp_directory),
            )
            tampered_descriptor = copy.deepcopy(package.descriptor)
            archive = cast(dict[str, Any], tampered_descriptor["archive"])
            archive["archive_sha256"] = "0" * 64
            try:
                FullPackageValidator(self._schema_root).validate(
                    package.archive_path,
                    _compact_bytes(tampered_descriptor),
                    package.manifest,
                    package.context,
                    package.verifications,
                )
            except PackageValidationError as exc:
                return exc.code
        raise AssertionError("Tampered synthetic Package was unexpectedly accepted.")

    def _build_package(
        self,
        case_id: str,
        input_document: Mapping[str, Any],
        output_directory: Path,
    ) -> _SyntheticPackage:
        evidence = cast(list[dict[str, Any]], input_document["evidence"])
        first = evidence[0]
        package_id = cast(str, first["package_id"])
        job_id = cast(str, first["job_id"])
        asset_id = cast(str, first["asset_id"])
        correlation_id = cast(str, first["correlation_id"])
        manifest_id = _uuid_child(package_id, "imp019-manifest")
        nonce = _nonce(case_id)
        synthetic = input_document.get("synthetic") is True
        if synthetic:
            package_created_at = datetime(2026, 7, 22, 8, 0, tzinfo=UTC)
        else:
            collected_at = cast(str, first["collected_at"])
            package_created_at = datetime.fromisoformat(
                collected_at.removesuffix("Z") + "+00:00"
            )
        manifest_issued_at = package_created_at - timedelta(minutes=1)
        manifest_expires_at = package_created_at + timedelta(minutes=30)
        package_expires_at = package_created_at + timedelta(minutes=20)
        received_at = package_created_at + timedelta(seconds=30)

        def timestamp(value: datetime) -> str:
            return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

        manifest = _load_object(
            self._schema_root / "examples" / "valid" / "collector_manifest.json"
        )
        manifest.update(
            {
                "id": manifest_id,
                "created_at": timestamp(manifest_issued_at),
                "correlation_id": correlation_id,
                "job_id": job_id,
                "asset_id": asset_id,
                "nonce": nonce,
                "issued_at": timestamp(manifest_issued_at),
                "expires_at": timestamp(manifest_expires_at),
            }
        )
        manifest["collector_constraint"].update(
            {
                "min_version": "0.1.0",
                "max_version_exclusive": "0.2.0",
                "release_channel": "DEV-UNTRUSTED",
            }
        )
        probe_keys = sorted(
            {(cast(str, item["probe_id"]), cast(str, item["probe_version"])) for item in evidence}
        )
        manifest["probes"] = [
            {
                "probe_id": probe_id,
                "probe_version": probe_version,
                "control_ids": sorted(
                    {
                        cast(str, item["control_id"])
                        for item in evidence
                        if item["probe_id"] == probe_id
                    }
                ),
                "required_privilege": cast(
                    str,
                    cast(
                        Mapping[str, object],
                        next(
                            (
                                item.get("execution_identity")
                                for item in evidence
                                if item["probe_id"] == probe_id
                                and isinstance(item.get("execution_identity"), Mapping)
                            ),
                            {"privilege": "STANDARD_USER"},
                        ),
                    ).get("privilege", "STANDARD_USER"),
                ),
                "timeout_seconds": 30,
                "max_output_bytes": 1048576,
                "parameters": {"synthetic": synthetic},
            }
            for probe_id, probe_version in probe_keys
        ]
        manifest_hash = canonical_sha256_without_fields(
            cast(dict[str, JsonValue], manifest),
            {"manifest_content_sha256", "authorization"},
        )
        manifest["manifest_content_sha256"] = manifest_hash
        manifest["authorization"]["signature"]["signed_sha256"] = manifest_hash
        manifest_bytes = _compact_bytes(manifest)

        descriptor = _load_object(
            self._schema_root / "examples" / "valid" / "audit_package.json"
        )
        descriptor.update(
            {
                "id": package_id,
                "created_at": timestamp(package_created_at),
                "correlation_id": correlation_id,
                "job_id": job_id,
                "asset_id": asset_id,
                "manifest_id": manifest_id,
                "manifest_hash": manifest_hash,
                "nonce": nonce,
                "issued_at": timestamp(package_created_at),
                "expires_at": timestamp(package_expires_at),
                "execution_attempt_id": _uuid_child(package_id, "imp019-attempt"),
            }
        )
        descriptor["collector"].update(
            {
                "version": "0.1.0",
                "probe_bundle_version": "0.1.0",
                "release_channel": "DEV-UNTRUSTED",
            }
        )
        if isinstance(input_document.get("host"), Mapping):
            descriptor["host"] = copy.deepcopy(input_document["host"])
        descriptor["authentication"] = {
            "profile": "ONLINE-AUTHENTICATED",
            "assurance_level": "HIGH",
            "authenticated_subject_id": _uuid_child(package_id, "imp019-subject"),
            "transport_receipt_id": _uuid_child(package_id, "imp019-receipt"),
        }

        archive_path = output_directory / "payload.zip"
        records: list[dict[str, Any]] = []
        with ZipFile(archive_path, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr("collector_manifest.json", manifest_bytes)
            for item in evidence:
                record = self._evidence_record(item)
                member_directory = (
                    "evidence" if record["collection_status"] == "COLLECTED" else "errors"
                )
                member_path = f"{member_directory}/{record['evidence_id']}.json"
                member_bytes = _compact_bytes(
                    {
                        "synthetic": synthetic,
                        "case_id": case_id,
                        "raw_value": record.get("raw_value"),
                        "error_code": record["error_code"],
                    }
                )
                record["evidence_sha256"] = sha256(member_bytes).hexdigest()
                archive.writestr(member_path, member_bytes)
                records.append(record)

        inspection = inspect_package_archive(archive_path)
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
                "path": item.path,
                "media_type": "application/json",
                "size_bytes": item.size_bytes,
                "sha256": item.sha256,
            }
            for item in inspection.files
        ]
        descriptor["evidence_records"] = records
        context = PackageValidationContext(
            organization_id=DEMO_ORGANIZATION_ID,
            asset_id=asset_id,
            job_id=job_id,
            endpoint_id=cast(str, manifest["submission"]["endpoint_id"]),
            received_at=_RECEIVED_AT if synthetic else received_at,
        )
        verifications = PackageGateVerifications(
            manifest_signature=DigestVerification(
                ExternalVerificationStatus.VERIFIED,
                manifest_hash,
            ),
            nonce=NonceVerification(NonceVerificationStatus.FRESH_RESERVED, nonce),
            package_authentication=PackageAuthenticationVerification(
                ExternalVerificationStatus.VERIFIED,
                PackageAuthenticationKind.ONLINE_TRANSPORT,
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
                DEMO_ORGANIZATION_ID,
                asset_id,
                job_id,
                inspection.archive_sha256,
                inspection.compressed_bytes,
            ),
        )
        return _SyntheticPackage(archive_path, descriptor, manifest, context, verifications)

    @staticmethod
    def _evidence_record(item: Mapping[str, Any]) -> dict[str, Any]:
        record: dict[str, Any] = {
            "evidence_id": item["source_evidence_id"],
            "control_id": item["control_id"],
            "guide_version": item["guide_version"],
            "probe_id": item["probe_id"],
            "probe_version": item["probe_version"],
            "collected_at": item["collected_at"],
            "execution_identity": copy.deepcopy(
                item.get(
                    "execution_identity",
                    {
                        "privilege": "STANDARD_USER",
                        "elevated": False,
                    },
                )
            ),
            "source_locator": copy.deepcopy(item["source_locator"]),
            "collection_status": item["collection_status"],
            "error_code": item["error_code"],
            "redacted": cast(dict[str, Any], item["redaction"])["applied"],
            "evidence_sha256": "0" * 64,
        }
        if item.get("normalized_value") is not None:
            record["raw_value"] = copy.deepcopy(item["normalized_value"])
        else:
            subject = cast(Mapping[str, Any], item["subject"])
            if subject.get("scope") == "VOLUME":
                record["normalized_candidate"] = {
                    "volume_id": subject["subject_key"]
                }
            elif subject.get("scope") == "USER":
                record["normalized_candidate"] = {
                    "user_sid": subject["user_sid"]
                }
            else:
                record["normalized_candidate"] = {
                    "scope": subject["scope"]
                }
        for optional in ("unit", "policy_scope", "policy_source"):
            if item.get(optional) is not None:
                record[optional] = item[optional]
        return record
