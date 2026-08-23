"""결정론적 Linux Evidence ZIP과 분리된 Package descriptor 생성."""

from __future__ import annotations

import copy
import os
import shutil
import stat
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid5
from zipfile import ZIP_STORED, ZipFile, ZipInfo

from security_audit.analysis.package_validation import inspect_package_archive
from security_audit.common.canonical_json import JsonValue, canonicalize_json

from .linux_local import LinuxProbeOutcome


@dataclass(frozen=True, slots=True)
class BuiltLinuxAuditPackage:
    archive_path: Path
    descriptor: dict[str, Any]
    descriptor_bytes: bytes


def _utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Package timestamps must be timezone-aware.")
    return value.isoformat().replace("+00:00", "Z")


def _member_info(path: str) -> ZipInfo:
    info = ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


def _evidence_document(
    outcome: LinuxProbeOutcome,
    *,
    evidence_id: UUID,
    collected_at: datetime,
) -> dict[str, JsonValue]:
    normalized_value = (
        outcome.normalized_value if outcome.collection_status == "COLLECTED" else ""
    )
    return {
        "schema_version": "2.0.0",
        "evidence_id": str(evidence_id),
        "probe_id": outcome.probe_id,
        "probe_version": outcome.probe_version,
        "control_ids": list(outcome.control_ids),
        "collected_at": _utc(collected_at),
        "required_privilege": outcome.required_privilege,
        "executed_privilege": outcome.executed_privilege,
        "collection_status": outcome.collection_status,
        "error_code": outcome.error_code,
        "exit_code": outcome.exit_code,
        "raw_output_sha256": outcome.raw_output_sha256,
        "normalized_sha256": outcome.normalized_sha256,
        "redaction_applied": outcome.redaction_applied,
        "normalized_value": normalized_value,
    }


def _write_deterministic_zip(path: Path, members: Mapping[str, bytes]) -> None:
    with path.open("xb") as stream, ZipFile(stream, "w", compression=ZIP_STORED) as archive:
        for member_path in sorted(members):
            archive.writestr(_member_info(member_path), members[member_path])


def build_linux_audit_package(
    *,
    manifest: Mapping[str, Any],
    outcomes: Sequence[LinuxProbeOutcome],
    archive_path: Path,
    package_id: UUID,
    collected_at: datetime,
    build_sha256: str,
    host_version: str,
    authentication: Mapping[str, JsonValue],
) -> BuiltLinuxAuditPackage:
    """새 출력 파일에만 쓰며 token·private key를 입력으로 받지 않습니다."""

    if archive_path.exists():
        raise FileExistsError(str(archive_path))
    if len(build_sha256) != 64:
        raise ValueError("build_sha256 must be a SHA-256 digest.")
    attempt_id = UUID(str(manifest["execution_attempt_id"]))
    manifest_bytes = canonicalize_json(cast(JsonValue, dict(manifest)))
    members: dict[str, bytes] = {"collector_manifest.json": manifest_bytes}
    evidence_records: list[dict[str, JsonValue]] = []
    seen_probe_ids: set[str] = set()
    for outcome in outcomes:
        if outcome.probe_id in seen_probe_ids:
            raise ValueError("A Probe outcome is duplicated.")
        seen_probe_ids.add(outcome.probe_id)
        evidence_id = uuid5(attempt_id, outcome.probe_id)
        directory = "evidence" if outcome.collection_status == "COLLECTED" else "errors"
        member_path = f"{directory}/{evidence_id}.json"
        evidence_bytes = canonicalize_json(
            _evidence_document(
                outcome,
                evidence_id=evidence_id,
                collected_at=collected_at,
            )
        )
        members[member_path] = evidence_bytes
        from hashlib import sha256

        evidence_sha256 = sha256(evidence_bytes).hexdigest()
        evidence_records.append(
            {
                "evidence_id": str(evidence_id),
                "probe_id": outcome.probe_id,
                "probe_version": outcome.probe_version,
                "control_ids": list(outcome.control_ids),
                "required_privilege": outcome.required_privilege,
                "collection_status": outcome.collection_status,
                "error_code": outcome.error_code,
                "member_path": member_path,
                "output_sha256": outcome.raw_output_sha256,
                "evidence_sha256": evidence_sha256,
                "redacted": outcome.redaction_applied,
            }
        )

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="secai-linux-package-") as temporary:
        temporary_root = Path(temporary)
        os.chmod(temporary_root, 0o700)
        staged_archive = temporary_root / "payload.zip"
        _write_deterministic_zip(staged_archive, members)
        with staged_archive.open("rb") as source, archive_path.open("xb") as destination:
            shutil.copyfileobj(source, destination, length=64 * 1024)
        os.chmod(archive_path, 0o600)

    inspection = inspect_package_archive(archive_path)
    inventory = [
        {
            "path": item.path,
            "media_type": "application/json",
            "size_bytes": item.size_bytes,
            "sha256": item.sha256,
        }
        for item in inspection.files
    ]
    target = cast(Mapping[str, object], manifest["target"])
    constraint = cast(Mapping[str, object], manifest["collector_constraint"])
    descriptor: dict[str, JsonValue] = {
        "schema_version": "2.0.0",
        "profile": "LINUX-ONESHOT-PACKAGE-V2",
        "id": str(package_id),
        "created_at": _utc(collected_at),
        "source": "collector",
        "producer_name": "sec-ai-linux-one-shot",
        "producer_version": "0.1.0",
        "correlation_id": str(manifest["correlation_id"]),
        "organization_id": str(manifest["organization_id"]),
        "subject_user_id": str(manifest["subject_user_id"]),
        "job_id": str(manifest["job_id"]),
        "asset_id": str(manifest["asset_id"]),
        "manifest_id": str(manifest["id"]),
        "manifest_hash": str(manifest["manifest_content_sha256"]),
        "nonce": str(manifest["nonce"]),
        "execution_attempt_id": str(manifest["execution_attempt_id"]),
        "issued_at": str(manifest["issued_at"]),
        "expires_at": str(manifest["expires_at"]),
        "collector": {
            "name": "sec-ai-linux-one-shot",
            "version": "0.1.0",
            "build_sha256": build_sha256,
            "probe_bundle_sha256": str(constraint["probe_bundle_sha256"]),
            "release_channel": str(constraint["release_channel"]),
        },
        "host": {
            "os_family": "LINUX",
            "distribution": str(target["distribution"]),
            "version_id": host_version,
            "architecture": "x86_64",
            "timezone": "UTC",
            "clock_status": "UNKNOWN",
        },
        "archive": {
            "format": "ZIP-STORED-OR-DEFLATE",
            "archive_sha256": inspection.archive_sha256,
            "content_set_sha256": inspection.content_set_sha256,
            "compressed_bytes": inspection.compressed_bytes,
            "uncompressed_bytes": inspection.uncompressed_bytes,
            "file_count": inspection.file_count,
        },
        "file_inventory": cast(list[JsonValue], inventory),
        "evidence_records": cast(list[JsonValue], evidence_records),
        "authentication": cast(dict[str, JsonValue], dict(authentication)),
    }
    descriptor_bytes = canonicalize_json(descriptor)
    return BuiltLinuxAuditPackage(
        archive_path=archive_path,
        descriptor=cast(dict[str, Any], descriptor),
        descriptor_bytes=descriptor_bytes,
    )


def write_linux_offline_descriptor(
    package: BuiltLinuxAuditPackage,
    descriptor_path: Path,
) -> Path:
    """오프라인 제출용 descriptor도 기존 파일을 덮어쓰지 않습니다."""

    with descriptor_path.open("xb") as stream:
        stream.write(package.descriptor_bytes)
    os.chmod(descriptor_path, 0o600)
    return descriptor_path


def replace_linux_package_authentication(
    package: BuiltLinuxAuditPackage,
    authentication: Mapping[str, JsonValue],
) -> BuiltLinuxAuditPackage:
    """Detached descriptor의 제출 보증만 바꾸며 Evidence ZIP은 변경하지 않습니다."""

    descriptor = copy.deepcopy(package.descriptor)
    descriptor["authentication"] = dict(authentication)
    descriptor_bytes = canonicalize_json(cast(JsonValue, descriptor))
    return BuiltLinuxAuditPackage(
        archive_path=package.archive_path,
        descriptor=descriptor,
        descriptor_bytes=descriptor_bytes,
    )
