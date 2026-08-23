"""Linux Collector artifact의 hash·Ed25519·SBOM·보안 Gate 계약."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ReleaseSigner = Callable[[bytes], tuple[str, bytes]]
_SIGNED_CHANNELS = {"SIGNED-PILOT", "SIGNED-PRODUCTION"}
_EXPECTED_FILENAMES = {
    "AUTO_X86_64": "secai-linux-check-x86_64",
    "UBUNTU_24_04": "secai-linux-check-ubuntu24-x86_64",
    "ROCKY_9": "secai-linux-check-rocky9-x86_64",
}


class LinuxReleaseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class LinuxReleaseVerification:
    download_allowed: bool
    artifact_count: int
    errors: tuple[str, ...]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Release timestamp must be timezone-aware.")
    return value.isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _signature_record(
    *,
    digest: str,
    sign: ReleaseSigner,
) -> dict[str, str]:
    key_id, value = sign(bytes.fromhex(digest))
    return {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "signed_sha256": digest,
        "value": base64.urlsafe_b64encode(value).decode("ascii").rstrip("="),
    }


def build_linux_release_manifest(
    *,
    artifacts: Mapping[str, Path],
    sbom_path: Path,
    third_party_notice_path: Path,
    vex_path: Path,
    version: str,
    release_channel: str,
    source_revision: str,
    lock_sha256: str,
    build_image_digest: str,
    created_at: datetime,
    sign: ReleaseSigner | None,
    dependency_scan: str,
    os_package_scan: str,
    malware_scan: str,
    lock_path: str = "requirements/lock/collector-build.lock",
    revoked_sha256: tuple[str, ...] = (),
    rollback_version: str | None = None,
) -> dict[str, Any]:
    if set(artifacts) != set(_EXPECTED_FILENAMES):
        raise LinuxReleaseError("All approved Linux artifacts are required.")
    if release_channel in _SIGNED_CHANNELS and sign is None:
        raise LinuxReleaseError("A signed channel requires an external Ed25519 signer.")
    artifact_items: list[dict[str, Any]] = []
    for distribution in sorted(artifacts):
        path = artifacts[distribution]
        if path.name != _EXPECTED_FILENAMES[distribution] or not path.is_file():
            raise LinuxReleaseError("Linux artifact filename or path is invalid.")
        digest = _sha256(path)
        signature: dict[str, str] | None = None
        if sign is not None:
            signature = _signature_record(digest=digest, sign=sign)
        artifact_items.append(
            {
                "distribution": distribution,
                "architecture": "x86_64",
                "filename": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": digest,
                "signature": signature,
            }
        )
    sbom_sha256 = _sha256(sbom_path)
    if not vex_path.is_file():
        raise LinuxReleaseError("The Linux release VEX document is missing.")
    gates_passed = (
        release_channel in _SIGNED_CHANNELS
        and sign is not None
        and dependency_scan == "PASS"
        and os_package_scan == "PASS"
        and malware_scan == "CLEAN"
    )
    manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "profile": "SECAI-LINUX-COLLECTOR-RELEASE-V1",
        "version": version,
        "release_channel": release_channel,
        "created_at": _utc(created_at),
        "source_revision": source_revision,
        "lock": {
            "path": lock_path,
            "sha256": lock_sha256,
        },
        "build_image_digest": build_image_digest,
        "artifacts": artifact_items,
        "sbom": {"filename": sbom_path.name, "sha256": sbom_sha256},
        "vex": {"filename": vex_path.name, "sha256": _sha256(vex_path)},
        "third_party_notice": {
            "filename": third_party_notice_path.name,
            "sha256": _sha256(third_party_notice_path),
        },
        "security_gates": {
            "dependency_scan": dependency_scan,
            "os_package_scan": os_package_scan,
            "malware_scan": malware_scan,
        },
        "revoked_sha256": list(revoked_sha256),
        "rollback_version": rollback_version,
        "download_allowed": gates_passed,
    }
    manifest_digest = hashlib.sha256(_canonical_bytes(manifest)).hexdigest()
    manifest["manifest_signature"] = (
        _signature_record(digest=manifest_digest, sign=sign) if sign is not None else None
    )
    return manifest


def _verify_signature(
    *,
    signature: object,
    digest: str,
    public_keys: Mapping[str, Ed25519PublicKey],
) -> bool:
    if not isinstance(signature, Mapping):
        return False
    key_id = str(signature.get("key_id", ""))
    key = public_keys.get(key_id)
    if (
        key is None
        or signature.get("algorithm") != "Ed25519"
        or signature.get("signed_sha256") != digest
    ):
        return False
    try:
        value = str(signature.get("value", ""))
        decoded = base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
        key.verify(decoded, bytes.fromhex(digest))
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_linux_release_manifest(
    manifest: Mapping[str, Any],
    *,
    artifact_root: Path,
    public_keys: Mapping[str, Ed25519PublicKey],
    fail_closed: bool = False,
) -> LinuxReleaseVerification:
    errors: list[str] = []
    if manifest.get("schema_version") != "1.0.0" or manifest.get(
        "profile"
    ) != "SECAI-LINUX-COLLECTOR-RELEASE-V1":
        errors.append("RELEASE_SCHEMA_INVALID")
    channel = str(manifest.get("release_channel", ""))
    if channel not in _SIGNED_CHANNELS:
        errors.append("RELEASE_CHANNEL_NOT_SIGNED")
    signed_manifest = dict(manifest)
    manifest_signature = signed_manifest.pop("manifest_signature", None)
    manifest_digest = hashlib.sha256(_canonical_bytes(signed_manifest)).hexdigest()
    if not _verify_signature(
        signature=manifest_signature,
        digest=manifest_digest,
        public_keys=public_keys,
    ):
        errors.append("MANIFEST_SIGNATURE_INVALID")
    gates = manifest.get("security_gates")
    if not isinstance(gates, Mapping) or (
        gates.get("dependency_scan") != "PASS"
        or gates.get("os_package_scan") != "PASS"
        or gates.get("malware_scan") != "CLEAN"
    ):
        errors.append("SECURITY_GATES_INCOMPLETE")
    revoked = set(manifest.get("revoked_sha256", []))
    raw_artifacts = manifest.get("artifacts")
    artifact_items = raw_artifacts if isinstance(raw_artifacts, list) else []
    seen_distributions: set[str] = set()
    for raw_item in artifact_items:
        if not isinstance(raw_item, Mapping):
            errors.append("ARTIFACT_RECORD_INVALID")
            continue
        distribution = str(raw_item.get("distribution", ""))
        filename = str(raw_item.get("filename", ""))
        if (
            distribution not in _EXPECTED_FILENAMES
            or filename != _EXPECTED_FILENAMES[distribution]
            or distribution in seen_distributions
        ):
            errors.append("ARTIFACT_SCOPE_INVALID")
            continue
        seen_distributions.add(distribution)
        path = artifact_root / filename
        if not path.is_file() or path.parent.resolve() != artifact_root.resolve():
            errors.append("ARTIFACT_MISSING")
            continue
        digest = _sha256(path)
        if raw_item.get("sha256") != digest or raw_item.get("size_bytes") != path.stat().st_size:
            errors.append("ARTIFACT_HASH_MISMATCH")
            continue
        if digest in revoked:
            errors.append("ARTIFACT_REVOKED")
        signature = raw_item.get("signature")
        if not isinstance(signature, Mapping):
            errors.append("ARTIFACT_SIGNATURE_MISSING")
            continue
        if not _verify_signature(
            signature=signature,
            digest=digest,
            public_keys=public_keys,
        ):
            errors.append("ARTIFACT_SIGNATURE_INVALID")
    if seen_distributions != set(_EXPECTED_FILENAMES):
        errors.append("ARTIFACT_SET_INCOMPLETE")
    sbom = manifest.get("sbom")
    if isinstance(sbom, Mapping):
        sbom_path = artifact_root / str(sbom.get("filename", ""))
        if (
            not sbom_path.is_file()
            or sbom_path.parent.resolve() != artifact_root.resolve()
            or _sha256(sbom_path) != sbom.get("sha256")
        ):
            errors.append("SBOM_INVALID")
    else:
        errors.append("SBOM_INVALID")
    vex = manifest.get("vex")
    if isinstance(vex, Mapping):
        vex_path = artifact_root / str(vex.get("filename", ""))
        if (
            not vex_path.is_file()
            or vex_path.parent.resolve() != artifact_root.resolve()
            or _sha256(vex_path) != vex.get("sha256")
        ):
            errors.append("VEX_INVALID")
    else:
        errors.append("VEX_INVALID")
    notice = manifest.get("third_party_notice")
    if isinstance(notice, Mapping):
        notice_path = artifact_root / str(notice.get("filename", ""))
        if (
            not notice_path.is_file()
            or notice_path.parent.resolve() != artifact_root.resolve()
            or _sha256(notice_path) != notice.get("sha256")
        ):
            errors.append("THIRD_PARTY_NOTICE_INVALID")
    else:
        errors.append("THIRD_PARTY_NOTICE_INVALID")
    if manifest.get("download_allowed") is not True:
        errors.append("MANIFEST_DOWNLOAD_DISABLED")
    report = LinuxReleaseVerification(
        download_allowed=not errors,
        artifact_count=len(artifact_items),
        errors=tuple(dict.fromkeys(errors)),
    )
    if fail_closed and errors:
        raise LinuxReleaseError("Linux release verification failed.")
    return report
