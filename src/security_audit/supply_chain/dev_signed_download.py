"""개발시험용 Windows·Linux 서명 배포와 일회용 다운로드 코드 계약."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CATALOG_PROFILE = "SECAI-DEV-SIGNED-DOWNLOAD-V1"
RELEASE_CHANNEL = "DEV-SIGNED-TEST"
TRUST_PROFILE = "SECAI-DEV-DOWNLOAD-TRUST-V1"
ACTIVE_POINTER_NAME = "active-release.json"
CATALOG_NAME = "dev-signed-download-catalog.json"
TRUST_NAME = "dev-download-public-key.json"
MAX_CATALOG_LIFETIME = timedelta(days=100)
DOWNLOAD_CODE_TTL = timedelta(minutes=10)
MAX_DOWNLOAD_CODE_TTL = timedelta(minutes=15)
MAX_DOWNLOAD_CODE_ATTEMPTS = 5
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_RELEASE_DIRECTORY = re.compile(r"^release-[0-9]{8}T[0-9]{6}Z$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

ReleaseSigner = Callable[[bytes], tuple[str, bytes]]


class DevArtifactPlatform(StrEnum):
    WINDOWS_X64 = "WINDOWS_X64"
    LINUX_AUTO_X64 = "LINUX_AUTO_X64"
    UBUNTU_24_04_X64 = "UBUNTU_24_04_X64"
    ROCKY_9_X64 = "ROCKY_9_X64"


_FILENAMES: Mapping[DevArtifactPlatform, str] = {
    DevArtifactPlatform.WINDOWS_X64: "SecAI-Collector-Windows-x64.exe",
    DevArtifactPlatform.LINUX_AUTO_X64: "secai-linux-check-x86_64",
    DevArtifactPlatform.UBUNTU_24_04_X64: (
        "secai-linux-check-ubuntu24-x86_64"
    ),
    DevArtifactPlatform.ROCKY_9_X64: "secai-linux-check-rocky9-x86_64",
}
_MEDIA_TYPES: Mapping[DevArtifactPlatform, str] = {
    DevArtifactPlatform.WINDOWS_X64: "application/vnd.microsoft.portable-executable",
    DevArtifactPlatform.LINUX_AUTO_X64: "application/octet-stream",
    DevArtifactPlatform.UBUNTU_24_04_X64: "application/octet-stream",
    DevArtifactPlatform.ROCKY_9_X64: "application/octet-stream",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _utc(value: datetime) -> str:
    _aware(value)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware.")


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("UTC timestamp is required.")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _aware(parsed)
    return parsed.astimezone(UTC)


def _signature_record(
    *,
    digest: str,
    sign: ReleaseSigner,
) -> dict[str, str]:
    key_id, signature = sign(bytes.fromhex(digest))
    if not key_id or len(key_id) > 128:
        raise ValueError("Development signing key ID is invalid.")
    return {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "signed_sha256": digest,
        "value": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def _verify_signature(
    *,
    signature: object,
    digest: str,
    public_keys: Mapping[str, Ed25519PublicKey],
) -> tuple[bool, str | None]:
    if not isinstance(signature, Mapping):
        return False, None
    key_id = signature.get("key_id")
    if not isinstance(key_id, str):
        return False, None
    key = public_keys.get(key_id)
    if (
        key is None
        or signature.get("algorithm") != "Ed25519"
        or signature.get("signed_sha256") != digest
    ):
        return False, key_id
    try:
        value = str(signature.get("value", ""))
        decoded = base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
        key.verify(decoded, bytes.fromhex(digest))
    except (InvalidSignature, ValueError):
        return False, key_id
    return True, key_id


def build_dev_signed_catalog(
    *,
    artifacts: Mapping[DevArtifactPlatform, Path],
    created_at: datetime,
    expires_at: datetime,
    sign: ReleaseSigner,
    provenance: Mapping[DevArtifactPlatform, Mapping[str, object]],
) -> dict[str, object]:
    _aware(created_at)
    _aware(expires_at)
    if (
        expires_at <= created_at
        or expires_at - created_at > MAX_CATALOG_LIFETIME
    ):
        raise ValueError("Development catalog lifetime is invalid.")
    if set(artifacts) != set(DevArtifactPlatform) or set(provenance) != set(
        DevArtifactPlatform
    ):
        raise ValueError("Windows and all approved Linux artifacts are required.")

    items: list[dict[str, object]] = []
    for platform in DevArtifactPlatform:
        path = artifacts[platform]
        if path.name != _FILENAMES[platform] or not path.is_file():
            raise ValueError("Development artifact filename or path is invalid.")
        digest = sha256_file(path)
        source = dict(provenance[platform])
        if source.get("security_gates") != "PASS":
            raise ValueError("Upstream artifact security gates did not pass.")
        items.append(
            {
                "platform": platform.value,
                "filename": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": digest,
                "media_type": _MEDIA_TYPES[platform],
                "signature": _signature_record(digest=digest, sign=sign),
                "provenance": source,
            }
        )

    catalog: dict[str, object] = {
        "schema_version": "1.0.0",
        "profile": CATALOG_PROFILE,
        "release_channel": RELEASE_CHANNEL,
        "created_at": _utc(created_at),
        "expires_at": _utc(expires_at),
        "production_release": False,
        "download_allowed": True,
        "warning": "개발시험 전용 임시 서명 파일이며 운영 서명이 아닙니다.",
        "artifacts": items,
        "revoked_sha256": [],
        "download_policy": {
            "authenticated_issue": True,
            "one_time_code": True,
            "ttl_seconds": int(DOWNLOAD_CODE_TTL.total_seconds()),
            "code_in_url": False,
        },
    }
    digest = hashlib.sha256(canonical_bytes(catalog)).hexdigest()
    catalog["catalog_signature"] = _signature_record(digest=digest, sign=sign)
    return catalog


@dataclass(frozen=True, slots=True)
class VerifiedDevArtifact:
    platform: DevArtifactPlatform
    filename: str
    path: Path
    size_bytes: int
    sha256: str
    media_type: str


@dataclass(frozen=True, slots=True)
class VerifiedDevRelease:
    release_channel: str
    production_release: bool
    key_id: str
    catalog_sha256: str
    artifact_root: Path
    artifacts: Mapping[DevArtifactPlatform, VerifiedDevArtifact]
    expires_at: datetime
    errors: tuple[str, ...]


def verify_dev_signed_catalog(
    catalog: Mapping[str, object],
    *,
    artifact_root: Path,
    public_keys: Mapping[str, Ed25519PublicKey],
    now: datetime,
    fail_closed: bool = False,
) -> VerifiedDevRelease:
    _aware(now)
    errors: list[str] = []
    root = artifact_root.resolve()
    if catalog.get("schema_version") != "1.0.0" or catalog.get(
        "profile"
    ) != CATALOG_PROFILE:
        errors.append("CATALOG_SCHEMA_INVALID")
    if catalog.get("release_channel") != RELEASE_CHANNEL:
        errors.append("CATALOG_CHANNEL_INVALID")
    if catalog.get("production_release") is not False:
        errors.append("PRODUCTION_RELEASE_FORBIDDEN")
    if catalog.get("download_allowed") is not True:
        errors.append("CATALOG_DOWNLOAD_DISABLED")
    try:
        created_at = _parse_utc(catalog.get("created_at"))
        expires_at = _parse_utc(catalog.get("expires_at"))
        if (
            expires_at <= created_at
            or expires_at - created_at > MAX_CATALOG_LIFETIME
            or now.astimezone(UTC) > expires_at
        ):
            errors.append("CATALOG_EXPIRED")
    except ValueError:
        created_at = now.astimezone(UTC)
        expires_at = created_at
        errors.append("CATALOG_TIME_INVALID")

    signed_catalog = dict(catalog)
    catalog_signature = signed_catalog.pop("catalog_signature", None)
    signed_digest = hashlib.sha256(canonical_bytes(signed_catalog)).hexdigest()
    catalog_signature_valid, catalog_key_id = _verify_signature(
        signature=catalog_signature,
        digest=signed_digest,
        public_keys=public_keys,
    )
    if not catalog_signature_valid:
        errors.append("CATALOG_SIGNATURE_INVALID")

    revoked = catalog.get("revoked_sha256")
    revoked_hashes = (
        {str(value) for value in revoked}
        if isinstance(revoked, list)
        else set()
    )
    if not isinstance(revoked, list):
        errors.append("REVOCATION_LIST_INVALID")

    verified: dict[DevArtifactPlatform, VerifiedDevArtifact] = {}
    raw_artifacts = catalog.get("artifacts")
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) != len(
        DevArtifactPlatform
    ):
        errors.append("ARTIFACT_SET_INCOMPLETE")
        raw_artifacts = []
    for raw in raw_artifacts:
        if not isinstance(raw, Mapping):
            errors.append("ARTIFACT_RECORD_INVALID")
            continue
        try:
            platform = DevArtifactPlatform(str(raw.get("platform", "")))
        except ValueError:
            errors.append("ARTIFACT_PLATFORM_INVALID")
            continue
        if platform in verified:
            errors.append("ARTIFACT_PLATFORM_DUPLICATE")
            continue
        filename = raw.get("filename")
        digest = raw.get("sha256")
        size_bytes = raw.get("size_bytes")
        media_type = raw.get("media_type")
        provenance = raw.get("provenance")
        if not isinstance(filename, str) or filename != _FILENAMES[platform]:
            errors.append("ARTIFACT_RECORD_INVALID")
            continue
        candidate = root / filename
        try:
            path_valid = (
                candidate.is_file()
                and candidate.resolve().parent == root
            )
        except OSError:
            path_valid = False
        if (
            not path_valid
            or not isinstance(digest, str)
            or not _SHA256.fullmatch(digest)
            or not isinstance(size_bytes, int)
            or size_bytes <= 0
            or not isinstance(media_type, str)
            or not isinstance(provenance, Mapping)
            or provenance.get("security_gates") != "PASS"
        ):
            errors.append("ARTIFACT_RECORD_INVALID")
            continue
        actual_digest = sha256_file(candidate)
        if actual_digest != digest or candidate.stat().st_size != size_bytes:
            errors.append("ARTIFACT_HASH_INVALID")
            continue
        signature_valid, key_id = _verify_signature(
            signature=raw.get("signature"),
            digest=digest,
            public_keys=public_keys,
        )
        if not signature_valid or key_id != catalog_key_id:
            errors.append("ARTIFACT_SIGNATURE_INVALID")
            continue
        if digest in revoked_hashes:
            errors.append("ARTIFACT_REVOKED")
            continue
        verified[platform] = VerifiedDevArtifact(
            platform=platform,
            filename=filename,
            path=candidate.resolve(),
            size_bytes=size_bytes,
            sha256=digest,
            media_type=media_type,
        )
    if set(verified) != set(DevArtifactPlatform):
        errors.append("ARTIFACT_SET_INCOMPLETE")

    report = VerifiedDevRelease(
        release_channel=str(catalog.get("release_channel", "")),
        production_release=bool(catalog.get("production_release", False)),
        key_id=catalog_key_id or "",
        catalog_sha256=hashlib.sha256(canonical_bytes(dict(catalog))).hexdigest(),
        artifact_root=root,
        artifacts=verified,
        expires_at=expires_at,
        errors=tuple(dict.fromkeys(errors)),
    )
    if fail_closed and report.errors:
        raise ValueError("Development signed download verification failed.")
    return report


def _load_json_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object.")
    return cast(dict[str, object], value)


def load_verified_dev_release(
    release_root: Path,
    *,
    now: datetime,
) -> VerifiedDevRelease:
    root = release_root.resolve()
    pointer = _load_json_object(root / ACTIVE_POINTER_NAME)
    directory_name = pointer.get("release_directory")
    if not isinstance(directory_name, str) or not _RELEASE_DIRECTORY.fullmatch(
        directory_name
    ):
        raise ValueError("Active development release pointer is invalid.")
    artifact_root = (root / directory_name).resolve()
    if artifact_root.parent != root or not artifact_root.is_dir():
        raise ValueError("Active development release directory is invalid.")

    trust = _load_json_object(root / TRUST_NAME)
    key_id = trust.get("key_id")
    encoded_key = trust.get("public_key_base64")
    if (
        trust.get("schema_version") != "1.0.0"
        or trust.get("profile") != TRUST_PROFILE
        or trust.get("algorithm") != "Ed25519"
        or not isinstance(key_id, str)
        or not isinstance(encoded_key, str)
    ):
        raise ValueError("Development download trust record is invalid.")
    try:
        raw_key = base64.urlsafe_b64decode(
            encoded_key + ("=" * (-len(encoded_key) % 4))
        )
        public_key = Ed25519PublicKey.from_public_bytes(raw_key)
    except ValueError as exc:
        raise ValueError("Development download public key is invalid.") from exc
    if hashlib.sha256(raw_key).hexdigest() != trust.get("public_key_sha256"):
        raise ValueError("Development download public key hash is invalid.")

    catalog = _load_json_object(artifact_root / CATALOG_NAME)
    release = verify_dev_signed_catalog(
        catalog,
        artifact_root=artifact_root,
        public_keys={key_id: public_key},
        now=now,
        fail_closed=True,
    )
    if release.key_id != key_id:
        raise ValueError("Development download key ID does not match trust record.")
    return release


class DevDownloadCodeErrorCode(StrEnum):
    INVALID = "DEV_DOWNLOAD_CODE_INVALID"
    EXPIRED = "DEV_DOWNLOAD_CODE_EXPIRED"
    ALREADY_USED = "DEV_DOWNLOAD_CODE_ALREADY_USED"
    ATTEMPTS_EXCEEDED = "DEV_DOWNLOAD_CODE_ATTEMPTS_EXCEEDED"
    SCOPE_MISMATCH = "DEV_DOWNLOAD_SCOPE_MISMATCH"


class DevDownloadCodeError(ValueError):
    def __init__(self, code: DevDownloadCodeErrorCode) -> None:
        super().__init__("개발 다운로드 코드를 확인할 수 없습니다.")
        self.code = code


@dataclass(frozen=True, slots=True)
class DevDownloadCodeRecord:
    code_ref: str
    code_hmac: str
    hash_key_version: str
    platform: DevArtifactPlatform
    subject_user_id: str
    catalog_sha256: str
    artifact_sha256: str
    issued_at: datetime
    expires_at: datetime
    failed_attempts: int = 0
    consumed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class IssuedDevDownloadCode:
    code: str
    platform: DevArtifactPlatform
    expires_at: datetime


class InMemoryDevDownloadCodeStore:
    """개발시험용 저장소이며 평문 다운로드 코드를 보관하지 않습니다."""

    def __init__(self) -> None:
        self._records: dict[str, DevDownloadCodeRecord] = {}
        self._lock = RLock()

    def get(self, code_ref: str) -> DevDownloadCodeRecord | None:
        with self._lock:
            return self._records.get(code_ref)

    def insert(self, record: DevDownloadCodeRecord) -> None:
        with self._lock:
            if record.code_ref in self._records:
                raise ValueError("Development download code already exists.")
            self._records[record.code_ref] = record

    def consume(
        self,
        *,
        code_ref: str,
        presented_hmac: str,
        platform: DevArtifactPlatform,
        catalog_sha256: str,
        artifact_sha256: str,
        received_at: datetime,
    ) -> DevDownloadCodeRecord:
        with self._lock:
            record = self._records.get(code_ref)
            if record is None or not hmac.compare_digest(
                record.code_hmac, presented_hmac
            ):
                if record is not None:
                    self._records[code_ref] = replace(
                        record,
                        failed_attempts=record.failed_attempts + 1,
                    )
                raise DevDownloadCodeError(DevDownloadCodeErrorCode.INVALID)
            if record.consumed_at is not None:
                raise DevDownloadCodeError(DevDownloadCodeErrorCode.ALREADY_USED)
            if record.failed_attempts >= MAX_DOWNLOAD_CODE_ATTEMPTS:
                raise DevDownloadCodeError(
                    DevDownloadCodeErrorCode.ATTEMPTS_EXCEEDED
                )
            if received_at > record.expires_at:
                raise DevDownloadCodeError(DevDownloadCodeErrorCode.EXPIRED)
            if (
                record.platform is not platform
                or record.catalog_sha256 != catalog_sha256
                or record.artifact_sha256 != artifact_sha256
            ):
                raise DevDownloadCodeError(DevDownloadCodeErrorCode.SCOPE_MISMATCH)
            consumed = replace(record, consumed_at=received_at)
            self._records[code_ref] = consumed
            return consumed


def _random_code_text(length: int) -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(length))


def _normalize_code(code: str) -> tuple[str, str]:
    normalized = "".join(character for character in code.upper() if character != "-")
    if len(normalized) != 20 or any(
        character not in _CODE_ALPHABET for character in normalized
    ):
        raise DevDownloadCodeError(DevDownloadCodeErrorCode.INVALID)
    return normalized[:4], normalized


class DevDownloadCodeService:
    def __init__(
        self,
        store: InMemoryDevDownloadCodeStore,
        *,
        hash_key: bytes,
        hash_key_version: str,
    ) -> None:
        if len(hash_key) < 32:
            raise ValueError("Development download hash key must be at least 256 bits.")
        self._store = store
        self._hash_key = bytes(hash_key)
        self._hash_key_version = hash_key_version

    def _hmac(self, normalized: str) -> str:
        return hmac.new(
            self._hash_key,
            normalized.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def issue(
        self,
        *,
        platform: DevArtifactPlatform,
        subject_user_id: str,
        catalog_sha256: str,
        artifact_sha256: str,
        issued_at: datetime,
        ttl: timedelta = DOWNLOAD_CODE_TTL,
    ) -> IssuedDevDownloadCode:
        _aware(issued_at)
        if ttl <= timedelta(0) or ttl > MAX_DOWNLOAD_CODE_TTL:
            raise ValueError("Development download code TTL is invalid.")
        if (
            not subject_user_id
            or not _SHA256.fullmatch(catalog_sha256)
            or not _SHA256.fullmatch(artifact_sha256)
        ):
            raise ValueError("Development download code scope is invalid.")
        while True:
            code_ref = _random_code_text(4)
            normalized = code_ref + _random_code_text(16)
            if self._store.get(code_ref) is None:
                break
        displayed = "-".join(
            normalized[index : index + 4] for index in range(0, 20, 4)
        )
        expires_at = issued_at + ttl
        self._store.insert(
            DevDownloadCodeRecord(
                code_ref=code_ref,
                code_hmac=self._hmac(normalized),
                hash_key_version=self._hash_key_version,
                platform=platform,
                subject_user_id=subject_user_id,
                catalog_sha256=catalog_sha256,
                artifact_sha256=artifact_sha256,
                issued_at=issued_at,
                expires_at=expires_at,
            )
        )
        return IssuedDevDownloadCode(
            code=displayed,
            platform=platform,
            expires_at=expires_at,
        )

    def consume(
        self,
        code: str,
        *,
        platform: DevArtifactPlatform,
        catalog_sha256: str,
        artifact_sha256: str,
        received_at: datetime,
    ) -> DevDownloadCodeRecord:
        _aware(received_at)
        code_ref, normalized = _normalize_code(code)
        return self._store.consume(
            code_ref=code_ref,
            presented_hmac=self._hmac(normalized),
            platform=platform,
            catalog_sha256=catalog_sha256,
            artifact_sha256=artifact_sha256,
            received_at=received_at,
        )
