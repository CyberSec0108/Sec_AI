"""Short-lived, single-success Collector Job credentials for IMP-032."""

from __future__ import annotations

import base64
import hmac
import secrets
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from threading import RLock
from uuid import UUID, uuid4

CREDENTIAL_SCHEME = "secai_job_v1"
MIN_HASH_KEY_BYTES = 32
DEFAULT_CREDENTIAL_TTL = timedelta(minutes=60)
MAX_CREDENTIAL_TTL = timedelta(hours=2)
MAX_FAILED_ATTEMPTS = 5


class CollectorCredentialCode(StrEnum):
    """Stable public outcomes that do not reveal credential material."""

    MALFORMED = "CREDENTIAL_MALFORMED"
    INVALID = "CREDENTIAL_INVALID"
    EXPIRED = "CREDENTIAL_EXPIRED"
    REVOKED = "CREDENTIAL_REVOKED"
    ALREADY_USED = "CREDENTIAL_ALREADY_USED"
    ATTEMPTS_EXCEEDED = "CREDENTIAL_ATTEMPTS_EXCEEDED"
    SCOPE_MISMATCH = "CREDENTIAL_SCOPE_MISMATCH"
    NONCE_REPLAYED = "NONCE_REPLAYED"


class CollectorCredentialError(ValueError):
    """Fail-closed credential rejection with a non-secret public code."""

    def __init__(self, code: CollectorCredentialCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class CollectorCredentialScope:
    """The exact upload capability granted to one Collector Job."""

    organization_id: str
    asset_id: str
    job_id: str
    manifest_id: str
    manifest_sha256: str
    nonce: str
    endpoint_id: str
    content_type: str
    schema_version: str
    max_archive_bytes: int

    def __post_init__(self) -> None:
        for value in (
            self.organization_id,
            self.asset_id,
            self.job_id,
            self.manifest_id,
        ):
            UUID(value)
        if len(self.manifest_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.manifest_sha256
        ):
            raise ValueError("manifest_sha256 must be lowercase SHA-256.")
        if (
            not self.nonce
            or not self.endpoint_id
            or self.content_type != "application/zip"
            or not self.schema_version
        ):
            raise ValueError("Credential scope strings cannot be empty.")
        if self.max_archive_bytes <= 0 or self.max_archive_bytes > 100 * 1024 * 1024:
            raise ValueError("max_archive_bytes is outside the absolute server limit.")


@dataclass(frozen=True, slots=True)
class CollectorCredentialRecord:
    """Server-side state. It deliberately contains no bearer secret."""

    credential_id: str
    scope: CollectorCredentialScope
    token_hash: str
    hash_key_version: str
    issued_at: datetime
    expires_at: datetime
    failed_attempts: int = 0
    used_at: datetime | None = None
    revoked_at: datetime | None = None
    receipt_id: str | None = None


@dataclass(frozen=True, slots=True)
class IssuedCollectorCredential:
    """One-time issuance response; ``token`` must remain in process memory."""

    credential_id: str
    token: str
    scope: CollectorCredentialScope
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class AuthorizedCollectorCredential:
    credential_id: str
    scope: CollectorCredentialScope
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class CollectorSubmissionReceipt:
    receipt_id: str
    credential_id: str
    organization_id: str
    asset_id: str
    job_id: str
    manifest_id: str
    package_id: str
    archive_sha256: str
    committed_at: datetime


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware.")


def _token_hash(hash_key: bytes, token: str) -> str:
    return hmac.new(hash_key, token.encode("ascii"), sha256).hexdigest()


def _split_token(token: str) -> str:
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != CREDENTIAL_SCHEME:
        raise CollectorCredentialError(
            CollectorCredentialCode.MALFORMED,
            "Collector credential format is invalid.",
        )
    try:
        UUID(parts[1])
        secret = base64.urlsafe_b64decode(parts[2] + ("=" * (-len(parts[2]) % 4)))
    except (ValueError, UnicodeEncodeError) as exc:
        raise CollectorCredentialError(
            CollectorCredentialCode.MALFORMED,
            "Collector credential format is invalid.",
        ) from exc
    if len(secret) != 32:
        raise CollectorCredentialError(
            CollectorCredentialCode.MALFORMED,
            "Collector credential format is invalid.",
        )
    return parts[1]


class InMemoryCollectorCredentialStore:
    """Atomic test/pure-service store; production persistence is a later auth migration."""

    def __init__(self) -> None:
        self._records: dict[str, CollectorCredentialRecord] = {}
        self._used_nonces: set[tuple[str, str, str, str]] = set()
        self._lock = RLock()

    def insert(self, record: CollectorCredentialRecord) -> None:
        with self._lock:
            if record.credential_id in self._records:
                raise ValueError("Credential ID already exists.")
            self._records[record.credential_id] = record

    def get(self, credential_id: str) -> CollectorCredentialRecord | None:
        with self._lock:
            return self._records.get(credential_id)

    def replace(self, record: CollectorCredentialRecord) -> None:
        with self._lock:
            if record.credential_id not in self._records:
                raise ValueError("Credential does not exist.")
            self._records[record.credential_id] = record

    def commit(
        self,
        *,
        credential_id: str,
        token_hash: str,
        received_at: datetime,
        package_id: str,
        archive_sha256: str,
    ) -> CollectorSubmissionReceipt:
        _aware(received_at)
        with self._lock:
            record = self._records.get(credential_id)
            if record is None or not hmac.compare_digest(record.token_hash, token_hash):
                raise CollectorCredentialError(
                    CollectorCredentialCode.INVALID,
                    "Collector credential is invalid.",
                )
            _check_record_state(record, received_at)
            nonce_key = (
                record.scope.organization_id,
                record.scope.asset_id,
                record.scope.job_id,
                record.scope.nonce,
            )
            if nonce_key in self._used_nonces:
                raise CollectorCredentialError(
                    CollectorCredentialCode.NONCE_REPLAYED,
                    "Collector submission nonce was already committed.",
                )
            receipt_id = str(uuid4())
            self._used_nonces.add(nonce_key)
            self._records[credential_id] = replace(
                record,
                used_at=received_at,
                receipt_id=receipt_id,
            )
            return CollectorSubmissionReceipt(
                receipt_id=receipt_id,
                credential_id=credential_id,
                organization_id=record.scope.organization_id,
                asset_id=record.scope.asset_id,
                job_id=record.scope.job_id,
                manifest_id=record.scope.manifest_id,
                package_id=package_id,
                archive_sha256=archive_sha256,
                committed_at=received_at,
            )


def _check_record_state(record: CollectorCredentialRecord, received_at: datetime) -> None:
    if record.revoked_at is not None:
        raise CollectorCredentialError(
            CollectorCredentialCode.REVOKED,
            "Collector credential was revoked.",
        )
    if record.used_at is not None:
        raise CollectorCredentialError(
            CollectorCredentialCode.ALREADY_USED,
            "Collector credential was already committed.",
        )
    if record.failed_attempts >= MAX_FAILED_ATTEMPTS:
        raise CollectorCredentialError(
            CollectorCredentialCode.ATTEMPTS_EXCEEDED,
            "Collector credential attempt limit was reached.",
        )
    if received_at > record.expires_at:
        raise CollectorCredentialError(
            CollectorCredentialCode.EXPIRED,
            "Collector credential has expired.",
        )


class CollectorCredentialService:
    """Issue and verify opaque capabilities while storing only a keyed hash."""

    def __init__(
        self,
        store: InMemoryCollectorCredentialStore,
        *,
        hash_key: bytes,
        hash_key_version: str,
    ) -> None:
        if len(hash_key) < MIN_HASH_KEY_BYTES:
            raise ValueError("Collector credential hash key must be at least 256 bits.")
        if not hash_key_version:
            raise ValueError("hash_key_version cannot be empty.")
        self._store = store
        self._hash_key = bytes(hash_key)
        self._hash_key_version = hash_key_version

    def issue(
        self,
        scope: CollectorCredentialScope,
        *,
        issued_at: datetime,
        ttl: timedelta = DEFAULT_CREDENTIAL_TTL,
    ) -> IssuedCollectorCredential:
        _aware(issued_at)
        if ttl <= timedelta(0) or ttl > MAX_CREDENTIAL_TTL:
            raise ValueError("Collector credential TTL must be positive and at most two hours.")
        credential_id = str(uuid4())
        secret = secrets.token_urlsafe(32)
        token = f"{CREDENTIAL_SCHEME}.{credential_id}.{secret}"
        expires_at = issued_at + ttl
        self._store.insert(
            CollectorCredentialRecord(
                credential_id=credential_id,
                scope=scope,
                token_hash=_token_hash(self._hash_key, token),
                hash_key_version=self._hash_key_version,
                issued_at=issued_at,
                expires_at=expires_at,
            )
        )
        return IssuedCollectorCredential(
            credential_id=credential_id,
            token=token,
            scope=scope,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def authorize(
        self,
        token: str,
        *,
        received_at: datetime,
    ) -> AuthorizedCollectorCredential:
        _aware(received_at)
        credential_id = _split_token(token)
        record = self._store.get(credential_id)
        presented_hash = _token_hash(self._hash_key, token)
        if record is None or not hmac.compare_digest(record.token_hash, presented_hash):
            self._record_failure(record)
            raise CollectorCredentialError(
                CollectorCredentialCode.INVALID,
                "Collector credential is invalid.",
            )
        try:
            _check_record_state(record, received_at)
        except CollectorCredentialError:
            raise
        return AuthorizedCollectorCredential(
            credential_id=record.credential_id,
            scope=record.scope,
            expires_at=record.expires_at,
        )

    def commit(
        self,
        token: str,
        *,
        received_at: datetime,
        package_id: str,
        archive_sha256: str,
    ) -> CollectorSubmissionReceipt:
        credential_id = _split_token(token)
        return self._store.commit(
            credential_id=credential_id,
            token_hash=_token_hash(self._hash_key, token),
            received_at=received_at,
            package_id=package_id,
            archive_sha256=archive_sha256,
        )

    def revoke(self, credential_id: str, *, revoked_at: datetime) -> None:
        _aware(revoked_at)
        record = self._store.get(credential_id)
        if record is None:
            return
        self._store.replace(replace(record, revoked_at=revoked_at))

    def _record_failure(self, record: CollectorCredentialRecord | None) -> None:
        if record is None:
            return
        self._store.replace(replace(record, failed_attempts=record.failed_attempts + 1))
