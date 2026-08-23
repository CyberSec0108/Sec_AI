"""사람용 일회용 코드와 실제 256-bit 제출 credential을 분리합니다."""

from __future__ import annotations

import hmac
import secrets
from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from threading import RLock
from typing import Any
from uuid import uuid4

from security_audit.security.auth import (
    AuthorizedCollectorCredential,
    CollectorCredentialScope,
    CollectorCredentialService,
    CollectorSubmissionReceipt,
    InMemoryCollectorCredentialStore,
    IssuedCollectorCredential,
)

DEVICE_CODE_TTL = timedelta(minutes=10)
MAX_DEVICE_CODE_TTL = timedelta(minutes=15)
MAX_DEVICE_CODE_ATTEMPTS = 5
MAX_EXCHANGES_PER_MINUTE = 20
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class DeviceCodeErrorCode(StrEnum):
    INVALID = "DEVICE_CODE_INVALID"
    EXPIRED = "DEVICE_CODE_EXPIRED"
    ALREADY_USED = "DEVICE_CODE_ALREADY_USED"
    ATTEMPTS_EXCEEDED = "DEVICE_CODE_ATTEMPTS_EXCEEDED"
    SELECTION_INVALID = "DEVICE_CODE_SELECTION_INVALID"


class DeviceCodeError(ValueError):
    def __init__(self, code: DeviceCodeErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class DeviceCodeRecord:
    code_ref: str
    code_hmac: str
    hash_key_version: str
    scope: CollectorCredentialScope
    subject_user_id: str
    manifest: dict[str, Any]
    choices: dict[str, tuple[CollectorCredentialScope, dict[str, Any]]] | None
    issued_at: datetime
    expires_at: datetime
    failed_attempts: int = 0
    exchanged_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class IssuedDeviceCode:
    code_ref: str
    code: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ExchangedLinuxConnection:
    subject_user_id: str
    manifest: dict[str, Any]
    credential: IssuedCollectorCredential
    transport_receipt_id: str


@dataclass(frozen=True, slots=True)
class AuthorizedLinuxConnection:
    subject_user_id: str
    credential: AuthorizedCollectorCredential
    transport_receipt_id: str


class InMemoryDeviceCodeStore:
    """개발·단위시험용 원자적 저장소이며 평문 code는 저장하지 않습니다."""

    def __init__(self) -> None:
        self._records: dict[str, DeviceCodeRecord] = {}
        self._lock = RLock()

    def insert(self, record: DeviceCodeRecord) -> None:
        with self._lock:
            if record.code_ref in self._records:
                raise ValueError("Device code reference already exists.")
            self._records[record.code_ref] = record

    def get(self, code_ref: str) -> DeviceCodeRecord | None:
        with self._lock:
            return self._records.get(code_ref)

    def consume(
        self,
        *,
        code_ref: str,
        presented_hmac: str,
        received_at: datetime,
    ) -> DeviceCodeRecord:
        with self._lock:
            record = self._records.get(code_ref)
            if record is None or not hmac.compare_digest(record.code_hmac, presented_hmac):
                if record is not None:
                    self._records[code_ref] = replace(
                        record,
                        failed_attempts=record.failed_attempts + 1,
                    )
                raise DeviceCodeError(
                    DeviceCodeErrorCode.INVALID,
                    "일회용 코드가 올바르지 않습니다.",
                )
            if record.exchanged_at is not None:
                raise DeviceCodeError(
                    DeviceCodeErrorCode.ALREADY_USED,
                    "이미 사용한 일회용 코드입니다.",
                )
            if record.failed_attempts >= MAX_DEVICE_CODE_ATTEMPTS:
                raise DeviceCodeError(
                    DeviceCodeErrorCode.ATTEMPTS_EXCEEDED,
                    "일회용 코드 시도 횟수를 초과했습니다.",
                )
            if received_at > record.expires_at:
                raise DeviceCodeError(
                    DeviceCodeErrorCode.EXPIRED,
                    "일회용 코드가 만료되었습니다.",
                )
            consumed = replace(record, exchanged_at=received_at)
            self._records[code_ref] = consumed
            return consumed


class InMemoryExchangeRateLimiter:
    """개발 API용 IP별 고정 상한이며 전달된 proxy header는 신뢰하지 않습니다."""

    def __init__(self, *, maximum: int = MAX_EXCHANGES_PER_MINUTE) -> None:
        if maximum <= 0:
            raise ValueError("Rate limit maximum must be positive.")
        self._maximum = maximum
        self._attempts: dict[str, deque[datetime]] = {}
        self._lock = RLock()

    def allow(self, key: str, *, received_at: datetime) -> bool:
        _aware(received_at)
        safe_key = key[:128] if key else "unknown"
        oldest = received_at - timedelta(minutes=1)
        with self._lock:
            attempts = self._attempts.setdefault(safe_key, deque())
            while attempts and attempts[0] <= oldest:
                attempts.popleft()
            if len(attempts) >= self._maximum:
                return False
            attempts.append(received_at)
            return True


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware.")


def _random_text(length: int) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def _normalize_code(code: str) -> tuple[str, str]:
    normalized = "".join(character for character in code.upper() if character != "-")
    if len(normalized) != 20 or any(character not in _ALPHABET for character in normalized):
        raise DeviceCodeError(
            DeviceCodeErrorCode.INVALID,
            "일회용 코드가 올바르지 않습니다.",
        )
    return normalized[:4], normalized


class LinuxOneShotConnectionService:
    def __init__(
        self,
        *,
        code_store: InMemoryDeviceCodeStore,
        credential_store: InMemoryCollectorCredentialStore,
        hash_key: bytes,
        hash_key_version: str,
    ) -> None:
        if len(hash_key) < 32:
            raise ValueError("Linux one-shot hash key must be at least 256 bits.")
        self._codes = code_store
        self._hash_key = bytes(hash_key)
        self._hash_key_version = hash_key_version
        self._credentials = CollectorCredentialService(
            credential_store,
            hash_key=hash_key,
            hash_key_version=hash_key_version,
        )
        self._credential_subjects: dict[str, tuple[str, str]] = {}
        self._credential_subjects_lock = RLock()

    def _hmac(self, normalized_code: str) -> str:
        return hmac.new(
            self._hash_key,
            normalized_code.encode("ascii"),
            sha256,
        ).hexdigest()

    def issue(
        self,
        scope: CollectorCredentialScope,
        *,
        subject_user_id: str,
        manifest: dict[str, Any],
        issued_at: datetime,
        ttl: timedelta = DEVICE_CODE_TTL,
    ) -> IssuedDeviceCode:
        _aware(issued_at)
        if ttl <= timedelta(0) or ttl > MAX_DEVICE_CODE_TTL:
            raise ValueError("Device code TTL must be positive and at most 15 minutes.")
        while True:
            code_ref = _random_text(4)
            secret = _random_text(16)
            normalized = code_ref + secret
            if self._codes.get(code_ref) is None:
                break
        displayed = "-".join(normalized[index : index + 4] for index in range(0, 20, 4))
        expires_at = issued_at + ttl
        self._codes.insert(
            DeviceCodeRecord(
                code_ref=code_ref,
                code_hmac=self._hmac(normalized),
                hash_key_version=self._hash_key_version,
                scope=scope,
                subject_user_id=subject_user_id,
                manifest=dict(manifest),
                choices=None,
                issued_at=issued_at,
                expires_at=expires_at,
            )
        )
        return IssuedDeviceCode(code_ref=code_ref, code=displayed, expires_at=expires_at)

    def issue_choices(
        self,
        choices: dict[str, tuple[CollectorCredentialScope, dict[str, Any]]],
        *,
        subject_user_id: str,
        issued_at: datetime,
        ttl: timedelta = DEVICE_CODE_TTL,
    ) -> IssuedDeviceCode:
        """식별 전에는 배포판을 고정하지 않고 교환 시 정확히 하나만 바인딩합니다."""

        _aware(issued_at)
        if ttl <= timedelta(0) or ttl > MAX_DEVICE_CODE_TTL:
            raise ValueError("Device code TTL must be positive and at most 15 minutes.")
        if not choices or any(
            not key or len(key) > 32 or not key.replace("_", "").isalnum()
            for key in choices
        ):
            raise ValueError("Device code selection choices are invalid.")
        normalized_choices = {
            key: (scope, dict(manifest))
            for key, (scope, manifest) in choices.items()
        }
        first_scope, first_manifest = next(iter(normalized_choices.values()))
        while True:
            code_ref = _random_text(4)
            secret = _random_text(16)
            normalized = code_ref + secret
            if self._codes.get(code_ref) is None:
                break
        displayed = "-".join(
            normalized[index : index + 4] for index in range(0, 20, 4)
        )
        expires_at = issued_at + ttl
        self._codes.insert(
            DeviceCodeRecord(
                code_ref=code_ref,
                code_hmac=self._hmac(normalized),
                hash_key_version=self._hash_key_version,
                scope=first_scope,
                subject_user_id=subject_user_id,
                manifest=dict(first_manifest),
                choices=normalized_choices,
                issued_at=issued_at,
                expires_at=expires_at,
            )
        )
        return IssuedDeviceCode(code_ref=code_ref, code=displayed, expires_at=expires_at)

    def exchange(
        self,
        code: str,
        *,
        received_at: datetime,
        selection_key: str | None = None,
    ) -> ExchangedLinuxConnection:
        _aware(received_at)
        code_ref, normalized = _normalize_code(code)
        record = self._codes.consume(
            code_ref=code_ref,
            presented_hmac=self._hmac(normalized),
            received_at=received_at,
        )
        scope = record.scope
        manifest = record.manifest
        if record.choices is not None:
            selected = record.choices.get(selection_key or "")
            if selected is None:
                raise DeviceCodeError(
                    DeviceCodeErrorCode.SELECTION_INVALID,
                    "자동 식별 결과에 맞는 점검 Manifest가 없습니다.",
                )
            scope, manifest = selected
        elif selection_key is not None:
            raise DeviceCodeError(
                DeviceCodeErrorCode.SELECTION_INVALID,
                "고정 배포판 코드에는 선택값을 사용할 수 없습니다.",
            )
        manifest_expiry_value = manifest.get("expires_at")
        if isinstance(manifest_expiry_value, str):
            manifest_expiry = datetime.fromisoformat(
                manifest_expiry_value.replace("Z", "+00:00")
            )
            remaining = min(timedelta(minutes=60), manifest_expiry - received_at)
        else:
            remaining = record.expires_at - received_at
        if remaining <= timedelta(0):
            raise DeviceCodeError(
                DeviceCodeErrorCode.EXPIRED,
                "점검 Manifest가 만료되었습니다.",
            )
        credential = self._credentials.issue(
            scope,
            issued_at=received_at,
            ttl=remaining,
        )
        transport_receipt_id = str(uuid4())
        with self._credential_subjects_lock:
            self._credential_subjects[credential.credential_id] = (
                record.subject_user_id,
                transport_receipt_id,
            )
        return ExchangedLinuxConnection(
            subject_user_id=record.subject_user_id,
            manifest=dict(manifest),
            credential=credential,
            transport_receipt_id=transport_receipt_id,
        )

    def authorize(
        self,
        token: str,
        *,
        received_at: datetime,
    ) -> AuthorizedCollectorCredential:
        return self._credentials.authorize(token, received_at=received_at)

    def authorize_connection(
        self,
        token: str,
        *,
        received_at: datetime,
    ) -> AuthorizedLinuxConnection:
        credential = self.authorize(token, received_at=received_at)
        with self._credential_subjects_lock:
            subject = self._credential_subjects.get(credential.credential_id)
        if subject is None:
            raise DeviceCodeError(
                DeviceCodeErrorCode.INVALID,
                "제출 연결 정보를 찾을 수 없습니다.",
            )
        return AuthorizedLinuxConnection(
            subject_user_id=subject[0],
            credential=credential,
            transport_receipt_id=subject[1],
        )

    def commit(
        self,
        token: str,
        *,
        received_at: datetime,
        package_id: str,
        archive_sha256: str,
    ) -> CollectorSubmissionReceipt:
        receipt = self._credentials.commit(
            token,
            received_at=received_at,
            package_id=package_id,
            archive_sha256=archive_sha256,
        )
        with self._credential_subjects_lock:
            self._credential_subjects.pop(receipt.credential_id, None)
        return receipt
