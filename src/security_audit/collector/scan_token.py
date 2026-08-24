"""원격 배치용 수집기 실행 토큰 계약.

로그인한 사용자가 수집기를 내려받을 때 사이드카 파일로 함께 배포되는 토큰이며,
평문은 저장하지 않고 HMAC만 보관합니다. 서명된 실행 파일 자체는 사용자별로
달라지지 않으므로 다운로드 카탈로그의 hash 검증이 그대로 유지됩니다.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import RLock

SCAN_TOKEN_TTL = timedelta(hours=24)
MAX_SCAN_TOKEN_RUNS = 3
_REFERENCE_LENGTH = 12
_REFERENCE_PATTERN = re.compile(r"^[0-9a-f]{12}$")
_SECRET_BYTES = 32


class ScanTokenErrorCode(StrEnum):
    INVALID = "SCAN_TOKEN_INVALID"
    EXPIRED = "SCAN_TOKEN_EXPIRED"
    RUNS_EXHAUSTED = "SCAN_TOKEN_RUNS_EXHAUSTED"
    SCOPE_MISMATCH = "SCAN_TOKEN_SCOPE_MISMATCH"


class ScanTokenError(ValueError):
    def __init__(self, code: ScanTokenErrorCode) -> None:
        super().__init__("점검 실행 토큰을 확인할 수 없습니다.")
        self.code = code


@dataclass(frozen=True, slots=True)
class ScanTokenRecord:
    token_ref: str
    token_hmac: str
    hash_key_version: str
    organization_id: str
    subject_user_id: str
    server_origin: str
    issued_at: datetime
    expires_at: datetime
    used_runs: int = 0
    failed_attempts: int = 0


@dataclass(frozen=True, slots=True)
class IssuedScanToken:
    token: str
    server_origin: str
    expires_at: datetime
    max_runs: int


@dataclass(frozen=True, slots=True)
class VerifiedScanToken:
    organization_id: str
    subject_user_id: str
    server_origin: str
    remaining_runs: int


@dataclass(frozen=True, slots=True)
class StartedScanRun:
    organization_id: str
    subject_user_id: str
    server_origin: str
    remaining_runs: int


def _split(token: str) -> tuple[str, str]:
    token_ref, separator, secret = token.partition(".")
    if not separator or not secret or _REFERENCE_PATTERN.fullmatch(token_ref) is None:
        raise ScanTokenError(ScanTokenErrorCode.INVALID)
    return token_ref, secret


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("점검 실행 토큰 시각은 UTC offset을 포함해야 합니다.")


class InMemoryScanTokenStore:
    """개발시험용 저장소이며 평문 토큰을 보관하지 않습니다."""

    def __init__(self) -> None:
        self._records: dict[str, ScanTokenRecord] = {}
        self._lock = RLock()

    def get(self, token_ref: str) -> ScanTokenRecord | None:
        with self._lock:
            return self._records.get(token_ref)

    def insert(self, record: ScanTokenRecord) -> None:
        with self._lock:
            if record.token_ref in self._records:
                raise ValueError("점검 실행 토큰 reference가 이미 있습니다.")
            self._records[record.token_ref] = record

    def verify(
        self,
        *,
        token_ref: str,
        presented_hmac: str,
        server_origin: str,
        received_at: datetime,
    ) -> ScanTokenRecord:
        with self._lock:
            return self._checked(
                token_ref=token_ref,
                presented_hmac=presented_hmac,
                server_origin=server_origin,
                received_at=received_at,
            )

    def _checked(
        self,
        *,
        token_ref: str,
        presented_hmac: str,
        server_origin: str,
        received_at: datetime,
    ) -> ScanTokenRecord:
        record = self._records.get(token_ref)
        if record is None or not hmac.compare_digest(
            record.token_hmac,
            presented_hmac,
        ):
            if record is not None:
                self._records[token_ref] = replace(
                    record,
                    failed_attempts=record.failed_attempts + 1,
                )
            raise ScanTokenError(ScanTokenErrorCode.INVALID)
        if received_at > record.expires_at:
            raise ScanTokenError(ScanTokenErrorCode.EXPIRED)
        if record.server_origin != server_origin:
            raise ScanTokenError(ScanTokenErrorCode.SCOPE_MISMATCH)
        return record

    def start_run(
        self,
        *,
        token_ref: str,
        presented_hmac: str,
        server_origin: str,
        received_at: datetime,
    ) -> ScanTokenRecord:
        with self._lock:
            record = self._checked(
                token_ref=token_ref,
                presented_hmac=presented_hmac,
                server_origin=server_origin,
                received_at=received_at,
            )
            if record.used_runs >= MAX_SCAN_TOKEN_RUNS:
                raise ScanTokenError(ScanTokenErrorCode.RUNS_EXHAUSTED)
            started = replace(record, used_runs=record.used_runs + 1)
            self._records[token_ref] = started
            return started


class ScanTokenService:
    def __init__(
        self,
        store: InMemoryScanTokenStore,
        *,
        hash_key: bytes,
        hash_key_version: str,
    ) -> None:
        if len(hash_key) < 32:
            raise ValueError("점검 실행 토큰 hash key는 256bit 이상이어야 합니다.")
        self._store = store
        self._hash_key = bytes(hash_key)
        self._hash_key_version = hash_key_version

    def _hmac(self, secret: str) -> str:
        return hmac.new(
            self._hash_key,
            secret.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def issue(
        self,
        *,
        organization_id: str,
        subject_user_id: str,
        server_origin: str,
        issued_at: datetime,
        ttl: timedelta = SCAN_TOKEN_TTL,
    ) -> IssuedScanToken:
        _aware(issued_at)
        if ttl <= timedelta(0) or ttl > SCAN_TOKEN_TTL:
            raise ValueError("점검 실행 토큰 유효기간이 올바르지 않습니다.")
        if not organization_id or not subject_user_id or not server_origin:
            raise ValueError("점검 실행 토큰 범위가 올바르지 않습니다.")
        while True:
            token_ref = secrets.token_hex(_REFERENCE_LENGTH // 2)
            if self._store.get(token_ref) is None:
                break
        secret = secrets.token_urlsafe(_SECRET_BYTES)
        expires_at = issued_at + ttl
        self._store.insert(
            ScanTokenRecord(
                token_ref=token_ref,
                token_hmac=self._hmac(secret),
                hash_key_version=self._hash_key_version,
                organization_id=organization_id,
                subject_user_id=subject_user_id,
                server_origin=server_origin,
                issued_at=issued_at,
                expires_at=expires_at,
            )
        )
        return IssuedScanToken(
            token=f"{token_ref}.{secret}",
            server_origin=server_origin,
            expires_at=expires_at,
            max_runs=MAX_SCAN_TOKEN_RUNS,
        )

    def verify(
        self,
        token: str,
        *,
        server_origin: str,
        received_at: datetime,
    ) -> VerifiedScanToken:
        """실행 횟수를 쓰지 않고 토큰 소유자만 확인합니다."""

        _aware(received_at)
        token_ref, secret = _split(token)
        record = self._store.verify(
            token_ref=token_ref,
            presented_hmac=self._hmac(secret),
            server_origin=server_origin,
            received_at=received_at,
        )
        return VerifiedScanToken(
            organization_id=record.organization_id,
            subject_user_id=record.subject_user_id,
            server_origin=record.server_origin,
            remaining_runs=MAX_SCAN_TOKEN_RUNS - record.used_runs,
        )

    def start_run(
        self,
        token: str,
        *,
        server_origin: str,
        received_at: datetime,
    ) -> StartedScanRun:
        """실행 1회를 소진하고 남은 횟수를 돌려줍니다."""

        _aware(received_at)
        token_ref, secret = _split(token)
        started = self._store.start_run(
            token_ref=token_ref,
            presented_hmac=self._hmac(secret),
            server_origin=server_origin,
            received_at=received_at,
        )
        return StartedScanRun(
            organization_id=started.organization_id,
            subject_user_id=started.subject_user_id,
            server_origin=started.server_origin,
            remaining_runs=MAX_SCAN_TOKEN_RUNS - started.used_runs,
        )


def utc_now() -> datetime:
    return datetime.now(UTC)
