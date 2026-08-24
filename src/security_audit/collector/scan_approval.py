"""수집기 실행을 계정 소유자의 브라우저 승인에 묶는 계약.

수집기는 코드를 입력받지 않고 승인 요청만 만들며, 사용자는 이미 로그인된
화면에서 대상 장비 이름을 확인한 뒤 승인합니다. 추가 권한 점검 동의는 이
승인 시점에 함께 기록합니다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from threading import RLock
from uuid import uuid4

SCAN_APPROVAL_TTL = timedelta(minutes=10)
MAX_DEVICE_NAME_LENGTH = 64
_DEVICE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ScanApprovalState(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DECLINED = "DECLINED"
    EXPIRED = "EXPIRED"


class ScanApprovalErrorCode(StrEnum):
    NOT_FOUND = "SCAN_APPROVAL_NOT_FOUND"
    OWNER_MISMATCH = "SCAN_APPROVAL_OWNER_MISMATCH"
    ALREADY_DECIDED = "SCAN_APPROVAL_ALREADY_DECIDED"
    EXPIRED = "SCAN_APPROVAL_EXPIRED"
    DEVICE_NAME_INVALID = "SCAN_APPROVAL_DEVICE_NAME_INVALID"


class ScanApprovalError(ValueError):
    def __init__(self, code: ScanApprovalErrorCode) -> None:
        super().__init__("점검 승인 요청을 확인할 수 없습니다.")
        self.code = code


@dataclass(frozen=True, slots=True)
class ScanApprovalRecord:
    request_id: str
    organization_id: str
    subject_user_id: str
    device_name: str
    requested_at: datetime
    expires_at: datetime
    state: ScanApprovalState = ScanApprovalState.PENDING
    elevated_consent: bool = False
    decided_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class RequestedScanApproval:
    request_id: str
    device_name: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ScanApprovalView:
    request_id: str
    device_name: str
    state: ScanApprovalState
    elevated_consent: bool
    decided_at: datetime | None


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("점검 승인 시각은 UTC offset을 포함해야 합니다.")


def _effective_state(
    record: ScanApprovalRecord,
    received_at: datetime,
) -> ScanApprovalState:
    if record.state is ScanApprovalState.PENDING and received_at > record.expires_at:
        return ScanApprovalState.EXPIRED
    return record.state


def _view(record: ScanApprovalRecord, state: ScanApprovalState) -> ScanApprovalView:
    return ScanApprovalView(
        request_id=record.request_id,
        device_name=record.device_name,
        state=state,
        elevated_consent=record.elevated_consent,
        decided_at=record.decided_at,
    )


class InMemoryScanApprovalStore:
    """개발시험용 저장소입니다."""

    def __init__(self) -> None:
        self._records: dict[str, ScanApprovalRecord] = {}
        self._lock = RLock()

    def get(self, request_id: str) -> ScanApprovalRecord | None:
        with self._lock:
            return self._records.get(request_id)

    def insert(self, record: ScanApprovalRecord) -> None:
        with self._lock:
            if record.request_id in self._records:
                raise ValueError("점검 승인 요청 id가 이미 있습니다.")
            self._records[record.request_id] = record

    def replace(self, record: ScanApprovalRecord) -> None:
        with self._lock:
            self._records[record.request_id] = record


class ScanApprovalService:
    def __init__(self, store: InMemoryScanApprovalStore) -> None:
        self._store = store
        self._lock = RLock()

    def request(
        self,
        *,
        organization_id: str,
        subject_user_id: str,
        device_name: str,
        requested_at: datetime,
        ttl: timedelta = SCAN_APPROVAL_TTL,
    ) -> RequestedScanApproval:
        _aware(requested_at)
        if _DEVICE_NAME_PATTERN.fullmatch(device_name) is None:
            raise ScanApprovalError(ScanApprovalErrorCode.DEVICE_NAME_INVALID)
        if ttl <= timedelta(0) or ttl > SCAN_APPROVAL_TTL:
            raise ValueError("점검 승인 유효기간이 올바르지 않습니다.")
        record = ScanApprovalRecord(
            request_id=str(uuid4()),
            organization_id=organization_id,
            subject_user_id=subject_user_id,
            device_name=device_name,
            requested_at=requested_at,
            expires_at=requested_at + ttl,
        )
        self._store.insert(record)
        return RequestedScanApproval(
            request_id=record.request_id,
            device_name=record.device_name,
            expires_at=record.expires_at,
        )

    def _require(self, request_id: str) -> ScanApprovalRecord:
        record = self._store.get(request_id)
        if record is None:
            raise ScanApprovalError(ScanApprovalErrorCode.NOT_FOUND)
        return record

    def pending_view(
        self,
        request_id: str,
        *,
        viewer_user_id: str,
        received_at: datetime,
    ) -> ScanApprovalView:
        """승인 화면이 대상 장비를 보여주기 전에 소유자를 확인합니다."""

        _aware(received_at)
        record = self._require(request_id)
        if record.subject_user_id != viewer_user_id:
            raise ScanApprovalError(ScanApprovalErrorCode.OWNER_MISMATCH)
        return _view(record, _effective_state(record, received_at))

    def poll(self, request_id: str, *, received_at: datetime) -> ScanApprovalView:
        _aware(received_at)
        record = self._require(request_id)
        return _view(record, _effective_state(record, received_at))

    def _decide(
        self,
        request_id: str,
        *,
        approving_user_id: str,
        state: ScanApprovalState,
        elevated_consent: bool,
        decided_at: datetime,
    ) -> ScanApprovalView:
        _aware(decided_at)
        with self._lock:
            record = self._require(request_id)
            if record.subject_user_id != approving_user_id:
                raise ScanApprovalError(ScanApprovalErrorCode.OWNER_MISMATCH)
            if record.state is not ScanApprovalState.PENDING:
                raise ScanApprovalError(ScanApprovalErrorCode.ALREADY_DECIDED)
            if decided_at > record.expires_at:
                raise ScanApprovalError(ScanApprovalErrorCode.EXPIRED)
            decided = replace(
                record,
                state=state,
                elevated_consent=elevated_consent,
                decided_at=decided_at,
            )
            self._store.replace(decided)
            return _view(decided, decided.state)

    def approve(
        self,
        request_id: str,
        *,
        approving_user_id: str,
        elevated_consent: bool,
        decided_at: datetime,
    ) -> ScanApprovalView:
        return self._decide(
            request_id,
            approving_user_id=approving_user_id,
            state=ScanApprovalState.APPROVED,
            elevated_consent=elevated_consent,
            decided_at=decided_at,
        )

    def decline(
        self,
        request_id: str,
        *,
        approving_user_id: str,
        decided_at: datetime,
    ) -> ScanApprovalView:
        return self._decide(
            request_id,
            approving_user_id=approving_user_id,
            state=ScanApprovalState.DECLINED,
            elevated_consent=False,
            decided_at=decided_at,
        )
