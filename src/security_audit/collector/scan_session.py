"""수집기 실행 토큰과 브라우저 승인을 잇는 응용 계층.

수집기는 사이드카 토큰으로 실행 1회를 소진해 승인 요청을 만들고, 사용자는
로그인된 화면에서 대상 장비를 확인한 뒤 승인합니다. HTTP 계층은 이 서비스를
얇게 감싸기만 합니다.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum

from .scan_approval import (
    ScanApprovalError,
    ScanApprovalErrorCode,
    ScanApprovalService,
    ScanApprovalState,
    ScanApprovalView,
)
from .scan_token import IssuedScanToken, ScanTokenService

APPROVAL_PATH = "/ui/scan-approve"


class ScanSessionErrorCode(StrEnum):
    NOT_APPROVED = "SCAN_SESSION_NOT_APPROVED"
    OWNER_MISMATCH = "SCAN_SESSION_OWNER_MISMATCH"


class ScanSessionError(ValueError):
    def __init__(self, code: ScanSessionErrorCode) -> None:
        super().__init__("점검 실행 인가를 확인할 수 없습니다.")
        self.code = code


@dataclass(frozen=True, slots=True)
class AuthorizedScan:
    request_id: str
    organization_id: str
    subject_user_id: str
    device_name: str
    elevated_consent: bool
    grant_code: str | None = None
    asset_id: str | None = None


@dataclass(frozen=True, slots=True)
class RegisteredScanSession:
    request_id: str
    device_name: str
    approve_url: str
    expires_at: datetime
    remaining_runs: int


class ScanSessionService:
    def __init__(
        self,
        *,
        tokens: ScanTokenService,
        approvals: ScanApprovalService,
    ) -> None:
        self._tokens = tokens
        self._approvals = approvals

    def issue_token(
        self,
        *,
        organization_id: str,
        subject_user_id: str,
        server_origin: str,
        issued_at: datetime,
    ) -> IssuedScanToken:
        """다운로드 시점에 사이드카로 내보낼 실행 토큰을 발급합니다."""

        return self._tokens.issue(
            organization_id=organization_id,
            subject_user_id=subject_user_id,
            server_origin=server_origin,
            issued_at=issued_at,
        )

    def register(
        self,
        token: str,
        *,
        device_name: str,
        server_origin: str,
        received_at: datetime,
    ) -> RegisteredScanSession:
        """토큰 실행 1회를 소진하고 소유자에게 보낼 승인 요청을 만듭니다."""

        started = self._tokens.start_run(
            token,
            server_origin=server_origin,
            received_at=received_at,
        )
        requested = self._approvals.request(
            organization_id=started.organization_id,
            subject_user_id=started.subject_user_id,
            device_name=device_name,
            requested_at=received_at,
        )
        return RegisteredScanSession(
            request_id=requested.request_id,
            device_name=requested.device_name,
            approve_url=(
                f"{started.server_origin}{APPROVAL_PATH}?req={requested.request_id}"
            ),
            expires_at=requested.expires_at,
            remaining_runs=started.remaining_runs,
        )

    def pending_view(
        self,
        request_id: str,
        *,
        viewer_user_id: str,
        received_at: datetime,
        include_grant: bool = True,
    ) -> ScanApprovalView:
        return self._approvals.pending_view(
            request_id,
            viewer_user_id=viewer_user_id,
            received_at=received_at,
            include_grant=include_grant,
        )

    def approve(
        self,
        request_id: str,
        *,
        approving_user_id: str,
        elevated_consent: bool,
        decided_at: datetime,
        grant_code: str | None = None,
        asset_id: str | None = None,
    ) -> ScanApprovalView:
        return self._approvals.approve(
            request_id,
            approving_user_id=approving_user_id,
            elevated_consent=elevated_consent,
            decided_at=decided_at,
            grant_code=grant_code,
            asset_id=asset_id,
        )

    def decline(
        self,
        request_id: str,
        *,
        approving_user_id: str,
        decided_at: datetime,
    ) -> ScanApprovalView:
        return self._approvals.decline(
            request_id,
            approving_user_id=approving_user_id,
            decided_at=decided_at,
        )

    def authorize_exchange(
        self,
        request_id: str,
        *,
        token: str,
        server_origin: str,
        received_at: datetime,
    ) -> AuthorizedScan:
        """승인된 요청과 같은 소유자의 토큰인지 확인합니다. 실행 횟수는 쓰지 않습니다."""

        verified = self._tokens.verify(
            token,
            server_origin=server_origin,
            received_at=received_at,
        )
        try:
            record = self._approvals.pending_view(
                request_id,
                viewer_user_id=verified.subject_user_id,
                received_at=received_at,
            )
        except ScanApprovalError as exc:
            if exc.code is ScanApprovalErrorCode.OWNER_MISMATCH:
                raise ScanSessionError(ScanSessionErrorCode.OWNER_MISMATCH) from exc
            raise
        if record.state is not ScanApprovalState.APPROVED:
            raise ScanSessionError(ScanSessionErrorCode.NOT_APPROVED)
        return AuthorizedScan(
            request_id=record.request_id,
            organization_id=verified.organization_id,
            subject_user_id=verified.subject_user_id,
            device_name=record.device_name,
            elevated_consent=record.elevated_consent,
            grant_code=record.grant_code,
            asset_id=record.asset_id,
        )

    def poll(self, request_id: str, *, received_at: datetime) -> ScanApprovalView:
        """상태만 알려줍니다. 코드는 토큰을 제시한 수집기에만 건넵니다."""

        view = self._approvals.poll(request_id, received_at=received_at)
        return replace(view, grant_code=None)
