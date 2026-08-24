from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from security_audit.collector.scan_approval import (
    SCAN_APPROVAL_TTL,
    InMemoryScanApprovalStore,
    RequestedScanApproval,
    ScanApprovalError,
    ScanApprovalErrorCode,
    ScanApprovalService,
    ScanApprovalState,
)

NOW = datetime(2026, 8, 23, 6, 0, tzinfo=UTC)
ORGANIZATION_ID = "46000000-0000-4000-8000-000000000001"
OWNER_ID = "46000000-0000-4000-8000-000000000003"
OTHER_ID = "46000000-0000-4000-8000-000000000099"
DEVICE = "DESKTOP-A17"


def _service() -> ScanApprovalService:
    return ScanApprovalService(InMemoryScanApprovalStore())


def _request(
    service: ScanApprovalService,
    *,
    requested_at: datetime = NOW,
) -> RequestedScanApproval:
    return service.request(
        organization_id=ORGANIZATION_ID,
        subject_user_id=OWNER_ID,
        device_name=DEVICE,
        requested_at=requested_at,
    )


def test_request_waits_for_the_owner_and_shows_the_target_device() -> None:
    service = _service()

    pending = _request(service)
    view = service.pending_view(
        pending.request_id,
        viewer_user_id=OWNER_ID,
        received_at=NOW + timedelta(seconds=5),
    )

    assert SCAN_APPROVAL_TTL == timedelta(minutes=10)
    assert pending.expires_at == NOW + SCAN_APPROVAL_TTL
    assert view.device_name == DEVICE
    assert view.state is ScanApprovalState.PENDING
    assert view.elevated_consent is False


def test_owner_approval_records_the_elevated_consent_choice() -> None:
    service = _service()
    pending = _request(service)

    decided = service.approve(
        pending.request_id,
        approving_user_id=OWNER_ID,
        elevated_consent=True,
        decided_at=NOW + timedelta(minutes=1),
    )
    polled = service.poll(pending.request_id, received_at=NOW + timedelta(minutes=2))

    assert decided.state is ScanApprovalState.APPROVED
    assert decided.elevated_consent is True
    assert decided.decided_at == NOW + timedelta(minutes=1)
    assert polled.state is ScanApprovalState.APPROVED
    assert polled.elevated_consent is True


def test_standard_scan_is_approved_without_the_elevated_consent() -> None:
    service = _service()
    pending = _request(service)

    decided = service.approve(
        pending.request_id,
        approving_user_id=OWNER_ID,
        elevated_consent=False,
        decided_at=NOW + timedelta(minutes=1),
    )

    assert decided.state is ScanApprovalState.APPROVED
    assert decided.elevated_consent is False


def test_another_account_can_neither_view_nor_approve_the_request() -> None:
    service = _service()
    pending = _request(service)

    with pytest.raises(ScanApprovalError) as blocked_view:
        service.pending_view(
            pending.request_id,
            viewer_user_id=OTHER_ID,
            received_at=NOW,
        )
    assert blocked_view.value.code is ScanApprovalErrorCode.OWNER_MISMATCH

    with pytest.raises(ScanApprovalError) as blocked_approval:
        service.approve(
            pending.request_id,
            approving_user_id=OTHER_ID,
            elevated_consent=True,
            decided_at=NOW,
        )
    assert blocked_approval.value.code is ScanApprovalErrorCode.OWNER_MISMATCH


def test_declined_request_is_final_and_reported_to_the_collector() -> None:
    service = _service()
    pending = _request(service)

    service.decline(
        pending.request_id,
        approving_user_id=OWNER_ID,
        decided_at=NOW + timedelta(minutes=1),
    )
    polled = service.poll(pending.request_id, received_at=NOW + timedelta(minutes=2))

    assert polled.state is ScanApprovalState.DECLINED
    with pytest.raises(ScanApprovalError) as decided_twice:
        service.approve(
            pending.request_id,
            approving_user_id=OWNER_ID,
            elevated_consent=True,
            decided_at=NOW + timedelta(minutes=3),
        )
    assert decided_twice.value.code is ScanApprovalErrorCode.ALREADY_DECIDED


def test_request_expires_and_cannot_be_approved_afterwards() -> None:
    service = _service()
    pending = _request(service)
    late = NOW + SCAN_APPROVAL_TTL + timedelta(seconds=1)

    polled = service.poll(pending.request_id, received_at=late)

    assert polled.state is ScanApprovalState.EXPIRED
    with pytest.raises(ScanApprovalError) as expired:
        service.approve(
            pending.request_id,
            approving_user_id=OWNER_ID,
            elevated_consent=True,
            decided_at=late,
        )
    assert expired.value.code is ScanApprovalErrorCode.EXPIRED


def test_unknown_request_is_refused() -> None:
    service = _service()

    with pytest.raises(ScanApprovalError) as unknown:
        service.poll("00000000-0000-4000-8000-000000000000", received_at=NOW)
    assert unknown.value.code is ScanApprovalErrorCode.NOT_FOUND


def test_approval_carries_the_machine_issued_code_to_the_collector() -> None:
    """사용자는 코드를 보지 않습니다. 승인 시 서버가 만든 코드를 프로그램이 받습니다."""

    service = _service()
    pending = _request(service)

    decided = service.approve(
        pending.request_id,
        approving_user_id=OWNER_ID,
        elevated_consent=True,
        decided_at=NOW + timedelta(minutes=1),
        grant_code="ABCD-EFGH-JKLM-NPQR-STUV",
    )
    polled = service.poll(pending.request_id, received_at=NOW + timedelta(minutes=2))

    assert decided.grant_code == "ABCD-EFGH-JKLM-NPQR-STUV"
    assert polled.grant_code == "ABCD-EFGH-JKLM-NPQR-STUV"


def test_pending_and_declined_requests_never_expose_a_code() -> None:
    service = _service()
    pending = _request(service)

    waiting = service.poll(pending.request_id, received_at=NOW)
    service.decline(
        pending.request_id,
        approving_user_id=OWNER_ID,
        decided_at=NOW + timedelta(minutes=1),
    )
    refused = service.poll(pending.request_id, received_at=NOW + timedelta(minutes=2))

    assert waiting.grant_code is None
    assert refused.grant_code is None


def test_owner_facing_view_hides_the_code_from_the_browser() -> None:
    service = _service()
    pending = _request(service)
    service.approve(
        pending.request_id,
        approving_user_id=OWNER_ID,
        elevated_consent=False,
        decided_at=NOW,
        grant_code="ABCD-EFGH-JKLM-NPQR-STUV",
    )

    view = service.pending_view(
        pending.request_id,
        viewer_user_id=OWNER_ID,
        received_at=NOW,
        include_grant=False,
    )

    assert view.state is ScanApprovalState.APPROVED
    assert view.grant_code is None
