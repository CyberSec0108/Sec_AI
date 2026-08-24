from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from security_audit.collector.scan_approval import (
    InMemoryScanApprovalStore,
    ScanApprovalError,
    ScanApprovalErrorCode,
    ScanApprovalService,
    ScanApprovalState,
)
from security_audit.collector.scan_session import ScanSessionService
from security_audit.collector.scan_token import (
    InMemoryScanTokenStore,
    ScanTokenError,
    ScanTokenErrorCode,
    ScanTokenService,
)

NOW = datetime(2026, 8, 23, 6, 0, tzinfo=UTC)
ORGANIZATION_ID = "46000000-0000-4000-8000-000000000001"
OWNER_ID = "46000000-0000-4000-8000-000000000003"
OTHER_ID = "46000000-0000-4000-8000-000000000099"
ORIGIN = "http://192.168.0.10:18480"


def _session() -> tuple[ScanSessionService, ScanTokenService]:
    tokens = ScanTokenService(
        InMemoryScanTokenStore(),
        hash_key=b"s" * 32,
        hash_key_version="v1",
    )
    approvals = ScanApprovalService(InMemoryScanApprovalStore())
    return ScanSessionService(tokens=tokens, approvals=approvals), tokens


def _token(tokens: ScanTokenService) -> str:
    return tokens.issue(
        organization_id=ORGANIZATION_ID,
        subject_user_id=OWNER_ID,
        server_origin=ORIGIN,
        issued_at=NOW,
    ).token


def test_register_spends_one_run_and_returns_the_owner_approval_url() -> None:
    session, tokens = _session()
    token = _token(tokens)

    registered = session.register(
        token,
        device_name="DESKTOP-A17",
        server_origin=ORIGIN,
        received_at=NOW,
    )

    assert registered.remaining_runs == 2
    assert registered.approve_url == (
        f"{ORIGIN}/ui/scan-approve?req={registered.request_id}"
    )
    assert registered.expires_at == NOW + timedelta(minutes=10)


def test_registered_request_belongs_to_the_token_owner_only() -> None:
    session, tokens = _session()
    registered = session.register(
        _token(tokens),
        device_name="DESKTOP-A17",
        server_origin=ORIGIN,
        received_at=NOW,
    )

    view = session.pending_view(
        registered.request_id,
        viewer_user_id=OWNER_ID,
        received_at=NOW,
    )
    assert view.device_name == "DESKTOP-A17"

    with pytest.raises(ScanApprovalError) as blocked:
        session.pending_view(
            registered.request_id,
            viewer_user_id=OTHER_ID,
            received_at=NOW,
        )
    assert blocked.value.code is ScanApprovalErrorCode.OWNER_MISMATCH


def test_collector_polls_until_the_owner_approves_with_consent() -> None:
    session, tokens = _session()
    registered = session.register(
        _token(tokens),
        device_name="DESKTOP-A17",
        server_origin=ORIGIN,
        received_at=NOW,
    )

    waiting = session.poll(registered.request_id, received_at=NOW)
    session.approve(
        registered.request_id,
        approving_user_id=OWNER_ID,
        elevated_consent=True,
        decided_at=NOW + timedelta(minutes=1),
    )
    granted = session.poll(
        registered.request_id,
        received_at=NOW + timedelta(minutes=2),
    )

    assert waiting.state is ScanApprovalState.PENDING
    assert granted.state is ScanApprovalState.APPROVED
    assert granted.elevated_consent is True


def test_expired_or_exhausted_token_cannot_register_a_new_run() -> None:
    session, tokens = _session()
    token = _token(tokens)

    for index in range(3):
        session.register(
            token,
            device_name=f"DESKTOP-A1{index}",
            server_origin=ORIGIN,
            received_at=NOW,
        )

    with pytest.raises(ScanTokenError) as exhausted:
        session.register(
            token,
            device_name="DESKTOP-A17",
            server_origin=ORIGIN,
            received_at=NOW,
        )
    assert exhausted.value.code is ScanTokenErrorCode.RUNS_EXHAUSTED

    fresh_session, fresh_tokens = _session()
    with pytest.raises(ScanTokenError) as expired:
        fresh_session.register(
            _token(fresh_tokens),
            device_name="DESKTOP-A17",
            server_origin=ORIGIN,
            received_at=NOW + timedelta(hours=24, seconds=1),
        )
    assert expired.value.code is ScanTokenErrorCode.EXPIRED


def test_issued_sidecar_token_can_immediately_register_a_run() -> None:
    session, _tokens = _session()

    issued = session.issue_token(
        organization_id=ORGANIZATION_ID,
        subject_user_id=OWNER_ID,
        server_origin=ORIGIN,
        issued_at=NOW,
    )
    registered = session.register(
        issued.token,
        device_name="DESKTOP-A17",
        server_origin=ORIGIN,
        received_at=NOW + timedelta(hours=1),
    )

    assert issued.max_runs == 3
    assert issued.expires_at == NOW + timedelta(hours=24)
    assert registered.remaining_runs == 2
