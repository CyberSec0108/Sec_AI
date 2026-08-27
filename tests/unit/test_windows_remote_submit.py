from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from security_audit.collector.scan_approval import (
    InMemoryScanApprovalStore,
    ScanApprovalService,
)
from security_audit.collector.scan_session import ScanSessionService
from security_audit.collector.scan_token import (
    InMemoryScanTokenStore,
    ScanTokenService,
)

NOW = datetime(2026, 8, 26, 6, 0, tzinfo=UTC)
ORGANIZATION_ID = "46000000-0000-4000-8000-000000000001"
OWNER_ID = "46000000-0000-4000-8000-000000000003"
ASSET_ID = "46000000-0000-4000-8000-000000000002"
ORIGIN = "http://192.168.0.10:18480"


def _session() -> tuple[ScanSessionService, ScanTokenService]:
    tokens = ScanTokenService(
        InMemoryScanTokenStore(),
        hash_key=b"w" * 32,
        hash_key_version="v1",
    )
    return (
        ScanSessionService(
            tokens=tokens,
            approvals=ScanApprovalService(InMemoryScanApprovalStore()),
        ),
        tokens,
    )


def _approved() -> tuple[ScanSessionService, str, str]:
    session, tokens = _session()
    token = tokens.issue(
        organization_id=ORGANIZATION_ID,
        subject_user_id=OWNER_ID,
        server_origin=ORIGIN,
        issued_at=NOW,
    ).token
    registered = session.register(
        token,
        device_name="DESKTOP-A17",
        server_origin=ORIGIN,
        received_at=NOW,
    )
    session.approve(
        registered.request_id,
        approving_user_id=OWNER_ID,
        elevated_consent=False,
        decided_at=NOW,
        asset_id=ASSET_ID,
    )
    return session, registered.request_id, token


def test_approval_records_the_asset_chosen_by_the_signed_in_owner() -> None:
    session, request_id, token = _approved()

    authorized = session.authorize_exchange(
        request_id,
        token=token,
        server_origin=ORIGIN,
        received_at=NOW + timedelta(minutes=1),
    )

    assert authorized.asset_id == ASSET_ID
    assert authorized.organization_id == ORGANIZATION_ID
    assert authorized.subject_user_id == OWNER_ID


def test_submission_endpoint_is_exposed_for_the_collector() -> None:
    from apps.api.scan_approval import router

    paths = {getattr(route, "path", "") for route in router.routes}

    assert "/api/v1/windows/scan/results" in paths


def test_submission_body_requires_the_token_and_the_result() -> None:
    from apps.api.scan_approval import SubmitWindowsResultBody
    from pydantic import ValidationError

    body = SubmitWindowsResultBody(
        token="0123456789ab.secret",  # noqa: S106 - 형식 시험값입니다.
        result={"result_kind": "LIVE_DRAFT_ASSESSMENT"},
    )

    assert body.result["result_kind"] == "LIVE_DRAFT_ASSESSMENT"
    with pytest.raises(ValidationError):
        SubmitWindowsResultBody(token="only-token")  # type: ignore[call-arg]  # noqa: S106
