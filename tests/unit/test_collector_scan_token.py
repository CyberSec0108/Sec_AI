from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from security_audit.collector.scan_token import (
    MAX_SCAN_TOKEN_RUNS,
    SCAN_TOKEN_TTL,
    InMemoryScanTokenStore,
    IssuedScanToken,
    ScanTokenError,
    ScanTokenErrorCode,
    ScanTokenService,
)

NOW = datetime(2026, 8, 23, 6, 0, tzinfo=UTC)
HASH_KEY = b"c" * 32
ORGANIZATION_ID = "46000000-0000-4000-8000-000000000001"
USER_ID = "46000000-0000-4000-8000-000000000003"
ORIGIN = "http://192.168.0.10:18480"


def _service() -> ScanTokenService:
    return ScanTokenService(
        InMemoryScanTokenStore(),
        hash_key=HASH_KEY,
        hash_key_version="v1",
    )


def _issue(
    service: ScanTokenService,
    *,
    issued_at: datetime = NOW,
) -> IssuedScanToken:
    return service.issue(
        organization_id=ORGANIZATION_ID,
        subject_user_id=USER_ID,
        server_origin=ORIGIN,
        issued_at=issued_at,
    )


def test_issued_token_lives_for_one_day_and_allows_three_runs() -> None:
    service = _service()

    issued = _issue(service)

    assert SCAN_TOKEN_TTL == timedelta(hours=24)
    assert MAX_SCAN_TOKEN_RUNS == 3
    assert issued.expires_at == NOW + timedelta(hours=24)
    assert issued.max_runs == 3
    assert issued.server_origin == ORIGIN


def test_three_runs_are_accepted_and_the_fourth_is_refused() -> None:
    service = _service()
    issued = _issue(service)

    remaining = [
        service.start_run(
            issued.token,
            server_origin=ORIGIN,
            received_at=NOW + timedelta(hours=index),
        ).remaining_runs
        for index in range(3)
    ]

    assert remaining == [2, 1, 0]
    with pytest.raises(ScanTokenError) as refused:
        service.start_run(
            issued.token,
            server_origin=ORIGIN,
            received_at=NOW + timedelta(hours=4),
        )
    assert refused.value.code is ScanTokenErrorCode.RUNS_EXHAUSTED


def test_token_is_refused_after_the_day_passes() -> None:
    service = _service()
    issued = _issue(service)

    service.start_run(
        issued.token,
        server_origin=ORIGIN,
        received_at=NOW + timedelta(hours=23, minutes=59),
    )

    with pytest.raises(ScanTokenError) as expired:
        service.start_run(
            issued.token,
            server_origin=ORIGIN,
            received_at=NOW + timedelta(hours=24, seconds=1),
        )
    assert expired.value.code is ScanTokenErrorCode.EXPIRED


def test_unknown_or_tampered_token_and_foreign_origin_are_refused() -> None:
    service = _service()
    issued = _issue(service)

    with pytest.raises(ScanTokenError) as unknown:
        service.start_run("aaaa.bbbb", server_origin=ORIGIN, received_at=NOW)
    assert unknown.value.code is ScanTokenErrorCode.INVALID

    reference, _, _secret = issued.token.partition(".")
    with pytest.raises(ScanTokenError) as tampered:
        service.start_run(
            f"{reference}.{'z' * 43}",
            server_origin=ORIGIN,
            received_at=NOW,
        )
    assert tampered.value.code is ScanTokenErrorCode.INVALID

    with pytest.raises(ScanTokenError) as foreign:
        service.start_run(
            issued.token,
            server_origin="http://10.0.0.9:18480",
            received_at=NOW,
        )
    assert foreign.value.code is ScanTokenErrorCode.SCOPE_MISMATCH


def test_store_keeps_only_the_hmac_and_carries_the_owner_scope() -> None:
    store = InMemoryScanTokenStore()
    service = ScanTokenService(store, hash_key=HASH_KEY, hash_key_version="v1")

    issued = _issue(service)
    reference, _, secret = issued.token.partition(".")
    record = store.get(reference)

    assert record is not None
    assert secret not in record.token_hmac
    assert len(record.token_hmac) == 64
    assert record.subject_user_id == USER_ID
    assert record.organization_id == ORGANIZATION_ID
    assert record.used_runs == 0
