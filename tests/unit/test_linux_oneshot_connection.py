from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from security_audit.collector.linux_connection import (
    DeviceCodeError,
    DeviceCodeErrorCode,
    InMemoryDeviceCodeStore,
    InMemoryExchangeRateLimiter,
    LinuxOneShotConnectionService,
)
from security_audit.security.auth import (
    CollectorCredentialCode,
    CollectorCredentialError,
    CollectorCredentialScope,
    InMemoryCollectorCredentialStore,
)

NOW = datetime(2026, 8, 6, 1, 0, tzinfo=UTC)


def _scope() -> CollectorCredentialScope:
    return CollectorCredentialScope(
        organization_id="81000000-0000-4000-8000-000000000001",
        asset_id="81000000-0000-4000-8000-000000000002",
        job_id="81000000-0000-4000-8000-000000000003",
        manifest_id="81000000-0000-4000-8000-000000000004",
        manifest_sha256="a" * 64,
        nonce="LinuxDeviceCodeNonce00000001",
        endpoint_id="linux.oneshot.submit.v1",
        content_type="application/zip",
        schema_version="2.0.0",
        max_archive_bytes=10 * 1024 * 1024,
    )


def _rocky_scope() -> CollectorCredentialScope:
    original = _scope()
    return CollectorCredentialScope(
        organization_id=original.organization_id,
        asset_id=original.asset_id,
        job_id=original.job_id,
        manifest_id="81000000-0000-4000-8000-000000000014",
        manifest_sha256="b" * 64,
        nonce="LinuxDeviceCodeNonce00000002",
        endpoint_id=original.endpoint_id,
        content_type=original.content_type,
        schema_version=original.schema_version,
        max_archive_bytes=original.max_archive_bytes,
    )


def _service() -> tuple[LinuxOneShotConnectionService, InMemoryDeviceCodeStore]:
    store = InMemoryDeviceCodeStore()
    return (
        LinuxOneShotConnectionService(
            code_store=store,
            credential_store=InMemoryCollectorCredentialStore(),
            hash_key=b"k" * 32,
            hash_key_version="test-v1",
        ),
        store,
    )


def test_device_code_is_human_readable_but_store_keeps_only_hmac() -> None:
    service, store = _service()
    issued = service.issue(
        _scope(),
        subject_user_id="81000000-0000-4000-8000-000000000005",
        manifest={"schema_version": "2.0.0"},
        issued_at=NOW,
    )

    assert issued.code.count("-") == 4
    record = store.get(issued.code_ref)
    assert record is not None
    assert issued.code not in repr(record)
    assert len(record.code_hmac) == 64


def test_code_exchange_returns_one_opaque_256_bit_credential_and_manifest() -> None:
    service, _store = _service()
    issued = service.issue(
        _scope(),
        subject_user_id="81000000-0000-4000-8000-000000000005",
        manifest={"schema_version": "2.0.0"},
        issued_at=NOW,
    )

    exchanged = service.exchange(issued.code, received_at=NOW + timedelta(minutes=1))

    assert exchanged.manifest == {"schema_version": "2.0.0"}
    assert exchanged.credential.token.startswith("secai_job_v1.")
    assert issued.code not in exchanged.credential.token
    with pytest.raises(DeviceCodeError) as replay:
        service.exchange(issued.code, received_at=NOW + timedelta(minutes=2))
    assert replay.value.code is DeviceCodeErrorCode.ALREADY_USED


def test_deferred_exchange_binds_one_code_to_the_detected_distribution_only() -> None:
    service, _store = _service()
    issued = service.issue_choices(
        {
            "UBUNTU_24_04": (_scope(), {"target": {"distribution": "UBUNTU_24_04"}}),
            "ROCKY_9": (_rocky_scope(), {"target": {"distribution": "ROCKY_9"}}),
        },
        subject_user_id="81000000-0000-4000-8000-000000000005",
        issued_at=NOW,
    )

    exchanged = service.exchange(
        issued.code,
        selection_key="ROCKY_9",
        received_at=NOW + timedelta(minutes=1),
    )

    assert exchanged.manifest["target"] == {"distribution": "ROCKY_9"}
    assert exchanged.credential.scope == _rocky_scope()


def test_deferred_exchange_rejects_unknown_selection_without_fallback() -> None:
    service, _store = _service()
    issued = service.issue_choices(
        {
            "UBUNTU_24_04": (_scope(), {"target": {"distribution": "UBUNTU_24_04"}}),
        },
        subject_user_id="81000000-0000-4000-8000-000000000005",
        issued_at=NOW,
    )

    with pytest.raises(DeviceCodeError) as rejected:
        service.exchange(
            issued.code,
            selection_key="DEBIAN_12",
            received_at=NOW + timedelta(minutes=1),
        )

    assert rejected.value.code is DeviceCodeErrorCode.SELECTION_INVALID


def test_expired_or_wrong_code_is_rejected_without_issuing_credential() -> None:
    service, _store = _service()
    issued = service.issue(
        _scope(),
        subject_user_id="81000000-0000-4000-8000-000000000005",
        manifest={"schema_version": "2.0.0"},
        issued_at=NOW,
        ttl=timedelta(minutes=5),
    )
    with pytest.raises(DeviceCodeError) as expired:
        service.exchange(issued.code, received_at=NOW + timedelta(minutes=6))
    assert expired.value.code is DeviceCodeErrorCode.EXPIRED

    changed = issued.code[:-1] + ("A" if issued.code[-1] != "A" else "B")
    with pytest.raises(DeviceCodeError) as invalid:
        service.exchange(changed, received_at=NOW + timedelta(minutes=1))
    assert invalid.value.code is DeviceCodeErrorCode.INVALID


def test_exchanged_credential_is_exact_scope_and_single_success() -> None:
    service, _store = _service()
    issued = service.issue(
        _scope(),
        subject_user_id="81000000-0000-4000-8000-000000000005",
        manifest={"schema_version": "2.0.0"},
        issued_at=NOW,
    )
    token = service.exchange(issued.code, received_at=NOW).credential.token
    authorized = service.authorize(token, received_at=NOW + timedelta(minutes=1))
    assert authorized.scope == _scope()

    receipt = service.commit(
        token,
        received_at=NOW + timedelta(minutes=2),
        package_id="82000000-0000-4000-8000-000000000001",
        archive_sha256="b" * 64,
    )
    assert receipt.job_id == _scope().job_id
    with pytest.raises(CollectorCredentialError) as replay:
        service.commit(
            token,
            received_at=NOW + timedelta(minutes=3),
            package_id="82000000-0000-4000-8000-000000000001",
            archive_sha256="b" * 64,
        )
    assert replay.value.code is CollectorCredentialCode.ALREADY_USED


def test_device_code_exchange_rate_limit_is_per_source_and_time_window() -> None:
    limiter = InMemoryExchangeRateLimiter(maximum=2)

    assert limiter.allow("192.0.2.10", received_at=NOW) is True
    assert limiter.allow("192.0.2.10", received_at=NOW + timedelta(seconds=1)) is True
    assert limiter.allow("192.0.2.10", received_at=NOW + timedelta(seconds=2)) is False
    assert limiter.allow("192.0.2.11", received_at=NOW + timedelta(seconds=2)) is True
    assert limiter.allow("192.0.2.10", received_at=NOW + timedelta(minutes=1)) is True
