from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security_audit.collector.scan_sidecar import (
    ScanSidecarError,
    build_scan_sidecar,
    read_scan_sidecar,
)

NOW = datetime(2026, 8, 26, 6, 0, tzinfo=UTC)
ORIGIN = "http://10.174.47.151:18480"
TOKEN = "0123456789ab.secret-value"  # noqa: S105 - 형식 시험값입니다.
KEY = Ed25519PrivateKey.generate()
KEY_ID = "secai-dev-download-test"


def _sign(payload: bytes) -> tuple[str, bytes]:
    return KEY_ID, KEY.sign(payload)


def _public_keys() -> dict[str, object]:
    return {KEY_ID: KEY.public_key()}


def _document() -> str:
    return build_scan_sidecar(
        token=TOKEN,
        server_origin=ORIGIN,
        expires_at=NOW + timedelta(hours=24),
        max_runs=3,
        sign=_sign,
    )


def test_signed_sidecar_round_trips() -> None:
    sidecar = read_scan_sidecar(_document(), public_keys=_public_keys())

    assert sidecar.server_origin == ORIGIN
    assert sidecar.token == TOKEN


def test_document_tells_the_reader_not_to_edit_it() -> None:
    loaded = json.loads(_document())

    assert "signature" in loaded
    assert loaded["signature"]["algorithm"] == "Ed25519"
    assert "편집" in loaded["notice"]


def test_changing_the_server_address_breaks_the_signature() -> None:
    tampered = json.loads(_document())
    tampered["server_origin"] = "http://10.9.9.9:18480"

    with pytest.raises(ScanSidecarError, match="서명"):
        read_scan_sidecar(json.dumps(tampered), public_keys=_public_keys())


def test_changing_the_token_or_expiry_breaks_the_signature() -> None:
    for field, value in (("token", "aaaa.bbbb"), ("max_runs", 99)):
        tampered = json.loads(_document())
        tampered[field] = value
        with pytest.raises(ScanSidecarError, match="서명"):
            read_scan_sidecar(json.dumps(tampered), public_keys=_public_keys())


def test_unknown_signing_key_is_refused() -> None:
    other = Ed25519PrivateKey.generate()

    with pytest.raises(ScanSidecarError, match="서명"):
        read_scan_sidecar(_document(), public_keys={KEY_ID: other.public_key()})


def test_unsigned_sidecar_is_refused_when_verification_is_required() -> None:
    unsigned = build_scan_sidecar(
        token=TOKEN,
        server_origin=ORIGIN,
        expires_at=NOW + timedelta(hours=24),
        max_runs=3,
    )

    with pytest.raises(ScanSidecarError, match="서명"):
        read_scan_sidecar(unsigned, public_keys=_public_keys())
