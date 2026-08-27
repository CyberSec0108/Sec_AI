from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from security_audit.collector.scan_sidecar import (
    ScanSidecarError,
    build_scan_sidecar,
    read_scan_sidecar,
)
from security_audit.collector.scan_sidecar_keys import (
    ScanSidecarKeyError,
    read_trusted_public_keys,
    signer_from_seed,
    trusted_keys_document,
)

SEED = "0" * 43
ORIGIN = "http://10.174.47.151:18480"


def test_the_same_seed_always_produces_the_same_key_id() -> None:
    first_id, _ = signer_from_seed(SEED)
    second_id, _ = signer_from_seed(SEED)

    assert first_id == second_id
    assert len(first_id) == 16


def test_a_sidecar_signed_by_the_server_verifies_against_the_published_keys() -> None:
    key_id, sign = signer_from_seed(SEED)
    document = build_scan_sidecar(
        token="0123456789ab.secret",  # noqa: S106 - 형식 시험값입니다.
        server_origin=ORIGIN,
        expires_at=datetime(2026, 8, 27, tzinfo=UTC) + timedelta(hours=24),
        max_runs=3,
        sign=sign,
    )
    published = trusted_keys_document(SEED)

    sidecar = read_scan_sidecar(
        document,
        public_keys=read_trusted_public_keys(published),
    )

    assert sidecar.server_origin == ORIGIN
    assert json.loads(published)["keys"][0]["key_id"] == key_id


def test_keys_from_another_server_do_not_verify() -> None:
    _, sign = signer_from_seed(SEED)
    document = build_scan_sidecar(
        token="0123456789ab.secret",  # noqa: S106 - 형식 시험값입니다.
        server_origin=ORIGIN,
        expires_at=datetime(2026, 8, 27, tzinfo=UTC) + timedelta(hours=24),
        max_runs=3,
        sign=sign,
    )
    other = trusted_keys_document("1" * 43)

    with pytest.raises(ScanSidecarError, match="서명"):
        read_scan_sidecar(document, public_keys=read_trusted_public_keys(other))


def test_an_unusable_seed_is_reported_clearly() -> None:
    with pytest.raises(ScanSidecarKeyError):
        signer_from_seed("short")


def test_a_damaged_trusted_key_file_is_reported_clearly() -> None:
    with pytest.raises(ScanSidecarKeyError):
        read_trusted_public_keys('{"keys": [{"key_id": "x", "public_key": "!!"}]}')


def _source(relative: str) -> str:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    return (root / relative).read_text(encoding="utf-8")


def test_the_windows_collector_verifies_the_sidecar_before_using_it() -> None:
    source = _source("src/security_audit/collector/cli.py")

    assert "load_verified_sidecar" in source


def test_the_linux_collector_verifies_the_sidecar_before_using_it() -> None:
    source = _source("src/security_audit/collector/linux_cli.py")

    assert "load_verified_sidecar" in source


def test_the_build_embeds_the_trusted_key_next_to_the_program() -> None:
    script = _source("tools/build_imp034_collector.py")

    assert "trusted_keys_document" in script
    assert "scan_sidecar_trusted_keys.json" in script


def test_without_a_sidecar_the_trusted_key_is_not_needed(tmp_path) -> None:
    from security_audit.collector.scan_sidecar_keys import load_verified_sidecar

    missing = tmp_path / "program.secai-scan.json"

    assert load_verified_sidecar(missing, tmp_path / "no-resources") is None


def test_with_a_sidecar_the_trusted_key_must_be_present(tmp_path) -> None:
    from security_audit.collector.scan_sidecar_keys import load_verified_sidecar

    sidecar = tmp_path / "program.secai-scan.json"
    sidecar.write_text("{}", encoding="utf-8")

    with pytest.raises(ScanSidecarKeyError):
        load_verified_sidecar(sidecar, tmp_path / "no-resources")


def test_the_linux_build_takes_the_key_without_writing_into_the_source_tree() -> None:
    script = _source("tools/build_linux_oneshot_collector.py")
    runner = _source("tools/build-linux-oneshot.ps1")

    assert "--sidecar-signing-key-file" in script
    assert 'work / "scan_sidecar_trusted_keys.json"' in script
    assert "scan-sidecar-signing-key" in runner
