from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from security_audit.collector.linux_cli import (
    _default_sidecar_path,
    _device_name,
    _load_sidecar,
)
from security_audit.collector.scan_sidecar import (
    ScanSidecarError,
    build_scan_sidecar,
)

NOW = datetime(2026, 8, 23, 6, 0, tzinfo=UTC)
ORIGIN = "http://192.168.0.10:18480"
TOKEN = "0123456789ab.secret-value"  # noqa: S105 - 형식 시험값입니다.


def _sidecar_document() -> str:
    return build_scan_sidecar(
        token=TOKEN,
        server_origin=ORIGIN,
        expires_at=NOW + timedelta(hours=24),
        max_runs=3,
    )


def test_hostname_is_reduced_to_a_safe_device_name() -> None:
    assert _device_name("DESKTOP-A17") == "DESKTOP-A17"
    assert _device_name("web01.example.com") == "web01.example.com"
    assert _device_name("서버 01") == "UNKNOWN-DEVICE"
    assert _device_name("") == "UNKNOWN-DEVICE"
    assert len(_device_name("a" * 200)) <= 64


def test_sidecar_is_read_from_the_file_next_to_the_program(tmp_path: Path) -> None:
    path = tmp_path / "secai-linux-check-x86_64.secai-scan.json"
    path.write_text(_sidecar_document(), encoding="utf-8")

    sidecar = _load_sidecar(path)

    assert sidecar is not None
    assert sidecar.server_origin == ORIGIN
    assert sidecar.token == TOKEN


def test_missing_sidecar_falls_back_to_the_manual_code_path(tmp_path: Path) -> None:
    assert _load_sidecar(tmp_path / "absent.secai-scan.json") is None


def test_broken_sidecar_is_reported_instead_of_being_ignored(tmp_path: Path) -> None:
    path = tmp_path / "broken.secai-scan.json"
    path.write_text("{ not json", encoding="utf-8")

    with pytest.raises(ScanSidecarError):
        _load_sidecar(path)


def test_default_sidecar_path_sits_beside_the_program() -> None:
    program = Path("/opt/secai/secai-linux-check-x86_64")

    assert _default_sidecar_path(program) == Path(
        "/opt/secai/secai-linux-check-x86_64.secai-scan.json"
    )
