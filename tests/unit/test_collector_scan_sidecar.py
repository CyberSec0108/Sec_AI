from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from security_audit.collector.scan_sidecar import (
    SIDECAR_NOTICE,
    SIDECAR_SCHEMA_VERSION,
    ScanSidecarError,
    build_scan_sidecar,
    read_scan_sidecar,
)

NOW = datetime(2026, 8, 23, 6, 0, tzinfo=UTC)
ORIGIN = "http://192.168.0.10:18480"
TOKEN = "0123456789ab.RUJ0Q0hGSjJLTE1OT1BRUlNUVVZXWFla"  # noqa: S105 - 형식 시험값


def test_sidecar_carries_the_server_and_token_without_extra_secrets() -> None:
    document = build_scan_sidecar(
        token=TOKEN,
        server_origin=ORIGIN,
        expires_at=NOW + timedelta(hours=24),
        max_runs=3,
    )

    assert json.loads(document) == {
        "schema_version": SIDECAR_SCHEMA_VERSION,
        "server_origin": ORIGIN,
        "token": TOKEN,
        "expires_at": "2026-08-24T06:00:00Z",
        "max_runs": 3,
        "notice": SIDECAR_NOTICE,
    }


def test_reader_returns_the_server_and_token_for_the_collector() -> None:
    document = build_scan_sidecar(
        token=TOKEN,
        server_origin=ORIGIN,
        expires_at=NOW + timedelta(hours=24),
        max_runs=3,
    )

    sidecar = read_scan_sidecar(document)

    assert sidecar.server_origin == ORIGIN
    assert sidecar.token == TOKEN
    assert sidecar.expires_at == NOW + timedelta(hours=24)
    assert sidecar.max_runs == 3


def test_reader_refuses_broken_or_unsafe_documents() -> None:
    with pytest.raises(ScanSidecarError):
        read_scan_sidecar("not json")

    with pytest.raises(ScanSidecarError):
        read_scan_sidecar(json.dumps({"schema_version": "9.9.9"}))

    with pytest.raises(ScanSidecarError):
        read_scan_sidecar(
            json.dumps(
                {
                    "schema_version": SIDECAR_SCHEMA_VERSION,
                    "server_origin": "ftp://192.168.0.10",
                    "token": TOKEN,
                    "expires_at": "2026-08-24T06:00:00Z",
                    "max_runs": 3,
                }
            )
        )


def test_builder_refuses_an_origin_that_is_not_an_exact_http_origin() -> None:
    with pytest.raises(ScanSidecarError):
        build_scan_sidecar(
            token=TOKEN,
            server_origin="http://192.168.0.10:18480/ui/",
            expires_at=NOW + timedelta(hours=24),
            max_runs=3,
        )


def test_settings_file_name_does_not_look_like_an_executable() -> None:
    from security_audit.collector.scan_sidecar import sidecar_name

    assert sidecar_name("SecAI-Collector-Windows-x64.exe") == (
        "SecAI-Collector-Windows-x64.secai-scan.json"
    )
    assert sidecar_name("SecAI-Collector-Windows-x64.EXE") == (
        "SecAI-Collector-Windows-x64.secai-scan.json"
    )
    assert sidecar_name("secai-linux-check-x86_64") == (
        "secai-linux-check-x86_64.secai-scan.json"
    )


def test_the_program_looks_for_the_settings_file_next_to_itself(tmp_path) -> None:
    from security_audit.collector.scan_sidecar import existing_sidecar_path

    program = tmp_path / "SecAI-Collector-Windows-x64.exe"
    program.write_text("", encoding="utf-8")
    expected = tmp_path / "SecAI-Collector-Windows-x64.secai-scan.json"

    assert existing_sidecar_path(program) == expected

    expected.write_text("{}", encoding="utf-8")
    assert existing_sidecar_path(program) == expected


def test_a_settings_file_downloaded_before_the_rename_still_works(tmp_path) -> None:
    from security_audit.collector.scan_sidecar import existing_sidecar_path

    program = tmp_path / "SecAI-Collector-Windows-x64.exe"
    program.write_text("", encoding="utf-8")
    legacy = tmp_path / "SecAI-Collector-Windows-x64.exe.secai-scan.json"
    legacy.write_text("{}", encoding="utf-8")

    assert existing_sidecar_path(program) == legacy
