from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from security_audit.application.windows_result_document import (
    WindowsResultDocumentError,
    build_windows_result_document,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _receipt() -> dict[str, Any]:
    return {
        "observed_at_utc": "2026-08-26T06:00:00Z",
        "results": [],
        "vulnerability_inventory": None,
    }


def test_document_carries_the_fixed_safety_flags() -> None:
    document = build_windows_result_document(
        PROJECT_ROOT,
        receipt=_receipt(),
        controls=[],
        result_id="a1b2c3d4e5f60718",
        sequence=1,
        attempt=1,
    )

    assert document["raw_values_persisted"] is False
    assert document["settings_modified"] is False
    assert document["official_finding_created"] is False
    assert document["ai_input_contains_raw_evidence"] is False
    assert document["result_id"] == "a1b2c3d4e5f60718"
    assert document["sequence"] == 1
    assert document["attempt"] == 1


def test_incomplete_rule_results_are_reported_as_collection_guidance() -> None:
    document = build_windows_result_document(
        PROJECT_ROOT,
        receipt=_receipt(),
        controls=[
            {
                "control_id": "PC-01",
                "display_status": "EVIDENCE_COLLECTED",
                "assessment_status": None,
            }
        ],
        result_id="a1b2c3d4e5f60718",
        sequence=1,
        attempt=1,
    )

    assert document["result_kind"] == "COLLECTION_GUIDANCE"
    assert document["explanations"] == []
    assert document["ai_explanation_inputs"] == []


def test_result_id_must_be_a_sixteen_character_hex() -> None:
    with pytest.raises(WindowsResultDocumentError):
        build_windows_result_document(
            PROJECT_ROOT,
            receipt=_receipt(),
            controls=[],
            result_id="not-hex",
            sequence=1,
            attempt=1,
        )


def test_cli_exposes_a_remote_scan_command() -> None:
    from security_audit.collector import cli

    parser = cli._parser()
    arguments = parser.parse_args(["remote-scan"])

    assert arguments.command == "remote-scan"


def test_remote_scan_falls_back_to_the_local_bridge_without_a_sidecar() -> None:
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[2]
        / "src/security_audit/collector/cli.py"
    ).read_text(encoding="utf-8")

    assert "perform_scan_handshake" in source
    assert "/api/v1/windows/scan/results" in source
    assert "build_windows_result_document" in source


def test_a_server_refusal_is_explained_instead_of_a_traceback(monkeypatch) -> None:
    """토큰이 만료되면 사용자에게 파이썬 traceback이 아니라 안내가 보여야 합니다."""

    import httpx

    from security_audit.collector import cli

    def _fail(_sidecar_path: object) -> int:
        request = httpx.Request("POST", "http://127.0.0.1:18480/api/v1/scan/approvals")
        raise httpx.HTTPStatusError(
            "401",
            request=request,
            response=httpx.Response(401, request=request),
        )

    monkeypatch.setattr(cli, "_remote_scan", _fail)

    assert cli.main(["remote-scan"]) == 1
