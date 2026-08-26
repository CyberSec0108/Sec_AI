from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest

from security_audit.persistence.database.windows_ai_repository import (
    WindowsAIOutputError,
    append_windows_ai_output,
    get_windows_ai_outputs,
)

ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
OWNER_ID = UUID("46000000-0000-4000-8000-000000000003")


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _Session:
    def __init__(self, rows: list[Any] | None = None) -> None:
        self.statements: list[tuple[str, dict[str, Any]]] = []
        self._rows = rows or []

    def execute(self, statement: Any, params: dict[str, Any] | None = None) -> _Result:
        self.statements.append((str(statement), dict(params or {})))
        return _Result(self._rows)


def test_append_scopes_the_write_to_the_owner() -> None:
    session = _Session()
    snapshot_id = uuid4()

    append_windows_ai_output(
        session,  # type: ignore[arg-type]
        organization_id=ORGANIZATION_ID,
        owner_user_id=OWNER_ID,
        snapshot_id=snapshot_id,
        output_key="PC-01",
        content="설명 본문",
        content_sha256="a" * 64,
    )

    scope = [item[0] for item in session.statements[:2]]
    assert scope == [
        "SELECT set_config('secai.organization_id', :value, true)",
        "SELECT set_config('secai.user_id', :value, true)",
    ]
    insert, params = session.statements[-1]
    assert "INSERT INTO windows_audit_ai_outputs" in insert
    assert "ON CONFLICT" in insert
    assert params["snapshot_id"] == snapshot_id
    assert params["output_key"] == "PC-01"


@pytest.mark.parametrize("output_key", ["PC-19", "U-01", "summary", "", "PC-1"])
def test_unsupported_output_keys_are_refused(output_key: str) -> None:
    session = _Session()

    with pytest.raises(WindowsAIOutputError):
        append_windows_ai_output(
            session,  # type: ignore[arg-type]
            organization_id=ORGANIZATION_ID,
            owner_user_id=OWNER_ID,
            snapshot_id=uuid4(),
            output_key=output_key,
            content="설명 본문",
            content_sha256="a" * 64,
        )


def test_reader_returns_one_generation_keyed_by_control() -> None:
    session = _Session(rows=[("PC-01", "첫 설명"), ("SUMMARY", "종합")])

    outputs = get_windows_ai_outputs(
        session,  # type: ignore[arg-type]
        organization_id=ORGANIZATION_ID,
        owner_user_id=OWNER_ID,
        snapshot_id=uuid4(),
    )

    assert outputs == {"PC-01": "첫 설명", "SUMMARY": "종합"}


def test_stream_body_accepts_an_optional_snapshot_to_persist_against() -> None:
    from apps.api.result_ai_explanation import ScanResultExplanationBody

    without = ScanResultExplanationBody(
        explanation_inputs=[{"control_id": "PC-01"}],
        test_environment_result=True,
    )
    with_snapshot = ScanResultExplanationBody(
        explanation_inputs=[{"control_id": "PC-01"}],
        test_environment_result=True,
        snapshot_id="46000000-0000-4000-8000-000000000010",
    )

    assert without.snapshot_id is None
    assert str(with_snapshot.snapshot_id) == "46000000-0000-4000-8000-000000000010"


def test_router_exposes_the_windows_ai_snapshot_restore() -> None:
    from apps.api.result_ai_explanation import router

    paths = {getattr(route, "path", "") for route in router.routes}

    assert "/api/v1/result-explanations/snapshot/{snapshot_id}" in paths


def test_stream_body_accepts_control_ids_already_restored() -> None:
    from apps.api.result_ai_explanation import ScanResultExplanationBody

    body = ScanResultExplanationBody(
        explanation_inputs=[{"control_id": "PC-01"}],
        test_environment_result=True,
        snapshot_id="46000000-0000-4000-8000-000000000010",
        restored_control_ids=["PC-01", "PC-02"],
        restored_summary=True,
    )

    assert body.restored_control_ids == ["PC-01", "PC-02"]
    assert body.restored_summary is True


def test_stream_body_refuses_unknown_control_ids() -> None:
    from apps.api.result_ai_explanation import ScanResultExplanationBody
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ScanResultExplanationBody(
            explanation_inputs=[{"control_id": "PC-01"}],
            test_environment_result=True,
            restored_control_ids=["U-01"],
        )


def test_stored_card_payload_round_trips_source_and_sources() -> None:
    from apps.api.result_ai_explanation import (
        decode_stored_control_card,
        encode_stored_control_card,
    )

    encoded = encode_stored_control_card(
        source="본문입니다.",
        knowledge_sources=[{"citation_id": "[1]"}],
    )
    decoded = decode_stored_control_card(encoded)

    assert decoded == {
        "source": "본문입니다.",
        "knowledge_sources": [{"citation_id": "[1]"}],
    }
    assert decode_stored_control_card("not json") is None


def test_windows_ui_wires_per_control_restore_and_partial_generation() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "apps/web/static/app"
    results = (root / "product-results.js").read_text(encoding="utf-8")
    integrated = (root / "product-results-integrated.js").read_text(encoding="utf-8")

    # 이력 저장 식별자를 통합 화면에 전달한다.
    assert "secai:windows-snapshot-ready" in results
    assert "stored.entry_id" in results
    assert "secai:windows-snapshot-ready" in integrated

    # 저장분을 먼저 읽고, 이미 있는 항목은 다시 만들지 않는다.
    assert "/api/v1/result-explanations/snapshot/" in integrated
    assert "restored_control_ids" in integrated
    assert "restored_summary" in integrated
    assert "snapshot_id: windowsSnapshotId" in integrated


def test_restore_waits_for_the_snapshot_id_before_giving_up() -> None:
    """이력 저장 응답이 늦게 와도 저장분을 놓치지 않아야 합니다."""

    from pathlib import Path

    integrated = (
        Path(__file__).resolve().parents[2]
        / "apps/web/static/app/product-results-integrated.js"
    ).read_text(encoding="utf-8")

    assert "waitForSnapshotId" in integrated
    assert "await waitForSnapshotId" in integrated
