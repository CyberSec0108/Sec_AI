from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from apps.api.linux_oneshot import (
    CreateLinuxOneShotBody,
    ExchangeLinuxOneShotBody,
    _pending_conflict_error,
    _pending_run_action,
    _validate_and_commit,
)
from fastapi import HTTPException
from pydantic import ValidationError

from security_audit.analysis.package_validation import PackageAuthenticationKind
from security_audit.persistence.database.linux_oneshot_repository import (
    LinuxOneShotRunRecord,
    find_pending_linux_oneshot_run,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class _RecordingResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def first(self) -> Any | None:
        return self._rows[0] if self._rows else None


class _RecordingSession:
    """SQL 본문과 인자만 확인하는 최소 stub입니다."""

    def __init__(
        self,
        statements: list[tuple[str, dict[str, Any]]],
        rows: list[Any],
    ) -> None:
        self._statements = statements
        self._rows = rows

    def execute(
        self,
        statement: Any,
        params: dict[str, Any] | None = None,
    ) -> _RecordingResult:
        self._statements.append((str(statement), dict(params or {})))
        return _RecordingResult(self._rows)


def test_oneshot_request_auto_discovers_distribution_and_rejects_manual_override() -> None:
    body = CreateLinuxOneShotBody(criteria=None)
    exchange = ExchangeLinuxOneShotBody(
        code="ABCD-EFGH-JKLM-NPQR-STUV",
        os_release='ID=rocky\nVERSION_ID="9.4"\n',
        machine="x86_64",
    )

    assert body.criteria is None
    assert exchange.machine == "x86_64"
    with pytest.raises(ValidationError):
        CreateLinuxOneShotBody(distribution="ROCKY_9", criteria=None)


def test_oneshot_ui_removes_distribution_choice_and_explains_auto_detection() -> None:
    page = (
        PROJECT_ROOT / "apps/web/templates/pages/linux_self_scan.html"
    ).read_text(encoding="utf-8")
    script = (
        PROJECT_ROOT / "apps/web/static/app/linux-self-scan.js"
    ).read_text(encoding="utf-8")

    assert 'name="self-distribution"' not in page
    assert "서버 종류와 버전은 프로그램이 자동으로 확인합니다" in page
    assert "selectedDistribution" not in script
    assert "JSON.stringify({criteria: null})" in script


def test_auto_binding_migration_adds_placeholder_then_exact_distribution() -> None:
    migration = (
        PROJECT_ROOT
        / "database/alembic/versions/0032_linux_oneshot_auto_discovery.py"
    ).read_text(encoding="utf-8")

    assert 'revision: str = "0032_linux_auto_discovery"' in migration
    assert 'down_revision: str | None = "0031_unified_audit_history"' in migration
    assert "self-auto" in migration
    assert "'AUTO'" in migration


def _descriptor() -> dict[str, Any]:
    path = (
        PROJECT_ROOT
        / "database"
        / "schemas"
        / "examples"
        / "valid"
        / "linux_audit_package.json"
    )
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def test_scope_mismatch_is_rejected_before_archive_or_rule_processing(
    tmp_path: Path,
) -> None:
    descriptor = _descriptor()
    record = LinuxOneShotRunRecord(
        run_id=UUID(descriptor["job_id"]),
        organization_id=UUID(descriptor["organization_id"]),
        owner_user_id=UUID(descriptor["subject_user_id"]),
        asset_id=UUID(descriptor["asset_id"]),
        distribution="UBUNTU_24_04",
        status="WAITING_UPLOAD",
        manifest={
            "id": descriptor["manifest_id"],
            "nonce": descriptor["nonce"],
            "execution_attempt_id": descriptor["execution_attempt_id"],
        },
        manifest_sha256=descriptor["manifest_hash"],
        package_sha256=None,
        submission_profile=None,
        assurance_level=None,
        result_json=None,
        result_sha256=None,
    )
    descriptor["job_id"] = "63000000-0000-4000-8000-000000000099"

    with pytest.raises(HTTPException) as rejected:
        _validate_and_commit(
            archive_path=tmp_path / "must-not-be-opened.zip",
            descriptor_bytes=json.dumps(descriptor).encode(),
            record=record,
            authentication_kind=PackageAuthenticationKind.OFFLINE_SUBMITTER,
            received_at=datetime(2026, 8, 6, tzinfo=UTC),
        )

    assert rejected.value.status_code == 403
    detail = cast(dict[str, str], rejected.value.detail)
    assert detail["code"] == "SUBMISSION_SCOPE_MISMATCH"


def test_expired_waiting_upload_run_is_replaced_and_fresh_one_conflicts() -> None:
    now = datetime(2026, 8, 23, 1, 0, tzinfo=UTC)

    assert _pending_run_action(datetime(2026, 8, 23, 0, 59, tzinfo=UTC), now) == "REPLACE"
    assert _pending_run_action(now, now) == "REPLACE"
    assert _pending_run_action(None, now) == "REPLACE"
    assert _pending_run_action(datetime(2026, 8, 23, 1, 30, tzinfo=UTC), now) == "CONFLICT"


def test_pending_conflict_tells_the_user_which_run_to_cancel() -> None:
    pending = UUID("dd627bc3-4a8e-4270-be26-a701be8d1c8a")

    rejected = _pending_conflict_error(pending)

    assert rejected.status_code == 409
    detail = cast(dict[str, str], rejected.detail)
    assert detail["code"] == "LINUX_ONESHOT_ALREADY_WAITING"
    assert detail["pending_run_id"] == str(pending)
    assert "취소" in detail["message"]


def test_pending_lookup_reads_only_active_owner_scoped_self_scans() -> None:
    statements: list[tuple[str, dict[str, Any]]] = []
    session = _RecordingSession(statements, rows=[])

    found = find_pending_linux_oneshot_run(
        cast(Any, session),
        organization_id=UUID("46000000-0000-4000-8000-000000000001"),
        owner_user_id=UUID("46000000-0000-4000-8000-000000000003"),
        asset_key="self-auto",
    )

    assert found is None
    query = statements[-1][0]
    assert "run_mode = 'ONESHOT_SELF'" in query
    assert "deleted_at IS NULL" in query
    assert "'WAITING_UPLOAD', 'VALIDATING'" in query
    assert statements[-1][1]["asset_key"] == "self-auto"
    assert [item[0] for item in statements[:2]] == [
        "SELECT set_config('secai.organization_id', :value, true)",
        "SELECT set_config('secai.user_id', :value, true)",
    ]


def test_self_scan_ui_shows_the_server_message_and_offers_cancellation() -> None:
    page = (
        PROJECT_ROOT / "apps/web/templates/pages/linux_self_scan.html"
    ).read_text(encoding="utf-8")
    script = (
        PROJECT_ROOT / "apps/web/static/app/linux-self-scan.js"
    ).read_text(encoding="utf-8")

    assert 'id="self-cancel-pending"' in page
    assert "readErrorDetail" in script
    assert "pending_run_id" in script
    assert 'method: "DELETE"' in script
    assert "새 Linux 자가 점검을 만들지 못했습니다" in script
