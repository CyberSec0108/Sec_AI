from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from apps.api.main import app
from fastapi.testclient import TestClient

from security_audit.application.product_features import (
    FeatureState,
    public_feature_registry,
)
from security_audit.persistence.database.queue_repository import (
    QueueRecoveryCode,
    QueueRecoveryError,
    validate_recovery_message,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"


def _valid_message() -> dict[str, object]:
    job_id = "44000000-0000-4000-8000-000000000001"
    return {
        "schema_version": "1.0",
        "task_name": "secai.maintenance.verify_delivery",
        "job_id": job_id,
        "asset_id": "44000000-0000-4000-8000-000000000002",
        "workflow_step": "IMP044_RECOVERY_PROBE",
        "expected_input_version": 1,
        "idempotency_key": f"job:{job_id}:IMP044_RECOVERY_PROBE:v1",
        "correlation_id": "44000000-0000-4000-8000-000000000003",
        "created_at": "2026-07-24T02:00:00Z",
    }


def test_imp044_policy_keeps_postgresql_as_truth_and_payload_identifier_only() -> None:
    policy = json.loads(
        (SCHEMA_ROOT / "imp044_queue_recovery_policy.json").read_text(
            encoding="utf-8"
        )
    )

    assert policy["delivery"]["guarantee"] == "AT_LEAST_ONCE"
    assert policy["delivery"]["result_backend_used"] is False
    assert policy["delivery"]["task_payload"] == "IDENTIFIERS_ONLY"
    assert policy["truth"]["workflow_state"] == "PostgreSQL"
    assert policy["truth"]["redis_is_rebuildable_transport"] is True
    assert policy["recovery"]["maximum_logical_results"] == 1
    assert policy["recovery"]["official_finding_count_change"] == 0
    assert policy["isolation"]["public_trigger_endpoint"] is False


def test_queue_message_is_exactly_bound_and_contains_no_sensitive_fields() -> None:
    validated = validate_recovery_message(_valid_message())

    assert UUID(str(validated["job_id"]))
    assert UUID(str(validated["asset_id"]))
    assert frozenset(validated) == {
        "schema_version",
        "task_name",
        "job_id",
        "asset_id",
        "workflow_step",
        "expected_input_version",
        "idempotency_key",
        "correlation_id",
        "created_at",
    }
    serialized = json.dumps(validated).casefold()
    for prohibited in (
        "password",
        "cookie",
        "token",
        "evidence_value",
        "registry",
        "command",
        "file_path",
    ):
        assert prohibited not in serialized


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("task_name", "user.supplied.task"),
        ("schema_version", "2.0"),
        ("workflow_step", "USER_STEP"),
        ("expected_input_version", 2),
        ("idempotency_key", "attacker-controlled"),
        ("job_id", "not-a-uuid"),
        ("created_at", "2026-07-24"),
    ),
)
def test_queue_message_rejects_untrusted_routing_or_scope(
    field: str,
    value: object,
) -> None:
    message = _valid_message()
    message[field] = value

    with pytest.raises(QueueRecoveryError) as captured:
        validate_recovery_message(message)

    assert captured.value.code == QueueRecoveryCode.INVALID_MESSAGE


def test_queue_message_rejects_unknown_fields() -> None:
    message = _valid_message()
    message["unexpected"] = "not-allowed"

    with pytest.raises(QueueRecoveryError):
        validate_recovery_message(message)


def test_worker_configuration_has_late_ack_loss_requeue_and_json_only() -> None:
    source = (PROJECT_ROOT / "apps" / "worker" / "celery_app.py").read_text(
        encoding="utf-8"
    )

    for setting in (
        'accept_content=["json"]',
        "task_acks_late=True",
        "task_acks_on_failure_or_timeout=True",
        "task_reject_on_worker_lost=True",
        "worker_prefetch_multiplier=1",
        "task_ignore_result=True",
        "worker_enable_remote_control=False",
    ):
        assert setting in source
    assert "pickle" not in source.casefold()
    assert "yaml" not in source.casefold()


def test_migration_has_outbox_attempt_result_uniqueness_and_runtime_grants() -> None:
    source = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0003_imp044_queue_outbox_recovery.py"
    ).read_text(encoding="utf-8")

    for table in (
        "workflow_steps",
        "outbox_events",
        "task_executions",
        "workflow_results",
    ):
        assert f'"{table}"' in source
    assert "uq_workflow_results_idempotency_key" in source
    assert "uq_task_executions_step_attempt" in source
    assert "GRANT SELECT, INSERT, UPDATE" in source


def test_queue_recovery_page_is_live_and_uses_sanitized_postgresql_status(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setattr(
        "apps.api.queue_recovery.latest_queue_recovery_summary",
        lambda: {
            "status": "SUCCEEDED",
            "status_label": "복구 확인 완료",
            "outbox_status": "PUBLISHED",
            "attempt_count": 3,
            "worker_lost_count": 1,
            "result_count": 1,
            "duplicate_result_count": 0,
            "settings_modified": False,
            "official_finding_created": False,
            "raw_payload_exposed": False,
        },
    )
    with TestClient(app) as client:
        page = client.get("/ui/queue-recovery")
        status_response = client.get("/api/v1/queue-recovery/status")

    assert page.status_code == 200
    for phrase in (
        "중간에 작업이 멈춰도 결과를 잃지 않습니다",
        "PostgreSQL",
        "중단 감지",
        "중복 결과",
        "공식 Finding 생성",
    ):
        assert phrase in page.text
    assert 'data-ui-standard="queue-recovery-v1"' in page.text
    assert status_response.status_code == 200
    assert status_response.json()["duplicate_result_count"] == 0
    registry = public_feature_registry()
    assert registry["queue_recovery"].state is FeatureState.LIVE
    assert registry["queue_recovery"].href == "/ui/queue-recovery"


def test_queue_recovery_surface_is_hidden_outside_development(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "false")
    with TestClient(app) as client:
        assert client.get("/ui/queue-recovery").status_code == 404
        assert client.get("/api/v1/queue-recovery/status").status_code == 404
