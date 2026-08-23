"""Sanitized IMP-044 recovery status for the local product surface."""

from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.models import WorkflowStepRecord
from security_audit.persistence.database.queue_repository import (
    RECOVERY_STEP_NAME,
    recovery_probe_status,
)


def _integer(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def latest_queue_recovery_summary() -> dict[str, object]:
    """Return PostgreSQL workflow truth without IDs, payloads or worker details."""

    engine = create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )
    try:
        with Session(engine) as session:
            latest_job_id = session.scalar(
                select(WorkflowStepRecord.job_id)
                .where(WorkflowStepRecord.step_name == RECOVERY_STEP_NAME)
                .order_by(WorkflowStepRecord.created_at.desc())
                .limit(1)
            )
            if latest_job_id is None:
                return {
                    "status": "NOT_RUN",
                    "status_label": "복구 시험 실행 전",
                    "attempt_count": 0,
                    "worker_lost_count": 0,
                    "result_count": 0,
                    "duplicate_result_count": 0,
                    "finding_count_changed": False,
                    "settings_modified": False,
                    "official_finding_created": False,
                }
            raw = recovery_probe_status(session, latest_job_id)
    finally:
        engine.dispose()
    result_count = _integer(raw["result_count"])
    status = str(raw["status"])
    return {
        "status": status,
        "status_label": {
            "DISPATCH_PENDING": "전달 대기",
            "QUEUED": "Worker 대기",
            "RUNNING": "복구 시험 진행 중",
            "SUCCEEDED": "복구 확인 완료",
            "FAILED": "복구 확인 필요",
            "QUARANTINED": "운영 검토 필요",
        }.get(status, "상태 확인 필요"),
        "outbox_status": raw["outbox_status"],
        "attempt_count": raw["attempt_count"],
        "worker_lost_count": raw["worker_lost_count"],
        "result_count": result_count,
        "duplicate_result_count": max(result_count - 1, 0),
        "settings_modified": False,
        "official_finding_created": False,
        "raw_payload_exposed": False,
    }
