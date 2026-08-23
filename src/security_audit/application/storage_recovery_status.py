"""Sanitized IMP-045 storage recovery status for the local product surface."""

from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from security_audit.common.secret_files import SecretFileError
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.models import StorageRecoveryRunRecord
from security_audit.persistence.database.storage_recovery_repository import (
    public_run_values,
)


def _not_run() -> dict[str, object]:
    return {
        "status": "NOT_RUN",
        "status_label": "저장소 복구시험 실행 전",
        "dependency_available": True,
        "postgres_status": "PENDING",
        "redis_status": "PENDING",
        "aistor_status": "PENDING",
        "finding_lineage_reproduced": False,
        "object_hash_reproduced": False,
        "pending_outbox_reconciled": False,
        "independent_failure_domain": False,
        "production_gate_complete": False,
        "raw_data_exposed": False,
        "secret_exposed": False,
    }


def _database_unavailable() -> dict[str, object]:
    return {
        "status": "DEPENDENCY_UNAVAILABLE",
        "status_label": "저장소 연결 확인 필요",
        "dependency_available": False,
        "postgres_status": "연결 확인 필요",
        "redis_status": "상태 확인 대기",
        "aistor_status": "상태 확인 대기",
        "finding_lineage_reproduced": False,
        "object_hash_reproduced": False,
        "pending_outbox_reconciled": False,
        "independent_failure_domain": False,
        "production_gate_complete": False,
        "raw_data_exposed": False,
        "secret_exposed": False,
    }


def latest_storage_recovery_summary() -> dict[str, object]:
    """Return recovery truth without IDs, paths, object keys or credentials."""

    try:
        engine = create_engine(
            ServiceSettings.from_environment().postgres_url(),
            pool_pre_ping=True,
            connect_args={"connect_timeout": 2},
        )
    except (OSError, ValueError, SecretFileError):
        return _database_unavailable()
    try:
        with Session(engine) as session:
            record = session.scalar(
                select(StorageRecoveryRunRecord)
                .order_by(StorageRecoveryRunRecord.created_at.desc())
                .limit(1)
            )
            if record is None:
                return _not_run()
            values = public_run_values(record)
    except (OSError, SQLAlchemyError):
        return _database_unavailable()
    finally:
        engine.dispose()
    status = str(values["status"])
    return {
        **values,
        "status_label": {
            "PREPARING": "복구시험 준비 중",
            "BACKUP_CREATED": "복구본 준비 완료",
            "OUTAGE_TESTING": "장애 대응 확인 중",
            "RESTORE_VALIDATING": "복원 결과 확인 중",
            "SUCCEEDED": "개발 복구훈련 완료",
            "FAILED": "복구 절차 확인 필요",
        }.get(status, "상태 확인 필요"),
        "dependency_available": True,
        "postgres_rpo_target_seconds": 900,
        "postgres_rto_target_seconds": 14400,
        "evidence_rpo_target_seconds": 3600,
        "evidence_rto_target_seconds": 28800,
        "raw_data_exposed": False,
        "secret_exposed": False,
    }
