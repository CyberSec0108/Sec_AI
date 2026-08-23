"""조직·사용자 범위로 격리된 네트워크 스위치 점검 결과 저장소."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session


def set_switch_audit_scope(
    session: Session,
    organization_id: UUID,
    owner_user_id: UUID,
) -> None:
    session.execute(
        text("SELECT set_config('secai.organization_id', :value, true)"),
        {"value": str(organization_id)},
    )
    session.execute(
        text("SELECT set_config('secai.user_id', :value, true)"),
        {"value": str(owner_user_id)},
    )


@dataclass(frozen=True, slots=True)
class SwitchAuditRunRecord:
    id: UUID
    asset_key: str
    asset_id: UUID
    platform: str
    platform_version: str
    status: str
    result_json: dict[str, Any] | None
    result_sha256: str | None
    error_code: str | None
    created_at: datetime
    completed_at: datetime | None


def create_switch_audit_run(
    session: Session,
    *,
    run_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    asset_key: str,
    asset_id: UUID,
    platform_version: str,
) -> None:
    set_switch_audit_scope(session, organization_id, owner_user_id)
    session.execute(
        text(
            """
            INSERT INTO switch_audit_runs (
                id, organization_id, owner_user_id, asset_key, asset_id,
                platform, platform_version, benchmark_id, status
            ) VALUES (
                :id, :organization_id, :owner_user_id, :asset_key, :asset_id,
                'ARUBA_AOS_CX', :platform_version,
                'SECAI-KISA-2026-N01-N38-AOSCX-DRAFT', 'QUEUED'
            )
            """
        ),
        {
            "id": run_id,
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "asset_key": asset_key,
            "asset_id": asset_id,
            "platform_version": platform_version,
        },
    )


def active_switch_audit_run(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    asset_key: str,
) -> UUID | None:
    set_switch_audit_scope(session, organization_id, owner_user_id)
    return session.execute(
        text(
            """
            SELECT id FROM switch_audit_runs
            WHERE organization_id = :organization_id
              AND owner_user_id = :owner_user_id
              AND asset_key = :asset_key
              AND status IN ('QUEUED', 'RUNNING')
            ORDER BY created_at DESC LIMIT 1
            """
        ),
        {
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "asset_key": asset_key,
        },
    ).scalar_one_or_none()


def latest_completed_switch_audit_run(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
) -> UUID | None:
    set_switch_audit_scope(session, organization_id, owner_user_id)
    return session.execute(
        text(
            """
            SELECT id FROM switch_audit_runs
            WHERE organization_id = :organization_id
              AND owner_user_id = :owner_user_id
              AND status = 'COMPLETED'
              AND result_json IS NOT NULL
              AND result_sha256 IS NOT NULL
            ORDER BY completed_at DESC NULLS LAST, created_at DESC
            LIMIT 1
            """
        ),
        {
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
        },
    ).scalar_one_or_none()


def load_switch_audit_run(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
) -> SwitchAuditRunRecord | None:
    set_switch_audit_scope(session, organization_id, owner_user_id)
    row = (
        session.execute(
            text(
                """
                SELECT id, asset_key, asset_id, platform, platform_version,
                       status, result_json, result_sha256, error_code,
                       created_at, completed_at
                FROM switch_audit_runs WHERE id = :run_id
                """
            ),
            {"run_id": run_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    return SwitchAuditRunRecord(
        id=row["id"],
        asset_key=str(row["asset_key"]),
        asset_id=row["asset_id"],
        platform=str(row["platform"]),
        platform_version=str(row["platform_version"]),
        status=str(row["status"]),
        result_json=dict(row["result_json"]) if row["result_json"] is not None else None,
        result_sha256=str(row["result_sha256"]) if row["result_sha256"] else None,
        error_code=str(row["error_code"]) if row["error_code"] else None,
        created_at=row["created_at"],
        completed_at=row["completed_at"],
    )


def append_switch_audit_event(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    event_type: str,
    payload: dict[str, Any],
) -> int:
    set_switch_audit_scope(session, organization_id, owner_user_id)
    session.execute(
        text("SELECT id FROM switch_audit_runs WHERE id = :run_id FOR UPDATE"),
        {"run_id": run_id},
    ).one()
    sequence = int(
        session.execute(
            text(
                "SELECT COALESCE(max(sequence), 0) + 1 "
                "FROM switch_audit_events WHERE run_id = :run_id"
            ),
            {"run_id": run_id},
        ).scalar_one()
    )
    session.execute(
        text(
            """
            INSERT INTO switch_audit_events (
                run_id, organization_id, owner_user_id,
                sequence, event_type, payload
            ) VALUES (
                :run_id, :organization_id, :owner_user_id,
                :sequence, :event_type, CAST(:payload AS jsonb)
            )
            """
        ),
        {
            "run_id": run_id,
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "sequence": sequence,
            "event_type": event_type,
            "payload": json.dumps(payload, ensure_ascii=False),
        },
    )
    return sequence


def mark_switch_audit_running(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
) -> None:
    set_switch_audit_scope(session, organization_id, owner_user_id)
    session.execute(
        text(
            "UPDATE switch_audit_runs SET status = 'RUNNING', started_at = now() "
            "WHERE id = :run_id AND status = 'QUEUED'"
        ),
        {"run_id": run_id},
    )


def finish_switch_audit_run(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    status: str,
    result_json: dict[str, Any] | None = None,
    result_sha256: str | None = None,
    error_code: str | None = None,
) -> None:
    set_switch_audit_scope(session, organization_id, owner_user_id)
    session.execute(
        text(
            """
            UPDATE switch_audit_runs SET
                status = :status,
                result_json = COALESCE(CAST(:result_json AS jsonb), result_json),
                result_sha256 = COALESCE(:result_sha256, result_sha256),
                error_code = :error_code,
                completed_at = now()
            WHERE id = :run_id AND status IN ('QUEUED', 'RUNNING')
            """
        ),
        {
            "status": status,
            "result_json": (
                None if result_json is None else json.dumps(result_json, ensure_ascii=False)
            ),
            "result_sha256": result_sha256,
            "error_code": error_code,
            "run_id": run_id,
        },
    )


def get_switch_ai_output(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    output_key: str,
) -> str | None:
    """현재 사용자 범위의 완성된 AI 설명을 반환합니다."""

    set_switch_audit_scope(session, organization_id, owner_user_id)
    return session.execute(
        text(
            "SELECT content FROM switch_audit_ai_outputs "
            "WHERE run_id = :run_id AND output_key = :output_key"
        ),
        {"run_id": run_id, "output_key": output_key},
    ).scalar_one_or_none()


def get_switch_ai_outputs(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    output_prefix: str,
) -> dict[str, str]:
    """현재 사용자 범위의 한 AI 출력 세대를 한 번의 조회로 반환합니다."""

    set_switch_audit_scope(session, organization_id, owner_user_id)
    rows = session.execute(
        text(
            "SELECT output_key, content FROM switch_audit_ai_outputs "
            "WHERE run_id = :run_id AND output_key LIKE :output_prefix "
            "ORDER BY output_key"
        ),
        {"run_id": run_id, "output_prefix": output_prefix + "%"},
    ).all()
    return {str(row[0]): str(row[1]) for row in rows}


def append_switch_ai_output(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    output_key: str,
    content: str,
    content_sha256: str,
) -> None:
    """완성된 AI 설명을 기존 값을 바꾸지 않고 한 번만 저장합니다."""

    set_switch_audit_scope(session, organization_id, owner_user_id)
    session.execute(
        text(
            """
            INSERT INTO switch_audit_ai_outputs (
                run_id, organization_id, owner_user_id,
                output_key, content, content_sha256
            ) VALUES (
                :run_id, :organization_id, :owner_user_id,
                :output_key, :content, :content_sha256
            )
            ON CONFLICT (run_id, output_key) DO NOTHING
            """
        ),
        {
            "run_id": run_id,
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "output_key": output_key,
            "content": content,
            "content_sha256": content_sha256,
        },
    )
