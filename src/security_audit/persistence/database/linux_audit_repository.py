"""Owner-scoped append-only persistence for Linux U-01~U-67 runs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session


def set_linux_audit_scope(session: Session, organization_id: UUID, owner_user_id: UUID) -> None:
    session.execute(
        text("SELECT set_config('secai.organization_id', :value, true)"),
        {"value": str(organization_id)},
    )
    session.execute(
        text("SELECT set_config('secai.user_id', :value, true)"), {"value": str(owner_user_id)}
    )


@dataclass(frozen=True, slots=True)
class LinuxAuditRunRecord:
    id: UUID
    asset_key: str
    asset_id: UUID
    distribution: str
    status: str
    result_json: dict[str, Any] | None
    result_sha256: str | None
    cancellation_requested: bool
    created_at: datetime
    completed_at: datetime | None


def create_linux_audit_run(
    session: Session,
    *,
    run_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    asset_key: str,
    asset_id: UUID,
    distribution: str,
) -> None:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    session.execute(
        text("""
            INSERT INTO linux_audit_runs (
                id, organization_id, owner_user_id, asset_key, asset_id,
                distribution, benchmark_id, status
            ) VALUES (
                :id, :organization_id, :owner_user_id, :asset_key, :asset_id,
                :distribution, 'KISA-2026-UNIX-U01-U67', 'QUEUED'
            )
        """),
        {
            "id": run_id,
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "asset_key": asset_key,
            "asset_id": asset_id,
            "distribution": distribution,
        },
    )


def active_linux_audit_run(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    asset_key: str,
) -> UUID | None:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    return session.execute(
        text("""
            SELECT id FROM linux_audit_runs
            WHERE organization_id = :organization_id
              AND owner_user_id = :owner_user_id
              AND asset_key = :asset_key
              AND status IN ('QUEUED', 'RUNNING')
            ORDER BY created_at DESC LIMIT 1
        """),
        {
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "asset_key": asset_key,
        },
    ).scalar_one_or_none()


def latest_completed_linux_audit_run(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
) -> UUID | None:
    """현재 사용자가 가장 최근에 완료한 Linux 결과 번호만 반환합니다."""

    set_linux_audit_scope(session, organization_id, owner_user_id)
    return session.execute(
        text("""
            SELECT id FROM linux_audit_runs
            WHERE organization_id = :organization_id
              AND owner_user_id = :owner_user_id
              AND status = 'COMPLETED'
              AND result_json IS NOT NULL
              AND result_sha256 IS NOT NULL
            ORDER BY completed_at DESC NULLS LAST, created_at DESC
            LIMIT 1
        """),
        {
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
        },
    ).scalar_one_or_none()


def load_linux_audit_run(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
) -> LinuxAuditRunRecord | None:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    row = (
        session.execute(
            text("""
            SELECT id, asset_key, asset_id, distribution, status, result_json,
                   result_sha256, cancellation_requested, created_at, completed_at
            FROM linux_audit_runs WHERE id = :run_id
        """),
            {"run_id": run_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    return LinuxAuditRunRecord(
        id=row["id"],
        asset_key=str(row["asset_key"]),
        asset_id=row["asset_id"],
        distribution=str(row["distribution"]),
        status=str(row["status"]),
        result_json=dict(row["result_json"]) if row["result_json"] is not None else None,
        result_sha256=str(row["result_sha256"]) if row["result_sha256"] else None,
        cancellation_requested=bool(row["cancellation_requested"]),
        created_at=row["created_at"],
        completed_at=row["completed_at"],
    )


def append_linux_audit_event(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    event_type: str,
    payload: dict[str, Any],
) -> int:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    session.execute(
        text("SELECT id FROM linux_audit_runs WHERE id = :run_id FOR UPDATE"), {"run_id": run_id}
    ).one()
    sequence = int(
        session.execute(
            text(
                "SELECT COALESCE(max(sequence), 0) + 1 "
                "FROM linux_audit_events WHERE run_id = :run_id"
            ),
            {"run_id": run_id},
        ).scalar_one()
    )
    session.execute(
        text("""
            INSERT INTO linux_audit_events (
                run_id, organization_id, owner_user_id, sequence, event_type, payload
            ) VALUES (
                :run_id, :organization_id, :owner_user_id, :sequence,
                :event_type, CAST(:payload AS jsonb)
            )
        """),
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


def list_linux_audit_events(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    after: int,
) -> list[dict[str, Any]]:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    rows = session.execute(
        text("""
            SELECT sequence, event_type, payload, created_at
            FROM linux_audit_events
            WHERE run_id = :run_id AND sequence > :after
            ORDER BY sequence LIMIT 200
        """),
        {"run_id": run_id, "after": after},
    ).mappings()
    return [
        {
            "sequence": int(row["sequence"]),
            "event_type": str(row["event_type"]),
            "payload": dict(row["payload"]),
            "created_at": row["created_at"].isoformat(),
        }
        for row in rows
    ]


def mark_linux_audit_running(
    session: Session, *, organization_id: UUID, owner_user_id: UUID, run_id: UUID
) -> None:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    session.execute(
        text(
            "UPDATE linux_audit_runs SET status = 'RUNNING', started_at = now() "
            "WHERE id = :run_id AND status = 'QUEUED'"
        ),
        {"run_id": run_id},
    )


def finish_linux_audit_run(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    status: str,
    result_json: dict[str, Any] | None = None,
    result_sha256: str | None = None,
) -> None:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    session.execute(
        text("""
            UPDATE linux_audit_runs SET status = :status,
                result_json = COALESCE(CAST(:result_json AS jsonb), result_json),
                result_sha256 = COALESCE(:result_sha256, result_sha256),
                completed_at = now()
            WHERE id = :run_id AND status IN ('QUEUED', 'RUNNING')
        """),
        {
            "status": status,
            "result_json": None
            if result_json is None
            else json.dumps(result_json, ensure_ascii=False),
            "result_sha256": result_sha256,
            "run_id": run_id,
        },
    )


def request_linux_audit_cancellation(
    session: Session, *, organization_id: UUID, owner_user_id: UUID, run_id: UUID
) -> bool:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    result = session.execute(
        text(
            "UPDATE linux_audit_runs SET cancellation_requested = true "
            "WHERE id = :run_id AND status IN ('QUEUED', 'RUNNING')"
        ),
        {"run_id": run_id},
    )
    return int(getattr(result, "rowcount", 0)) > 0


def get_ai_output(
    session: Session, *, organization_id: UUID, owner_user_id: UUID, run_id: UUID, output_key: str
) -> str | None:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    return session.execute(
        text(
            "SELECT content FROM linux_audit_ai_outputs "
            "WHERE run_id = :run_id AND output_key = :key"
        ),
        {"run_id": run_id, "key": output_key},
    ).scalar_one_or_none()


def get_ai_outputs(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    output_prefix: str,
) -> dict[str, str]:
    """현재 사용자 범위의 한 AI 출력 세대를 한 번의 조회로 반환합니다."""

    set_linux_audit_scope(session, organization_id, owner_user_id)
    rows = session.execute(
        text(
            "SELECT output_key, content FROM linux_audit_ai_outputs "
            "WHERE run_id = :run_id AND output_key LIKE :prefix "
            "ORDER BY output_key"
        ),
        {"run_id": run_id, "prefix": output_prefix + "%"},
    ).all()
    return {str(row[0]): str(row[1]) for row in rows}


def append_ai_output(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    output_key: str,
    content: str,
    content_sha256: str,
) -> None:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    session.execute(
        text("""
            INSERT INTO linux_audit_ai_outputs (
                run_id, organization_id, owner_user_id,
                output_key, content, content_sha256
            )
            VALUES (:run_id, :organization_id, :owner_user_id, :key, :content, :sha256)
            ON CONFLICT (run_id, output_key) DO NOTHING
        """),
        {
            "run_id": run_id,
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "key": output_key,
            "content": content,
            "sha256": content_sha256,
        },
    )
