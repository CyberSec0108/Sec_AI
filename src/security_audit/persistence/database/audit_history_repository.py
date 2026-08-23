"""Windows snapshot과 세 플랫폼 통합 이력의 PostgreSQL adapter입니다."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import cast
from uuid import UUID, uuid4

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from security_audit.application.audit_history import (
    AuditHistoryContractError,
    AuditHistoryPolicy,
    ValidatedWindowsAuditPresentation,
    ValidatedWindowsAuditSnapshot,
)
from security_audit.common.canonical_json import JsonValue

from .models import (
    AuditHistoryPolicyRecord,
    WindowsAuditPresentationRecord,
    WindowsAuditSnapshotRecord,
)

DEFAULT_RETENTION_DAYS = 365
DEFAULT_BACKUP_REQUIRED = True
DEFAULT_DELETION_MODE = "HOLD"


@dataclass(frozen=True, slots=True)
class AuditHistoryRecord:
    id: UUID
    platform: str
    asset_label: str
    result_id: str
    result_version: int
    completed_at: datetime
    result_json: dict[str, JsonValue]
    result_sha256: str
    criteria_sha256: str | None
    total_count: int | None


@dataclass(frozen=True, slots=True)
class StoredWindowsAuditSnapshot:
    id: UUID
    created: bool
    result_sha256: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class StoredWindowsAuditPresentation:
    id: UUID
    windows_snapshot_id: UUID
    presentation_kind: str
    presentation_version: int
    payload_json: dict[str, JsonValue]
    payload_sha256: str
    created_at: datetime
    created: bool


def set_audit_history_scope(
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


def _policy(record: AuditHistoryPolicyRecord) -> AuditHistoryPolicy:
    return AuditHistoryPolicy(
        id=record.id,
        version=record.version,
        retention_days=record.retention_days,
        backup_required=record.backup_required,
        deletion_mode=record.deletion_mode,
        created_at=record.created_at,
    )


def effective_audit_history_policy(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
) -> AuditHistoryPolicy | None:
    set_audit_history_scope(session, organization_id, owner_user_id)
    record = session.scalar(
        select(AuditHistoryPolicyRecord)
        .where(AuditHistoryPolicyRecord.organization_id == organization_id)
        .order_by(AuditHistoryPolicyRecord.version.desc())
        .limit(1)
    )
    return _policy(record) if record is not None else None


def ensure_default_audit_history_policy(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
) -> AuditHistoryPolicy:
    current = effective_audit_history_policy(
        session,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
    )
    if current is not None:
        return current
    statement = (
        insert(AuditHistoryPolicyRecord)
        .values(
            id=uuid4(),
            organization_id=organization_id,
            version=1,
            retention_days=DEFAULT_RETENTION_DAYS,
            backup_required=DEFAULT_BACKUP_REQUIRED,
            deletion_mode=DEFAULT_DELETION_MODE,
            created_by=owner_user_id,
        )
        .on_conflict_do_nothing(
            index_elements=[
                AuditHistoryPolicyRecord.organization_id,
                AuditHistoryPolicyRecord.version,
            ]
        )
    )
    session.execute(statement)
    policy = effective_audit_history_policy(
        session,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
    )
    if policy is None:
        raise AuditHistoryContractError("AUDIT_HISTORY_POLICY_UNAVAILABLE")
    return policy


def append_audit_history_policy(
    session: Session,
    *,
    organization_id: UUID,
    created_by: UUID,
    retention_days: int,
    backup_required: bool,
    deletion_mode: str,
) -> AuditHistoryPolicy:
    candidate = AuditHistoryPolicy(
        id=None,
        version=1,
        retention_days=retention_days,
        backup_required=backup_required,
        deletion_mode=deletion_mode,
        created_at=None,
    )
    set_audit_history_scope(session, organization_id, created_by)
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
        {"scope": f"audit-history-policy:{organization_id}"},
    )
    current = session.scalar(
        select(func.max(AuditHistoryPolicyRecord.version)).where(
            AuditHistoryPolicyRecord.organization_id == organization_id
        )
    )
    record = AuditHistoryPolicyRecord(
        id=uuid4(),
        organization_id=organization_id,
        version=int(current or 0) + 1,
        retention_days=candidate.retention_days,
        backup_required=candidate.backup_required,
        deletion_mode=candidate.deletion_mode,
        created_by=created_by,
    )
    session.add(record)
    session.flush()
    session.refresh(record)
    return _policy(record)


def append_windows_audit_snapshot(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    asset_id: UUID,
    snapshot: ValidatedWindowsAuditSnapshot,
) -> StoredWindowsAuditSnapshot:
    policy = ensure_default_audit_history_policy(
        session,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
    )
    if policy.id is None:
        raise AuditHistoryContractError("AUDIT_HISTORY_POLICY_UNAVAILABLE")
    snapshot_id = uuid4()
    statement = (
        insert(WindowsAuditSnapshotRecord)
        .values(
            id=snapshot_id,
            organization_id=organization_id,
            owner_user_id=owner_user_id,
            asset_id=asset_id,
            retention_policy_id=policy.id,
            result_id=snapshot.result_id,
            result_version=snapshot.result_version,
            observed_at=snapshot.observed_at,
            result_json=snapshot.result_json,
            result_sha256=snapshot.result_sha256,
            criteria_sha256=snapshot.criteria_sha256,
            total_count=snapshot.counts["total"],
            pass_count=snapshot.counts["pass"],
            fail_count=snapshot.counts["fail"],
            error_count=snapshot.counts["error"],
            review_count=snapshot.counts["review"],
            not_applicable_count=snapshot.counts["not_applicable"],
        )
        .on_conflict_do_nothing(
            index_elements=[
                WindowsAuditSnapshotRecord.organization_id,
                WindowsAuditSnapshotRecord.owner_user_id,
                WindowsAuditSnapshotRecord.result_id,
                WindowsAuditSnapshotRecord.result_version,
            ]
        )
        .returning(WindowsAuditSnapshotRecord.id)
    )
    inserted_id = session.scalar(statement)
    record = session.scalar(
        select(WindowsAuditSnapshotRecord).where(
            WindowsAuditSnapshotRecord.organization_id == organization_id,
            WindowsAuditSnapshotRecord.owner_user_id == owner_user_id,
            WindowsAuditSnapshotRecord.result_id == snapshot.result_id,
            WindowsAuditSnapshotRecord.result_version == snapshot.result_version,
        )
    )
    if record is None:
        raise AuditHistoryContractError("WINDOWS_AUDIT_SNAPSHOT_SCOPE_DENIED")
    if record.asset_id != asset_id or record.result_sha256 != snapshot.result_sha256:
        raise AuditHistoryContractError("WINDOWS_AUDIT_SNAPSHOT_CONFLICT")
    return StoredWindowsAuditSnapshot(
        id=record.id,
        created=inserted_id == snapshot_id,
        result_sha256=record.result_sha256,
        created_at=record.created_at,
    )


def _stored_windows_presentation(
    record: WindowsAuditPresentationRecord,
    *,
    created: bool,
) -> StoredWindowsAuditPresentation:
    return StoredWindowsAuditPresentation(
        id=record.id,
        windows_snapshot_id=record.windows_snapshot_id,
        presentation_kind=record.presentation_kind,
        presentation_version=record.presentation_version,
        payload_json=cast(dict[str, JsonValue], dict(record.payload_json)),
        payload_sha256=record.payload_sha256,
        created_at=record.created_at,
        created=created,
    )


def _windows_snapshot_by_result(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    result_id: str,
    result_version: int,
) -> WindowsAuditSnapshotRecord | None:
    return session.scalar(
        select(WindowsAuditSnapshotRecord).where(
            WindowsAuditSnapshotRecord.organization_id == organization_id,
            WindowsAuditSnapshotRecord.owner_user_id == owner_user_id,
            WindowsAuditSnapshotRecord.result_id == result_id,
            WindowsAuditSnapshotRecord.result_version == result_version,
        )
    )


def append_windows_audit_presentation(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    presentation: ValidatedWindowsAuditPresentation,
) -> StoredWindowsAuditPresentation:
    """동일 payload retry는 재사용하고 변경된 화면만 새 version으로 추가합니다."""

    set_audit_history_scope(session, organization_id, owner_user_id)
    snapshot = _windows_snapshot_by_result(
        session,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
        result_id=presentation.result_id,
        result_version=presentation.result_version,
    )
    if snapshot is None:
        raise AuditHistoryContractError("WINDOWS_AUDIT_SNAPSHOT_NOT_FOUND")
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
        {
            "scope": (
                f"windows-audit-presentation:{snapshot.id}:"
                f"{presentation.presentation_kind}"
            )
        },
    )
    existing = session.scalar(
        select(WindowsAuditPresentationRecord).where(
            WindowsAuditPresentationRecord.windows_snapshot_id == snapshot.id,
            WindowsAuditPresentationRecord.presentation_kind
            == presentation.presentation_kind,
            WindowsAuditPresentationRecord.payload_sha256
            == presentation.payload_sha256,
        )
    )
    if existing is not None:
        return _stored_windows_presentation(existing, created=False)
    latest_version = session.scalar(
        select(func.max(WindowsAuditPresentationRecord.presentation_version)).where(
            WindowsAuditPresentationRecord.windows_snapshot_id == snapshot.id,
            WindowsAuditPresentationRecord.presentation_kind
            == presentation.presentation_kind,
        )
    )
    record = WindowsAuditPresentationRecord(
        id=uuid4(),
        organization_id=organization_id,
        owner_user_id=owner_user_id,
        windows_snapshot_id=snapshot.id,
        presentation_kind=presentation.presentation_kind,
        presentation_version=int(latest_version or 0) + 1,
        payload_json=presentation.payload,
        payload_sha256=presentation.payload_sha256,
    )
    session.add(record)
    session.flush()
    session.refresh(record)
    return _stored_windows_presentation(record, created=True)


def load_windows_audit_presentations(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    result_id: str,
    result_version: int,
) -> dict[str, StoredWindowsAuditPresentation]:
    """로그인 소유자의 결과에 연결된 종류별 최신 화면만 읽습니다."""

    set_audit_history_scope(session, organization_id, owner_user_id)
    snapshot = _windows_snapshot_by_result(
        session,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
        result_id=result_id,
        result_version=result_version,
    )
    if snapshot is None:
        return {}
    records = session.scalars(
        select(WindowsAuditPresentationRecord)
        .where(WindowsAuditPresentationRecord.windows_snapshot_id == snapshot.id)
        .order_by(
            WindowsAuditPresentationRecord.presentation_kind,
            WindowsAuditPresentationRecord.presentation_version.desc(),
        )
    )
    latest: dict[str, StoredWindowsAuditPresentation] = {}
    for record in records:
        if record.presentation_kind not in latest:
            latest[record.presentation_kind] = _stored_windows_presentation(
                record,
                created=False,
            )
    return latest


_UNIFIED_HISTORY_SQL = text(
    """
    WITH unified AS (
        SELECT
            id,
            'WINDOWS'::text AS platform,
            'Windows PC'::text AS asset_label,
            result_id::text AS result_id,
            result_version,
            observed_at AS completed_at,
            result_json,
            result_sha256::text AS result_sha256,
            criteria_sha256::text AS criteria_sha256
        FROM windows_audit_snapshots
        WHERE organization_id = :organization_id
          AND owner_user_id = :owner_user_id
        UNION ALL
        SELECT
            id,
            'LINUX'::text AS platform,
            CASE distribution
                WHEN 'UBUNTU_22_04' THEN 'Ubuntu 22.04'
                WHEN 'UBUNTU_24_04' THEN 'Ubuntu 24.04'
                WHEN 'DEBIAN_12' THEN 'Debian 12'
                WHEN 'ROCKY_9' THEN 'Rocky Linux 9'
                WHEN 'RHEL_9' THEN 'Red Hat Enterprise Linux 9'
                WHEN 'ALMALINUX_9' THEN 'AlmaLinux 9'
                ELSE 'Linux 서버'
            END AS asset_label,
            id::text AS result_id,
            1 AS result_version,
            completed_at,
            result_json,
            result_sha256::text AS result_sha256,
            result_json ->> 'criteria_sha256' AS criteria_sha256
        FROM linux_audit_runs
        WHERE organization_id = :organization_id
          AND owner_user_id = :owner_user_id
          AND status = 'COMPLETED'
          AND deleted_at IS NULL
          AND completed_at IS NOT NULL
          AND result_json IS NOT NULL
          AND result_sha256 IS NOT NULL
        UNION ALL
        SELECT
            id,
            'SWITCH'::text AS platform,
            'Aruba AOS-CX ' || platform_version AS asset_label,
            id::text AS result_id,
            1 AS result_version,
            completed_at,
            result_json,
            result_sha256::text AS result_sha256,
            result_json ->> 'criteria_sha256' AS criteria_sha256
        FROM switch_audit_runs
        WHERE organization_id = :organization_id
          AND owner_user_id = :owner_user_id
          AND status = 'COMPLETED'
          AND completed_at IS NOT NULL
          AND result_json IS NOT NULL
          AND result_sha256 IS NOT NULL
    ), filtered AS (
        SELECT * FROM unified
        WHERE (CAST(:platform AS text) IS NULL OR platform = CAST(:platform AS text))
          AND (
              CAST(:completed_from AS timestamptz) IS NULL
              OR completed_at >= CAST(:completed_from AS timestamptz)
          )
          AND (
              CAST(:completed_before AS timestamptz) IS NULL
              OR completed_at < CAST(:completed_before AS timestamptz)
          )
    )
    SELECT *, count(*) OVER () AS total_count
    FROM filtered
    ORDER BY completed_at DESC, platform, id DESC
    LIMIT :limit OFFSET :offset
    """
)


def _history_record(row: dict[str, object]) -> AuditHistoryRecord:
    return AuditHistoryRecord(
        id=cast(UUID, row["id"]),
        platform=str(row["platform"]),
        asset_label=str(row["asset_label"]),
        result_id=str(row["result_id"]),
        result_version=int(cast(int, row["result_version"])),
        completed_at=cast(datetime, row["completed_at"]),
        result_json=cast(dict[str, JsonValue], dict(cast(dict[str, object], row["result_json"]))),
        result_sha256=str(row["result_sha256"]),
        criteria_sha256=(
            str(row["criteria_sha256"]) if row.get("criteria_sha256") else None
        ),
        total_count=(int(cast(int, row["total_count"])) if row.get("total_count") else None),
    )


def list_audit_history(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    platform: str | None,
    completed_from: datetime | None,
    completed_before: datetime | None,
    limit: int,
    offset: int,
) -> tuple[AuditHistoryRecord, ...]:
    set_audit_history_scope(session, organization_id, owner_user_id)
    rows = session.execute(
        _UNIFIED_HISTORY_SQL,
        {
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "platform": platform,
            "completed_from": completed_from,
            "completed_before": completed_before,
            "limit": limit,
            "offset": offset,
        },
    ).mappings()
    return tuple(_history_record(dict(row)) for row in rows)


def load_audit_history_record(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    platform: str,
    entry_id: UUID,
) -> AuditHistoryRecord | None:
    set_audit_history_scope(session, organization_id, owner_user_id)
    table = {
        "WINDOWS": "windows_audit_snapshots",
        "LINUX": "linux_audit_runs",
        "SWITCH": "switch_audit_runs",
    }.get(platform)
    if table is None:
        raise AuditHistoryContractError("PLATFORM_INVALID")
    platform_projection = {
        "WINDOWS": (
            "'Windows PC' AS asset_label, result_id::text AS result_id, "
            "result_version, observed_at AS completed_at, "
            "criteria_sha256::text AS criteria_sha256"
        ),
        "LINUX": (
            "CASE distribution WHEN 'UBUNTU_22_04' THEN 'Ubuntu 22.04' "
            "WHEN 'UBUNTU_24_04' THEN 'Ubuntu 24.04' "
            "WHEN 'DEBIAN_12' THEN 'Debian 12' "
            "WHEN 'ROCKY_9' THEN 'Rocky Linux 9' "
            "WHEN 'RHEL_9' THEN 'Red Hat Enterprise Linux 9' "
            "WHEN 'ALMALINUX_9' THEN 'AlmaLinux 9' ELSE 'Linux 서버' END "
            "AS asset_label, id::text AS result_id, 1 AS result_version, "
            "completed_at, result_json ->> 'criteria_sha256' AS criteria_sha256"
        ),
        "SWITCH": (
            "'Aruba AOS-CX ' || platform_version AS asset_label, "
            "id::text AS result_id, 1 AS result_version, completed_at, "
            "result_json ->> 'criteria_sha256' AS criteria_sha256"
        ),
    }[platform]
    status_clause = {
        "WINDOWS": "",
        "LINUX": (
            "AND status = 'COMPLETED' AND deleted_at IS NULL "
            "AND completed_at IS NOT NULL"
        ),
        "SWITCH": "AND status = 'COMPLETED' AND completed_at IS NOT NULL",
    }[platform]
    query = text(
        f"""
        SELECT id, :platform AS platform,
               {platform_projection},
               result_json, result_sha256::text AS result_sha256,
               NULL::bigint AS total_count
        FROM {table}
        WHERE id = :entry_id
          AND organization_id = :organization_id
          AND owner_user_id = :owner_user_id
          {status_clause}
        """  # noqa: S608 - table and projection come from the closed platform map.
    )
    row = session.execute(
        query,
        {
            "platform": platform,
            "entry_id": entry_id,
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
        },
    ).mappings().one_or_none()
    return _history_record(dict(row)) if row is not None else None
