"""Owner-scoped append-only persistence for PRODUCT-AI-08 reports."""

from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from security_audit.application.result_report import (
    ReportContractError,
    ReportKind,
    ValidatedReportSnapshot,
)

from .models import (
    ResultReportAccessEventRecord,
    ResultReportRecord,
    ResultReportSnapshotRecord,
)


def set_result_report_scope(
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


def get_or_create_snapshot(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    asset_id: UUID,
    snapshot: ValidatedReportSnapshot,
) -> ResultReportSnapshotRecord:
    set_result_report_scope(session, organization_id, owner_user_id)
    statement = (
        insert(ResultReportSnapshotRecord)
        .values(
            id=uuid4(),
            organization_id=organization_id,
            owner_user_id=owner_user_id,
            asset_id=asset_id,
            result_id=snapshot.result_id,
            result_version=snapshot.result_version,
            snapshot_sha256=snapshot.snapshot_sha256,
            snapshot_payload=snapshot.snapshot_payload,
        )
        .on_conflict_do_nothing(
            index_elements=[
                ResultReportSnapshotRecord.organization_id,
                ResultReportSnapshotRecord.owner_user_id,
                ResultReportSnapshotRecord.result_id,
                ResultReportSnapshotRecord.result_version,
                ResultReportSnapshotRecord.snapshot_sha256,
            ]
        )
    )
    session.execute(statement)
    record = session.scalar(
        select(ResultReportSnapshotRecord).where(
            ResultReportSnapshotRecord.organization_id == organization_id,
            ResultReportSnapshotRecord.owner_user_id == owner_user_id,
            ResultReportSnapshotRecord.result_id == snapshot.result_id,
            ResultReportSnapshotRecord.result_version == snapshot.result_version,
            ResultReportSnapshotRecord.snapshot_sha256 == snapshot.snapshot_sha256,
        )
    )
    if record is None:
        raise ReportContractError("REPORT_SNAPSHOT_SCOPE_DENIED")
    if record.asset_id != asset_id:
        raise ReportContractError("REPORT_SNAPSHOT_CONFLICT")
    return record


def allocate_report_version(
    session: Session,
    *,
    snapshot: ResultReportSnapshotRecord,
    report_kind: ReportKind,
) -> int:
    session.execute(
        text(
            "SELECT pg_advisory_xact_lock("
            "hashtextextended(:report_identity, 0))"
        ),
        {
            "report_identity": (
                f"{snapshot.organization_id}:{snapshot.owner_user_id}:"
                f"{snapshot.result_id}:{snapshot.result_version}:{report_kind.value}"
            )
        },
    )
    current = session.scalar(
        select(func.max(ResultReportRecord.report_version))
        .join(
            ResultReportSnapshotRecord,
            ResultReportSnapshotRecord.id == ResultReportRecord.snapshot_id,
        )
        .where(
            ResultReportSnapshotRecord.organization_id == snapshot.organization_id,
            ResultReportSnapshotRecord.owner_user_id == snapshot.owner_user_id,
            ResultReportSnapshotRecord.result_id == snapshot.result_id,
            ResultReportSnapshotRecord.result_version == snapshot.result_version,
            ResultReportRecord.report_kind == report_kind.value,
        )
    )
    return int(current or 0) + 1


def append_report(
    session: Session,
    *,
    snapshot: ResultReportSnapshotRecord,
    report_kind: ReportKind,
    report_version: int,
    content_sha256: str,
    pdf_sha256: str,
    pdf_bytes: bytes,
    model_manifest: dict[str, object],
    generated_by: UUID,
) -> ResultReportRecord:
    record = ResultReportRecord(
        id=uuid4(),
        snapshot_id=snapshot.id,
        organization_id=snapshot.organization_id,
        owner_user_id=snapshot.owner_user_id,
        asset_id=snapshot.asset_id,
        report_kind=report_kind.value,
        report_version=report_version,
        content_sha256=content_sha256,
        pdf_sha256=pdf_sha256,
        pdf_bytes=pdf_bytes,
        model_manifest=model_manifest,
        generated_by=generated_by,
    )
    session.add(record)
    session.flush()
    return record


def list_reports(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    result_id: str,
    result_version: int,
    include_technical: bool,
) -> tuple[ResultReportRecord, ...]:
    set_result_report_scope(session, organization_id, owner_user_id)
    statement = (
        select(ResultReportRecord)
        .join(
            ResultReportSnapshotRecord,
            ResultReportSnapshotRecord.id == ResultReportRecord.snapshot_id,
        )
        .where(
            ResultReportSnapshotRecord.result_id == result_id,
            ResultReportSnapshotRecord.result_version == result_version,
        )
    )
    if not include_technical:
        statement = statement.where(ResultReportRecord.report_kind == "USER")
    return tuple(
        session.scalars(
            statement.order_by(
                ResultReportRecord.created_at.desc(),
                ResultReportRecord.report_version.desc(),
            )
        )
    )


def get_report(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    report_id: UUID,
) -> ResultReportRecord | None:
    set_result_report_scope(session, organization_id, owner_user_id)
    return session.scalar(
        select(ResultReportRecord).where(ResultReportRecord.id == report_id)
    )


def append_access_event(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    event_type: str,
    outcome: str,
    reason_code: str,
    requested_report_id: UUID | None = None,
    report_id: UUID | None = None,
    event_metadata: dict[str, object] | None = None,
) -> ResultReportAccessEventRecord:
    set_result_report_scope(session, organization_id, owner_user_id)
    record = ResultReportAccessEventRecord(
        id=uuid4(),
        organization_id=organization_id,
        owner_user_id=owner_user_id,
        requested_report_id=requested_report_id,
        report_id=report_id,
        event_type=event_type,
        outcome=outcome,
        reason_code=reason_code,
        event_metadata=event_metadata or {},
    )
    session.add(record)
    session.flush()
    return record
