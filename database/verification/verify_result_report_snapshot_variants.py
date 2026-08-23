"""관리자 결과가 뒤늦게 합쳐져도 기존 PDF를 보존하는지 검증한다."""

from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from security_audit.application.result_report import (
    ReportKind,
    ValidatedReportSnapshot,
)
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.models import ResultReportSnapshotRecord
from security_audit.persistence.database.result_report_repository import (
    allocate_report_version,
    append_report,
    get_or_create_snapshot,
    set_result_report_scope,
)

ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
OWNER_USER_ID = UUID("46000000-0000-4000-8000-000000000003")
ASSET_ID = UUID("46000000-0000-4000-8000-000000000002")
RESULT_ID = "cafe0000cafe0000"
RESULT_VERSION = 999_998


def _snapshot(digest: str) -> ValidatedReportSnapshot:
    return ValidatedReportSnapshot(
        result_id=RESULT_ID,
        result_version=RESULT_VERSION,
        observed_at_utc="2026-08-05T14:00:00Z",
        explanation_inputs=(),
        ai_explanation=None,
        test_environment_result=True,
        snapshot_payload={"verification": digest},
        snapshot_sha256=digest,
    )


def main() -> None:
    engine = create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )
    summary: dict[str, object] = {}
    with Session(engine) as session:
        transaction = session.begin()
        try:
            first = get_or_create_snapshot(
                session,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                asset_id=ASSET_ID,
                snapshot=_snapshot("a" * 64),
            )
            first_version = allocate_report_version(
                session,
                snapshot=first,
                report_kind=ReportKind.USER,
            )
            append_report(
                session,
                snapshot=first,
                report_kind=ReportKind.USER,
                report_version=first_version,
                content_sha256="c" * 64,
                pdf_sha256="d" * 64,
                pdf_bytes=b"%PDF-1.4\n%%EOF\n",
                model_manifest={},
                generated_by=OWNER_USER_ID,
            )
            second = get_or_create_snapshot(
                session,
                organization_id=ORGANIZATION_ID,
                owner_user_id=OWNER_USER_ID,
                asset_id=ASSET_ID,
                snapshot=_snapshot("b" * 64),
            )
            second_version = allocate_report_version(
                session,
                snapshot=second,
                report_kind=ReportKind.USER,
            )
            append_report(
                session,
                snapshot=second,
                report_kind=ReportKind.USER,
                report_version=second_version,
                content_sha256="e" * 64,
                pdf_sha256="f" * 64,
                pdf_bytes=b"%PDF-1.4\n%%EOF\n",
                model_manifest={},
                generated_by=OWNER_USER_ID,
            )
            set_result_report_scope(session, ORGANIZATION_ID, OWNER_USER_ID)
            variant_count = session.scalar(
                select(func.count())
                .select_from(ResultReportSnapshotRecord)
                .where(
                    ResultReportSnapshotRecord.result_id == RESULT_ID,
                    ResultReportSnapshotRecord.result_version == RESULT_VERSION,
                )
            )
            summary = {
                "distinct_snapshot_ids": first.id != second.id,
                "variant_count": int(variant_count or 0),
                "report_versions": [first_version, second_version],
                "rolled_back": True,
            }
            if summary != {
                "distinct_snapshot_ids": True,
                "variant_count": 2,
                "report_versions": [1, 2],
                "rolled_back": True,
            }:
                raise RuntimeError("RESULT_REPORT_SNAPSHOT_VARIANT_VERIFICATION_FAILED")
        finally:
            transaction.rollback()
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
