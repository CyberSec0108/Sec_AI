"""IMP-020 Package-to-Finding 회귀 검증을 위한 비-Web 지원 서비스입니다."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from sqlalchemy import Engine, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from security_audit.analysis.finding import FindingReplayAction
from security_audit.application.demo_evaluation import (
    DEMO_CASES,
    DEMO_ENGINE_ARTIFACT_SHA256,
    DEMO_ORGANIZATION_ID,
    SyntheticPc07Pipeline,
)
from security_audit.persistence.database import (
    AppendFindingCommand,
    AssetRecord,
    AuditJobRecord,
    FindingCurrentRecord,
    FindingVersionRecord,
    OrganizationRecord,
    append_or_get_finding,
)


class FindingPipelineVerificationService:
    """합성 Package를 평가하고 append-only Finding 저장 계약을 검증합니다."""

    def __init__(self, engine: Engine, project_root: Path) -> None:
        self._engine = engine
        self._pipeline = SyntheticPc07Pipeline(project_root)

    def list_cases(self) -> list[dict[str, str]]:
        return [
            {
                "id": item.id,
                "label": item.label,
                "description": item.description,
                "expected_status": item.expected_status,
            }
            for item in DEMO_CASES
        ]

    def run_case(self, case_id: str) -> dict[str, Any]:
        evaluation = self._pipeline.evaluate(case_id)
        finding = evaluation.finding
        with Session(self._engine) as session, session.begin():
            self._ensure_scope(session, evaluation.asset_id, evaluation.job_id)
            resolution = append_or_get_finding(
                session,
                AppendFindingCommand(
                    organization_id=evaluation.organization_id,
                    engine_artifact_sha256=DEMO_ENGINE_ARTIFACT_SHA256,
                    finding_version=1,
                ),
                finding,
            )
            if resolution.action is FindingReplayAction.CREATE:
                subject = cast(dict[str, Any], finding["subject"])
                session.execute(
                    insert(FindingCurrentRecord)
                    .values(
                        organization_id=UUID(evaluation.organization_id),
                        job_id=UUID(evaluation.job_id),
                        control_id=cast(str, finding["control_id"]),
                        subject_scope=cast(str, subject["scope"]),
                        subject_key=cast(str, subject["subject_key"]),
                        finding_id=UUID(cast(str, finding["id"])),
                        revision=1,
                    )
                    .on_conflict_do_nothing()
                )
        return {
            "case_id": case_id,
            "action": resolution.action,
            "finding_id": resolution.fingerprint.finding_id,
            "status": finding["status"],
            "package_validated": evaluation.package_validated,
            "normalized_evidence_count": evaluation.normalized_evidence_count,
        }

    def list_findings(self) -> list[dict[str, Any]]:
        with Session(self._engine) as session:
            records = session.scalars(
                select(FindingVersionRecord)
                .where(
                    FindingVersionRecord.organization_id == UUID(DEMO_ORGANIZATION_ID)
                )
                .order_by(FindingVersionRecord.created_at.desc())
            ).all()
        return [self._view(record) for record in records]

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        try:
            parsed_id = UUID(finding_id)
        except ValueError:
            return None
        with Session(self._engine) as session:
            record = session.scalar(
                select(FindingVersionRecord).where(
                    FindingVersionRecord.id == parsed_id,
                    FindingVersionRecord.organization_id == UUID(DEMO_ORGANIZATION_ID),
                )
            )
        return self._view(record) if record is not None else None

    @staticmethod
    def _ensure_scope(session: Session, asset_id: str, job_id: str) -> None:
        organization_uuid = UUID(DEMO_ORGANIZATION_ID)
        asset_uuid = UUID(asset_id)
        job_uuid = UUID(job_id)
        session.execute(
            insert(OrganizationRecord)
            .values(id=organization_uuid)
            .on_conflict_do_nothing()
        )
        session.execute(
            insert(AssetRecord)
            .values(id=asset_uuid, organization_id=organization_uuid)
            .on_conflict_do_nothing()
        )
        session.execute(
            insert(AuditJobRecord)
            .values(
                id=job_uuid,
                organization_id=organization_uuid,
                asset_id=asset_uuid,
                evaluation_as_of=datetime(2026, 7, 22, 8, 0, tzinfo=UTC),
            )
            .on_conflict_do_nothing()
        )

    @staticmethod
    def _view(record: FindingVersionRecord) -> dict[str, Any]:
        document = cast(dict[str, Any], record.finding_document)
        rule_result = cast(dict[str, Any], document["rule_result"])
        return {
            "id": str(record.id),
            "job_id": str(record.job_id),
            "asset_id": str(record.asset_id),
            "control_id": record.control_id,
            "status": record.status,
            "finding_version": record.finding_version,
            "input_sha256": record.input_sha256,
            "output_sha256": record.output_sha256,
            "evidence_set_sha256": record.evidence_set_sha256,
            "audit_pack_version": record.audit_pack_version,
            "rule_version": rule_result.get("rule_version"),
            "created_at": record.created_at.isoformat(),
            "actual": rule_result.get("actual"),
            "expected": rule_result.get("expected"),
            "result_code": rule_result.get("result_code"),
            "rationale_code": rule_result.get("rationale_code"),
            "citations": rule_result.get("citations", []),
            "document": document,
        }
