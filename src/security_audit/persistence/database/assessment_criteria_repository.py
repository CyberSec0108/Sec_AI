"""RLS 범위 안에서 점검 기준 버전을 추가하고 조회합니다."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, cast
from uuid import UUID, uuid4

from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session

from security_audit.application.assessment_criteria import (
    CriteriaProfile,
    CriteriaSelection,
    CriteriaSelectionKind,
    CriteriaSelectionSource,
    CriteriaValue,
    validate_criteria_values,
)

from .models import AssessmentCriteriaProfileRecord, AssessmentCriteriaSelectionRecord


def _set_scope(
    session: Session,
    *,
    organization_id: UUID,
    user_id: UUID,
    is_administrator: bool,
) -> None:
    session.execute(
        text("SELECT set_config('secai.organization_id', :value, true)"),
        {"value": str(organization_id)},
    )
    session.execute(
        text("SELECT set_config('secai.user_id', :value, true)"),
        {"value": str(user_id)},
    )
    session.execute(
        text("SELECT set_config('secai.is_administrator', :value, true)"),
        {"value": "true" if is_administrator else "false"},
    )


def _profile(record: AssessmentCriteriaProfileRecord) -> CriteriaProfile:
    return CriteriaProfile(
        id=record.id,
        organization_id=record.organization_id,
        owner_user_id=record.owner_user_id,
        scope=cast(Literal["ORGANIZATION", "PERSONAL"], record.scope),
        name=record.name,
        version=record.version,
        values=validate_criteria_values(record.criteria_document),
        document_sha256=record.document_sha256,
        change_reason=record.change_reason,
        created_by=record.created_by,
        created_at=record.created_at,
    )


def _selection(record: AssessmentCriteriaSelectionRecord) -> CriteriaSelection:
    return CriteriaSelection(
        id=record.id,
        organization_id=record.organization_id,
        user_id=record.user_id,
        selection_kind=cast(CriteriaSelectionKind, record.selection_kind),
        personal_profile_id=record.personal_profile_id,
        criteria_sha256=record.criteria_sha256,
        selected_at=record.selected_at,
        source=cast(CriteriaSelectionSource, record.source),
    )


class SqlAssessmentCriteriaRepository:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def append(
        self,
        *,
        organization_id: UUID,
        owner_user_id: UUID | None,
        scope: Literal["ORGANIZATION", "PERSONAL"],
        name: str,
        values: Mapping[str, CriteriaValue],
        document_sha256: str,
        change_reason: str,
        created_by: UUID,
        is_administrator: bool,
    ) -> CriteriaProfile:
        with Session(self._engine) as session, session.begin():
            _set_scope(
                session,
                organization_id=organization_id,
                user_id=created_by,
                is_administrator=is_administrator,
            )
            identity = f"{organization_id}:{owner_user_id}:{scope}:{name}"
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:identity, 0))"),
                {"identity": identity},
            )
            statement = select(
                func.max(AssessmentCriteriaProfileRecord.version)
            ).where(
                AssessmentCriteriaProfileRecord.organization_id == organization_id,
                AssessmentCriteriaProfileRecord.scope == scope,
                AssessmentCriteriaProfileRecord.name == name,
            )
            if owner_user_id is None:
                statement = statement.where(
                    AssessmentCriteriaProfileRecord.owner_user_id.is_(None)
                )
            else:
                statement = statement.where(
                    AssessmentCriteriaProfileRecord.owner_user_id == owner_user_id
                )
            version = int(session.scalar(statement) or 0) + 1
            record = AssessmentCriteriaProfileRecord(
                id=uuid4(),
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                scope=scope,
                name=name,
                version=version,
                criteria_document={
                    key: list(value) if isinstance(value, tuple) else value
                    for key, value in values.items()
                },
                document_sha256=document_sha256,
                change_reason=change_reason,
                created_by=created_by,
            )
            session.add(record)
            session.flush()
            session.refresh(record)
            return _profile(record)

    def latest_organization(self, organization_id: UUID) -> CriteriaProfile | None:
        with Session(self._engine) as session, session.begin():
            _set_scope(
                session,
                organization_id=organization_id,
                user_id=UUID(int=0),
                is_administrator=False,
            )
            record = session.scalar(
                select(AssessmentCriteriaProfileRecord)
                .where(
                    AssessmentCriteriaProfileRecord.organization_id == organization_id,
                    AssessmentCriteriaProfileRecord.scope == "ORGANIZATION",
                )
                .order_by(AssessmentCriteriaProfileRecord.version.desc())
                .limit(1)
            )
            return _profile(record) if record else None

    def latest_personal(
        self,
        organization_id: UUID,
        owner_user_id: UUID,
    ) -> tuple[CriteriaProfile, ...]:
        with Session(self._engine) as session, session.begin():
            _set_scope(
                session,
                organization_id=organization_id,
                user_id=owner_user_id,
                is_administrator=False,
            )
            records = session.scalars(
                select(AssessmentCriteriaProfileRecord)
                .where(
                    AssessmentCriteriaProfileRecord.organization_id == organization_id,
                    AssessmentCriteriaProfileRecord.owner_user_id == owner_user_id,
                    AssessmentCriteriaProfileRecord.scope == "PERSONAL",
                )
                .order_by(
                    AssessmentCriteriaProfileRecord.name.asc(),
                    AssessmentCriteriaProfileRecord.version.desc(),
                )
            )
            latest: dict[str, AssessmentCriteriaProfileRecord] = {}
            for record in records:
                latest.setdefault(record.name, record)
            return tuple(_profile(item) for item in latest.values())

    def get_personal(
        self,
        organization_id: UUID,
        owner_user_id: UUID,
        profile_id: UUID,
    ) -> CriteriaProfile | None:
        with Session(self._engine) as session, session.begin():
            _set_scope(
                session,
                organization_id=organization_id,
                user_id=owner_user_id,
                is_administrator=False,
            )
            record = session.scalar(
                select(AssessmentCriteriaProfileRecord).where(
                    AssessmentCriteriaProfileRecord.id == profile_id,
                    AssessmentCriteriaProfileRecord.organization_id == organization_id,
                    AssessmentCriteriaProfileRecord.owner_user_id == owner_user_id,
                    AssessmentCriteriaProfileRecord.scope == "PERSONAL",
                )
            )
            return _profile(record) if record else None

    def append_selection(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        selection_kind: CriteriaSelectionKind,
        personal_profile_id: UUID | None,
        criteria_sha256: str,
        source: CriteriaSelectionSource,
        is_administrator: bool,
    ) -> CriteriaSelection:
        with Session(self._engine) as session, session.begin():
            _set_scope(
                session,
                organization_id=organization_id,
                user_id=user_id,
                is_administrator=is_administrator,
            )
            record = AssessmentCriteriaSelectionRecord(
                id=uuid4(),
                organization_id=organization_id,
                user_id=user_id,
                selection_kind=selection_kind,
                personal_profile_id=personal_profile_id,
                criteria_sha256=criteria_sha256,
                source=source,
            )
            session.add(record)
            session.flush()
            session.refresh(record)
            return _selection(record)

    def latest_selection(
        self,
        organization_id: UUID,
        user_id: UUID,
    ) -> CriteriaSelection | None:
        history = self.selection_history(organization_id, user_id, limit=1)
        return history[0] if history else None

    def selection_history(
        self,
        organization_id: UUID,
        user_id: UUID,
        *,
        limit: int = 20,
    ) -> tuple[CriteriaSelection, ...]:
        with Session(self._engine) as session, session.begin():
            _set_scope(
                session,
                organization_id=organization_id,
                user_id=user_id,
                is_administrator=False,
            )
            records = session.scalars(
                select(AssessmentCriteriaSelectionRecord)
                .where(
                    AssessmentCriteriaSelectionRecord.organization_id
                    == organization_id,
                    AssessmentCriteriaSelectionRecord.user_id == user_id,
                )
                .order_by(
                    AssessmentCriteriaSelectionRecord.selected_at.desc(),
                    AssessmentCriteriaSelectionRecord.id.desc(),
                )
                .limit(min(max(limit, 1), 100))
            )
            return tuple(_selection(record) for record in records)
