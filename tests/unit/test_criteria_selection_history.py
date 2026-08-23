from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Literal, cast
from uuid import UUID, uuid4

import pytest

from security_audit.application.assessment_criteria import (
    AssessmentCriteriaService,
    CriteriaContractError,
    CriteriaProfile,
    CriteriaSelection,
    CriteriaSelectionKind,
    CriteriaSelectionSource,
    CriteriaValue,
)
from security_audit.security.auth import AuthenticatedPrincipal, HumanRole

ORGANIZATION_ID = UUID("10000000-0000-4000-8000-000000000001")
USER_ID = UUID("20000000-0000-4000-8000-000000000001")
NOW = datetime(2026, 8, 2, 9, 0, tzinfo=UTC)


class MemoryCriteriaRepository:
    def __init__(self) -> None:
        self.profiles: list[CriteriaProfile] = []
        self.selections: list[CriteriaSelection] = []

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
        del is_administrator
        profile = CriteriaProfile(
            id=uuid4(),
            organization_id=organization_id,
            owner_user_id=owner_user_id,
            scope=scope,
            name=name,
            version=1,
            values=dict(values),
            document_sha256=document_sha256,
            change_reason=change_reason,
            created_by=created_by,
            created_at=NOW,
        )
        self.profiles.append(profile)
        return profile

    def latest_organization(self, organization_id: UUID) -> CriteriaProfile | None:
        return next(
            (
                profile
                for profile in reversed(self.profiles)
                if profile.organization_id == organization_id
                and profile.scope == "ORGANIZATION"
            ),
            None,
        )

    def latest_personal(
        self,
        organization_id: UUID,
        owner_user_id: UUID,
    ) -> tuple[CriteriaProfile, ...]:
        return tuple(
            profile
            for profile in self.profiles
            if profile.organization_id == organization_id
            and profile.owner_user_id == owner_user_id
            and profile.scope == "PERSONAL"
        )

    def get_personal(
        self,
        organization_id: UUID,
        owner_user_id: UUID,
        profile_id: UUID,
    ) -> CriteriaProfile | None:
        return next(
            (
                profile
                for profile in self.profiles
                if profile.id == profile_id
                and profile.organization_id == organization_id
                and profile.owner_user_id == owner_user_id
                and profile.scope == "PERSONAL"
            ),
            None,
        )

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
        del is_administrator
        selection = CriteriaSelection(
            id=uuid4(),
            organization_id=organization_id,
            user_id=user_id,
            selection_kind=selection_kind,
            personal_profile_id=personal_profile_id,
            criteria_sha256=criteria_sha256,
            selected_at=NOW,
            source=source,
        )
        self.selections.append(selection)
        return selection

    def latest_selection(
        self,
        organization_id: UUID,
        user_id: UUID,
    ) -> CriteriaSelection | None:
        return next(
            (
                item
                for item in reversed(self.selections)
                if item.organization_id == organization_id and item.user_id == user_id
            ),
            None,
        )

    def selection_history(
        self,
        organization_id: UUID,
        user_id: UUID,
        *,
        limit: int = 20,
    ) -> tuple[CriteriaSelection, ...]:
        return tuple(
            item
            for item in reversed(self.selections)
            if item.organization_id == organization_id and item.user_id == user_id
        )[:limit]


def _principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=USER_ID,
        username="criteria-user",
        display_name="기준 사용자",
        organization_id=ORGANIZATION_ID,
        roles=frozenset({HumanRole.USER}),
        asset_ids=frozenset(),
        auth_methods=frozenset({"password"}),
        session_created_at=NOW,
        reauthenticated_at=NOW,
    )


def test_selection_history_restores_personal_then_exact_kisa_values() -> None:
    repository = MemoryCriteriaRepository()
    service = AssessmentCriteriaService(repository)
    profile = service.save_personal(
        _principal(),
        name="강화 기준",
        values={"password_maximum_age_days": 30},
        change_reason="테스트",
    )

    service.select(
        _principal(),
        selection_kind="PERSONAL",
        personal_profile_id=profile.id,
    )
    personal = service.options(_principal())
    assert personal["selected_kind"] == "PERSONAL"
    assert personal["selected_personal_profile"]["id"] == str(profile.id)  # type: ignore[index]

    service.select(_principal(), selection_kind="KISA_DEFAULT", source="RESET")
    official = service.options(_principal())
    assert official["selected_kind"] == "KISA_DEFAULT"
    assert official["selected_personal_profile"] is None
    assert len(official["selection_history"]) == 2  # type: ignore[arg-type]


def test_scan_dialog_can_request_kisa_default_without_reusing_saved_personal_selection() -> None:
    repository = MemoryCriteriaRepository()
    service = AssessmentCriteriaService(repository)
    profile = service.save_personal(
        _principal(),
        name="내 강화 기준",
        values={"password_maximum_age_days": 30},
        change_reason="테스트",
    )
    service.select(
        _principal(),
        selection_kind="PERSONAL",
        personal_profile_id=profile.id,
    )

    options = service.options(_principal(), selection_kind="KISA_DEFAULT")

    assert options["selected_kind"] == "KISA_DEFAULT"
    assert options["selected_personal_profile"] is None
    effective = cast(list[Mapping[str, object]], options["effective"])
    assert all(item["source"] == "KISA_DEFAULT" for item in effective)


def test_scan_start_records_only_the_exact_criteria_snapshot() -> None:
    repository = MemoryCriteriaRepository()
    service = AssessmentCriteriaService(repository)
    options = service.options(_principal())

    selection = service.select(
        _principal(),
        selection_kind="KISA_DEFAULT",
        source="SCAN_START",
        expected_criteria_sha256=str(options["effective_sha256"]),
    )

    assert selection.source == "SCAN_START"
    assert len(repository.selections) == 1
    with pytest.raises(CriteriaContractError, match="변경되었습니다"):
        service.select(
            _principal(),
            selection_kind="KISA_DEFAULT",
            source="SCAN_START",
            expected_criteria_sha256="0" * 64,
        )
    assert len(repository.selections) == 1
