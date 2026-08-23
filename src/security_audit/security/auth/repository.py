"""PostgreSQL repository for local accounts and opaque browser sessions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID, uuid4

from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session

from security_audit.persistence.database.models import (
    AuthenticationAuditEventRecord,
    BrowserSessionRecord,
    UserAccountRecord,
    UserAssetAssignmentRecord,
    UserRoleAssignmentRecord,
)
from security_audit.security.auth.contracts import HumanRole, SessionPhase


@dataclass(frozen=True, slots=True)
class AccountSnapshot:
    id: UUID
    organization_id: UUID
    username_canonical: str
    display_name: str
    status: str
    password_hash: str
    credential_version: int
    role_assignment_version: int
    password_changed_at: datetime
    failed_attempts: int
    locked_until: datetime | None
    mfa_code_hash: str | None = None
    mfa_issued_at: datetime | None = None
    mfa_expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class StoredSession:
    session_id_hash: str
    user_id: UUID | None
    active_organization_id: UUID | None
    phase: SessionPhase
    credential_version: int
    role_assignment_version: int
    auth_methods: str
    csrf_token_hash: str
    mfa_attempts: int
    authenticated_at: datetime | None
    reauthenticated_at: datetime | None
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    idle_expires_at: datetime
    revoked_at: datetime | None


class AuthenticationRepository(Protocol):
    def account_by_username(self, username: str) -> AccountSnapshot | None: ...

    def account_by_id(self, user_id: UUID) -> AccountSnapshot | None: ...

    def roles(self, user_id: UUID, organization_id: UUID) -> frozenset[HumanRole]: ...

    def asset_ids(self, user_id: UUID, organization_id: UUID) -> frozenset[UUID]: ...

    def create_session(self, values: Mapping[str, object]) -> None: ...

    def session(self, session_id_hash: str) -> StoredSession | None: ...

    def revoke_session(
        self,
        session_id_hash: str,
        now: datetime,
        reason: str,
    ) -> None: ...

    def revoke_user_sessions(
        self,
        user_id: UUID,
        now: datetime,
        reason: str,
        except_hash: str | None = None,
    ) -> None: ...

    def touch_session(
        self,
        session_id_hash: str,
        now: datetime,
        idle_expires_at: datetime,
    ) -> None: ...

    def register_login_failure(
        self,
        account: AccountSnapshot,
        now: datetime,
        lock_until: datetime | None,
    ) -> None: ...

    def reset_login_failures(self, user_id: UUID, now: datetime) -> None: ...

    def increment_mfa_failure(self, session_id_hash: str) -> None: ...

    def audit(
        self,
        event_type: str,
        outcome: str,
        reason_code: str,
        session_reference: str | None,
        user_id: UUID | None = None,
        organization_id: UUID | None = None,
    ) -> None: ...


def _account(record: UserAccountRecord) -> AccountSnapshot:
    return AccountSnapshot(
        id=record.id,
        organization_id=record.organization_id,
        username_canonical=record.username_canonical,
        display_name=record.display_name,
        status=record.status,
        password_hash=record.password_hash,
        credential_version=record.credential_version,
        role_assignment_version=record.role_assignment_version,
        password_changed_at=record.password_changed_at,
        failed_attempts=record.failed_attempts,
        locked_until=record.locked_until,
        mfa_code_hash=record.mfa_code_hash,
        mfa_issued_at=record.mfa_issued_at,
        mfa_expires_at=record.mfa_expires_at,
    )


def _stored_session(record: BrowserSessionRecord) -> StoredSession:
    return StoredSession(
        session_id_hash=record.session_id_hash,
        user_id=record.user_id,
        active_organization_id=record.active_organization_id,
        phase=SessionPhase(record.phase),
        credential_version=record.credential_version,
        role_assignment_version=record.role_assignment_version,
        auth_methods=record.auth_methods,
        csrf_token_hash=record.csrf_token_hash,
        mfa_attempts=record.mfa_attempts,
        authenticated_at=record.authenticated_at,
        reauthenticated_at=record.reauthenticated_at,
        created_at=record.created_at,
        last_seen_at=record.last_seen_at,
        expires_at=record.expires_at,
        idle_expires_at=record.idle_expires_at,
        revoked_at=record.revoked_at,
    )


class SqlAuthenticationRepository:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def account_by_username(self, username: str) -> AccountSnapshot | None:
        with Session(self._engine) as session:
            record = session.scalar(
                select(UserAccountRecord).where(
                    UserAccountRecord.username_canonical == username
                )
            )
            return _account(record) if record is not None else None

    def account_by_id(self, user_id: UUID) -> AccountSnapshot | None:
        with Session(self._engine) as session:
            record = session.get(UserAccountRecord, user_id)
            return _account(record) if record is not None else None

    def roles(self, user_id: UUID, organization_id: UUID) -> frozenset[HumanRole]:
        with Session(self._engine) as session:
            names = session.scalars(
                select(UserRoleAssignmentRecord.role_name).where(
                    UserRoleAssignmentRecord.user_id == user_id,
                    UserRoleAssignmentRecord.organization_id == organization_id,
                    UserRoleAssignmentRecord.revoked_at.is_(None),
                )
            ).all()
        return frozenset(HumanRole(name) for name in names)

    def asset_ids(self, user_id: UUID, organization_id: UUID) -> frozenset[UUID]:
        with Session(self._engine) as session:
            values = session.scalars(
                select(UserAssetAssignmentRecord.asset_id).where(
                    UserAssetAssignmentRecord.user_id == user_id,
                    UserAssetAssignmentRecord.organization_id == organization_id,
                    UserAssetAssignmentRecord.revoked_at.is_(None),
                )
            ).all()
        return frozenset(values)

    def create_session(self, values: Mapping[str, object]) -> None:
        with Session(self._engine) as session, session.begin():
            session.add(BrowserSessionRecord(**dict(values)))

    def session(self, session_id_hash: str) -> StoredSession | None:
        with Session(self._engine) as session:
            record = session.get(BrowserSessionRecord, session_id_hash)
            return _stored_session(record) if record is not None else None

    def revoke_session(
        self,
        session_id_hash: str,
        now: datetime,
        reason: str,
    ) -> None:
        with Session(self._engine) as session, session.begin():
            session.execute(
                update(BrowserSessionRecord)
                .where(
                    BrowserSessionRecord.session_id_hash == session_id_hash,
                    BrowserSessionRecord.revoked_at.is_(None),
                )
                .values(revoked_at=now, revoke_reason=reason)
            )

    def revoke_user_sessions(
        self,
        user_id: UUID,
        now: datetime,
        reason: str,
        except_hash: str | None = None,
    ) -> None:
        statement = update(BrowserSessionRecord).where(
            BrowserSessionRecord.user_id == user_id,
            BrowserSessionRecord.revoked_at.is_(None),
        )
        if except_hash is not None:
            statement = statement.where(
                BrowserSessionRecord.session_id_hash != except_hash
            )
        with Session(self._engine) as session, session.begin():
            session.execute(statement.values(revoked_at=now, revoke_reason=reason))

    def touch_session(
        self,
        session_id_hash: str,
        now: datetime,
        idle_expires_at: datetime,
    ) -> None:
        with Session(self._engine) as session, session.begin():
            session.execute(
                update(BrowserSessionRecord)
                .where(
                    BrowserSessionRecord.session_id_hash == session_id_hash,
                    BrowserSessionRecord.revoked_at.is_(None),
                )
                .values(last_seen_at=now, idle_expires_at=idle_expires_at)
            )

    def register_login_failure(
        self,
        account: AccountSnapshot,
        now: datetime,
        lock_until: datetime | None,
    ) -> None:
        values: dict[str, object] = {
            "failed_attempts": account.failed_attempts + 1,
            "updated_at": now,
        }
        if lock_until is not None:
            values.update({"status": "TEMP_LOCKED", "locked_until": lock_until})
        with Session(self._engine) as session, session.begin():
            session.execute(
                update(UserAccountRecord)
                .where(UserAccountRecord.id == account.id)
                .values(**values)
            )

    def reset_login_failures(self, user_id: UUID, now: datetime) -> None:
        with Session(self._engine) as session, session.begin():
            session.execute(
                update(UserAccountRecord)
                .where(UserAccountRecord.id == user_id)
                .values(
                    failed_attempts=0,
                    status="ACTIVE",
                    locked_until=None,
                    updated_at=now,
                )
            )

    def increment_mfa_failure(self, session_id_hash: str) -> None:
        with Session(self._engine) as session, session.begin():
            session.execute(
                update(BrowserSessionRecord)
                .where(BrowserSessionRecord.session_id_hash == session_id_hash)
                .values(mfa_attempts=BrowserSessionRecord.mfa_attempts + 1)
            )

    def audit(
        self,
        event_type: str,
        outcome: str,
        reason_code: str,
        session_reference: str | None,
        user_id: UUID | None = None,
        organization_id: UUID | None = None,
    ) -> None:
        with Session(self._engine) as session, session.begin():
            session.add(
                AuthenticationAuditEventRecord(
                    id=uuid4(),
                    user_id=user_id,
                    organization_id=organization_id,
                    event_type=event_type,
                    outcome=outcome,
                    reason_code=reason_code,
                    session_reference=session_reference,
                )
            )
