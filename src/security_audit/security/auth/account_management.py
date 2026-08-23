"""승인 기반 로컬 계정 생성과 사용자 계정 설정 서비스."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from sqlalchemy import Engine, case, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from security_audit.persistence.database.models import (
    AuthenticationAuditEventRecord,
    BrowserSessionRecord,
    OrganizationRecord,
    UserAccountRecord,
    UserRoleAssignmentRecord,
)
from security_audit.security.auth.contracts import AuthenticatedPrincipal, HumanRole
from security_audit.security.auth.passwords import (
    Argon2PasswordService,
    validate_password_policy,
)

_USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_MFA_VALID_DAYS = 30
_STATUS_ACTIONS: dict[str, tuple[frozenset[str], str, bool]] = {
    "approve": (frozenset({"PENDING_APPROVAL"}), "ACTIVE", True),
    "reject": (frozenset({"PENDING_APPROVAL"}), "REJECTED", False),
    "disable": (frozenset({"ACTIVE"}), "DISABLED", False),
    "activate": (frozenset({"DISABLED"}), "ACTIVE", True),
}


class AccountManagementError(ValueError):
    def __init__(self, public_message: str) -> None:
        super().__init__(public_message)
        self.public_message = public_message


@dataclass(frozen=True, slots=True)
class ManagedAccount:
    id: UUID
    organization_id: UUID
    username: str
    display_name: str
    status: str
    password_hash: str
    credential_version: int
    created_at: datetime
    updated_at: datetime
    mfa_code_hash: str | None = None
    mfa_issued_at: datetime | None = None
    mfa_expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class IssuedMfaCode:
    code: str
    expires_at: datetime


def mfa_code_digest(signing_key: bytes, user_id: UUID, code: str) -> str:
    payload = f"secai-mfa:{user_id}:{code}".encode("ascii")
    return hmac.new(signing_key, payload, hashlib.sha256).hexdigest()


class AccountManagementRepository(Protocol):
    def registration_organization_id(self) -> UUID | None: ...

    def account_by_username(self, username: str) -> ManagedAccount | None: ...

    def account_by_id(self, user_id: UUID) -> ManagedAccount | None: ...

    def create_pending_account(
        self,
        *,
        organization_id: UUID,
        username: str,
        display_name: str,
        password_hash: str,
        now: datetime,
    ) -> ManagedAccount | None: ...

    def list_accounts(
        self,
        organization_id: UUID,
        limit: int = 100,
    ) -> tuple[ManagedAccount, ...]: ...

    def transition_account(
        self,
        *,
        user_id: UUID,
        organization_id: UUID,
        from_statuses: frozenset[str],
        to_status: str,
        now: datetime,
        grant_user_role: bool,
    ) -> ManagedAccount | None: ...

    def update_display_name(
        self,
        user_id: UUID,
        organization_id: UUID,
        display_name: str,
        now: datetime,
    ) -> ManagedAccount | None: ...

    def change_password(
        self,
        user_id: UUID,
        organization_id: UUID,
        password_hash: str,
        now: datetime,
    ) -> bool: ...

    def update_mfa_code(
        self,
        user_id: UUID,
        organization_id: UUID,
        code_hash: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> bool: ...

    def revoke_user_sessions(self, user_id: UUID, now: datetime, reason: str) -> None: ...

    def audit(
        self,
        event_type: str,
        outcome: str,
        reason_code: str,
        user_id: UUID | None,
        organization_id: UUID | None,
    ) -> None: ...


def _managed_account(record: UserAccountRecord) -> ManagedAccount:
    return ManagedAccount(
        id=record.id,
        organization_id=record.organization_id,
        username=record.username_canonical,
        display_name=record.display_name,
        status=record.status,
        password_hash=record.password_hash,
        credential_version=record.credential_version,
        created_at=record.created_at,
        updated_at=record.updated_at,
        mfa_code_hash=record.mfa_code_hash,
        mfa_issued_at=record.mfa_issued_at,
        mfa_expires_at=record.mfa_expires_at,
    )


class SqlAccountManagementRepository:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def registration_organization_id(self) -> UUID | None:
        with Session(self._engine) as session:
            administrator_organization_id = session.scalar(
                select(UserAccountRecord.organization_id)
                .join(
                    UserRoleAssignmentRecord,
                    UserRoleAssignmentRecord.user_id == UserAccountRecord.id,
                )
                .where(
                    UserRoleAssignmentRecord.organization_id
                    == UserAccountRecord.organization_id,
                    UserRoleAssignmentRecord.role_name == HumanRole.ADMIN.value,
                    UserRoleAssignmentRecord.revoked_at.is_(None),
                    UserAccountRecord.status.in_(("ACTIVE", "TEMP_LOCKED")),
                )
                .order_by(
                    UserRoleAssignmentRecord.granted_at,
                    UserAccountRecord.created_at,
                )
                .limit(1)
            )
            if administrator_organization_id is not None:
                return administrator_organization_id
            return session.scalar(
                select(OrganizationRecord.id).order_by(OrganizationRecord.created_at).limit(1)
            )

    def account_by_username(self, username: str) -> ManagedAccount | None:
        with Session(self._engine) as session:
            record = session.scalar(
                select(UserAccountRecord).where(
                    UserAccountRecord.username_canonical == username
                )
            )
            return _managed_account(record) if record is not None else None

    def account_by_id(self, user_id: UUID) -> ManagedAccount | None:
        with Session(self._engine) as session:
            record = session.get(UserAccountRecord, user_id)
            return _managed_account(record) if record is not None else None

    def create_pending_account(
        self,
        *,
        organization_id: UUID,
        username: str,
        display_name: str,
        password_hash: str,
        now: datetime,
    ) -> ManagedAccount | None:
        record = UserAccountRecord(
            id=uuid4(),
            organization_id=organization_id,
            username_canonical=username,
            display_name=display_name,
            status="PENDING_APPROVAL",
            password_hash=password_hash,
            credential_version=1,
            role_assignment_version=1,
            password_changed_at=now,
            failed_attempts=0,
            locked_until=None,
            created_at=now,
            updated_at=now,
        )
        try:
            with Session(self._engine) as session, session.begin():
                session.add(record)
                session.flush()
                result = _managed_account(record)
        except IntegrityError:
            return None
        return result

    def list_accounts(
        self,
        organization_id: UUID,
        limit: int = 100,
    ) -> tuple[ManagedAccount, ...]:
        safe_limit = max(1, min(limit, 100))
        status_order = case(
            (UserAccountRecord.status == "PENDING_APPROVAL", 0),
            (UserAccountRecord.status == "ACTIVE", 1),
            (UserAccountRecord.status == "DISABLED", 2),
            else_=3,
        )
        with Session(self._engine) as session:
            records = session.scalars(
                select(UserAccountRecord)
                .where(UserAccountRecord.organization_id == organization_id)
                .order_by(status_order, UserAccountRecord.created_at.desc())
                .limit(safe_limit)
            ).all()
            return tuple(_managed_account(record) for record in records)

    def transition_account(
        self,
        *,
        user_id: UUID,
        organization_id: UUID,
        from_statuses: frozenset[str],
        to_status: str,
        now: datetime,
        grant_user_role: bool,
    ) -> ManagedAccount | None:
        with Session(self._engine) as session, session.begin():
            record = session.scalar(
                select(UserAccountRecord)
                .where(
                    UserAccountRecord.id == user_id,
                    UserAccountRecord.organization_id == organization_id,
                )
                .with_for_update()
            )
            if record is None or record.status not in from_statuses:
                return None
            record.status = to_status
            record.failed_attempts = 0
            record.locked_until = None
            record.updated_at = now
            if grant_user_role:
                assignment = session.scalar(
                    select(UserRoleAssignmentRecord).where(
                        UserRoleAssignmentRecord.user_id == user_id,
                        UserRoleAssignmentRecord.organization_id == organization_id,
                        UserRoleAssignmentRecord.role_name == HumanRole.USER.value,
                    )
                )
                if assignment is None:
                    session.add(
                        UserRoleAssignmentRecord(
                            id=uuid4(),
                            user_id=user_id,
                            organization_id=organization_id,
                            role_name=HumanRole.USER.value,
                            granted_at=now,
                            revoked_at=None,
                        )
                    )
                    record.role_assignment_version += 1
                elif assignment.revoked_at is not None:
                    assignment.revoked_at = None
                    assignment.granted_at = now
                    record.role_assignment_version += 1
            session.flush()
            result = _managed_account(record)
        return result

    def update_display_name(
        self,
        user_id: UUID,
        organization_id: UUID,
        display_name: str,
        now: datetime,
    ) -> ManagedAccount | None:
        with Session(self._engine) as session, session.begin():
            record = session.scalar(
                select(UserAccountRecord).where(
                    UserAccountRecord.id == user_id,
                    UserAccountRecord.organization_id == organization_id,
                )
            )
            if record is None:
                return None
            record.display_name = display_name
            record.updated_at = now
            session.flush()
            result = _managed_account(record)
        return result

    def change_password(
        self,
        user_id: UUID,
        organization_id: UUID,
        password_hash: str,
        now: datetime,
    ) -> bool:
        with Session(self._engine) as session, session.begin():
            record = session.scalar(
                select(UserAccountRecord)
                .where(
                    UserAccountRecord.id == user_id,
                    UserAccountRecord.organization_id == organization_id,
                    UserAccountRecord.status == "ACTIVE",
                )
                .with_for_update()
            )
            if record is None:
                return False
            record.password_hash = password_hash
            record.credential_version += 1
            record.password_changed_at = now
            record.failed_attempts = 0
            record.locked_until = None
            record.updated_at = now
            return True

    def update_mfa_code(
        self,
        user_id: UUID,
        organization_id: UUID,
        code_hash: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> bool:
        with Session(self._engine) as session, session.begin():
            record = session.scalar(
                select(UserAccountRecord)
                .where(
                    UserAccountRecord.id == user_id,
                    UserAccountRecord.organization_id == organization_id,
                    UserAccountRecord.status == "ACTIVE",
                )
                .with_for_update()
            )
            if record is None:
                return False
            record.mfa_code_hash = code_hash
            record.mfa_issued_at = issued_at
            record.mfa_expires_at = expires_at
            record.credential_version += 1
            record.updated_at = issued_at
            return True

    def revoke_user_sessions(self, user_id: UUID, now: datetime, reason: str) -> None:
        with Session(self._engine) as session, session.begin():
            session.execute(
                update(BrowserSessionRecord)
                .where(
                    BrowserSessionRecord.user_id == user_id,
                    BrowserSessionRecord.revoked_at.is_(None),
                )
                .values(revoked_at=now, revoke_reason=reason)
            )

    def audit(
        self,
        event_type: str,
        outcome: str,
        reason_code: str,
        user_id: UUID | None,
        organization_id: UUID | None,
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
                    session_reference=None,
                )
            )


class AccountManagementService:
    def __init__(
        self,
        repository: AccountManagementRepository,
        password_service: Argon2PasswordService | None = None,
        mfa_signing_key: bytes | None = None,
    ) -> None:
        self._repository = repository
        self._passwords = password_service or Argon2PasswordService()
        self._mfa_signing_key = mfa_signing_key

    @staticmethod
    def _username(value: str) -> str:
        username = unicodedata.normalize("NFC", value).strip().casefold()
        if not _USERNAME_PATTERN.fullmatch(username) or ".." in username:
            raise AccountManagementError(
                "사용자 이름은 영문 소문자 또는 숫자로 시작하는 3~64자로 입력해 주세요."
            )
        return username

    @staticmethod
    def _display_name(value: str) -> str:
        display_name = unicodedata.normalize("NFC", value).strip()
        if not display_name or len(display_name) > 128:
            raise AccountManagementError("표시 이름은 1~128자로 입력해 주세요.")
        if any(unicodedata.category(character).startswith("C") for character in display_name):
            raise AccountManagementError("표시 이름에 제어 문자를 사용할 수 없습니다.")
        return display_name

    @staticmethod
    def _require_admin(principal: AuthenticatedPrincipal) -> None:
        if HumanRole.ADMIN not in principal.roles:
            raise AccountManagementError("관리자 권한이 필요합니다.")

    def request_registration(
        self,
        username: str,
        display_name: str,
        password: str,
        password_confirmation: str,
        now: datetime | None = None,
    ) -> bool:
        canonical = self._username(username)
        safe_display_name = self._display_name(display_name)
        if password != password_confirmation:
            raise AccountManagementError("새 비밀번호 확인이 일치하지 않습니다.")
        policy = validate_password_policy(password, canonical)
        if not policy.accepted:
            raise AccountManagementError(" ".join(policy.reasons))
        organization_id = self._repository.registration_organization_id()
        if organization_id is None:
            raise AccountManagementError("가입 요청을 받을 조직이 준비되지 않았습니다.")
        current_time = now or datetime.now(UTC)
        account = self._repository.create_pending_account(
            organization_id=organization_id,
            username=canonical,
            display_name=safe_display_name,
            password_hash=self._passwords.hash(password),
            now=current_time,
        )
        self._repository.audit(
            "ACCOUNT_REGISTRATION_REQUEST",
            "ALLOW" if account is not None else "DENY",
            "PENDING_APPROVAL" if account is not None else "DUPLICATE_REQUEST",
            account.id if account is not None else None,
            organization_id,
        )
        return account is not None

    def list_accounts(self, principal: AuthenticatedPrincipal) -> tuple[ManagedAccount, ...]:
        self._require_admin(principal)
        return self._repository.list_accounts(principal.organization_id)

    def change_status(
        self,
        principal: AuthenticatedPrincipal,
        user_id: UUID,
        action: str,
        now: datetime | None = None,
    ) -> ManagedAccount:
        self._require_admin(principal)
        transition = _STATUS_ACTIONS.get(action)
        if transition is None:
            raise AccountManagementError("지원하지 않는 계정 관리 작업입니다.")
        if user_id == principal.user_id and action in {"reject", "disable"}:
            raise AccountManagementError("현재 로그인한 본인 계정은 중지할 수 없습니다.")
        from_statuses, to_status, grant_user_role = transition
        current_time = now or datetime.now(UTC)
        account = self._repository.transition_account(
            user_id=user_id,
            organization_id=principal.organization_id,
            from_statuses=from_statuses,
            to_status=to_status,
            now=current_time,
            grant_user_role=grant_user_role,
        )
        if account is None:
            raise AccountManagementError("계정 상태가 이미 변경되었거나 계정을 찾을 수 없습니다.")
        if action in {"reject", "disable"}:
            self._repository.revoke_user_sessions(user_id, current_time, f"ACCOUNT_{to_status}")
        self._repository.audit(
            "ACCOUNT_STATUS_CHANGE",
            "ALLOW",
            f"ACCOUNT_{to_status}",
            principal.user_id,
            principal.organization_id,
        )
        return account

    def update_display_name(
        self,
        principal: AuthenticatedPrincipal,
        display_name: str,
        now: datetime | None = None,
    ) -> ManagedAccount:
        current_time = now or datetime.now(UTC)
        account = self._repository.update_display_name(
            principal.user_id,
            principal.organization_id,
            self._display_name(display_name),
            current_time,
        )
        if account is None:
            raise AccountManagementError("계정 정보를 변경할 수 없습니다.")
        self._repository.audit(
            "ACCOUNT_PROFILE_CHANGE",
            "ALLOW",
            "DISPLAY_NAME_CHANGED",
            principal.user_id,
            principal.organization_id,
        )
        return account

    def change_password(
        self,
        principal: AuthenticatedPrincipal,
        current_password: str,
        new_password: str,
        password_confirmation: str,
        now: datetime | None = None,
    ) -> None:
        account = self._repository.account_by_id(principal.user_id)
        if account is None or account.status != "ACTIVE":
            raise AccountManagementError("계정 정보를 변경할 수 없습니다.")
        if not self._passwords.verify(account.password_hash, current_password):
            self._repository.audit(
                "ACCOUNT_PASSWORD_CHANGE",
                "DENY",
                "CURRENT_PASSWORD_MISMATCH",
                principal.user_id,
                principal.organization_id,
            )
            raise AccountManagementError("현재 비밀번호가 올바르지 않습니다.")
        if new_password != password_confirmation:
            raise AccountManagementError("새 비밀번호 확인이 일치하지 않습니다.")
        if self._passwords.verify(account.password_hash, new_password):
            raise AccountManagementError("현재 비밀번호와 다른 새 비밀번호를 입력해 주세요.")
        policy = validate_password_policy(new_password, principal.username)
        if not policy.accepted:
            raise AccountManagementError(" ".join(policy.reasons))
        current_time = now or datetime.now(UTC)
        changed = self._repository.change_password(
            principal.user_id,
            principal.organization_id,
            self._passwords.hash(new_password),
            current_time,
        )
        if not changed:
            raise AccountManagementError("비밀번호를 변경할 수 없습니다.")
        self._repository.revoke_user_sessions(
            principal.user_id,
            current_time,
            "PASSWORD_CHANGED",
        )
        self._repository.audit(
            "ACCOUNT_PASSWORD_CHANGE",
            "ALLOW",
            "PASSWORD_CHANGED",
            principal.user_id,
            principal.organization_id,
        )

    def renew_mfa_code(
        self,
        principal: AuthenticatedPrincipal,
        user_id: UUID,
        now: datetime | None = None,
    ) -> IssuedMfaCode:
        self._require_admin(principal)
        if self._mfa_signing_key is None or len(self._mfa_signing_key) < 32:
            raise AccountManagementError("인증 코드 발급 설정이 준비되지 않았습니다.")
        current_time = now or datetime.now(UTC)
        expires_at = current_time + timedelta(days=_MFA_VALID_DAYS)
        code = f"{secrets.randbelow(1_000_000):06d}"
        changed = self._repository.update_mfa_code(
            user_id,
            principal.organization_id,
            mfa_code_digest(self._mfa_signing_key, user_id, code),
            current_time,
            expires_at,
        )
        if not changed:
            raise AccountManagementError("사용 중인 계정에만 인증 코드를 발급할 수 있습니다.")
        self._repository.revoke_user_sessions(user_id, current_time, "MFA_CODE_REISSUED")
        self._repository.audit(
            "ACCOUNT_MFA_CODE_REISSUE",
            "ALLOW",
            "MFA_CODE_REISSUED",
            principal.user_id,
            principal.organization_id,
        )
        return IssuedMfaCode(code=code, expires_at=expires_at)
