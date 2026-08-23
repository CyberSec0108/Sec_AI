from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from security_audit.security.auth import (
    AccountManagementError,
    AccountManagementService,
    Argon2PasswordService,
    AuthenticatedPrincipal,
    HumanRole,
    ManagedAccount,
)
from security_audit.security.auth.account_management import mfa_code_digest

ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
ADMIN_ID = UUID("46000000-0000-4000-8000-000000000003")


class MemoryAccountManagementRepository:
    def __init__(self) -> None:
        now = datetime.now(UTC)
        password_service = Argon2PasswordService()
        self.accounts: dict[UUID, ManagedAccount] = {
            ADMIN_ID: ManagedAccount(
                id=ADMIN_ID,
                organization_id=ORGANIZATION_ID,
                username="local-owner",
                display_name="관리자",
                status="ACTIVE",
                password_hash=password_service.hash("Valid9!Password"),
                credential_version=1,
                created_at=now,
                updated_at=now,
            )
        }
        self.roles: dict[UUID, set[HumanRole]] = {ADMIN_ID: {HumanRole.USER, HumanRole.ADMIN}}
        self.revoked_users: list[UUID] = []
        self.audit_events: list[tuple[str, str, str, UUID | None]] = []
        self.mfa_hashes: dict[UUID, tuple[str, datetime]] = {}

    def registration_organization_id(self) -> UUID | None:
        return ORGANIZATION_ID

    def account_by_username(self, username: str) -> ManagedAccount | None:
        return next((a for a in self.accounts.values() if a.username == username), None)

    def account_by_id(self, user_id: UUID) -> ManagedAccount | None:
        return self.accounts.get(user_id)

    def create_pending_account(
        self,
        *,
        organization_id: UUID,
        username: str,
        display_name: str,
        password_hash: str,
        now: datetime,
    ) -> ManagedAccount | None:
        if self.account_by_username(username) is not None:
            return None
        account = ManagedAccount(
            id=uuid4(),
            organization_id=organization_id,
            username=username,
            display_name=display_name,
            status="PENDING_APPROVAL",
            password_hash=password_hash,
            credential_version=1,
            created_at=now,
            updated_at=now,
        )
        self.accounts[account.id] = account
        return account

    def list_accounts(self, organization_id: UUID, limit: int = 100) -> tuple[ManagedAccount, ...]:
        return tuple(
            account
            for account in self.accounts.values()
            if account.organization_id == organization_id
        )[:limit]

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
        account = self.accounts.get(user_id)
        if (
            account is None
            or account.organization_id != organization_id
            or account.status not in from_statuses
        ):
            return None
        account = replace(account, status=to_status, updated_at=now)
        self.accounts[user_id] = account
        if grant_user_role:
            self.roles.setdefault(user_id, set()).add(HumanRole.USER)
        return account

    def update_display_name(
        self, user_id: UUID, organization_id: UUID, display_name: str, now: datetime
    ) -> ManagedAccount | None:
        account = self.accounts.get(user_id)
        if account is None or account.organization_id != organization_id:
            return None
        account = replace(account, display_name=display_name, updated_at=now)
        self.accounts[user_id] = account
        return account

    def change_password(
        self,
        user_id: UUID,
        organization_id: UUID,
        password_hash: str,
        now: datetime,
    ) -> bool:
        account = self.accounts.get(user_id)
        if account is None or account.organization_id != organization_id:
            return False
        self.accounts[user_id] = replace(
            account,
            password_hash=password_hash,
            credential_version=account.credential_version + 1,
            updated_at=now,
        )
        return True

    def update_mfa_code(
        self,
        user_id: UUID,
        organization_id: UUID,
        code_hash: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> bool:
        account = self.accounts.get(user_id)
        if (
            account is None
            or account.organization_id != organization_id
            or account.status != "ACTIVE"
        ):
            return False
        self.accounts[user_id] = replace(
            account,
            mfa_code_hash=code_hash,
            mfa_issued_at=issued_at,
            mfa_expires_at=expires_at,
            credential_version=account.credential_version + 1,
            updated_at=issued_at,
        )
        self.mfa_hashes[user_id] = (code_hash, expires_at)
        return True

    def revoke_user_sessions(self, user_id: UUID, now: datetime, reason: str) -> None:
        del now, reason
        self.revoked_users.append(user_id)

    def audit(
        self,
        event_type: str,
        outcome: str,
        reason_code: str,
        user_id: UUID | None,
        organization_id: UUID | None,
    ) -> None:
        del organization_id
        self.audit_events.append((event_type, outcome, reason_code, user_id))


def _principal(*roles: HumanRole) -> AuthenticatedPrincipal:
    now = datetime.now(UTC)
    return AuthenticatedPrincipal(
        user_id=ADMIN_ID,
        username="local-owner",
        display_name="관리자",
        organization_id=ORGANIZATION_ID,
        roles=frozenset(roles),
        asset_ids=frozenset(),
        auth_methods=frozenset({"password", "dev-test-mfa"}),
        session_created_at=now,
        reauthenticated_at=now,
    )


def test_registration_is_pending_and_never_stores_plaintext_password() -> None:
    repository = MemoryAccountManagementRepository()
    service = AccountManagementService(repository)
    candidate = "".join(("Strong9!", "Password"))

    created = service.request_registration(
        "new-user", "새 사용자", candidate, candidate
    )

    assert created
    account = repository.account_by_username("new-user")
    assert account is not None
    assert account.status == "PENDING_APPROVAL"
    assert account.password_hash != candidate
    assert account.password_hash.startswith("$argon2id$")
    assert not repository.roles.get(account.id)


def test_only_admin_can_approve_and_approved_account_gets_user_role() -> None:
    repository = MemoryAccountManagementRepository()
    service = AccountManagementService(repository)
    service.request_registration("new-user", "새 사용자", "Strong9!Password", "Strong9!Password")
    account = repository.account_by_username("new-user")
    assert account is not None

    with pytest.raises(AccountManagementError):
        service.change_status(_principal(HumanRole.USER), account.id, "approve")

    approved = service.change_status(
        _principal(HumanRole.USER, HumanRole.ADMIN), account.id, "approve"
    )
    assert approved.status == "ACTIVE"
    assert HumanRole.USER in repository.roles[account.id]


def test_admin_cannot_disable_own_account() -> None:
    service = AccountManagementService(MemoryAccountManagementRepository())
    with pytest.raises(AccountManagementError) as rejected:
        service.change_status(_principal(HumanRole.ADMIN), ADMIN_ID, "disable")
    assert "본인" in rejected.value.public_message


def test_password_change_checks_current_password_and_revokes_all_sessions() -> None:
    repository = MemoryAccountManagementRepository()
    service = AccountManagementService(repository)
    principal = _principal(HumanRole.ADMIN)

    service.change_password(
        principal,
        "Valid9!Password",
        "Changed9!Password",
        "Changed9!Password",
    )

    updated = repository.accounts[ADMIN_ID]
    assert Argon2PasswordService().verify(updated.password_hash, "Changed9!Password")
    assert updated.credential_version == 2
    assert repository.revoked_users == [ADMIN_ID]


def test_admin_can_reissue_masked_user_mfa_code_without_storing_plaintext() -> None:
    repository = MemoryAccountManagementRepository()
    signing_key = b"unit-test-session-index-key-32-bytes-minimum"
    service = AccountManagementService(repository, mfa_signing_key=signing_key)

    issued = service.renew_mfa_code(_principal(HumanRole.ADMIN), ADMIN_ID)

    assert len(issued.code) == 6
    assert issued.code.isascii() and issued.code.isdigit()
    stored_hash, stored_expiry = repository.mfa_hashes[ADMIN_ID]
    assert stored_hash == mfa_code_digest(signing_key, ADMIN_ID, issued.code)
    assert issued.code not in stored_hash
    assert stored_expiry == issued.expires_at
    assert repository.revoked_users == [ADMIN_ID]


def test_account_management_ui_and_migration_contracts() -> None:
    root = Path(__file__).resolve().parents[2]
    login = (root / "apps/web/templates/pages/login.html").read_text(encoding="utf-8")
    registration = (root / "apps/web/templates/pages/register.html").read_text(encoding="utf-8")
    settings = (root / "apps/web/templates/pages/account_settings.html").read_text(encoding="utf-8")
    admin = (root / "apps/web/templates/pages/admin_accounts.html").read_text(encoding="utf-8")
    account_management = (
        root / "src/security_audit/security/auth/account_management.py"
    ).read_text(encoding="utf-8")
    mfa = (root / "apps/web/templates/pages/mfa.html").read_text(encoding="utf-8")
    migration = (
        root / "database/alembic/versions/0013_account_approval_management.py"
    ).read_text(encoding="utf-8")

    assert 'href="/auth/register"' in login
    assert 'action="/auth/login" class="auth-form" target="_self"' in login
    assert 'action="/auth/register"' in registration
    assert 'name="csrf_token"' in registration
    assert 'action="/auth/settings/password"' in settings
    assert 'action="/admin/accounts/' in admin
    assert 'name="csrf_token"' in admin
    assert 'action="/admin/accounts/' in admin and "/renew-mfa" in admin
    assert "<colgroup>" in admin
    assert "account-security-actions" in admin
    assert "변경할 작업 없음" not in admin
    assert 'strftime("%Y-%m-%d %H:%M")' in admin
    assert "UserRoleAssignmentRecord.role_name == HumanRole.ADMIN.value" in account_management
    assert 'UserAccountRecord.status.in_(("ACTIVE", "TEMP_LOCKED"))' in account_management
    assert 'type="password" name="code"' in mfa
    assert 'action="/auth/mfa" class="auth-form" target="_self"' in mfa
    for removed_copy in (
        "두 번째 보안 확인",
        "6자리 인증코드 입력",
        "비밀번호가 노출되더라도 바로 로그인되지 않도록 한 번 더 확인합니다.",
    ):
        assert removed_copy not in mfa
    assert "PENDING_APPROVAL" in migration
    assert "REJECTED" in migration
    mfa_migration = (
        root / "database/alembic/versions/0014_user_mfa_code_management.py"
    ).read_text(encoding="utf-8")
    assert "mfa_code_hash" in mfa_migration
