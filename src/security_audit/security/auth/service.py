"""Local password + development test-MFA authentication service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import unicodedata
from datetime import UTC, datetime, timedelta

from security_audit.security.auth.account_management import mfa_code_digest
from security_audit.security.auth.contracts import (
    AuthenticatedPrincipal,
    AuthenticationCode,
    AuthenticationError,
    HumanRole,
    SessionContext,
    SessionPhase,
)
from security_audit.security.auth.passwords import Argon2PasswordService
from security_audit.security.auth.repository import (
    AccountSnapshot,
    AuthenticationRepository,
    StoredSession,
)
from security_audit.security.auth.settings import AuthenticationSettings

_GENERIC_LOGIN_MESSAGE = "로그인 정보가 올바르지 않거나 현재 로그인할 수 없습니다."


class LocalAuthenticationService:
    def __init__(
        self,
        repository: AuthenticationRepository,
        settings: AuthenticationSettings,
        session_index_key: bytes,
        dev_mfa_code: str,
        password_service: Argon2PasswordService | None = None,
    ) -> None:
        if len(session_index_key) < 32:
            raise RuntimeError("The session index key must contain at least 32 bytes.")
        if settings.profile != "DEV-LOCAL":
            raise RuntimeError("Local test MFA is restricted to DEV-LOCAL.")
        if len(dev_mfa_code) != 6 or not dev_mfa_code.isascii() or not dev_mfa_code.isdigit():
            raise RuntimeError("The DEV-LOCAL test MFA code must be six ASCII digits.")
        self._repository = repository
        self.settings = settings
        self._key = session_index_key
        self._passwords = password_service or Argon2PasswordService()

    @staticmethod
    def canonical_username(username: str) -> str:
        return unicodedata.normalize("NFC", username).strip().casefold()

    def _session_hash(self, token: str) -> str:
        return hmac.new(self._key, token.encode(), hashlib.sha256).hexdigest()

    def _csrf_token(self, token: str) -> str:
        digest = hmac.new(
            self._key,
            b"csrf:" + token.encode(),
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    @staticmethod
    def _csrf_hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _reference(self, session_hash: str) -> str:
        return session_hash[:12]

    def _create_session(
        self,
        *,
        now: datetime,
        phase: SessionPhase,
        user: AccountSnapshot | None = None,
        auth_methods: str = "",
        privileged: bool = False,
    ) -> SessionContext:
        token = secrets.token_urlsafe(32)
        session_hash = self._session_hash(token)
        csrf_token = self._csrf_token(token)
        if phase is SessionPhase.AUTHENTICATED:
            expires_at = now + timedelta(hours=self.settings.absolute_timeout_hours)
            idle_minutes = (
                self.settings.privileged_idle_timeout_minutes
                if privileged
                else self.settings.idle_timeout_minutes
            )
        else:
            expires_at = now + timedelta(
                minutes=self.settings.pre_auth_timeout_minutes
            )
            idle_minutes = self.settings.pre_auth_timeout_minutes
        self._repository.create_session(
            {
                "session_id_hash": session_hash,
                "user_id": user.id if user else None,
                "active_organization_id": user.organization_id if user else None,
                "phase": phase.value,
                "credential_version": user.credential_version if user else 0,
                "role_assignment_version": (
                    user.role_assignment_version if user else 0
                ),
                "auth_methods": auth_methods,
                "csrf_token_hash": self._csrf_hash(csrf_token),
                "mfa_attempts": 0,
                "authenticated_at": (
                    now if phase is SessionPhase.AUTHENTICATED else None
                ),
                "reauthenticated_at": (
                    now if phase is SessionPhase.AUTHENTICATED else None
                ),
                "created_at": now,
                "last_seen_at": now,
                "expires_at": expires_at,
                "idle_expires_at": now + timedelta(minutes=idle_minutes),
                "revoked_at": None,
                "revoke_reason": None,
            }
        )
        return SessionContext(token, csrf_token, phase, expires_at)

    def new_pre_auth(self, now: datetime | None = None) -> SessionContext:
        return self._create_session(
            now=now or datetime.now(UTC),
            phase=SessionPhase.PRE_AUTH,
        )

    def pending_context(
        self,
        token: str | None,
        now: datetime | None = None,
    ) -> SessionContext:
        current_time = now or datetime.now(UTC)
        _, stored = self._load_session(
            token,
            SessionPhase.MFA_PENDING,
            current_time,
        )
        return SessionContext(
            token=token or "",
            csrf_token=self._csrf_token(token or ""),
            phase=SessionPhase.MFA_PENDING,
            expires_at=stored.expires_at,
        )

    def _load_session(
        self,
        token: str | None,
        expected_phase: SessionPhase,
        now: datetime,
    ) -> tuple[str, StoredSession]:
        if not token:
            raise AuthenticationError(
                AuthenticationCode.REQUIRED,
                "로그인이 필요합니다.",
            )
        session_hash = self._session_hash(token)
        stored = self._repository.session(session_hash)
        if stored is None or stored.phase is not expected_phase:
            raise AuthenticationError(
                AuthenticationCode.REQUIRED,
                "로그인을 다시 시작해 주세요.",
            )
        if stored.revoked_at is not None:
            raise AuthenticationError(
                AuthenticationCode.SESSION_REVOKED,
                "종료된 로그인입니다. 다시 로그인해 주세요.",
            )
        if now >= stored.expires_at or now >= stored.idle_expires_at:
            self._repository.revoke_session(session_hash, now, "TIMEOUT")
            raise AuthenticationError(
                AuthenticationCode.SESSION_EXPIRED,
                "로그인 시간이 만료되었습니다. 다시 로그인해 주세요.",
            )
        return session_hash, stored

    def verify_csrf(
        self,
        session_token: str | None,
        supplied_token: str | None,
        origin: str | None,
        referer: str | None,
        fetch_site: str | None,
        expected_phase: SessionPhase,
        now: datetime | None = None,
    ) -> None:
        current_time = now or datetime.now(UTC)
        _, stored = self._load_session(session_token, expected_phase, current_time)
        if fetch_site == "cross-site":
            self._reject_csrf()
        trusted_source = origin
        if trusted_source is None and referer is not None:
            trusted_source = referer
        canonical_source = trusted_source is not None and (
            trusted_source == self.settings.canonical_origin
            or trusted_source.startswith(self.settings.canonical_origin + "/")
        )
        dev_browser_same_origin = (
            self.settings.profile == "DEV-LOCAL"
            and fetch_site == "same-origin"
        )
        if not canonical_source and not dev_browser_same_origin:
            self._reject_csrf()
        if supplied_token is None or not hmac.compare_digest(
            stored.csrf_token_hash,
            self._csrf_hash(supplied_token),
        ):
            self._reject_csrf()

    @staticmethod
    def _reject_csrf() -> None:
        raise AuthenticationError(
            AuthenticationCode.CSRF_REJECTED,
            "요청의 보안 확인값이 올바르지 않습니다. 화면을 새로 열어 주세요.",
        )

    def password_login(
        self,
        pre_auth_token: str | None,
        username: str,
        password: str,
        now: datetime | None = None,
    ) -> SessionContext:
        current_time = now or datetime.now(UTC)
        old_hash, _ = self._load_session(
            pre_auth_token,
            SessionPhase.PRE_AUTH,
            current_time,
        )
        canonical = self.canonical_username(username)
        account = self._repository.account_by_username(canonical)
        if account is None:
            self._passwords.verify_dummy(password)
            self._repository.audit(
                "LOGIN_PASSWORD",
                "DENY",
                "UNKNOWN_SUBJECT",
                self._reference(old_hash),
            )
            raise AuthenticationError(
                AuthenticationCode.INVALID_CREDENTIALS,
                _GENERIC_LOGIN_MESSAGE,
            )
        locked = (
            account.status == "TEMP_LOCKED"
            and account.locked_until is not None
            and current_time < account.locked_until
        )
        if account.status in {"PENDING_APPROVAL", "DISABLED", "REJECTED"} or locked:
            self._passwords.verify_dummy(password)
            self._repository.audit(
                "LOGIN_PASSWORD",
                "DENY",
                "ACCOUNT_UNAVAILABLE",
                self._reference(old_hash),
                account.id,
                account.organization_id,
            )
            raise AuthenticationError(
                AuthenticationCode.INVALID_CREDENTIALS,
                _GENERIC_LOGIN_MESSAGE,
            )
        if not self._passwords.verify(account.password_hash, password):
            failure_count = account.failed_attempts + 1
            lock_until = (
                current_time + timedelta(minutes=15)
                if failure_count >= 10
                else None
            )
            self._repository.register_login_failure(
                account,
                current_time,
                lock_until,
            )
            self._repository.audit(
                "LOGIN_PASSWORD",
                "DENY",
                "BAD_PASSWORD",
                self._reference(old_hash),
                account.id,
                account.organization_id,
            )
            raise AuthenticationError(
                AuthenticationCode.INVALID_CREDENTIALS,
                _GENERIC_LOGIN_MESSAGE,
            )
        if current_time >= account.password_changed_at + timedelta(days=30):
            self._repository.audit(
                "LOGIN_PASSWORD",
                "DENY",
                "PASSWORD_EXPIRED",
                self._reference(old_hash),
                account.id,
                account.organization_id,
            )
            raise AuthenticationError(
                AuthenticationCode.INVALID_CREDENTIALS,
                "비밀번호 사용기간이 지났습니다. 승인된 계정 복구 절차로 변경해 주세요.",
            )
        self._repository.revoke_session(old_hash, current_time, "PASSWORD_VERIFIED")
        pending = self._create_session(
            now=current_time,
            phase=SessionPhase.MFA_PENDING,
            user=account,
            auth_methods="password",
        )
        self._repository.audit(
            "LOGIN_PASSWORD",
            "ALLOW",
            "MFA_REQUIRED",
            self._reference(self._session_hash(pending.token)),
            account.id,
            account.organization_id,
        )
        return pending

    def complete_dev_mfa(
        self,
        pending_token: str | None,
        supplied_code: str,
        now: datetime | None = None,
    ) -> SessionContext:
        current_time = now or datetime.now(UTC)
        old_hash, stored = self._load_session(
            pending_token,
            SessionPhase.MFA_PENDING,
            current_time,
        )
        if stored.user_id is None:
            raise AuthenticationError(
                AuthenticationCode.INVALID_MFA,
                "두 번째 인증을 다시 시작해 주세요.",
            )
        account = self._repository.account_by_id(stored.user_id)
        if account is None:
            raise AuthenticationError(
                AuthenticationCode.INVALID_MFA,
                "두 번째 인증을 다시 시작해 주세요.",
            )
        supplied_hash = mfa_code_digest(self._key, account.id, supplied_code)
        valid_factor = (
            account.status == "ACTIVE"
            and account.mfa_code_hash is not None
            and account.mfa_expires_at is not None
            and current_time < account.mfa_expires_at
            and hmac.compare_digest(supplied_hash, account.mfa_code_hash)
        )
        if stored.mfa_attempts >= 5 or not valid_factor:
            self._repository.increment_mfa_failure(old_hash)
            if stored.mfa_attempts + 1 >= 5:
                self._repository.revoke_session(old_hash, current_time, "MFA_LIMIT")
            self._repository.audit(
                "LOGIN_MFA",
                "DENY",
                "FACTOR_FAILED",
                self._reference(old_hash),
                account.id,
                account.organization_id,
            )
            raise AuthenticationError(
                AuthenticationCode.INVALID_MFA,
                "인증코드가 올바르지 않거나 사용할 수 없습니다.",
            )
        roles = self._repository.roles(account.id, account.organization_id)
        if not roles:
            self._repository.revoke_session(old_hash, current_time, "NO_ACTIVE_ROLE")
            raise AuthenticationError(
                AuthenticationCode.INVALID_CREDENTIALS,
                _GENERIC_LOGIN_MESSAGE,
            )
        self._repository.revoke_session(old_hash, current_time, "MFA_VERIFIED")
        authenticated = self._create_session(
            now=current_time,
            phase=SessionPhase.AUTHENTICATED,
            user=account,
            auth_methods="password,dev-test-mfa",
            privileged=bool(
                roles
                & {
                    HumanRole.SECURITY_OFFICER,
                    HumanRole.APPROVER,
                    HumanRole.ADMIN,
                }
            ),
        )
        self._repository.reset_login_failures(account.id, current_time)
        self._repository.audit(
            "LOGIN_MFA",
            "ALLOW",
            "AUTHENTICATED",
            self._reference(self._session_hash(authenticated.token)),
            account.id,
            account.organization_id,
        )
        return authenticated

    def authenticate(
        self,
        token: str | None,
        meaningful_activity: bool,
        now: datetime | None = None,
    ) -> SessionContext:
        current_time = now or datetime.now(UTC)
        session_hash, stored = self._load_session(
            token,
            SessionPhase.AUTHENTICATED,
            current_time,
        )
        if stored.user_id is None or stored.active_organization_id is None:
            raise AuthenticationError(
                AuthenticationCode.REQUIRED,
                "로그인이 필요합니다.",
            )
        account = self._repository.account_by_id(stored.user_id)
        if (
            account is None
            or account.status != "ACTIVE"
            or account.credential_version != stored.credential_version
            or account.role_assignment_version != stored.role_assignment_version
            or account.organization_id != stored.active_organization_id
        ):
            self._repository.revoke_session(
                session_hash,
                current_time,
                "IDENTITY_CHANGED",
            )
            raise AuthenticationError(
                AuthenticationCode.SESSION_REVOKED,
                "계정 또는 권한이 변경되어 다시 로그인해야 합니다.",
            )
        roles = self._repository.roles(account.id, account.organization_id)
        if not roles:
            self._repository.revoke_session(session_hash, current_time, "NO_ACTIVE_ROLE")
            raise AuthenticationError(
                AuthenticationCode.SESSION_REVOKED,
                "사용 가능한 역할이 없어 로그인이 종료되었습니다.",
            )
        authenticated_at = stored.authenticated_at or stored.created_at
        reauthenticated_at = stored.reauthenticated_at or authenticated_at
        principal = AuthenticatedPrincipal(
            user_id=account.id,
            username=account.username_canonical,
            display_name=account.display_name,
            organization_id=account.organization_id,
            roles=roles,
            asset_ids=self._repository.asset_ids(
                account.id,
                account.organization_id,
            ),
            auth_methods=frozenset(
                method for method in stored.auth_methods.split(",") if method
            ),
            session_created_at=stored.created_at,
            reauthenticated_at=reauthenticated_at,
        )
        if meaningful_activity:
            idle_minutes = (
                self.settings.privileged_idle_timeout_minutes
                if principal.privileged
                else self.settings.idle_timeout_minutes
            )
            idle_expiry = min(
                stored.expires_at,
                current_time + timedelta(minutes=idle_minutes),
            )
            self._repository.touch_session(
                session_hash,
                current_time,
                idle_expiry,
            )
        return SessionContext(
            token=token or "",
            csrf_token=self._csrf_token(token or ""),
            phase=SessionPhase.AUTHENTICATED,
            expires_at=stored.expires_at,
            principal=principal,
        )

    def revoke_current(
        self,
        token: str,
        reason: str = "LOGOUT",
        now: datetime | None = None,
    ) -> None:
        current_time = now or datetime.now(UTC)
        session_hash = self._session_hash(token)
        stored = self._repository.session(session_hash)
        self._repository.revoke_session(session_hash, current_time, reason)
        self._repository.audit(
            "SESSION_REVOKE",
            "ALLOW",
            reason,
            self._reference(session_hash),
            stored.user_id if stored else None,
            stored.active_organization_id if stored else None,
        )

    def revoke_all(
        self,
        token: str,
        now: datetime | None = None,
    ) -> None:
        current_time = now or datetime.now(UTC)
        session_hash, stored = self._load_session(
            token,
            SessionPhase.AUTHENTICATED,
            current_time,
        )
        if stored.user_id is None:
            raise AuthenticationError(
                AuthenticationCode.REQUIRED,
                "로그인이 필요합니다.",
            )
        self._repository.revoke_user_sessions(
            stored.user_id,
            current_time,
            "LOGOUT_ALL",
        )
        self._repository.audit(
            "SESSION_REVOKE_ALL",
            "ALLOW",
            "LOGOUT_ALL",
            self._reference(session_hash),
            stored.user_id,
            stored.active_organization_id,
        )

    def audit_authorization(
        self,
        token: str | None,
        principal: AuthenticatedPrincipal,
        permission: str,
        allowed: bool,
        reason_code: str,
    ) -> None:
        """Record a scope decision without storing a raw session or resource ID."""
        session_reference = (
            self._reference(self._session_hash(token)) if token else None
        )
        self._repository.audit(
            f"AUTHORIZATION_{permission}",
            "ALLOW" if allowed else "DENY",
            reason_code,
            session_reference,
            principal.user_id,
            principal.organization_id,
        )
