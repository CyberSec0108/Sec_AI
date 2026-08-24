from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import pytest
from apps.api.main import app
from fastapi.testclient import TestClient

from security_audit.security.auth import (
    Argon2PasswordService,
    AuthenticatedPrincipal,
    AuthenticationCode,
    AuthenticationError,
    AuthenticationSettings,
    HumanRole,
    LocalAuthenticationService,
    SessionPhase,
    validate_password_policy,
)
from security_audit.security.auth.account_management import mfa_code_digest
from security_audit.security.auth.repository import AccountSnapshot, StoredSession
from security_audit.security.rbac import (
    AuthorizationOutcome,
    Permission,
    authorize,
)

ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
ASSET_ID = UUID("46000000-0000-4000-8000-000000000002")
OTHER_ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000091")
OTHER_ASSET_ID = UUID("46000000-0000-4000-8000-000000000092")
USER_ID = UUID("46000000-0000-4000-8000-000000000003")
ORIGIN = "http://testserver"


class MemoryAuthenticationRepository:
    def __init__(self, account: AccountSnapshot) -> None:
        self.accounts = {account.id: account}
        self.usernames = {account.username_canonical: account.id}
        self.sessions: dict[str, StoredSession] = {}
        self.user_roles = {account.id: frozenset({HumanRole.USER})}
        self.user_assets = {account.id: frozenset({ASSET_ID})}
        self.audit_events: list[tuple[str, str, str]] = []

    def account_by_username(self, username: str) -> AccountSnapshot | None:
        user_id = self.usernames.get(username)
        return self.accounts.get(user_id) if user_id else None

    def account_by_id(self, user_id: UUID) -> AccountSnapshot | None:
        return self.accounts.get(user_id)

    def roles(
        self,
        user_id: UUID,
        organization_id: UUID,
    ) -> frozenset[HumanRole]:
        if organization_id != ORGANIZATION_ID:
            return frozenset()
        return self.user_roles.get(user_id, frozenset())

    def asset_ids(
        self,
        user_id: UUID,
        organization_id: UUID,
    ) -> frozenset[UUID]:
        if organization_id != ORGANIZATION_ID:
            return frozenset()
        return self.user_assets.get(user_id, frozenset())

    def create_session(self, values: Mapping[str, object]) -> None:
        self.sessions[str(values["session_id_hash"])] = StoredSession(
            session_id_hash=str(values["session_id_hash"]),
            user_id=cast(UUID | None, values["user_id"]),
            active_organization_id=cast(
                UUID | None,
                values["active_organization_id"],
            ),
            phase=SessionPhase(str(values["phase"])),
            credential_version=cast(int, values["credential_version"]),
            role_assignment_version=cast(int, values["role_assignment_version"]),
            auth_methods=str(values["auth_methods"]),
            csrf_token_hash=str(values["csrf_token_hash"]),
            mfa_attempts=cast(int, values["mfa_attempts"]),
            authenticated_at=cast(datetime | None, values["authenticated_at"]),
            reauthenticated_at=cast(
                datetime | None,
                values["reauthenticated_at"],
            ),
            created_at=cast(datetime, values["created_at"]),
            last_seen_at=cast(datetime, values["last_seen_at"]),
            expires_at=cast(datetime, values["expires_at"]),
            idle_expires_at=cast(datetime, values["idle_expires_at"]),
            revoked_at=cast(datetime | None, values["revoked_at"]),
        )

    def session(self, session_id_hash: str) -> StoredSession | None:
        return self.sessions.get(session_id_hash)

    def revoke_session(
        self,
        session_id_hash: str,
        now: datetime,
        reason: str,
    ) -> None:
        del reason
        stored = self.sessions.get(session_id_hash)
        if stored is not None and stored.revoked_at is None:
            self.sessions[session_id_hash] = replace(stored, revoked_at=now)

    def revoke_user_sessions(
        self,
        user_id: UUID,
        now: datetime,
        reason: str,
        except_hash: str | None = None,
    ) -> None:
        del reason
        for key, stored in tuple(self.sessions.items()):
            if (
                stored.user_id == user_id
                and key != except_hash
                and stored.revoked_at is None
            ):
                self.sessions[key] = replace(stored, revoked_at=now)

    def touch_session(
        self,
        session_id_hash: str,
        now: datetime,
        idle_expires_at: datetime,
    ) -> None:
        stored = self.sessions[session_id_hash]
        self.sessions[session_id_hash] = replace(
            stored,
            last_seen_at=now,
            idle_expires_at=idle_expires_at,
        )

    def register_login_failure(
        self,
        account: AccountSnapshot,
        now: datetime,
        lock_until: datetime | None,
    ) -> None:
        updated = replace(
            account,
            failed_attempts=account.failed_attempts + 1,
            status="TEMP_LOCKED" if lock_until else account.status,
            locked_until=lock_until,
        )
        self.accounts[account.id] = updated

    def reset_login_failures(self, user_id: UUID, now: datetime) -> None:
        del now
        self.accounts[user_id] = replace(
            self.accounts[user_id],
            failed_attempts=0,
            status="ACTIVE",
            locked_until=None,
        )

    def increment_mfa_failure(self, session_id_hash: str) -> None:
        stored = self.sessions[session_id_hash]
        self.sessions[session_id_hash] = replace(
            stored,
            mfa_attempts=stored.mfa_attempts + 1,
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
        del session_reference, user_id, organization_id
        self.audit_events.append((event_type, outcome, reason_code))


def _service() -> tuple[LocalAuthenticationService, MemoryAuthenticationRepository]:
    password_service = Argon2PasswordService()
    session_key = b"unit-test-session-index-key-32-bytes-minimum"
    account = AccountSnapshot(
        id=USER_ID,
        organization_id=ORGANIZATION_ID,
        username_canonical="local-owner",
        display_name="로컬 개발 사용자",
        status="ACTIVE",
        password_hash=password_service.hash("Valid9!Password"),
        credential_version=1,
        role_assignment_version=1,
        password_changed_at=datetime.now(UTC),
        failed_attempts=0,
        locked_until=None,
        mfa_code_hash=mfa_code_digest(session_key, USER_ID, "123456"),
        mfa_issued_at=datetime.now(UTC),
        mfa_expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    repository = MemoryAuthenticationRepository(account)
    settings = AuthenticationSettings(
        enabled=True,
        profile="DEV-LOCAL",
        canonical_origin=ORIGIN,
        cookie_name="secai_dev_session",
        secure_cookie=False,
        session_index_key_file="unused",
        dev_mfa_code_file="unused",
    )
    return (
        LocalAuthenticationService(
            repository,
            settings,
            session_key,
            "123456",
            password_service,
        ),
        repository,
    )


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _login(client: TestClient) -> None:
    login = client.get("/auth/login")
    assert login.status_code == 200
    favicon = client.get("/favicon.ico", follow_redirects=False)
    assert favicon.status_code == 204
    assert "location" not in favicon.headers
    password = client.post(
        "/auth/login",
        data={
            "username": "local-owner",
            "password": "Valid9!Password",
            "csrf_token": _csrf(login.text),
            "next": "/",
        },
        headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"},
        follow_redirects=False,
    )
    assert password.status_code == 303
    assert password.headers["location"].startswith("/auth/mfa")
    mfa = client.get(password.headers["location"])
    assert mfa.status_code == 200
    completed = client.post(
        "/auth/mfa",
        data={"code": "123456", "csrf_token": _csrf(mfa.text), "next": "/"},
        headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"},
        follow_redirects=False,
    )
    assert completed.status_code == 303
    assert completed.headers["location"] == "/"


def test_password_policy_and_argon2id_boundary() -> None:
    assert validate_password_policy("Valid9!Password", "local-owner").accepted
    rejected = validate_password_policy("short1!", "local-owner")
    assert not rejected.accepted

    password_service = Argon2PasswordService()
    encoded = password_service.hash("Valid9!Password")
    assert encoded.startswith("$argon2id$")
    assert password_service.verify(encoded, "Valid9!Password")
    assert not password_service.verify(encoded, "Wrong9!Password")


def test_password_mfa_rotation_idle_timeout_and_replay_rejection() -> None:
    service, _ = _service()
    started = datetime(2026, 7, 24, 1, 0, tzinfo=UTC)
    pre_auth = service.new_pre_auth(started)
    service.verify_csrf(
        pre_auth.token,
        pre_auth.csrf_token,
        ORIGIN,
        None,
        "same-origin",
        pre_auth.phase,
        started,
    )
    pending = service.password_login(
        pre_auth.token,
        "local-owner",
        "Valid9!Password",
        started,
    )
    with pytest.raises(AuthenticationError) as reused:
        service.password_login(
            pre_auth.token,
            "local-owner",
            "Valid9!Password",
            started,
        )
    assert reused.value.code is AuthenticationCode.SESSION_REVOKED

    authenticated = service.complete_dev_mfa(
        pending.token,
        "123456",
        started,
    )
    context = service.authenticate(
        authenticated.token,
        meaningful_activity=False,
        now=started + timedelta(minutes=29),
    )
    assert context.principal is not None
    with pytest.raises(AuthenticationError) as expired:
        service.authenticate(
            authenticated.token,
            meaningful_activity=False,
            now=started + timedelta(minutes=31),
        )
    assert expired.value.code is AuthenticationCode.SESSION_EXPIRED


def test_csrf_is_bound_to_one_rotating_session() -> None:
    service, _ = _service()
    first = service.new_pre_auth()
    second = service.new_pre_auth()
    with pytest.raises(AuthenticationError) as rejected:
        service.verify_csrf(
            first.token,
            second.csrf_token,
            ORIGIN,
            None,
            "same-origin",
            first.phase,
        )
    assert rejected.value.code is AuthenticationCode.CSRF_REJECTED


def test_dev_local_accepts_browser_verified_same_origin_alias() -> None:
    service, _ = _service()
    pre_auth = service.new_pre_auth()

    service.verify_csrf(
        pre_auth.token,
        pre_auth.csrf_token,
        "http://127.0.0.1:18480",
        None,
        "same-origin",
        pre_auth.phase,
    )

    with pytest.raises(AuthenticationError) as rejected:
        service.verify_csrf(
            pre_auth.token,
            pre_auth.csrf_token,
            "http://evil.invalid",
            None,
            "cross-site",
            pre_auth.phase,
        )
    assert rejected.value.code is AuthenticationCode.CSRF_REJECTED


def test_password_expiry_is_enforced_at_thirty_days() -> None:
    service, repository = _service()
    account = repository.accounts[USER_ID]
    repository.accounts[USER_ID] = replace(
        account,
        password_changed_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    started = datetime(2026, 7, 24, tzinfo=UTC)
    pre_auth = service.new_pre_auth(started)
    with pytest.raises(AuthenticationError) as rejected:
        service.password_login(
            pre_auth.token,
            "local-owner",
            "Valid9!Password",
            started,
        )
    assert "비밀번호 사용기간" in rejected.value.public_message
    assert ("LOGIN_PASSWORD", "DENY", "PASSWORD_EXPIRED") in repository.audit_events


def test_pending_approval_account_cannot_start_login() -> None:
    service, repository = _service()
    repository.accounts[USER_ID] = replace(
        repository.accounts[USER_ID],
        status="PENDING_APPROVAL",
    )
    pre_auth = service.new_pre_auth()

    with pytest.raises(AuthenticationError) as rejected:
        service.password_login(
            pre_auth.token,
            "local-owner",
            "Valid9!Password",
        )

    assert rejected.value.code is AuthenticationCode.INVALID_CREDENTIALS
    assert ("LOGIN_PASSWORD", "DENY", "ACCOUNT_UNAVAILABLE") in repository.audit_events


def test_role_version_change_revokes_an_existing_session() -> None:
    service, repository = _service()
    started = datetime(2026, 7, 24, 1, 0, tzinfo=UTC)
    pre_auth = service.new_pre_auth(started)
    pending = service.password_login(
        pre_auth.token,
        "local-owner",
        "Valid9!Password",
        started,
    )
    authenticated = service.complete_dev_mfa(pending.token, "123456", started)
    repository.accounts[USER_ID] = replace(
        repository.accounts[USER_ID],
        role_assignment_version=2,
    )
    with pytest.raises(AuthenticationError) as rejected:
        service.authenticate(authenticated.token, False, started)
    assert rejected.value.code is AuthenticationCode.SESSION_REVOKED


def test_rbac_is_deny_by_default_and_scopes_assets() -> None:
    principal = AuthenticatedPrincipal(
        user_id=USER_ID,
        username="local-owner",
        display_name="로컬 개발 사용자",
        organization_id=ORGANIZATION_ID,
        roles=frozenset({HumanRole.USER}),
        asset_ids=frozenset({ASSET_ID}),
        auth_methods=frozenset({"password", "dev-test-mfa"}),
        session_created_at=datetime.now(UTC),
        reauthenticated_at=datetime.now(UTC),
    )
    assert authorize(
        principal,
        Permission.ASSET_READ,
        ORGANIZATION_ID,
        ASSET_ID,
    ).allowed
    assert (
        authorize(
            principal,
            Permission.ASSET_READ,
            OTHER_ORGANIZATION_ID,
            ASSET_ID,
        ).outcome
        is AuthorizationOutcome.NOT_FOUND
    )
    assert (
        authorize(
            principal,
            Permission.ASSET_READ,
            ORGANIZATION_ID,
            OTHER_ASSET_ID,
        ).outcome
        is AuthorizationOutcome.NOT_FOUND
    )
    assert (
        authorize(
            principal,
            Permission.EVIDENCE_DOWNLOAD,
            ORGANIZATION_ID,
            ASSET_ID,
        ).outcome
        is AuthorizationOutcome.FORBIDDEN
    )


def test_login_page_idor_fragment_sse_download_csrf_and_revoke(
    monkeypatch: Any,
) -> None:
    service, _ = _service()
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_PROFILE", "DEV-LOCAL")
    monkeypatch.setenv("SECAI_AUTH_CANONICAL_ORIGIN", ORIGIN)

    from apps.api import auth_support, authentication, main, security_surface

    auth_support.auth_settings.cache_clear()
    monkeypatch.setattr(auth_support, "get_auth_service", lambda: service)
    monkeypatch.setattr(authentication, "get_auth_service", lambda: service)
    monkeypatch.setattr(security_surface, "get_auth_service", lambda: service)
    monkeypatch.setattr(main, "authenticate_request", auth_support.authenticate_request)

    with TestClient(app) as client:
        anonymous_page = client.get("/", follow_redirects=False)
        assert anonymous_page.status_code == 303
        assert anonymous_page.headers["location"] == "/auth/login?next=/"

        _login(client)
        home = client.get("/")
        assert home.status_code == 200
        assert '>계정정보</a>' in home.text

        base = f"/api/v1/security/organizations/{ORGANIZATION_ID}/assets/{ASSET_ID}"
        assigned = client.get(base)
        fragment = client.get(
            base.replace("/api/v1/", "/ui/") + "/fragment",
            headers={"HX-Request": "true"},
        )
        events = client.get(
            base + "/events",
            headers={"Accept": "text/event-stream"},
        )
        download = client.get(base + "/download")
        wrong_asset = client.get(
            base.replace(str(ASSET_ID), str(OTHER_ASSET_ID))
        )
        wrong_org = client.get(
            base.replace(str(ORGANIZATION_ID), str(OTHER_ORGANIZATION_ID))
        )

        assert assigned.status_code == 200
        assert fragment.status_code == 200
        assert "서버 권한검사를 통과했습니다" in fragment.text
        assert events.status_code == 200
        assert "security-status" in events.text
        assert download.status_code == 403
        assert wrong_asset.status_code == 404
        assert wrong_org.status_code == 404

        session_page = client.get("/auth/session")
        token = _csrf(session_page.text)
        cross_site = client.post(
            "/auth/logout",
            data={"csrf_token": token},
            headers={"Origin": "http://evil.invalid", "Sec-Fetch-Site": "cross-site"},
        )
        assert cross_site.status_code == 403
        assert client.get("/").status_code == 200

        logged_out = client.post(
            "/auth/logout",
            data={"csrf_token": token},
            headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"},
            follow_redirects=False,
        )
        assert logged_out.status_code == 303
        assert client.get("/api/v1/product/features").status_code == 401
        assert client.get(base + "/events").status_code == 401

    auth_support.auth_settings.cache_clear()


def test_administrator_tools_are_hidden_and_forbidden_for_general_user(
    monkeypatch: Any,
) -> None:
    service, _ = _service()
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_PROFILE", "DEV-LOCAL")
    monkeypatch.setenv("SECAI_AUTH_CANONICAL_ORIGIN", ORIGIN)

    from apps.api import auth_support, authentication, linux_asset_management, main

    auth_support.auth_settings.cache_clear()
    monkeypatch.setattr(auth_support, "get_auth_service", lambda: service)
    monkeypatch.setattr(authentication, "get_auth_service", lambda: service)
    monkeypatch.setattr(main, "authenticate_request", auth_support.authenticate_request)
    monkeypatch.setattr(
        linux_asset_management,
        "_service",
        lambda: type("EmptyLinuxAssets", (), {"list": lambda self, principal: ()})(),
    )

    with TestClient(app) as client:
        _login(client)
        session = client.get("/auth/session")
        assert session.status_code == 200
        assert 'id="administrator-tools-toggle"' not in session.text
        assert 'id="administrator-tools"' not in session.text

        for path in (
            "/ui/queue-recovery",
            "/api/v1/queue-recovery/status",
            "/ui/storage-recovery",
            "/api/v1/storage-recovery/status",
            "/ui/model-runtime",
            "/api/v1/model-runtime",
            "/admin/linux-servers",
        ):
            assert client.get(path).status_code == 403
        assert client.get("/ui/full-audit").status_code == 404
        assert client.get("/api/v1/demo/full-audit").status_code == 404

    auth_support.auth_settings.cache_clear()


def test_administrator_sees_account_tools_and_management_links(
    monkeypatch: Any,
) -> None:
    service, repository = _service()
    repository.user_roles[USER_ID] = frozenset({HumanRole.USER, HumanRole.ADMIN})
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_PROFILE", "DEV-LOCAL")
    monkeypatch.setenv("SECAI_AUTH_CANONICAL_ORIGIN", ORIGIN)

    from apps.api import auth_support, authentication, linux_asset_management, main

    auth_support.auth_settings.cache_clear()
    monkeypatch.setattr(auth_support, "get_auth_service", lambda: service)
    monkeypatch.setattr(authentication, "get_auth_service", lambda: service)
    monkeypatch.setattr(main, "authenticate_request", auth_support.authenticate_request)
    monkeypatch.setattr(
        linux_asset_management,
        "_service",
        lambda: type("EmptyLinuxAssets", (), {"list": lambda self, principal: ()})(),
    )

    with TestClient(app) as client:
        _login(client)
        session = client.get("/auth/session")
        assert session.status_code == 200
        assert 'id="administrator-tools-toggle"' not in session.text
        assert 'id="administrator-tools"' in session.text
        assert 'href="/admin/accounts"' in session.text
        assert 'href="/ui/queue-recovery"' in session.text
        assert 'href="/ui/storage-recovery"' in session.text
        assert 'href="/ui/model-runtime"' in session.text
        assert 'href="/admin/linux-servers"' in session.text
        assert "Linux 서버 관리" in session.text
        assert 'href="/ui/full-audit"' not in session.text
        linux_servers = client.get("/admin/linux-servers")
        assert linux_servers.status_code == 200
        assert "새 서버 등록" in linux_servers.text
        assert "등록하고 SSH 공개키 자동 발급" in linux_servers.text

    auth_support.auth_settings.cache_clear()


def test_imp046_migration_compose_and_web_security_contracts() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    migration = (
        root
        / "database"
        / "alembic"
        / "versions"
        / "0005_imp046_auth_rbac_web_security.py"
    ).read_text(encoding="utf-8")
    compose = (root / "deploy" / "compose" / "compose.dev.yml").read_text(
        encoding="utf-8"
    )
    main_source = (root / "apps" / "api" / "main.py").read_text(encoding="utf-8")

    for table in (
        "user_accounts",
        "user_role_assignments",
        "user_asset_assignments",
        "browser_sessions",
        "authentication_audit_events",
    ):
        assert table in migration
    assert "SECAI_AUTH_PROFILE: DEV-LOCAL" in compose
    assert "SECAI_AUTH_CANONICAL_ORIGIN: http://localhost:18480" in compose
    assert "Valid9!Password" not in compose
    assert "123456" not in compose
    for header in (
        "Content-Security-Policy",
        "Permissions-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
    ):
        assert header in main_source


def test_login_uses_one_click_security_brand_without_removed_copy() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    login = (root / "apps" / "web" / "templates" / "pages" / "login.html").read_text(
        encoding="utf-8"
    )
    header = (
        root / "apps" / "web" / "templates" / "components" / "audit_ui.html"
    ).read_text(encoding="utf-8")
    home = (
        root / "apps" / "web" / "templates" / "pages" / "product_home.html"
    ).read_text(encoding="utf-8")
    stylesheet = (
        root / "apps" / "web" / "static" / "app" / "app.css"
    ).read_text(encoding="utf-8")

    assert 'data-brand-icon="one-click-security"' in login
    assert "원클릭 보안 점검" in login
    assert "원클릭 보안 점검" in header
    assert "원클릭 보안 점검" in home
    for removed_copy in (
        "내 계정으로 로그인",
        "내 PC 점검 결과와 조직 자료를 다른 사용자와 안전하게 분리합니다.",
        "비밀번호 다음에 개발용 두 번째 인증을 확인합니다.",
        "보안 프로필:",
    ):
        assert removed_copy not in login
    assert ".brand-mark svg" in stylesheet
