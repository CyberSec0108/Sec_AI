"""FastAPI integration for the approved DEV-LOCAL authentication boundary."""

from __future__ import annotations

from functools import lru_cache

from fastapi import HTTPException, Request, status
from sqlalchemy import Engine, create_engine

from security_audit.common.secret_files import read_required_secret
from security_audit.common.service_settings import ServiceSettings
from security_audit.security.auth import (
    AccountManagementService,
    AuthenticatedPrincipal,
    AuthenticationError,
    AuthenticationSettings,
    HumanRole,
    LocalAuthenticationService,
    SessionContext,
    SessionPhase,
    SqlAccountManagementRepository,
)
from security_audit.security.auth.repository import SqlAuthenticationRepository


@lru_cache(maxsize=1)
def auth_settings() -> AuthenticationSettings:
    return AuthenticationSettings.from_environment()


@lru_cache(maxsize=1)
def _auth_engine() -> Engine:
    return create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )


@lru_cache(maxsize=1)
def get_auth_service() -> LocalAuthenticationService:
    settings = auth_settings()
    if not settings.enabled:
        raise RuntimeError("Authentication service requested while disabled.")
    return LocalAuthenticationService(
        SqlAuthenticationRepository(_auth_engine()),
        settings,
        read_required_secret(settings.session_index_key_file).encode(),
        read_required_secret(settings.dev_mfa_code_file),
    )


@lru_cache(maxsize=1)
def get_account_management_service() -> AccountManagementService:
    if not auth_enabled():
        raise RuntimeError("Account management requested while authentication is disabled.")
    settings = auth_settings()
    return AccountManagementService(
        SqlAccountManagementRepository(_auth_engine()),
        mfa_signing_key=read_required_secret(settings.session_index_key_file).encode(),
    )


def auth_enabled() -> bool:
    return auth_settings().enabled


def request_session_token(request: Request) -> str | None:
    return request.cookies.get(auth_settings().cookie_name)


def meaningful_foreground_request(request: Request) -> bool:
    if request.headers.get("x-secai-background", "").casefold() == "true":
        return False
    if request.headers.get("accept", "").startswith("text/event-stream"):
        return False
    return request.method in {"POST", "PUT", "PATCH", "DELETE"} or (
        request.method == "GET"
        and not request.url.path.endswith("/status")
        and "/events" not in request.url.path
    )


def authenticate_request(request: Request) -> SessionContext:
    context = get_auth_service().authenticate(
        request_session_token(request),
        meaningful_foreground_request(request),
    )
    request.state.auth_context = context
    return context


def current_context(request: Request) -> SessionContext:
    context = getattr(request.state, "auth_context", None)
    if not isinstance(context, SessionContext):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Authentication required.",
        )
    return context


def current_principal(request: Request) -> AuthenticatedPrincipal:
    principal = current_context(request).principal
    if principal is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Authentication required.",
        )
    return principal


def require_administrator(request: Request) -> AuthenticatedPrincipal | None:
    """관리자 운영 화면과 API의 서버 측 역할 경계를 확인합니다."""

    if not auth_enabled():
        return None
    principal = current_principal(request)
    if HumanRole.ADMIN not in principal.roles:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Administrator access required.",
        )
    return principal


def verify_authenticated_csrf(
    request: Request,
    supplied_token: str | None,
) -> None:
    try:
        get_auth_service().verify_csrf(
            request_session_token(request),
            supplied_token,
            request.headers.get("origin"),
            request.headers.get("referer"),
            request.headers.get("sec-fetch-site"),
            SessionPhase.AUTHENTICATED,
        )
    except AuthenticationError as exc:
        raise HTTPException(
            authentication_error_status(exc),
            exc.public_message,
        ) from exc


def authentication_error_status(error: AuthenticationError) -> int:
    if error.code.value == "CSRF_REJECTED":
        return status.HTTP_403_FORBIDDEN
    return status.HTTP_401_UNAUTHORIZED
