"""User-facing login, test MFA, logout and session controls."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Form, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from apps.api.auth_support import (
    auth_settings,
    current_context,
    current_principal,
    get_account_management_service,
    get_auth_service,
    request_session_token,
    verify_authenticated_csrf,
)
from security_audit.application.product_features import administrator_feature_registry
from security_audit.security.auth import (
    AccountManagementError,
    AuthenticationError,
    HumanRole,
    SessionContext,
    SessionPhase,
)

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")


def _safe_return_path(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    if "\\" in value or "\r" in value or "\n" in value:
        return "/"
    return value


def _set_session_cookie(
    response: HTMLResponse | RedirectResponse,
    context: SessionContext,
) -> None:
    settings = auth_settings()
    response.set_cookie(
        settings.cookie_name,
        context.token,
        max_age=max(
            1,
            int((context.expires_at - datetime.now(UTC)).total_seconds()),
        ),
        secure=settings.secure_cookie,
        httponly=True,
        samesite="lax",
        path="/",
    )


def _expire_session_cookie(response: HTMLResponse | RedirectResponse) -> None:
    settings = auth_settings()
    response.delete_cookie(
        settings.cookie_name,
        secure=settings.secure_cookie,
        httponly=True,
        samesite="lax",
        path="/",
    )


def _login_page(
    request: Request,
    context: SessionContext,
    return_path: str,
    error_message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    response = templates.TemplateResponse(
        request=request,
        name="pages/login.html",
        context={
            "csrf_token": context.csrf_token,
            "return_path": return_path,
            "error_message": error_message,
            "auth_profile": auth_settings().profile,
        },
        status_code=status_code,
    )
    _set_session_cookie(response, context)
    return response


@router.get("/auth/login", response_class=HTMLResponse)
def login_page(request: Request, next: str | None = None) -> HTMLResponse:
    context = get_auth_service().new_pre_auth()
    return _login_page(request, context, _safe_return_path(next))


@router.post("/auth/login", response_class=HTMLResponse)
def login_password(
    request: Request,
    username: Annotated[str, Form(min_length=1, max_length=128)],
    password: Annotated[str, Form(min_length=1, max_length=512)],
    csrf_token: Annotated[str, Form()],
    next: Annotated[str, Form()] = "/",
) -> Response:
    service = get_auth_service()
    return_path = _safe_return_path(next)
    token = request_session_token(request)
    try:
        service.verify_csrf(
            token,
            csrf_token,
            request.headers.get("origin"),
            request.headers.get("referer"),
            request.headers.get("sec-fetch-site"),
            SessionPhase.PRE_AUTH,
        )
        context = service.password_login(token, username, password)
    except AuthenticationError as exc:
        replacement = service.new_pre_auth()
        return _login_page(
            request,
            replacement,
            return_path,
            exc.public_message,
            status.HTTP_401_UNAUTHORIZED,
        )
    response = RedirectResponse(
        f"/auth/mfa?next={return_path}",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    _set_session_cookie(response, context)
    return response


def _registration_page(
    request: Request,
    context: SessionContext,
    *,
    error_message: str | None = None,
    success_message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    response = templates.TemplateResponse(
        request=request,
        name="pages/register.html",
        context={
            "csrf_token": context.csrf_token,
            "error_message": error_message,
            "success_message": success_message,
        },
        status_code=status_code,
    )
    _set_session_cookie(response, context)
    return response


@router.get("/auth/register", response_class=HTMLResponse)
def registration_page(request: Request) -> HTMLResponse:
    return _registration_page(request, get_auth_service().new_pre_auth())


@router.post("/auth/register", response_class=HTMLResponse)
def request_registration(
    request: Request,
    username: Annotated[str, Form(min_length=3, max_length=64)],
    display_name: Annotated[str, Form(min_length=1, max_length=128)],
    password: Annotated[str, Form(min_length=1, max_length=512)],
    password_confirmation: Annotated[str, Form(min_length=1, max_length=512)],
    csrf_token: Annotated[str, Form()],
) -> HTMLResponse:
    auth_service = get_auth_service()
    token = request_session_token(request)
    try:
        auth_service.verify_csrf(
            token,
            csrf_token,
            request.headers.get("origin"),
            request.headers.get("referer"),
            request.headers.get("sec-fetch-site"),
            SessionPhase.PRE_AUTH,
        )
        get_account_management_service().request_registration(
            username,
            display_name,
            password,
            password_confirmation,
        )
    except (AuthenticationError, AccountManagementError) as exc:
        replacement = auth_service.new_pre_auth()
        return _registration_page(
            request,
            replacement,
            error_message=exc.public_message,
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    replacement = auth_service.new_pre_auth()
    return _registration_page(
        request,
        replacement,
        success_message=(
            "계정 생성 요청을 접수했습니다. 관리자가 승인하면 로그인할 수 있습니다."
        ),
    )


def _mfa_page(
    request: Request,
    context: SessionContext,
    return_path: str,
    error_message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    response = templates.TemplateResponse(
        request=request,
        name="pages/mfa.html",
        context={
            "csrf_token": context.csrf_token,
            "return_path": return_path,
            "error_message": error_message,
        },
        status_code=status_code,
    )
    _set_session_cookie(response, context)
    return response


@router.get("/auth/mfa", response_class=HTMLResponse)
def mfa_page(
    request: Request,
    next: str | None = None,
) -> Response:
    token = request_session_token(request)
    service = get_auth_service()
    try:
        context = service.pending_context(token)
    except AuthenticationError:
        response = RedirectResponse(
            "/auth/login",
            status_code=status.HTTP_303_SEE_OTHER,
        )
        _expire_session_cookie(response)
        return response
    return _mfa_page(request, context, _safe_return_path(next))


@router.post("/auth/mfa", response_class=HTMLResponse)
def complete_mfa(
    request: Request,
    code: Annotated[str, Form(pattern=r"^[0-9]{6}$")],
    csrf_token: Annotated[str, Form()],
    next: Annotated[str, Form()] = "/",
) -> Response:
    service = get_auth_service()
    return_path = _safe_return_path(next)
    token = request_session_token(request)
    try:
        service.verify_csrf(
            token,
            csrf_token,
            request.headers.get("origin"),
            request.headers.get("referer"),
            request.headers.get("sec-fetch-site"),
            SessionPhase.MFA_PENDING,
        )
        context = service.complete_dev_mfa(token, code)
    except AuthenticationError as exc:
        response = RedirectResponse(
            "/auth/login",
            status_code=status.HTTP_303_SEE_OTHER,
        )
        _expire_session_cookie(response)
        response.headers["X-SecAI-Auth-Error"] = exc.code.value
        return response
    response = RedirectResponse(return_path, status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(response, context)
    return response


@router.get("/auth/session", response_class=HTMLResponse)
def session_page(request: Request) -> HTMLResponse:
    context = current_context(request)
    principal = context.principal
    administrator_features: tuple[dict[str, str | None], ...] = ()
    if principal is not None and HumanRole.ADMIN in principal.roles:
        administrator_features = tuple(
            feature.public_view()
            for feature_id, feature in administrator_feature_registry().items()
            if feature_id
            in {
                "queue_recovery",
                "storage_recovery",
                "model_runtime",
                "criteria_defaults",
                "linux_asset_management",
            }
        )
    return templates.TemplateResponse(
        request=request,
        name="pages/session.html",
        context={
            "identity": context.principal,
            "csrf_token": context.csrf_token,
            "expires_at": context.expires_at,
            "auth_profile": auth_settings().profile,
            "administrator_features": administrator_features,
        },
    )


def _account_settings_page(
    request: Request,
    *,
    error_message: str | None = None,
    success_message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    context = current_context(request)
    return templates.TemplateResponse(
        request=request,
        name="pages/account_settings.html",
        context={
            "identity": context.principal,
            "csrf_token": context.csrf_token,
            "error_message": error_message,
            "success_message": success_message,
        },
        status_code=status_code,
    )


@router.get("/auth/settings", response_class=HTMLResponse)
def account_settings_page(request: Request) -> HTMLResponse:
    return _account_settings_page(request)


@router.post("/auth/settings/profile", response_class=HTMLResponse)
def update_account_profile(
    request: Request,
    display_name: Annotated[str, Form(min_length=1, max_length=128)],
    csrf_token: Annotated[str, Form()],
) -> HTMLResponse:
    verify_authenticated_csrf(request, csrf_token)
    try:
        get_account_management_service().update_display_name(
            current_principal(request),
            display_name,
        )
    except AccountManagementError as exc:
        return _account_settings_page(
            request,
            error_message=exc.public_message,
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return _account_settings_page(request, success_message="표시 이름을 변경했습니다.")


@router.post("/auth/settings/password", response_class=HTMLResponse)
def update_account_password(
    request: Request,
    current_password: Annotated[str, Form(min_length=1, max_length=512)],
    new_password: Annotated[str, Form(min_length=1, max_length=512)],
    password_confirmation: Annotated[str, Form(min_length=1, max_length=512)],
    csrf_token: Annotated[str, Form()],
) -> Response:
    verify_authenticated_csrf(request, csrf_token)
    try:
        get_account_management_service().change_password(
            current_principal(request),
            current_password,
            new_password,
            password_confirmation,
        )
    except AccountManagementError as exc:
        return _account_settings_page(
            request,
            error_message=exc.public_message,
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    response = RedirectResponse(
        "/auth/login?password_changed=1",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    _expire_session_cookie(response)
    return response


_ACCOUNT_STATUS_LABELS = {
    "PENDING_APPROVAL": "승인 대기",
    "ACTIVE": "사용 중",
    "TEMP_LOCKED": "일시 잠김",
    "DISABLED": "사용 중지",
    "REJECTED": "승인 거절",
}


def _admin_accounts_page(
    request: Request,
    *,
    error_message: str | None = None,
    success_message: str | None = None,
    issued_mfa_code: str | None = None,
    issued_mfa_user: str | None = None,
    issued_mfa_expires_at: datetime | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    context = current_context(request)
    principal = current_principal(request)
    try:
        accounts = get_account_management_service().list_accounts(principal)
    except AccountManagementError as exc:
        return templates.TemplateResponse(
            request=request,
            name="pages/admin_accounts.html",
            context={
                "identity": principal,
                "csrf_token": context.csrf_token,
                "accounts": (),
                "status_labels": _ACCOUNT_STATUS_LABELS,
                "error_message": exc.public_message,
                "success_message": None,
                "issued_mfa_code": None,
                "issued_mfa_user": None,
                "issued_mfa_expires_at": None,
            },
            status_code=status.HTTP_403_FORBIDDEN,
        )
    return templates.TemplateResponse(
        request=request,
        name="pages/admin_accounts.html",
        context={
            "identity": principal,
            "csrf_token": context.csrf_token,
            "accounts": accounts,
            "status_labels": _ACCOUNT_STATUS_LABELS,
            "error_message": error_message,
            "success_message": success_message,
            "issued_mfa_code": issued_mfa_code,
            "issued_mfa_user": issued_mfa_user,
            "issued_mfa_expires_at": issued_mfa_expires_at,
        },
        status_code=status_code,
    )


@router.get("/admin/accounts", response_class=HTMLResponse)
def admin_accounts_page(request: Request) -> HTMLResponse:
    return _admin_accounts_page(request)


@router.post("/admin/accounts/{user_id}/{action}", response_class=HTMLResponse)
def change_account_status(
    request: Request,
    user_id: UUID,
    action: str,
    csrf_token: Annotated[str, Form()],
) -> HTMLResponse:
    verify_authenticated_csrf(request, csrf_token)
    principal = current_principal(request)
    issued = None
    issued_for = None
    try:
        service = get_account_management_service()
        if action == "renew-mfa":
            target = next(
                (account for account in service.list_accounts(principal) if account.id == user_id),
                None,
            )
            if target is None:
                raise AccountManagementError("계정을 찾을 수 없습니다.")
            issued = service.renew_mfa_code(principal, user_id)
            issued_for = target.display_name
        else:
            target = service.change_status(principal, user_id, action)
            if action == "approve":
                issued = service.renew_mfa_code(principal, user_id)
                issued_for = target.display_name
    except AccountManagementError as exc:
        return _admin_accounts_page(
            request,
            error_message=exc.public_message,
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    if issued is not None:
        return _admin_accounts_page(
            request,
            success_message=(
                "인증 코드를 새로 발급했습니다. "
                "이 화면에서 한 번만 복사할 수 있습니다."
            ),
            issued_mfa_code=issued.code,
            issued_mfa_user=issued_for,
            issued_mfa_expires_at=issued.expires_at,
        )
    return _admin_accounts_page(request, success_message="계정 상태를 변경했습니다.")


@router.post("/auth/logout")
def logout(
    request: Request,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    verify_authenticated_csrf(request, csrf_token)
    token = request_session_token(request)
    if token:
        get_auth_service().revoke_current(token)
    response = RedirectResponse(
        "/auth/login",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    _expire_session_cookie(response)
    return response


@router.post("/auth/sessions/revoke-all")
def revoke_all_sessions(
    request: Request,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    verify_authenticated_csrf(request, csrf_token)
    token = request_session_token(request)
    if token:
        get_auth_service().revoke_all(token)
    response = RedirectResponse(
        "/auth/login",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    _expire_session_cookie(response)
    return response
