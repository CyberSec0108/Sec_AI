from __future__ import annotations

from collections.abc import Awaitable, Callable
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from apps.api.assessment_criteria import router as assessment_criteria_router
from apps.api.audit_history import router as audit_history_router
from apps.api.auth_support import (
    auth_enabled,
    auth_settings,
    authenticate_request,
)
from apps.api.authentication import router as authentication_router
from apps.api.chat_conversation import router as chat_conversation_router
from apps.api.dev_signed_downloads import router as dev_signed_downloads_router
from apps.api.guide_store import router as guide_store_router
from apps.api.health import check_dependencies
from apps.api.linux_asset_management import router as linux_asset_management_router
from apps.api.linux_audit import router as linux_audit_router
from apps.api.linux_oneshot import router as linux_oneshot_router
from apps.api.model_runtime import router as model_runtime_router
from apps.api.product import router as product_router
from apps.api.queue_recovery import router as queue_recovery_router
from apps.api.result_ai_explanation import router as result_ai_explanation_router
from apps.api.result_reports import router as result_reports_router
from apps.api.scan_approval import router as scan_approval_router
from apps.api.security_surface import router as security_surface_router
from apps.api.storage_recovery import router as storage_recovery_router
from apps.api.switch_audit import router as switch_audit_router
from apps.api.vulnerability_check import router as vulnerability_check_router
from security_audit import __version__
from security_audit.security.auth import AuthenticationError

app = FastAPI(
    title="Sec_AI Audit API",
    version=__version__,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.mount("/static", StaticFiles(directory="apps/web/static"), name="static")
app.include_router(authentication_router)
app.include_router(assessment_criteria_router)
app.include_router(audit_history_router)
app.include_router(chat_conversation_router)
app.include_router(dev_signed_downloads_router)
app.include_router(security_surface_router)
app.include_router(product_router)
app.include_router(result_ai_explanation_router)
app.include_router(result_reports_router)
app.include_router(queue_recovery_router)
app.include_router(storage_recovery_router)
app.include_router(guide_store_router)
app.include_router(model_runtime_router)
app.include_router(linux_audit_router)
app.include_router(linux_asset_management_router)
app.include_router(linux_oneshot_router)
app.include_router(switch_audit_router)
app.include_router(vulnerability_check_router)
app.include_router(scan_approval_router)


def _authentication_exempt(path: str) -> bool:
    return (
        path.startswith("/health/")
        or path.startswith("/static/")
        or path
        in {
            "/auth/login",
            "/auth/mfa",
            "/auth/register",
            "/favicon.ico",
            "/ui/launcher-connect",
            "/api/v1/linux/one-shot/exchange",
            "/api/v1/linux/one-shot/submit",
        }
        or path.startswith("/api/v1/dev-downloads/fetch/")
    )


def _api_request(request: Request) -> bool:
    return request.url.path.startswith("/api/")


def _canonical_browser_redirect_url(request: Request) -> str | None:
    """브라우저 세션을 단일 loopback 호스트에 고정합니다."""

    path = request.url.path
    if path.startswith("/api/") or path.startswith("/health/"):
        return None
    canonical_origin = auth_settings().canonical_origin
    canonical = urlsplit(canonical_origin)
    requested_host = request.url.hostname
    if canonical.hostname != "localhost" or requested_host not in {
        "127.0.0.1",
        "::1",
    }:
        return None
    target: str = canonical_origin + path
    query = str(request.url.query)
    if query:
        target += "?" + query
    return target


@app.middleware("http")
async def authenticated_web_boundary(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    if not auth_enabled() or _authentication_exempt(request.url.path):
        return await call_next(request)
    try:
        authenticate_request(request)
    except AuthenticationError:
        if _api_request(request):
            return Response(
                content='{"detail":"Authentication required."}',
                status_code=status.HTTP_401_UNAUTHORIZED,
                media_type="application/json",
                headers={"Cache-Control": "no-store"},
            )
        return_path = request.url.path
        if request.url.query:
            return_path += "?" + request.url.query
        return RedirectResponse(
            f"/auth/login?next={quote(return_path, safe='/')}",
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Cache-Control": "no-store"},
        )
    return await call_next(request)


@app.middleware("http")
async def secure_response_headers(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    canonical_url = _canonical_browser_redirect_url(request)
    response: Response
    if canonical_url is not None:
        response = RedirectResponse(
            canonical_url,
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Cache-Control": "no-store"},
        )
    else:
        response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; font-src 'self'; "
        "connect-src 'self' http://127.0.0.1:18481 "
        "http://127.0.0.1:18482; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'; trusted-types 'none'; "
        "require-trusted-types-for 'script'"
    )
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), usb=()"
    )
    if auth_enabled():
        response.headers["X-SecAI-Auth-Profile"] = auth_settings().profile
    return response


@app.get("/health/live")
async def health_live() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "audit-api",
        "version": __version__,
    }


@app.get("/favicon.ico", include_in_schema=False, status_code=status.HTTP_204_NO_CONTENT)
async def favicon() -> Response:
    """Avoid rotating the pre-auth cookie for the browser's implicit icon request."""
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/health/ready")
async def health_ready(response: Response) -> dict[str, object]:
    dependencies = await check_dependencies()
    ready = all(dependencies.values())
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if ready else "not_ready",
        "service": "audit-api",
        "version": __version__,
        "dependencies": dependencies,
    }
