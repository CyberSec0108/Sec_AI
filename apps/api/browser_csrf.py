"""Session-bound CSRF for authenticated UI with legacy synthetic-test fallback."""

from __future__ import annotations

import os

from fastapi import HTTPException, Request, status

from apps.api.auth_support import (
    auth_enabled,
    current_context,
    verify_authenticated_csrf,
)
from security_audit.common.secret_files import read_required_secret


def browser_csrf_token(request: Request) -> str:
    if auth_enabled():
        return current_context(request).csrf_token
    direct = os.getenv("SECAI_DEMO_CSRF_TOKEN")
    if direct:
        return direct
    return read_required_secret(
        os.getenv("SECAI_DEMO_CSRF_TOKEN_FILE", "/run/secrets/demo_csrf_token")
    )


def verify_browser_csrf(request: Request, supplied: str | None) -> None:
    if auth_enabled():
        verify_authenticated_csrf(request, supplied)
        return
    if supplied != browser_csrf_token(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF validation failed.")
    origin = request.headers.get("origin")
    if origin is not None and origin.rstrip("/") != str(request.base_url).rstrip("/"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Origin validation failed.")
