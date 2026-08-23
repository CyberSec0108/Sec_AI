"""IMP-045 sanitized storage recovery status surface."""

from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from apps.api.auth_support import require_administrator
from security_audit.application.storage_recovery_status import (
    latest_storage_recovery_summary,
)

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")


def _require_product_demo() -> None:
    if os.getenv("SECAI_DEV_DEMO_ENABLED", "").casefold() != "true":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


@router.get("/api/v1/storage-recovery/status")
def storage_recovery_status(request: Request) -> dict[str, object]:
    _require_product_demo()
    require_administrator(request)
    return latest_storage_recovery_summary()


@router.get("/ui/storage-recovery", response_class=HTMLResponse)
def storage_recovery_page(request: Request) -> HTMLResponse:
    _require_product_demo()
    require_administrator(request)
    return templates.TemplateResponse(
        request=request,
        name="pages/storage_recovery.html",
        context={"recovery": latest_storage_recovery_summary()},
    )
