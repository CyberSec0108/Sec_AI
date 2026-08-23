"""IMP-040 product-first local UI and feature-state API."""

from __future__ import annotations

import os
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from apps.api.browser_csrf import browser_csrf_token
from security_audit.application.administrator_scan import (
    CONSENT_VERSION,
    administrator_probe_disclosures,
)
from security_audit.application.product_features import (
    home_feature_registry,
    public_feature_registry,
)

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")

HELP_TOPICS = frozenset(
    {"windows", "vulnerability", "linux", "network", "guide", "account"}
)
_RESULT_RECHECK_CONTROLS = (
    {"control_id": "PC-01", "title": "비밀번호의 주기적 변경", "probe_id": None},
    {
        "control_id": "PC-02",
        "title": "비밀번호 관리정책 설정",
        "probe_id": "win.security.password-policy",
    },
    {"control_id": "PC-03", "title": "복구 콘솔 자동 로그온 금지", "probe_id": None},
    {
        "control_id": "PC-04",
        "title": "불필요한 공유 폴더 제거",
        "probe_id": "win.network.smb-shares",
    },
    {"control_id": "PC-05", "title": "불필요한 서비스 제거", "probe_id": None},
    {
        "control_id": "PC-06",
        "title": "비인가 메신저 사용 금지",
        "probe_id": "win.software.messengers",
    },
    {"control_id": "PC-07", "title": "파일시스템을 NTFS 형식으로 설정", "probe_id": None},
    {
        "control_id": "PC-08",
        "title": "Windows 외 다른 OS 부팅 제한",
        "probe_id": "win.boot.entries",
    },
    {"control_id": "PC-09", "title": "브라우저 종료 시 임시 파일 삭제", "probe_id": None},
    {
        "control_id": "PC-10",
        "title": "보안 패치와 권고사항 적용",
        "probe_id": "win.update.compliance",
    },
    {"control_id": "PC-11", "title": "지원이 종료되지 않은 Windows 사용", "probe_id": None},
    {"control_id": "PC-12", "title": "Windows 자동 로그온 제거", "probe_id": None},
    {"control_id": "PC-13", "title": "백신 설치와 주기적 업데이트", "probe_id": None},
    {"control_id": "PC-14", "title": "백신 실시간 감시 활성화", "probe_id": None},
    {"control_id": "PC-15", "title": "침입차단 기능 활성화", "probe_id": None},
    {"control_id": "PC-16", "title": "화면보호기 대기 시간과 암호 보호", "probe_id": None},
    {"control_id": "PC-17", "title": "이동식 미디어 자동실행 방지", "probe_id": None},
    {"control_id": "PC-18", "title": "원격지원 금지 정책 설정", "probe_id": None},
)


def _require_product_demo() -> None:
    if os.getenv("SECAI_DEV_DEMO_ENABLED", "false").casefold() != "true":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")


def _features() -> dict[str, dict[str, str | None]]:
    return {
        feature_id: feature.public_view()
        for feature_id, feature in public_feature_registry().items()
    }


def _home_features() -> dict[str, dict[str, str | None]]:
    return {
        feature_id: feature.public_view()
        for feature_id, feature in home_feature_registry().items()
    }


def _require_chat_ui_live() -> None:
    _require_product_demo()
    if os.getenv("SECAI_CHAT_LIVE_ENABLED", "false").casefold() != "true":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")


@router.get("/", response_class=HTMLResponse)
def product_home(request: Request) -> HTMLResponse:
    _require_product_demo()
    return templates.TemplateResponse(
        request=request,
        name="pages/product_home.html",
        context={
            "csrf_token": browser_csrf_token(request),
            "features": _home_features(),
            "administrator_probes": administrator_probe_disclosures(),
            "administrator_consent_version": CONSENT_VERSION,
        },
    )


@router.get("/ui/launcher-connect", response_class=HTMLResponse)
def launcher_connect(request: Request) -> HTMLResponse:
    """Keep the browser-held Launcher token across an optional login flow."""

    _require_product_demo()
    return templates.TemplateResponse(
        request=request,
        name="pages/launcher_connect.html",
        context={},
    )


@router.get("/ui/guide-chat", response_class=HTMLResponse)
def guide_chat(request: Request) -> HTMLResponse:
    _require_chat_ui_live()
    return templates.TemplateResponse(
        request=request,
        name="pages/guide_chat.html",
        context={"csrf_token": browser_csrf_token(request)},
    )


@router.get("/ui/administrator-scan")
def administrator_scan() -> RedirectResponse:
    _require_product_demo()
    return RedirectResponse(
        "/ui/results#administrator-scan",
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    )


@router.get("/ui/help", response_class=HTMLResponse)
def product_help(
    request: Request,
    topic: Annotated[str, Query(max_length=32)] = "windows",
) -> HTMLResponse:
    _require_product_demo()
    selected_topic = topic if topic in HELP_TOPICS else "windows"
    return templates.TemplateResponse(
        request=request,
        name="pages/product_help.html",
        context={"help_topic": selected_topic},
    )


@router.get("/ui/result-center", response_class=HTMLResponse)
def result_center(request: Request) -> HTMLResponse:
    """장비 종류를 먼저 고른 뒤 각 전용 결과 화면으로 이동합니다."""

    _require_product_demo()
    return templates.TemplateResponse(
        request=request,
        name="pages/result_center.html",
        context={},
    )


@router.get("/ui/results", response_class=HTMLResponse)
def product_results(request: Request) -> HTMLResponse:
    _require_product_demo()
    return templates.TemplateResponse(
        request=request,
        name="pages/product_results.html",
        context={
            "administrator_probes": administrator_probe_disclosures(),
            "recheck_controls": _RESULT_RECHECK_CONTROLS,
            "administrator_consent_version": CONSENT_VERSION,
            "csrf_token": browser_csrf_token(request),
        },
    )


@router.get("/ui/ai-analysis", response_class=HTMLResponse)
def product_ai_analysis(request: Request) -> HTMLResponse:
    _require_product_demo()
    return templates.TemplateResponse(
        request=request,
        name="pages/result_ai_analysis.html",
        context={"csrf_token": browser_csrf_token(request)},
    )


@router.get("/ui/launcher-return", response_class=HTMLResponse)
def launcher_return(
    request: Request,
    status_value: Annotated[str, Query(alias="status", pattern="^COMPLETED$")],
    total: Annotated[int, Query(ge=15, le=15)],
    collected: Annotated[int, Query(ge=0, le=15)],
    errors: Annotated[int, Query(ge=0, le=15)],
) -> HTMLResponse:
    _require_product_demo()
    if collected + errors != total:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid summary.")
    return templates.TemplateResponse(
        request=request,
        name="pages/launcher_return.html",
        context={
            "status": status_value,
            "total": total,
            "collected": collected,
            "errors": errors,
        },
    )


@router.get("/api/v1/product/features")
def feature_registry() -> dict[str, Any]:
    _require_product_demo()
    return {
        "registry_version": "1.0.0",
        "features": _features(),
        "preview_persists_data": False,
        "preview_calls_collection": False,
        "preview_calls_evaluation": False,
        "official_finding_created": False,
    }
