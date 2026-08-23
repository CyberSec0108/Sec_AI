"""DEV-LOCAL 전용 Windows·Linux 임시 서명 파일 다운로드 API."""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict

from apps.api.auth_support import auth_enabled, current_principal
from apps.api.browser_csrf import browser_csrf_token, verify_browser_csrf
from security_audit.collector.linux_connection import InMemoryExchangeRateLimiter
from security_audit.security.auth import AuthenticatedPrincipal
from security_audit.supply_chain.dev_signed_download import (
    DevArtifactPlatform,
    DevDownloadCodeError,
    DevDownloadCodeService,
    InMemoryDevDownloadCodeStore,
    VerifiedDevArtifact,
    VerifiedDevRelease,
    load_verified_dev_release,
)

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")
MAX_DOWNLOAD_CODE_BYTES = 64
MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
_PLATFORM_LABELS = {
    DevArtifactPlatform.WINDOWS_X64: "Windows 10·11 x64",
    DevArtifactPlatform.LINUX_AUTO_X64: "Linux 자동 식별 x86_64",
    DevArtifactPlatform.UBUNTU_24_04_X64: "Ubuntu Server 24.04 x86_64",
    DevArtifactPlatform.ROCKY_9_X64: "Rocky Linux 9 x86_64",
}


class IssueDevDownloadBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    platform: DevArtifactPlatform


class _Runtime:
    def __init__(self) -> None:
        self.codes = DevDownloadCodeService(
            InMemoryDevDownloadCodeStore(),
            hash_key=secrets.token_bytes(32),
            hash_key_version="dev-process-ephemeral-v1",
        )
        self.rate_limiter = InMemoryExchangeRateLimiter()


@lru_cache(maxsize=1)
def _runtime() -> _Runtime:
    return _Runtime()


def _feature_enabled() -> None:
    if (
        os.getenv("SECAI_DEV_SIGNED_DOWNLOAD_ENABLED", "false").casefold()
        != "true"
        or os.getenv("SECAI_AUTH_PROFILE", "").upper() != "DEV-LOCAL"
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")


def _release_root() -> Path:
    value = os.getenv("SECAI_DEV_SIGNED_DOWNLOAD_ROOT")
    if not value:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "개발용 다운로드 파일이 준비되지 않았습니다.",
        )
    return Path(value)


def _load_release(*, public_error: bool = False) -> VerifiedDevRelease:
    try:
        return load_verified_dev_release(_release_root(), now=datetime.now(UTC))
    except (OSError, ValueError, HTTPException) as exc:
        if public_error:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "다운로드 파일을 확인할 수 없습니다.",
            ) from exc
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "개발용 서명 파일 검증이 완료되지 않았습니다.",
        ) from exc


def _require_user(request: Request) -> AuthenticatedPrincipal:
    _feature_enabled()
    if not auth_enabled():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Authentication required.")
    return current_principal(request)


def _artifact_view(artifact: VerifiedDevArtifact) -> dict[str, object]:
    return {
        "platform": artifact.platform.value,
        "label": _PLATFORM_LABELS[artifact.platform],
        "filename": artifact.filename,
        "size_bytes": artifact.size_bytes,
        "sha256": artifact.sha256,
    }


def dev_signed_artifact_status(platform: DevArtifactPlatform) -> dict[str, object]:
    try:
        _feature_enabled()
        release = _load_release()
        artifact = release.artifacts[platform]
    except (HTTPException, KeyError):
        return {
            "status": "DEV-UNAVAILABLE",
            "download_allowed": False,
            "download_page": "/ui/dev-downloads",
        }
    return {
        "status": release.release_channel,
        "download_allowed": True,
        "download_page": "/ui/dev-downloads",
        "filename": artifact.filename,
        "sha256": artifact.sha256,
        "expires_at": release.expires_at.isoformat().replace("+00:00", "Z"),
    }


@router.get("/ui/dev-downloads", response_class=HTMLResponse)
def dev_signed_download_page(request: Request) -> HTMLResponse:
    _require_user(request)
    return templates.TemplateResponse(
        request=request,
        name="pages/dev_signed_downloads.html",
        context={"csrf_token": browser_csrf_token(request)},
    )


@router.get("/api/v1/dev-downloads/status")
def dev_signed_download_status(request: Request) -> dict[str, object]:
    _require_user(request)
    release = _load_release()
    return {
        "release_channel": release.release_channel,
        "production_release": False,
        "warning": "개발시험 전용 임시 서명 파일이며 운영 서명이 아닙니다.",
        "key_id": release.key_id,
        "catalog_sha256": release.catalog_sha256,
        "expires_at": release.expires_at.isoformat().replace("+00:00", "Z"),
        "artifacts": [
            _artifact_view(release.artifacts[platform])
            for platform in DevArtifactPlatform
        ],
    }


@router.post("/api/v1/dev-downloads/codes", status_code=status.HTTP_201_CREATED)
def issue_dev_download_code(
    request: Request,
    body: IssueDevDownloadBody,
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> dict[str, object]:
    principal = _require_user(request)
    verify_browser_csrf(request, csrf_token)
    release = _load_release()
    artifact = release.artifacts[body.platform]
    issued = _runtime().codes.issue(
        platform=body.platform,
        subject_user_id=str(principal.user_id),
        catalog_sha256=release.catalog_sha256,
        artifact_sha256=artifact.sha256,
        issued_at=datetime.now(UTC),
    )
    return {
        **_artifact_view(artifact),
        "code": issued.code,
        "expires_at": issued.expires_at.isoformat().replace("+00:00", "Z"),
        "fetch_url": f"/api/v1/dev-downloads/fetch/{body.platform.value}",
        "terminal_base_url": "http://127.0.0.1:18480",
        "release_channel": release.release_channel,
        "production_release": False,
    }


@router.post("/api/v1/dev-downloads/fetch/{platform}")
async def fetch_dev_signed_artifact(
    request: Request,
    platform: DevArtifactPlatform,
) -> Response:
    _feature_enabled()
    remote = request.client.host if request.client is not None else "unknown"
    received_at = datetime.now(UTC)
    if not _runtime().rate_limiter.allow(remote, received_at=received_at):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "다운로드 시도 횟수를 초과했습니다.",
        )
    body = await request.body()
    if not body or len(body) > MAX_DOWNLOAD_CODE_BYTES:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "다운로드 코드를 확인할 수 없습니다.",
        )
    try:
        code = body.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "다운로드 코드를 확인할 수 없습니다.",
        ) from exc
    release = _load_release(public_error=True)
    artifact = release.artifacts[platform]
    if artifact.size_bytes > MAX_ARTIFACT_BYTES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "다운로드 파일이 없습니다.")
    try:
        payload = artifact.path.read_bytes()
    except OSError as exc:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "다운로드 파일이 없습니다.",
        ) from exc
    if (
        len(payload) != artifact.size_bytes
        or hashlib.sha256(payload).hexdigest() != artifact.sha256
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "다운로드 파일 검증에 실패했습니다.",
        )
    try:
        _runtime().codes.consume(
            code,
            platform=platform,
            catalog_sha256=release.catalog_sha256,
            artifact_sha256=artifact.sha256,
            received_at=received_at,
        )
    except DevDownloadCodeError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "다운로드 코드를 확인할 수 없습니다.",
        ) from exc
    return Response(
        content=payload,
        media_type=artifact.media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{artifact.filename}"',
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "X-SecAI-SHA256": artifact.sha256,
            "X-SecAI-Release-Channel": release.release_channel,
            "X-SecAI-Signature-Key-Id": release.key_id,
        },
    )
