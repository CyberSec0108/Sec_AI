"""Safe product inventory for the approved KISA guide search store."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path, PurePosixPath
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session

from apps.api.auth_support import auth_enabled, current_principal
from security_audit.common.service_settings import ServiceSettings
from security_audit.guides.contracts import file_sha256, load_json_strict
from security_audit.persistence.database.guide_repository import (
    GuideStoreSnapshot,
    load_guide_store_snapshot,
)

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")

_DEV_ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
_GUIDE_ID = "kisa-major-infrastructure-detailed-guide"
_GUIDE_VERSION = "2026"
_SCOPE_ID = "kisa-2026-pc"
_GUIDE_SOURCE_PDF = Path(
    os.getenv("SECAI_GUIDE_SOURCE_PDF", "/run/secai-guides/kisa-2026.pdf")
)
_PUBLIC_GUIDE_SOURCE_ROOT = Path(
    os.getenv("SECAI_PUBLIC_GUIDE_SOURCE_ROOT", "/run/secai-public-guides")
)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PUBLIC_GUIDE_MANIFEST_PATH = PROJECT_ROOT / "guides" / "public_guides_manifest.json"


def _require_product_demo() -> None:
    if os.getenv("SECAI_DEV_DEMO_ENABLED", "false").casefold() != "true":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")


@lru_cache(maxsize=1)
def _engine() -> Engine:
    return create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )


def _load_snapshot(organization_id: UUID) -> GuideStoreSnapshot:
    with Session(_engine()) as session, session.begin():
        return load_guide_store_snapshot(
            session,
            organization_id=organization_id,
            guide_id=_GUIDE_ID,
            guide_version=_GUIDE_VERSION,
            scope_id=_SCOPE_ID,
        )


def _organization_id(request: Request) -> UUID:
    if auth_enabled():
        return current_principal(request).organization_id
    return _DEV_ORGANIZATION_ID


def _approved_source(
    guide_id: str,
    guide_version: str,
) -> tuple[Path, int, int] | None:
    if (guide_id, guide_version) == (_GUIDE_ID, _GUIDE_VERSION):
        return _GUIDE_SOURCE_PDF, 7, 873
    manifest = load_json_strict(_PUBLIC_GUIDE_MANIFEST_PATH)
    documents = manifest.get("documents")
    if not isinstance(documents, list):
        return None
    matches = [
        item
        for item in documents
        if isinstance(item, dict)
        and item.get("guide_id") == guide_id
        and item.get("version") == guide_version
        and item.get("status") == "APPROVED"
        and item.get("retrieval_role") == "SUPPLEMENTAL_EXPLANATION"
        and item.get("decision_authority") is False
    ]
    if len(matches) != 1:
        return None
    document = matches[0]
    relative_value = document.get("relative_path")
    page_count = document.get("page_count")
    source_sha256 = document.get("source_sha256")
    if (
        not isinstance(relative_value, str)
        or not isinstance(page_count, int)
        or not isinstance(source_sha256, str)
    ):
        return None
    relative = PurePosixPath(relative_value)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or relative.parts[:2] != ("data", "public_guides")
        or relative.suffix.casefold() != ".pdf"
    ):
        return None
    root = _PUBLIC_GUIDE_SOURCE_ROOT.resolve()
    source_path = (root / Path(*relative.parts[2:])).resolve()
    try:
        source_path.relative_to(root)
    except ValueError:
        return None
    if not source_path.is_file() or file_sha256(source_path) != source_sha256:
        return None
    return source_path, 1, page_count


def _public_snapshot(snapshot: GuideStoreSnapshot) -> dict[str, object]:
    return {
        "postgresql_version": snapshot.postgresql_version,
        "pgvector_version": snapshot.pgvector_version,
        "document_count": snapshot.document_count,
        "chunk_count": snapshot.chunk_count,
        "embedding_count": snapshot.embedding_count,
        "active_generation_count": snapshot.active_generation_count,
        "generation_status": snapshot.generation_status,
        "embedding_model_id": snapshot.embedding_model_id,
        "embedding_dimension": snapshot.embedding_dimension,
        "metric_type": snapshot.metric_type,
        "guide_id": snapshot.guide_id,
        "guide_version": snapshot.guide_version,
        "scope_id": snapshot.scope_id,
        "chunks": [
            {
                "pdf_page_number": chunk.pdf_page_number,
                "control_id": chunk.control_id,
                "text": chunk.text,
                "text_sha256": chunk.text_sha256,
            }
            for chunk in snapshot.chunks
        ],
        "raw_embeddings_included": False,
    }


@router.get("/api/v1/guides/{guide_id}/{guide_version}/source.pdf")
def guide_source_pdf(
    request: Request,
    guide_id: str,
    guide_version: str,
    requested_page: int | None = None,
) -> FileResponse:
    """로그인 사용자가 승인된 원본 PDF의 인용 쪽을 확인하게 한다."""

    _require_product_demo()
    if not auth_enabled():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "로그인이 필요합니다.")
    current_principal(request)
    approved = _approved_source(guide_id, guide_version)
    if approved is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "승인된 가이드를 찾지 못했습니다.")
    source_path, first_page, last_page = approved
    if requested_page is not None and not first_page <= requested_page <= last_page:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "PDF 쪽 번호가 가이드 범위를 벗어났습니다.",
        )
    if not source_path.is_file():
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "승인된 원본 PDF를 열 수 없습니다.",
        )
    response_headers = {
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
    }
    if requested_page is not None:
        response_headers["X-SecAI-Source-PDF-Page"] = str(requested_page)
    return FileResponse(
        path=source_path,
        media_type="application/pdf",
        filename=f"{guide_id}-{guide_version}.pdf",
        content_disposition_type="inline",
        headers=response_headers,
    )


@router.get("/api/v1/guides/{guide_id}/{guide_version}/source-page")
def guide_source_page(
    request: Request,
    guide_id: str,
    guide_version: str,
    pdf_page_number: int,
) -> RedirectResponse:
    """인증을 확인한 뒤 브라우저 PDF 뷰어의 요청 쪽으로 직접 이동한다."""

    _require_product_demo()
    if not auth_enabled():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "로그인이 필요합니다.")
    current_principal(request)
    approved = _approved_source(guide_id, guide_version)
    if approved is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "승인된 가이드를 찾지 못했습니다.")
    source_path, first_page, last_page = approved
    if not first_page <= pdf_page_number <= last_page:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "PDF 쪽 번호가 가이드 범위를 벗어났습니다.",
        )
    if not source_path.is_file():
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "승인된 가이드 원본을 사용할 수 없습니다.",
        )
    source_pdf_path = request.url_for(
        "guide_source_pdf",
        guide_id=guide_id,
        guide_version=guide_version,
    ).path
    source_pdf_url = (
        f"{source_pdf_path}?requested_page={pdf_page_number}"
        f"#page={pdf_page_number}&zoom=page-width"
    )
    return RedirectResponse(
        url=source_pdf_url,
        status_code=status.HTTP_303_SEE_OTHER,
        headers={
            "Cache-Control": "private, no-store",
            "X-SecAI-Source-PDF-Page": str(pdf_page_number),
        },
    )


@router.get("/api/v1/guide-store")
def guide_store_api(request: Request) -> dict[str, object]:
    _require_product_demo()
    return _public_snapshot(_load_snapshot(_organization_id(request)))


@router.get("/ui/guide-store", response_class=HTMLResponse)
def guide_store_page(request: Request) -> HTMLResponse:
    _require_product_demo()
    snapshot = _load_snapshot(_organization_id(request))
    return templates.TemplateResponse(
        request=request,
        name="pages/guide_store.html",
        context={"store": snapshot},
    )
