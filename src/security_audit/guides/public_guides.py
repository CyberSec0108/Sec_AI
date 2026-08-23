"""공개 공공기관 가이드의 원본 계보·페이지 색인·검색 역할 계약."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

import fitz  # type: ignore[import-untyped]

from security_audit.guides.contracts import (
    file_sha256,
    load_json_strict,
    normalize_page_text,
    text_sha256,
)
from security_audit.guides.retrieval import GuidePageText

_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,127}$")
_TOPIC_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_SEARCH_TOKEN_PATTERN = re.compile(r"[0-9A-Za-z가-힣]+")
_ALLOWED_STATUSES = frozenset(
    {
        "DOWNLOADED_PENDING_INGEST",
        "APPROVED",
        "RETIRED",
    }
)


@dataclass(frozen=True, slots=True)
class PublicGuideSourceReport:
    errors: tuple[str, ...]
    document_count: int
    page_count: int
    size_bytes: int

    @property
    def accepted(self) -> bool:
        return not self.errors


def load_public_guide_manifest(project_root: Path) -> dict[str, Any]:
    """중복 키를 거부하며 공공 가이드 manifest를 읽습니다."""

    return load_json_strict(project_root / "guides" / "public_guides_manifest.json")


def public_guide_page_map_path(
    project_root: Path,
    document: dict[str, Any],
) -> Path:
    """manifest에 고정된 Page Map 경로가 안전한 생성물 위치인지 확인합니다."""

    value = document.get("page_map_relative_path")
    if not isinstance(value, str):
        raise ValueError("PUBLIC_GUIDE_PAGE_MAP_PATH_INVALID")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or relative.parts[:3] != ("guides", "page_maps", "public_guides")
        or relative.suffix.casefold() != ".json"
    ):
        raise ValueError("PUBLIC_GUIDE_PAGE_MAP_PATH_INVALID")
    root = project_root.resolve()
    resolved = (root / Path(*relative.parts)).resolve()
    try:
        resolved.relative_to(root / "guides" / "page_maps" / "public_guides")
    except ValueError as exc:
        raise ValueError("PUBLIC_GUIDE_PAGE_MAP_PATH_INVALID") from exc
    return resolved


def _safe_source_path(project_root: Path, value: object) -> Path | None:
    if not isinstance(value, str):
        return None
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or relative.parts[:2] != ("data", "public_guides")
        or relative.suffix.casefold() != ".pdf"
    ):
        return None
    root = project_root.resolve()
    resolved = (root / Path(*relative.parts)).resolve()
    try:
        resolved.relative_to(root / "data" / "public_guides")
    except ValueError:
        return None
    return resolved


def _documents(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    value = manifest.get("documents")
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError("PUBLIC_GUIDE_DOCUMENTS_INVALID")
    return cast(list[dict[str, Any]], value)


def _append(errors: list[str], condition: bool, code: str) -> None:
    if condition:
        errors.append(code)


def _page_indexability(normalized: str) -> tuple[bool, str | None]:
    if not normalized:
        return False, "EMPTY_TEXT_LAYER"
    if _SEARCH_TOKEN_PATTERN.search(normalized) is None:
        return False, "NO_SEARCHABLE_TOKEN"
    return True, None


def verify_public_guide_sources(
    project_root: Path,
    manifest: dict[str, Any],
) -> PublicGuideSourceReport:
    """원본 파일과 설명 전용 권한 경계를 함께 fail-closed 검증합니다."""

    errors: list[str] = []
    try:
        documents = _documents(manifest)
    except ValueError:
        return PublicGuideSourceReport(("PUBLIC_GUIDE_DOCUMENTS_INVALID",), 0, 0, 0)

    _append(
        errors,
        manifest.get("default_retrieval_role") != "SUPPLEMENTAL_EXPLANATION",
        "PUBLIC_GUIDE_RETRIEVAL_ROLE_INVALID",
    )
    _append(
        errors,
        manifest.get("decision_authority") is not False
        or manifest.get("audit_pack_activation_allowed") is not False,
        "PUBLIC_GUIDE_DECISION_AUTHORITY_FORBIDDEN",
    )
    _append(
        errors,
        manifest.get("redistribution_allowed") is not False,
        "PUBLIC_GUIDE_REDISTRIBUTION_FORBIDDEN",
    )
    policy = manifest.get("license_policy")
    _append(
        errors,
        not isinstance(policy, dict)
        or policy.get("status") != "APPROVED_INTERNAL_ONLY"
        or policy.get("derivative_text_storage_allowed") is not True
        or policy.get("embedding_storage_allowed") is not True
        or policy.get("redistribution_allowed") is not False,
        "PUBLIC_GUIDE_LICENSE_POLICY_INVALID",
    )

    identities: set[tuple[str, str]] = set()
    page_count = 0
    size_bytes = 0
    for document in documents:
        guide_id = document.get("guide_id")
        version = document.get("version")
        identity = (str(guide_id), str(version))
        _append(
            errors,
            not isinstance(guide_id, str)
            or _IDENTIFIER_PATTERN.fullmatch(guide_id) is None
            or not isinstance(version, str)
            or not version.strip(),
            "PUBLIC_GUIDE_IDENTITY_INVALID",
        )
        _append(
            errors,
            identity in identities,
            "PUBLIC_GUIDE_IDENTITY_NOT_UNIQUE",
        )
        identities.add(identity)
        _append(
            errors,
            document.get("retrieval_role") != "SUPPLEMENTAL_EXPLANATION",
            "PUBLIC_GUIDE_RETRIEVAL_ROLE_INVALID",
        )
        _append(
            errors,
            document.get("decision_authority") is not False,
            "PUBLIC_GUIDE_DECISION_AUTHORITY_FORBIDDEN",
        )
        _append(
            errors,
            document.get("status") not in _ALLOWED_STATUSES,
            "PUBLIC_GUIDE_STATUS_INVALID",
        )
        topics = document.get("topics")
        platforms = document.get("platforms")
        _append(
            errors,
            not isinstance(topics, list)
            or not topics
            or any(
                not isinstance(item, str) or _TOPIC_PATTERN.fullmatch(item) is None
                for item in topics
            ),
            "PUBLIC_GUIDE_TOPICS_INVALID",
        )
        _append(
            errors,
            not isinstance(platforms, list)
            or not platforms
            or any(
                not isinstance(item, str) or _TOPIC_PATTERN.fullmatch(item) is None
                for item in platforms
            ),
            "PUBLIC_GUIDE_PLATFORMS_INVALID",
        )

        source_path = _safe_source_path(project_root, document.get("relative_path"))
        if source_path is None:
            errors.append("PUBLIC_GUIDE_SOURCE_PATH_UNSAFE")
            continue
        if not source_path.is_file():
            errors.append("PUBLIC_GUIDE_SOURCE_MISSING")
            continue
        actual_size = source_path.stat().st_size
        actual_hash = file_sha256(source_path)
        size_bytes += actual_size
        _append(
            errors,
            actual_size != document.get("size_bytes"),
            "PUBLIC_GUIDE_SOURCE_SIZE_MISMATCH",
        )
        _append(
            errors,
            actual_hash != document.get("source_sha256"),
            "PUBLIC_GUIDE_SOURCE_SHA256_MISMATCH",
        )
        try:
            with fitz.open(source_path) as pdf:
                actual_pages = pdf.page_count
                page_count += actual_pages
                _append(
                    errors,
                    bool(pdf.is_encrypted) != document.get("encrypted"),
                    "PUBLIC_GUIDE_SOURCE_ENCRYPTION_MISMATCH",
                )
                _append(
                    errors,
                    actual_pages != document.get("page_count"),
                    "PUBLIC_GUIDE_SOURCE_PAGE_COUNT_MISMATCH",
                )
                _append(
                    errors,
                    pdf.metadata.get("format") != document.get("pdf_version"),
                    "PUBLIC_GUIDE_SOURCE_PDF_VERSION_MISMATCH",
                )
        except (RuntimeError, ValueError):
            errors.append("PUBLIC_GUIDE_SOURCE_PDF_INVALID")

    return PublicGuideSourceReport(
        errors=tuple(sorted(set(errors))),
        document_count=len(documents),
        page_count=page_count,
        size_bytes=size_bytes,
    )


def build_public_guide_page_map(
    project_root: Path,
    document: dict[str, Any],
) -> dict[str, Any]:
    """원본의 모든 페이지를 보존하고 실제 text가 있는 페이지만 색인합니다."""

    source_path = _safe_source_path(project_root, document.get("relative_path"))
    if source_path is None or not source_path.is_file():
        raise ValueError("PUBLIC_GUIDE_SOURCE_INVALID")
    actual_hash = file_sha256(source_path)
    if actual_hash != document.get("source_sha256"):
        raise ValueError("PUBLIC_GUIDE_SOURCE_SHA256_MISMATCH")

    pages: list[dict[str, Any]] = []
    with fitz.open(source_path) as pdf:
        if pdf.is_encrypted or pdf.page_count != document.get("page_count"):
            raise ValueError("PUBLIC_GUIDE_SOURCE_PDF_INVALID")
        for page_index, page in enumerate(pdf):
            raw_text = page.get_text("text")
            normalized = normalize_page_text(raw_text)
            if "\ufffd" in normalized or "\x00" in normalized:
                raise ValueError("PUBLIC_GUIDE_PAGE_TEXT_CORRUPTED")
            indexable, skip_reason = _page_indexability(normalized)
            pages.append(
                {
                    "pdf_page_index": page_index,
                    "pdf_page_number": page_index + 1,
                    "printed_page_number": page_index + 1,
                    "text_sha256": text_sha256(raw_text),
                    "normalized_text_chars": len(normalized),
                    "indexable": indexable,
                    "skip_reason": skip_reason,
                    "control_ids": ["GUIDE-PAGE"] if indexable else [],
                }
            )
    return {
        "schema_version": "1.0.0",
        "guide_id": document["guide_id"],
        "guide_version": document["version"],
        "source_sha256": actual_hash,
        "source_page_count": document["page_count"],
        "scope_id": document["scope_id"],
        "pdf_page_start": 1,
        "pdf_page_end": document["page_count"],
        "chunker_version": "public-page-text-v1",
        "pages": pages,
    }


def extract_public_guide_pages(
    project_root: Path,
    document: dict[str, Any],
    page_map: dict[str, Any],
) -> tuple[GuidePageText, ...]:
    """고정 Page Map을 원본과 재검증하고 색인 가능한 페이지만 반환합니다."""

    if (
        page_map.get("guide_id") != document.get("guide_id")
        or page_map.get("guide_version") != document.get("version")
        or page_map.get("source_sha256") != document.get("source_sha256")
        or page_map.get("scope_id") != document.get("scope_id")
    ):
        raise ValueError("PUBLIC_GUIDE_PAGE_MAP_IDENTITY_MISMATCH")
    mapped_pages = page_map.get("pages")
    if not isinstance(mapped_pages, list):
        raise ValueError("PUBLIC_GUIDE_PAGE_MAP_INVALID")
    expected_count = document.get("page_count")
    if (
        not isinstance(expected_count, int)
        or len(mapped_pages) != expected_count
        or [item.get("pdf_page_number") for item in mapped_pages]
        != list(range(1, expected_count + 1))
    ):
        raise ValueError("PUBLIC_GUIDE_PAGE_MAP_INVALID")

    source_path = _safe_source_path(project_root, document.get("relative_path"))
    if source_path is None or file_sha256(source_path) != document.get("source_sha256"):
        raise ValueError("PUBLIC_GUIDE_SOURCE_SHA256_MISMATCH")

    extracted: list[GuidePageText] = []
    with fitz.open(source_path) as pdf:
        for page_index, mapped in enumerate(mapped_pages):
            if not isinstance(mapped, dict):
                raise ValueError("PUBLIC_GUIDE_PAGE_MAP_INVALID")
            raw_text = pdf[page_index].get_text("text")
            normalized = normalize_page_text(raw_text)
            indexable, skip_reason = _page_indexability(normalized)
            if (
                mapped.get("pdf_page_index") != page_index
                or mapped.get("text_sha256") != text_sha256(raw_text)
                or mapped.get("normalized_text_chars") != len(normalized)
                or mapped.get("indexable") is not indexable
                or mapped.get("skip_reason") != skip_reason
            ):
                raise ValueError("PUBLIC_GUIDE_PAGE_MAP_TEXT_MISMATCH")
            if not indexable:
                if skip_reason not in {"EMPTY_TEXT_LAYER", "NO_SEARCHABLE_TOKEN"}:
                    raise ValueError("PUBLIC_GUIDE_PAGE_SKIP_REASON_INVALID")
                continue
            if mapped.get("control_ids") != ["GUIDE-PAGE"]:
                raise ValueError("PUBLIC_GUIDE_PAGE_CONTROL_INVALID")
            extracted.append(
                GuidePageText(
                    pdf_page_number=page_index + 1,
                    control_id="GUIDE-PAGE",
                    text=normalized,
                )
            )
    return tuple(extracted)


def select_supplemental_guides(
    manifest: dict[str, Any],
    *,
    platform: str,
    topics: tuple[str, ...],
) -> tuple[dict[str, Any], ...]:
    """플랫폼과 주제가 모두 일치하는 설명 전용 문서만 선택합니다."""

    if (
        _TOPIC_PATTERN.fullmatch(platform) is None
        or not topics
        or any(_TOPIC_PATTERN.fullmatch(topic) is None for topic in topics)
    ):
        raise ValueError("PUBLIC_GUIDE_ROUTE_INVALID")
    requested = set(topics)
    selected: list[dict[str, Any]] = []
    for document in _documents(manifest):
        if (
            document.get("retrieval_role") != "SUPPLEMENTAL_EXPLANATION"
            or document.get("decision_authority") is not False
            or document.get("status") == "RETIRED"
        ):
            continue
        platforms = document.get("platforms")
        document_topics = document.get("topics")
        if (
            isinstance(platforms, list)
            and platform in platforms
            and isinstance(document_topics, list)
            and requested.intersection(document_topics)
        ):
            selected.append(dict(document))
    return tuple(selected)
