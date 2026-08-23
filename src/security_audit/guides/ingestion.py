"""Exact-source PDF inspection and ClamAV gate for approved guide ingestion."""

from __future__ import annotations

import socket
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import fitz  # type: ignore[import-untyped]

from security_audit.guides.contracts import (
    file_sha256,
    normalize_page_text,
    text_sha256,
)
from security_audit.guides.retrieval import GuidePageText

_MAX_SCAN_BYTES = 100 * 1024 * 1024
_SCAN_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class MalwareScanResult:
    status: str
    engine: str
    source_sha256: str
    size_bytes: int
    response: str

    @property
    def accepted(self) -> bool:
        return self.status == "CLEAN"


@dataclass(frozen=True, slots=True)
class GuidePdfQualityReport:
    errors: tuple[str, ...]
    source_sha256: str
    page_count: int
    pdf_page_start: int
    pdf_page_end: int
    extraction_mode: str
    ocr_required_pages: int
    pages: tuple[GuidePageText, ...]

    @property
    def accepted(self) -> bool:
        return not self.errors


def _clamd_response(connection: socket.socket) -> str:
    chunks: list[bytes] = []
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
        if b"\0" in chunk:
            break
    return b"".join(chunks).rstrip(b"\0\n").decode("utf-8", errors="replace")


def scan_pdf_with_clamav(
    source_path: Path,
    *,
    host: str,
    port: int,
) -> MalwareScanResult:
    """Stream the exact PDF to clamd without copying it into a writable volume."""

    resolved = source_path.resolve()
    size_bytes = resolved.stat().st_size if resolved.is_file() else 0
    if size_bytes <= 0 or size_bytes > _MAX_SCAN_BYTES:
        raise ValueError("GUIDE_SOURCE_SCAN_SIZE_INVALID")

    with socket.create_connection((host, port), timeout=10) as connection:
        connection.settimeout(120)
        connection.sendall(b"zINSTREAM\0")
        with resolved.open("rb") as stream:
            for chunk in iter(lambda: stream.read(_SCAN_CHUNK_BYTES), b""):
                connection.sendall(struct.pack("!I", len(chunk)))
                connection.sendall(chunk)
        connection.sendall(struct.pack("!I", 0))
        response = _clamd_response(connection)

    with socket.create_connection((host, port), timeout=10) as connection:
        connection.sendall(b"zVERSION\0")
        engine = _clamd_response(connection)

    return MalwareScanResult(
        status="CLEAN" if response.endswith(": OK") else "DETECTED_OR_ERROR",
        engine=engine,
        source_sha256=file_sha256(resolved),
        size_bytes=size_bytes,
        response=response.replace(str(resolved), resolved.name),
    )


def _mapped_pages(page_map: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    pages = page_map.get("pages")
    if not isinstance(pages, list) or not all(isinstance(page, dict) for page in pages):
        raise ValueError("GUIDE_PAGE_MAP_INVALID")
    return pages


def inspect_guide_pdf(
    source_path: Path,
    page_map: Mapping[str, Any],
) -> GuidePdfQualityReport:
    """Verify all mapped pages against the exact IMP-047 text fingerprints."""

    errors: list[str] = []
    resolved = source_path.resolve()
    expected_source_hash = page_map.get("source_sha256")
    actual_source_hash = file_sha256(resolved)
    if actual_source_hash != expected_source_hash:
        errors.append("SOURCE_SHA256_MISMATCH")

    mapped_pages = _mapped_pages(page_map)
    start = page_map.get("pdf_page_start")
    end = page_map.get("pdf_page_end")
    if not isinstance(start, int) or not isinstance(end, int) or start > end:
        raise ValueError("GUIDE_PAGE_RANGE_INVALID")
    expected_numbers = list(range(start, end + 1))
    actual_numbers = [int(page["pdf_page_number"]) for page in mapped_pages]
    if actual_numbers != expected_numbers:
        errors.append("PAGE_MAP_NOT_CONTIGUOUS")

    extracted: list[GuidePageText] = []
    ocr_required_pages = 0
    with fitz.open(resolved) as document:
        if document.is_encrypted:
            errors.append("SOURCE_PDF_ENCRYPTED")
        if document.page_count != page_map.get("source_page_count"):
            errors.append("SOURCE_PAGE_COUNT_MISMATCH")
        for mapped in mapped_pages:
            page_number = int(mapped["pdf_page_number"])
            text = document[page_number - 1].get_text("text")
            normalized = normalize_page_text(text)
            if not normalized:
                ocr_required_pages += 1
                errors.append(f"PAGE_{page_number}_TEXT_LAYER_EMPTY")
            if "\ufffd" in normalized or "\x00" in normalized:
                errors.append(f"PAGE_{page_number}_TEXT_CORRUPTED")
            if text_sha256(text) != mapped.get("text_sha256"):
                errors.append(f"PAGE_{page_number}_TEXT_SHA256_MISMATCH")
            if len(normalized) != mapped.get("normalized_text_chars"):
                errors.append(f"PAGE_{page_number}_TEXT_LENGTH_MISMATCH")
            control_ids = mapped.get("control_ids")
            control_id = (
                str(control_ids[0])
                if isinstance(control_ids, list) and control_ids
                else "PC-INTRO"
            )
            extracted.append(
                GuidePageText(
                    pdf_page_number=page_number,
                    control_id=control_id,
                    text=normalized,
                )
            )

    return GuidePdfQualityReport(
        errors=tuple(sorted(set(errors))),
        source_sha256=actual_source_hash,
        page_count=len(extracted),
        pdf_page_start=start,
        pdf_page_end=end,
        extraction_mode="TEXT_LAYER",
        ocr_required_pages=ocr_required_pages,
        pages=tuple(extracted),
    )
