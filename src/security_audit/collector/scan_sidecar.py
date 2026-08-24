"""수집기와 함께 배포되는 사이드카 파일 계약.

서명된 실행 파일은 모든 사용자에게 동일하게 유지하고, 사용자별 서버 주소와
실행 토큰만 이 파일로 전달합니다. 실행 파일 자체를 바꾸지 않으므로 다운로드
카탈로그의 hash 검증이 그대로 성립합니다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

SIDECAR_SCHEMA_VERSION = "1.0.0"
SIDECAR_SUFFIX = ".secai-scan.json"
_ALLOWED_SCHEMES = frozenset({"http", "https"})


class ScanSidecarError(ValueError):
    def __init__(self, message: str = "점검 실행 사이드카 파일을 확인할 수 없습니다.") -> None:
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ScanSidecar:
    server_origin: str
    token: str
    expires_at: datetime
    max_runs: int


def _validated_origin(server_origin: str) -> str:
    parsed = urlsplit(server_origin)
    if (
        parsed.scheme not in _ALLOWED_SCHEMES
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ScanSidecarError("서버 주소는 정확한 origin이어야 합니다.")
    return server_origin.rstrip("/")


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ScanSidecarError("만료 시각은 UTC offset을 포함해야 합니다.")
    return value.isoformat().replace("+00:00", "Z")


def build_scan_sidecar(
    *,
    token: str,
    server_origin: str,
    expires_at: datetime,
    max_runs: int,
) -> str:
    """다운로드 화면이 내려보낼 사이드카 문서를 만듭니다."""

    if not token:
        raise ScanSidecarError("실행 토큰이 비어 있습니다.")
    if max_runs <= 0:
        raise ScanSidecarError("실행 가능 횟수가 올바르지 않습니다.")
    return json.dumps(
        {
            "schema_version": SIDECAR_SCHEMA_VERSION,
            "server_origin": _validated_origin(server_origin),
            "token": token,
            "expires_at": _utc_text(expires_at),
            "max_runs": max_runs,
        },
        ensure_ascii=False,
        indent=2,
    )


def _required(document: dict[str, Any], key: str) -> Any:
    value = document.get(key)
    if value is None:
        raise ScanSidecarError(f"사이드카 항목이 없습니다: {key}")
    return value


def read_scan_sidecar(document: str) -> ScanSidecar:
    """수집기가 사이드카를 읽을 때 형식과 범위를 먼저 확인합니다."""

    try:
        loaded = json.loads(document)
    except json.JSONDecodeError as exc:
        raise ScanSidecarError() from exc
    if not isinstance(loaded, dict):
        raise ScanSidecarError()
    if loaded.get("schema_version") != SIDECAR_SCHEMA_VERSION:
        raise ScanSidecarError("지원하지 않는 사이드카 schema version입니다.")
    raw_expires = str(_required(loaded, "expires_at"))
    try:
        expires_at = datetime.fromisoformat(raw_expires.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScanSidecarError("만료 시각 형식이 올바르지 않습니다.") from exc
    max_runs = _required(loaded, "max_runs")
    if not isinstance(max_runs, int) or isinstance(max_runs, bool) or max_runs <= 0:
        raise ScanSidecarError("실행 가능 횟수가 올바르지 않습니다.")
    return ScanSidecar(
        server_origin=_validated_origin(str(_required(loaded, "server_origin"))),
        token=str(_required(loaded, "token")),
        expires_at=expires_at,
        max_runs=max_runs,
    )
