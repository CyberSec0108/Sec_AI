"""수집기와 함께 배포되는 사이드카 파일 계약.

서명된 실행 파일은 모든 사용자에게 동일하게 유지하고, 사용자별 서버 주소와
실행 토큰만 이 파일로 전달합니다. 실행 파일 자체를 바꾸지 않으므로 다운로드
카탈로그의 hash 검증이 그대로 성립합니다.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SIDECAR_SCHEMA_VERSION = "1.0.0"
SIDECAR_SUFFIX = ".secai-scan.json"
SIDECAR_NOTICE = (
    "이 파일은 점검 프로그램이 읽는 설정입니다. 편집하면 서명이 깨져 실행이 중단됩니다."
)
UNKNOWN_DEVICE_NAME = "UNKNOWN-DEVICE"
_SIGNATURE_MISSING = "사이드카에 서버 서명이 없습니다. 다시 내려받으세요."
_SIGNATURE_BROKEN = "사이드카 서명이 맞지 않습니다. 파일이 변경되었을 수 있습니다."
_DEVICE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
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


type SidecarSigner = Callable[[bytes], tuple[str, bytes]]


def _signed_payload(document: Mapping[str, Any]) -> bytes:
    """서명 대상은 signature를 제외한 정본 JSON입니다."""

    body = {key: value for key, value in document.items() if key != "signature"}
    return json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


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
    sign: SidecarSigner | None = None,
) -> str:
    """다운로드 화면이 내려보낼 사이드카 문서를 만듭니다.

    서명을 주면 주소·토큰 조작을 수집기가 거부할 수 있습니다.
    """

    if not token:
        raise ScanSidecarError("실행 토큰이 비어 있습니다.")
    if max_runs <= 0:
        raise ScanSidecarError("실행 가능 횟수가 올바르지 않습니다.")
    document: dict[str, Any] = {
        "schema_version": SIDECAR_SCHEMA_VERSION,
        "server_origin": _validated_origin(server_origin),
        "token": token,
        "expires_at": _utc_text(expires_at),
        "max_runs": max_runs,
        "notice": SIDECAR_NOTICE,
    }
    if sign is not None:
        payload = _signed_payload(document)
        key_id, signature = sign(payload)
        if not key_id or len(key_id) > 128:
            raise ScanSidecarError("서명 키 식별자가 올바르지 않습니다.")
        document["signature"] = {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "signed_sha256": hashlib.sha256(payload).hexdigest(),
            "value": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        }
    return json.dumps(document, ensure_ascii=False, indent=2)


def _required(document: dict[str, Any], key: str) -> Any:
    value = document.get(key)
    if value is None:
        raise ScanSidecarError(f"사이드카 항목이 없습니다: {key}")
    return value


def _verify_signature(
    loaded: dict[str, Any],
    public_keys: Mapping[str, Ed25519PublicKey],
) -> None:
    """주소·토큰이 손대어졌으면 여기서 실행을 멈춥니다."""

    block = loaded.get("signature")
    if not isinstance(block, dict):
        raise ScanSidecarError(_SIGNATURE_MISSING)
    if block.get("algorithm") != "Ed25519":
        raise ScanSidecarError(_SIGNATURE_BROKEN)
    public_key = public_keys.get(str(block.get("key_id", "")))
    if public_key is None:
        raise ScanSidecarError(_SIGNATURE_BROKEN)
    encoded = str(block.get("value", ""))
    payload = _signed_payload(loaded)
    try:
        signature = base64.urlsafe_b64decode(encoded + ("=" * (-len(encoded) % 4)))
        public_key.verify(signature, payload)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ScanSidecarError(_SIGNATURE_BROKEN) from exc


def read_scan_sidecar(
    document: str,
    *,
    public_keys: Mapping[str, Ed25519PublicKey] | None = None,
) -> ScanSidecar:
    """수집기가 사이드카를 읽을 때 서명과 형식을 먼저 확인합니다."""

    try:
        loaded = json.loads(document)
    except json.JSONDecodeError as exc:
        raise ScanSidecarError() from exc
    if not isinstance(loaded, dict):
        raise ScanSidecarError()
    if loaded.get("schema_version") != SIDECAR_SCHEMA_VERSION:
        raise ScanSidecarError("지원하지 않는 사이드카 schema version입니다.")
    if public_keys is not None:
        _verify_signature(loaded, public_keys)
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


def device_name(hostname: str) -> str:
    """승인 화면이 보여줄 장비 이름입니다. 규칙을 못 맞추면 표시하지 않습니다."""

    trimmed = hostname.strip()[:64]
    if _DEVICE_NAME_PATTERN.fullmatch(trimmed) is None:
        return UNKNOWN_DEVICE_NAME
    return trimmed


def sidecar_name(artifact_filename: str) -> str:
    """실행 파일 확장자를 떼고 붙입니다. `...exe.json`처럼 보이지 않게 합니다."""

    base = artifact_filename
    if base.casefold().endswith(".exe"):
        base = base[: -len(".exe")]
    return base + SIDECAR_SUFFIX


def default_sidecar_path(program_path: Path) -> Path:
    return program_path.with_name(sidecar_name(program_path.name))


def legacy_sidecar_path(program_path: Path) -> Path:
    """이름을 바꾸기 전에 내려받은 설정 파일도 그대로 인식합니다."""

    return program_path.with_name(program_path.name + SIDECAR_SUFFIX)


def existing_sidecar_path(program_path: Path) -> Path:
    """설정 파일이 실제로 있는 경로를 고릅니다. 없으면 현재 이름을 돌려줍니다."""

    current = default_sidecar_path(program_path)
    if current.is_file():
        return current
    legacy = legacy_sidecar_path(program_path)
    if legacy.is_file():
        return legacy
    return current


def load_sidecar(
    path: Path,
    *,
    public_keys: Mapping[str, Ed25519PublicKey] | None = None,
) -> ScanSidecar | None:
    """사이드카가 없으면 호출자가 기존 방식으로 되돌아갑니다."""

    if not path.is_file():
        return None
    return read_scan_sidecar(
        path.read_text(encoding="utf-8"),
        public_keys=public_keys,
    )
