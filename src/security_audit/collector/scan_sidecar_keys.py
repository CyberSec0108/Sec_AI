"""사이드카 서명 키를 서버와 수집기가 같은 규칙으로 다루는 지점.

서버는 비밀 seed 하나만 보관하고, 수집기는 빌드 시점에 함께 넣어 둔 공개 키
목록만 신뢰합니다. key_id는 공개 키에서 계산하므로 양쪽이 따로 관리할 값이
없습니다.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from security_audit.collector.scan_sidecar import (
    ScanSidecar,
    SidecarSigner,
    read_scan_sidecar,
)

KEY_ID_LENGTH = 16
TRUSTED_KEYS_RELATIVE = Path("collectors/one_shot/contracts/scan_sidecar_trusted_keys.json")
_SEED_BYTES = 32


class ScanSidecarKeyError(RuntimeError):
    """서명 키를 읽을 수 없을 때 올립니다."""


def _decode(value: str, *, expected: int | None = None) -> bytes:
    trimmed = value.strip()
    try:
        raw = base64.urlsafe_b64decode(trimmed + ("=" * (-len(trimmed) % 4)))
    except (ValueError, TypeError) as exc:
        raise ScanSidecarKeyError("서명 키 형식이 올바르지 않습니다.") from exc
    if expected is not None and len(raw) != expected:
        raise ScanSidecarKeyError("서명 키 길이가 올바르지 않습니다.")
    return raw


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def key_id_for(public_key: Ed25519PublicKey) -> str:
    """공개 키에서 계산하므로 서버와 수집기가 같은 값을 얻습니다."""

    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:KEY_ID_LENGTH]


def _private_key(seed: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(_decode(seed, expected=_SEED_BYTES))


def signer_from_seed(seed: str) -> tuple[str, SidecarSigner]:
    """서버가 사이드카에 서명할 때 쓰는 콜백을 만듭니다."""

    private_key = _private_key(seed)
    key_id = key_id_for(private_key.public_key())

    def sign(payload: bytes) -> tuple[str, bytes]:
        return key_id, private_key.sign(payload)

    return key_id, sign


def trusted_keys_document(seed: str) -> str:
    """빌드 시점에 수집기에 넣어 둘 공개 키 목록입니다."""

    public_key = _private_key(seed).public_key()
    return (
        json.dumps(
            {
                "schema_version": "1.0.0",
                "keys": [
                    {
                        "key_id": key_id_for(public_key),
                        "algorithm": "Ed25519",
                        "public_key": _encode(
                            public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
                        ),
                    }
                ],
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def read_trusted_public_keys(document: str) -> Mapping[str, Ed25519PublicKey]:
    """수집기가 신뢰할 공개 키만 읽어 들입니다."""

    try:
        loaded = json.loads(document)
    except json.JSONDecodeError as exc:
        raise ScanSidecarKeyError("신뢰 키 목록을 읽을 수 없습니다.") from exc
    records = loaded.get("keys") if isinstance(loaded, dict) else None
    if not isinstance(records, list) or not records:
        raise ScanSidecarKeyError("신뢰 키 목록이 비어 있습니다.")
    keys: dict[str, Ed25519PublicKey] = {}
    for record in records:
        if not isinstance(record, dict) or record.get("algorithm") not in {
            None,
            "Ed25519",
        }:
            raise ScanSidecarKeyError("신뢰 키 항목이 올바르지 않습니다.")
        raw = _decode(str(record.get("public_key", "")), expected=32)
        public_key = Ed25519PublicKey.from_public_bytes(raw)
        expected = key_id_for(public_key)
        if str(record.get("key_id", "")) != expected:
            raise ScanSidecarKeyError("신뢰 키 식별자가 공개 키와 맞지 않습니다.")
        keys[expected] = public_key
    return keys


def trusted_keys_path(collection_root: Path) -> Path:
    """빌드 때 함께 넣어 둔 신뢰 키 파일의 위치입니다.

    수집기마다 자원을 두는 위치가 달라 호출자가 기준 경로를 넘깁니다.
    """

    return collection_root / TRUSTED_KEYS_RELATIVE


def load_trusted_public_keys(collection_root: Path) -> Mapping[str, Ed25519PublicKey]:
    """신뢰 키가 없으면 서명을 확인할 수 없으므로 실행을 멈춥니다."""

    path = trusted_keys_path(collection_root)
    try:
        document = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScanSidecarKeyError(
            "신뢰 키 파일이 없어 사이드카를 확인할 수 없습니다. 다시 내려받으세요."
        ) from exc
    return read_trusted_public_keys(document)


def load_verified_sidecar(path: Path, collection_root: Path) -> ScanSidecar | None:
    """사이드카가 없으면 기존 방식으로 진행하고, 있으면 서명부터 확인합니다."""

    if not path.is_file():
        return None
    return read_scan_sidecar(
        path.read_text(encoding="utf-8"),
        public_keys=load_trusted_public_keys(collection_root),
    )
