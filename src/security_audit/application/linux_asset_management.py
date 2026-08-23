"""관리자 전용 Linux SSH 서버 등록과 키 수명주기 계약."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from security_audit.platforms import LinuxDistribution
from security_audit.security.auth import AuthenticatedPrincipal, HumanRole

_ALIAS = re.compile(r"^[0-9A-Za-z가-힣][0-9A-Za-z가-힣 _.-]{1,79}$")
_USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class LinuxAssetContractError(ValueError):
    """잘못된 등록값 또는 허용되지 않은 서버 접근을 거부합니다."""


@dataclass(frozen=True, slots=True)
class ManagedLinuxAsset:
    asset_id: UUID
    organization_id: UUID
    alias: str
    host: str
    port: int
    ssh_username: str
    credential_ref: UUID
    public_key: str
    host_key: str | None
    host_key_fingerprint: str | None
    distribution: LinuxDistribution | None
    platform_version: str | None
    architecture: str | None
    state: str
    created_by: UUID
    created_at: datetime
    updated_at: datetime

    def administrator_view(self) -> dict[str, object]:
        return {
            "asset_id": str(self.asset_id),
            "alias": self.alias,
            "host": self.host,
            "port": self.port,
            "ssh_username": self.ssh_username,
            "public_key": self.public_key,
            "host_key_fingerprint": self.host_key_fingerprint,
            "distribution": self.distribution.value if self.distribution else None,
            "platform_version": self.platform_version,
            "architecture": self.architecture,
            "state": self.state,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class LinuxPlatformVerification:
    distribution: LinuxDistribution
    version: str
    architecture: str


@dataclass(frozen=True, slots=True)
class LinuxVerificationTarget:
    host: str
    port: int
    username: str
    private_key: Path
    known_hosts: Path


class LinuxAssetRepository(Protocol):
    def register(
        self,
        principal: AuthenticatedPrincipal,
        *,
        asset_id: UUID,
        alias: str,
        host: str,
        port: int,
        ssh_username: str,
        credential_ref: UUID,
        public_key: str,
    ) -> ManagedLinuxAsset: ...

    def list(self, principal: AuthenticatedPrincipal) -> tuple[ManagedLinuxAsset, ...]: ...

    def get(
        self, principal: AuthenticatedPrincipal, asset_id: UUID
    ) -> ManagedLinuxAsset | None: ...

    def activate(
        self,
        principal: AuthenticatedPrincipal,
        *,
        asset_id: UUID,
        normalized_host_key: str,
        host_key_fingerprint: str,
        verification: LinuxPlatformVerification,
    ) -> ManagedLinuxAsset: ...

    def suspend(
        self, principal: AuthenticatedPrincipal, asset_id: UUID
    ) -> ManagedLinuxAsset: ...


class LinuxAssetKeyStore:
    """DB 밖 보호 디렉터리에 Ed25519 개인키와 pinned host key를 보관합니다."""

    def __init__(self, root: Path) -> None:
        self._root = root

    def _directory(self, credential_ref: UUID) -> Path:
        return self._root / str(credential_ref)

    def private_key_path(self, credential_ref: UUID) -> Path:
        return self._directory(credential_ref) / "identity"

    def known_hosts_path(self, credential_ref: UUID) -> Path:
        return self._directory(credential_ref) / "known_hosts"

    def generate(self, credential_ref: UUID) -> str:
        directory = self._directory(credential_ref)
        directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        directory.chmod(0o700)
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        key_path = self.private_key_path(credential_ref)
        try:
            with key_path.open("xb") as handle:
                handle.write(private_bytes)
            key_path.chmod(0o600)
        except Exception:
            if key_path.exists():
                key_path.unlink()
            directory.rmdir()
            raise
        return private_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        ).decode("ascii")

    def pin_host_key(
        self,
        credential_ref: UUID,
        *,
        host: str,
        port: int,
        normalized_host_key: str,
    ) -> Path:
        host_token = host if port == 22 else f"[{host}]:{port}"
        path = self.known_hosts_path(credential_ref)
        content = f"{host_token} {normalized_host_key}\n"
        if path.exists():
            if path.read_text(encoding="ascii") != content:
                raise LinuxAssetContractError(
                    "이미 확인한 호스트 키와 다릅니다. 키 변경은 별도 승인 절차가 필요합니다."
                )
            return path
        with path.open("x", encoding="ascii", newline="\n") as handle:
            handle.write(content)
        path.chmod(0o600)
        return path

    def discard_unregistered(self, credential_ref: UUID) -> None:
        """DB 등록 실패 직후 이번 요청이 만든 키 파일만 정리합니다."""

        directory = self._directory(credential_ref)
        for path in (
            self.known_hosts_path(credential_ref),
            self.private_key_path(credential_ref),
        ):
            if path.is_file():
                path.unlink()
        if directory.is_dir():
            directory.rmdir()


def require_asset_administrator(principal: AuthenticatedPrincipal) -> None:
    if HumanRole.ADMIN not in principal.roles:
        raise LinuxAssetContractError("관리자만 Linux 서버를 등록할 수 있습니다.")


def validate_linux_alias(alias: str) -> str:
    value = alias.strip()
    if _ALIAS.fullmatch(value) is None:
        raise LinuxAssetContractError("서버 별칭은 2~80자의 문자와 숫자로 입력해 주세요.")
    return value


def validate_linux_username(username: str) -> str:
    value = username.strip()
    if _USERNAME.fullmatch(value) is None:
        raise LinuxAssetContractError("SSH 계정 이름 형식이 올바르지 않습니다.")
    return value


def validate_linux_endpoint(
    host: str,
    port: int,
    *,
    allowed_cidrs: tuple[str, ...],
    allowed_ports: tuple[int, ...],
) -> str:
    """DNS 재바인딩을 피하도록 등록 대상은 승인된 CIDR의 IP 리터럴로 제한합니다."""

    try:
        address = ipaddress.ip_address(host.strip())
        networks = tuple(ipaddress.ip_network(item, strict=False) for item in allowed_cidrs)
    except ValueError as exc:
        raise LinuxAssetContractError("서버 주소는 승인된 네트워크의 IP로 입력해 주세요.") from exc
    if (
        not networks
        or address.version != 4
        or not any(address in network for network in networks)
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    ):
        raise LinuxAssetContractError("이 IP 주소는 서버 등록 허용 범위에 포함되지 않습니다.")
    if port not in allowed_ports:
        raise LinuxAssetContractError("허용된 SSH 포트만 등록할 수 있습니다.")
    return address.compressed


def normalize_ssh_host_key(value: str) -> tuple[str, str]:
    parts = value.strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise LinuxAssetContractError("Ed25519 SSH 호스트 공개키를 입력해 주세요.")
    normalized = f"{parts[0]} {parts[1]}"
    try:
        loaded = serialization.load_ssh_public_key(normalized.encode("ascii"))
        raw = base64.b64decode(parts[1], validate=True)
    except (ValueError, TypeError) as exc:
        raise LinuxAssetContractError("SSH 호스트 공개키 형식이 올바르지 않습니다.") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise LinuxAssetContractError("Ed25519 SSH 호스트 공개키만 사용할 수 있습니다.")
    fingerprint = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return normalized, f"SHA256:{fingerprint}"


class LinuxAssetManagementService:
    def __init__(
        self,
        repository: LinuxAssetRepository,
        key_store: LinuxAssetKeyStore,
        *,
        allowed_cidrs: tuple[str, ...],
        allowed_ports: tuple[int, ...],
        verifier: Callable[[LinuxVerificationTarget], LinuxPlatformVerification],
    ) -> None:
        self._repository = repository
        self._key_store = key_store
        self._allowed_cidrs = allowed_cidrs
        self._allowed_ports = allowed_ports
        self._verifier = verifier

    def list(self, principal: AuthenticatedPrincipal) -> tuple[ManagedLinuxAsset, ...]:
        require_asset_administrator(principal)
        return self._repository.list(principal)

    def register(
        self,
        principal: AuthenticatedPrincipal,
        *,
        alias: str,
        host: str,
        port: int,
        ssh_username: str,
    ) -> ManagedLinuxAsset:
        require_asset_administrator(principal)
        safe_alias = validate_linux_alias(alias)
        safe_host = validate_linux_endpoint(
            host,
            port,
            allowed_cidrs=self._allowed_cidrs,
            allowed_ports=self._allowed_ports,
        )
        safe_username = validate_linux_username(ssh_username)
        asset_id = uuid4()
        credential_ref = uuid4()
        public_key = self._key_store.generate(credential_ref)
        try:
            return self._repository.register(
                principal,
                asset_id=asset_id,
                alias=safe_alias,
                host=safe_host,
                port=port,
                ssh_username=safe_username,
                credential_ref=credential_ref,
                public_key=public_key,
            )
        except Exception:
            self._key_store.discard_unregistered(credential_ref)
            raise

    def activate(
        self,
        principal: AuthenticatedPrincipal,
        *,
        asset_id: UUID,
        host_key: str,
        fingerprint_confirmed: bool,
    ) -> ManagedLinuxAsset:
        require_asset_administrator(principal)
        if not fingerprint_confirmed:
            raise LinuxAssetContractError("호스트 키 지문을 별도 경로로 확인해 주세요.")
        asset = self._repository.get(principal, asset_id)
        if asset is None:
            raise LinuxAssetContractError("등록된 Linux 서버를 찾을 수 없습니다.")
        if asset.state == "SUSPENDED":
            raise LinuxAssetContractError("중지된 서버는 연결 확인을 할 수 없습니다.")
        normalized, fingerprint = normalize_ssh_host_key(host_key)
        known_hosts = self._key_store.pin_host_key(
            asset.credential_ref,
            host=asset.host,
            port=asset.port,
            normalized_host_key=normalized,
        )
        verification = self._verifier(
            LinuxVerificationTarget(
                host=asset.host,
                port=asset.port,
                username=asset.ssh_username,
                private_key=self._key_store.private_key_path(asset.credential_ref),
                known_hosts=known_hosts,
            )
        )
        return self._repository.activate(
            principal,
            asset_id=asset_id,
            normalized_host_key=normalized,
            host_key_fingerprint=fingerprint,
            verification=verification,
        )

    def suspend(
        self, principal: AuthenticatedPrincipal, *, asset_id: UUID
    ) -> ManagedLinuxAsset:
        require_asset_administrator(principal)
        return self._repository.suspend(principal, asset_id)
