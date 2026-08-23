from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security_audit.application.linux_asset_management import (
    LinuxAssetContractError,
    LinuxAssetKeyStore,
    LinuxAssetManagementService,
    LinuxPlatformVerification,
    ManagedLinuxAsset,
    normalize_ssh_host_key,
    validate_linux_endpoint,
)
from security_audit.platforms import LinuxDistribution
from security_audit.security.auth import AuthenticatedPrincipal, HumanRole

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _principal(*, administrator: bool) -> AuthenticatedPrincipal:
    now = datetime.now(UTC)
    return AuthenticatedPrincipal(
        user_id=uuid4(),
        username="admin" if administrator else "user",
        display_name="관리자" if administrator else "사용자",
        organization_id=uuid4(),
        roles=(
            frozenset({HumanRole.ADMIN, HumanRole.USER})
            if administrator
            else frozenset({HumanRole.USER})
        ),
        asset_ids=frozenset(),
        auth_methods=frozenset({"PASSWORD", "DEV_MFA"}),
        session_created_at=now,
        reauthenticated_at=now,
    )


class _MemoryRepository:
    def __init__(self) -> None:
        self.record: ManagedLinuxAsset | None = None

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
    ) -> ManagedLinuxAsset:
        now = datetime.now(UTC)
        self.record = ManagedLinuxAsset(
            asset_id=asset_id,
            organization_id=principal.organization_id,
            alias=alias,
            host=host,
            port=port,
            ssh_username=ssh_username,
            credential_ref=credential_ref,
            public_key=public_key,
            host_key=None,
            host_key_fingerprint=None,
            distribution=None,
            platform_version=None,
            architecture=None,
            state="KEY_INSTALL_PENDING",
            created_by=principal.user_id,
            created_at=now,
            updated_at=now,
        )
        return self.record

    def list(self, principal: AuthenticatedPrincipal) -> tuple[ManagedLinuxAsset, ...]:
        return (self.record,) if self.record is not None else ()

    def get(
        self, principal: AuthenticatedPrincipal, asset_id: UUID
    ) -> ManagedLinuxAsset | None:
        return self.record if self.record and self.record.asset_id == asset_id else None

    def activate(
        self,
        principal: AuthenticatedPrincipal,
        *,
        asset_id: UUID,
        normalized_host_key: str,
        host_key_fingerprint: str,
        verification: LinuxPlatformVerification,
    ) -> ManagedLinuxAsset:
        assert self.record is not None
        self.record = replace(
            self.record,
            host_key=normalized_host_key,
            host_key_fingerprint=host_key_fingerprint,
            distribution=verification.distribution,
            platform_version=verification.version,
            architecture=verification.architecture,
            state="ACTIVE",
        )
        return self.record

    def suspend(
        self, principal: AuthenticatedPrincipal, asset_id: UUID
    ) -> ManagedLinuxAsset:
        assert self.record is not None and self.record.asset_id == asset_id
        self.record = replace(self.record, state="SUSPENDED")
        return self.record


def test_linux_asset_key_store_generates_only_public_material_for_the_ui(
    tmp_path: Path,
) -> None:
    store = LinuxAssetKeyStore(tmp_path)
    credential_ref = uuid4()

    public_key = store.generate(credential_ref)
    private_key = store.private_key_path(credential_ref)

    assert public_key.startswith("ssh-ed25519 ")
    assert private_key.is_file()
    assert "PRIVATE KEY" in private_key.read_text(encoding="ascii")
    if os.name != "nt":
        assert private_key.stat().st_mode & 0o777 == 0o600
    assert str(private_key) not in public_key
    with pytest.raises(FileExistsError):
        store.generate(credential_ref)


def test_linux_asset_endpoint_is_limited_to_approved_networks_and_ssh_port() -> None:
    assert validate_linux_endpoint(
        "192.168.110.146",
        22,
        allowed_cidrs=("192.168.110.0/24",),
        allowed_ports=(22,),
    ) == "192.168.110.146"

    for address in ("127.0.0.1", "169.254.169.254", "8.8.8.8", "server.local"):
        with pytest.raises(LinuxAssetContractError):
            validate_linux_endpoint(
                address,
                22,
                allowed_cidrs=("192.168.110.0/24",),
                allowed_ports=(22,),
            )
    with pytest.raises(LinuxAssetContractError):
        validate_linux_endpoint(
            "192.168.110.146",
            2222,
            allowed_cidrs=("192.168.110.0/24",),
            allowed_ports=(22,),
        )


def test_linux_asset_host_key_requires_valid_ed25519_public_key() -> None:
    key = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii")

    normalized, fingerprint = normalize_ssh_host_key(key + " server-comment")

    assert normalized == key
    assert fingerprint.startswith("SHA256:")
    with pytest.raises(LinuxAssetContractError):
        normalize_ssh_host_key("ssh-rsa not-a-real-key")


def test_admin_registers_and_activates_server_without_selecting_distribution(
    tmp_path: Path,
) -> None:
    repository = _MemoryRepository()
    service = LinuxAssetManagementService(
        repository,
        LinuxAssetKeyStore(tmp_path),
        allowed_cidrs=("192.168.110.0/24",),
        allowed_ports=(22,),
        verifier=lambda target: LinuxPlatformVerification(
            LinuxDistribution.ROCKY_9,
            "9.4",
            "X86_64",
        ),
    )
    administrator = _principal(administrator=True)

    pending = service.register(
        administrator,
        alias="회계 Linux 서버",
        host="192.168.110.150",
        port=22,
        ssh_username="secai-audit",
    )
    host_key = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii")
    active = service.activate(
        administrator,
        asset_id=pending.asset_id,
        host_key=host_key,
        fingerprint_confirmed=True,
    )

    assert pending.state == "KEY_INSTALL_PENDING"
    assert active.state == "ACTIVE"
    assert active.distribution is LinuxDistribution.ROCKY_9
    assert active.host_key_fingerprint and active.host_key_fingerprint.startswith("SHA256:")
    assert pending.distribution is None
    with pytest.raises(LinuxAssetContractError, match="관리자만"):
        service.register(
            _principal(administrator=False),
            alias="사용자 서버",
            host="192.168.110.151",
            port=22,
            ssh_username="secai-audit",
        )


def test_linux_server_management_is_an_admin_card_and_secure_runtime_surface() -> None:
    registry = (
        PROJECT_ROOT / "src/security_audit/application/product_features.py"
    ).read_text(encoding="utf-8")
    session_api = (PROJECT_ROOT / "apps/api/authentication.py").read_text(
        encoding="utf-8"
    )
    route = (PROJECT_ROOT / "apps/api/linux_asset_management.py").read_text(
        encoding="utf-8"
    )
    template = (
        PROJECT_ROOT / "apps/web/templates/pages/admin_linux_servers.html"
    ).read_text(encoding="utf-8")
    compose = (PROJECT_ROOT / "deploy/compose/compose.yml").read_text(encoding="utf-8")

    assert 'feature_id="linux_asset_management"' in registry
    assert '"linux_asset_management"' in session_api
    assert 'require_administrator(request)' in route
    assert 'verify_browser_csrf(request, csrf_token)' in route
    assert "개인키" not in template
    assert "SSH 공개키" in template
    assert "서버 종류" not in template
    assert "SECAI_LINUX_ASSET_KEY_ROOT" in compose
    assert "target: /run/secai-linux-asset-keys" in compose
    assert "read_only: false" in compose


def test_linux_asset_migration_is_scoped_and_does_not_grant_delete() -> None:
    migration = (
        PROJECT_ROOT
        / "database/alembic/versions/0034_linux_managed_assets.py"
    ).read_text(encoding="utf-8")

    assert 'down_revision: str | None = "0033_windows_presentations"' in migration
    assert "CREATE TABLE linux_managed_assets" in migration
    assert "ENABLE ROW LEVEL SECURITY" in migration
    assert "secai.is_administrator" in migration
    assert "GRANT SELECT, INSERT, UPDATE ON linux_managed_assets" in migration
    assert "GRANT DELETE" not in migration
    assert "private_key" not in migration
