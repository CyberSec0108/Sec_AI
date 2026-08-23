"""조직 범위가 적용된 Linux 관리 서버 저장소."""

from __future__ import annotations

import json
from datetime import datetime
from typing import cast
from uuid import UUID, uuid4

from sqlalchemy import Engine, text
from sqlalchemy.engine import RowMapping
from sqlalchemy.orm import Session

from security_audit.application.linux_asset_management import (
    LinuxAssetContractError,
    LinuxPlatformVerification,
    ManagedLinuxAsset,
)
from security_audit.platforms import LinuxDistribution
from security_audit.security.auth import AuthenticatedPrincipal, HumanRole


def _set_scope(session: Session, principal: AuthenticatedPrincipal) -> None:
    session.execute(
        text("SELECT set_config('secai.organization_id', :value, true)"),
        {"value": str(principal.organization_id)},
    )
    session.execute(
        text("SELECT set_config('secai.user_id', :value, true)"),
        {"value": str(principal.user_id)},
    )
    session.execute(
        text("SELECT set_config('secai.is_administrator', :value, true)"),
        {"value": "true" if HumanRole.ADMIN in principal.roles else "false"},
    )


def _record(row: RowMapping) -> ManagedLinuxAsset:
    distribution_value = row["distribution"]
    return ManagedLinuxAsset(
        asset_id=cast(UUID, row["asset_id"]),
        organization_id=cast(UUID, row["organization_id"]),
        alias=str(row["alias"]),
        host=str(row["host"]),
        port=int(cast(int, row["port"])),
        ssh_username=str(row["ssh_username"]),
        credential_ref=cast(UUID, row["credential_ref"]),
        public_key=str(row["public_key"]),
        host_key=str(row["host_key"]) if row["host_key"] is not None else None,
        host_key_fingerprint=(
            str(row["host_key_fingerprint"])
            if row["host_key_fingerprint"] is not None
            else None
        ),
        distribution=(
            LinuxDistribution(str(distribution_value))
            if distribution_value is not None
            else None
        ),
        platform_version=(
            str(row["platform_version"]) if row["platform_version"] is not None else None
        ),
        architecture=(
            str(row["architecture"]) if row["architecture"] is not None else None
        ),
        state=str(row["state"]),
        created_by=cast(UUID, row["created_by"]),
        created_at=cast(datetime, row["created_at"]),
        updated_at=cast(datetime, row["updated_at"]),
    )


_SELECT = """
    SELECT asset_id, organization_id, alias, host(host) AS host, port,
           ssh_username, credential_ref, public_key, host_key,
           host_key_fingerprint, distribution, platform_version, architecture,
           state, created_by, created_at, updated_at
    FROM linux_managed_assets
"""


class SqlLinuxAssetRepository:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

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
        with Session(self._engine) as session, session.begin():
            _set_scope(session, principal)
            session.execute(
                text("INSERT INTO assets (id, organization_id) VALUES (:id, :organization_id)"),
                {"id": asset_id, "organization_id": principal.organization_id},
            )
            row = session.execute(
                text(
                    """
                    INSERT INTO linux_managed_assets (
                        asset_id, organization_id, alias, host, port, ssh_username,
                        credential_ref, public_key, state, created_by
                    ) VALUES (
                        :asset_id, :organization_id, :alias, CAST(:host AS inet), :port,
                        :ssh_username, :credential_ref, :public_key,
                        'KEY_INSTALL_PENDING', :created_by
                    )
                    RETURNING asset_id, organization_id, alias, host(host) AS host, port,
                              ssh_username, credential_ref, public_key, host_key,
                              host_key_fingerprint, distribution, platform_version,
                              architecture, state, created_by, created_at, updated_at
                    """
                ),
                {
                    "asset_id": asset_id,
                    "organization_id": principal.organization_id,
                    "alias": alias,
                    "host": host,
                    "port": port,
                    "ssh_username": ssh_username,
                    "credential_ref": credential_ref,
                    "public_key": public_key,
                    "created_by": principal.user_id,
                },
            ).mappings().one()
            self._event(
                session,
                principal,
                asset_id=asset_id,
                event_type="REGISTERED",
                detail={"state": "KEY_INSTALL_PENDING"},
            )
            return _record(row)

    def list(self, principal: AuthenticatedPrincipal) -> tuple[ManagedLinuxAsset, ...]:
        with Session(self._engine) as session, session.begin():
            _set_scope(session, principal)
            rows = session.execute(
                text(_SELECT + " ORDER BY created_at DESC"),
            ).mappings()
            return tuple(_record(row) for row in rows)

    def list_active(
        self, principal: AuthenticatedPrincipal
    ) -> tuple[ManagedLinuxAsset, ...]:
        with Session(self._engine) as session, session.begin():
            _set_scope(session, principal)
            rows = session.execute(
                text(_SELECT + " WHERE state = 'ACTIVE' ORDER BY alias, asset_id"),
            ).mappings()
            return tuple(_record(row) for row in rows)

    def get(
        self, principal: AuthenticatedPrincipal, asset_id: UUID
    ) -> ManagedLinuxAsset | None:
        with Session(self._engine) as session, session.begin():
            _set_scope(session, principal)
            row = session.execute(
                text(_SELECT + " WHERE asset_id = :asset_id"),
                {"asset_id": asset_id},
            ).mappings().one_or_none()
            return _record(row) if row is not None else None

    def activate(
        self,
        principal: AuthenticatedPrincipal,
        *,
        asset_id: UUID,
        normalized_host_key: str,
        host_key_fingerprint: str,
        verification: LinuxPlatformVerification,
    ) -> ManagedLinuxAsset:
        with Session(self._engine) as session, session.begin():
            _set_scope(session, principal)
            row = session.execute(
                text(
                    """
                    UPDATE linux_managed_assets
                    SET host_key = :host_key,
                        host_key_fingerprint = :host_key_fingerprint,
                        distribution = :distribution,
                        platform_version = :platform_version,
                        architecture = :architecture,
                        state = 'ACTIVE',
                        updated_at = now()
                    WHERE asset_id = :asset_id
                      AND state IN ('KEY_INSTALL_PENDING', 'ACTIVE')
                    RETURNING asset_id, organization_id, alias, host(host) AS host, port,
                              ssh_username, credential_ref, public_key, host_key,
                              host_key_fingerprint, distribution, platform_version,
                              architecture, state, created_by, created_at, updated_at
                    """
                ),
                {
                    "asset_id": asset_id,
                    "host_key": normalized_host_key,
                    "host_key_fingerprint": host_key_fingerprint,
                    "distribution": verification.distribution.value,
                    "platform_version": verification.version,
                    "architecture": verification.architecture,
                },
            ).mappings().one_or_none()
            if row is None:
                raise LinuxAssetContractError("활성화할 Linux 서버를 찾을 수 없습니다.")
            self._event(
                session,
                principal,
                asset_id=asset_id,
                event_type="CONNECTION_VERIFIED",
                detail={
                    "state": "ACTIVE",
                    "host_key_fingerprint": host_key_fingerprint,
                    "distribution": verification.distribution.value,
                    "platform_version": verification.version,
                    "architecture": verification.architecture,
                },
            )
            return _record(row)

    def suspend(
        self, principal: AuthenticatedPrincipal, asset_id: UUID
    ) -> ManagedLinuxAsset:
        with Session(self._engine) as session, session.begin():
            _set_scope(session, principal)
            row = session.execute(
                text(
                    """
                    UPDATE linux_managed_assets
                    SET state = 'SUSPENDED', updated_at = now()
                    WHERE asset_id = :asset_id AND state <> 'SUSPENDED'
                    RETURNING asset_id, organization_id, alias, host(host) AS host, port,
                              ssh_username, credential_ref, public_key, host_key,
                              host_key_fingerprint, distribution, platform_version,
                              architecture, state, created_by, created_at, updated_at
                    """
                ),
                {"asset_id": asset_id},
            ).mappings().one_or_none()
            if row is None:
                raise LinuxAssetContractError("중지할 Linux 서버를 찾을 수 없습니다.")
            self._event(
                session,
                principal,
                asset_id=asset_id,
                event_type="SUSPENDED",
                detail={"state": "SUSPENDED"},
            )
            return _record(row)

    @staticmethod
    def _event(
        session: Session,
        principal: AuthenticatedPrincipal,
        *,
        asset_id: UUID,
        event_type: str,
        detail: dict[str, object],
    ) -> None:
        session.execute(
            text(
                """
                INSERT INTO linux_managed_asset_events (
                    id, organization_id, asset_id, actor_user_id, event_type, detail
                ) VALUES (
                    :id, :organization_id, :asset_id, :actor_user_id, :event_type,
                    CAST(:detail AS jsonb)
                )
                """
            ),
            {
                "id": uuid4(),
                "organization_id": principal.organization_id,
                "asset_id": asset_id,
                "actor_user_id": principal.user_id,
                "event_type": event_type,
                "detail": json.dumps(detail, ensure_ascii=False),
            },
        )
