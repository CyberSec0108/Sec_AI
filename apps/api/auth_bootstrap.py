"""One-shot DEV-LOCAL named account bootstrap; never prints credentials."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import create_engine, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from security_audit.common.secret_files import read_required_secret
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.models import (
    AssetRecord,
    OrganizationRecord,
    UserAccountRecord,
    UserAssetAssignmentRecord,
    UserRoleAssignmentRecord,
)
from security_audit.security.auth import (
    Argon2PasswordService,
    AuthenticationSettings,
    validate_password_policy,
)
from security_audit.security.auth.account_management import mfa_code_digest

_ORGANIZATION_ID = UUID("46000000-0000-4000-8000-000000000001")
_ASSET_ID = UUID("46000000-0000-4000-8000-000000000002")
_USER_ID = UUID("46000000-0000-4000-8000-000000000003")
_ROLE_ID = UUID("46000000-0000-4000-8000-000000000004")
_ASSIGNMENT_ID = UUID("46000000-0000-4000-8000-000000000005")
_ADMIN_ROLE_ID = UUID("46000000-0000-4000-8000-000000000006")
_SECURITY_OFFICER_ROLE_ID = UUID("46000000-0000-4000-8000-000000000007")


def main() -> int:
    settings = AuthenticationSettings.from_environment()
    if not settings.enabled or settings.profile != "DEV-LOCAL":
        raise RuntimeError("DEV account bootstrap requires the DEV-LOCAL profile.")
    username = os.getenv("SECAI_AUTH_DEV_USERNAME", "local-owner").strip().casefold()
    display_name = os.getenv("SECAI_AUTH_DEV_DISPLAY_NAME", "로컬 개발 사용자")
    password = read_required_secret(
        os.getenv(
            "SECAI_AUTH_DEV_PASSWORD_FILE",
            "/run/secrets/auth_dev_password",
        )
    )
    session_index_key = read_required_secret(settings.session_index_key_file).encode()
    dev_mfa_code = read_required_secret(settings.dev_mfa_code_file)
    policy = validate_password_policy(password, username)
    if not policy.accepted:
        raise RuntimeError("Generated DEV password does not meet the approved policy.")

    engine = create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )
    now = datetime.now(UTC)
    with Session(engine) as session, session.begin():
        existing = session.scalar(
            select(UserAccountRecord).where(
                UserAccountRecord.username_canonical == username
            )
        )
        if existing is not None:
            admin_assignment = session.scalar(
                select(UserRoleAssignmentRecord).where(
                    UserRoleAssignmentRecord.user_id == existing.id,
                    UserRoleAssignmentRecord.organization_id == existing.organization_id,
                    UserRoleAssignmentRecord.role_name == "ADMIN",
                )
            )
            if admin_assignment is None:
                session.add(
                    UserRoleAssignmentRecord(
                        id=_ADMIN_ROLE_ID,
                        user_id=existing.id,
                        organization_id=existing.organization_id,
                        role_name="ADMIN",
                        granted_at=now,
                        revoked_at=None,
                    )
                )
                existing.role_assignment_version += 1
            elif admin_assignment.revoked_at is not None:
                admin_assignment.revoked_at = None
                admin_assignment.granted_at = now
                existing.role_assignment_version += 1
            security_officer_assignment = session.scalar(
                select(UserRoleAssignmentRecord).where(
                    UserRoleAssignmentRecord.user_id == existing.id,
                    UserRoleAssignmentRecord.organization_id == existing.organization_id,
                    UserRoleAssignmentRecord.role_name == "SECURITY_OFFICER",
                )
            )
            if security_officer_assignment is None:
                session.add(
                    UserRoleAssignmentRecord(
                        id=_SECURITY_OFFICER_ROLE_ID,
                        user_id=existing.id,
                        organization_id=existing.organization_id,
                        role_name="SECURITY_OFFICER",
                        granted_at=now,
                        revoked_at=None,
                    )
                )
                existing.role_assignment_version += 1
            elif security_officer_assignment.revoked_at is not None:
                security_officer_assignment.revoked_at = None
                security_officer_assignment.granted_at = now
                existing.role_assignment_version += 1
            if existing.mfa_code_hash is None:
                existing.mfa_code_hash = mfa_code_digest(
                    session_index_key,
                    existing.id,
                    dev_mfa_code,
                )
                existing.mfa_issued_at = now
                existing.mfa_expires_at = now + timedelta(days=30)
                existing.credential_version += 1
            print(
                "DEV-LOCAL administrator and security-officer account is ready; "
                "credentials were not changed."
            )
            return 0
        session.execute(
            insert(OrganizationRecord)
            .values(id=_ORGANIZATION_ID)
            .on_conflict_do_nothing()
        )
        session.execute(
            insert(AssetRecord)
            .values(id=_ASSET_ID, organization_id=_ORGANIZATION_ID)
            .on_conflict_do_nothing()
        )
        session.add(
            UserAccountRecord(
                id=_USER_ID,
                organization_id=_ORGANIZATION_ID,
                username_canonical=username,
                display_name=display_name,
                status="ACTIVE",
                password_hash=Argon2PasswordService().hash(password),
                credential_version=1,
                role_assignment_version=1,
                password_changed_at=now,
                failed_attempts=0,
                locked_until=None,
                mfa_code_hash=mfa_code_digest(
                    session_index_key,
                    _USER_ID,
                    dev_mfa_code,
                ),
                mfa_issued_at=now,
                mfa_expires_at=now + timedelta(days=30),
            )
        )
        session.add(
            UserRoleAssignmentRecord(
                id=_ROLE_ID,
                user_id=_USER_ID,
                organization_id=_ORGANIZATION_ID,
                role_name="USER",
                granted_at=now,
                revoked_at=None,
            )
        )
        session.add(
            UserRoleAssignmentRecord(
                id=_ADMIN_ROLE_ID,
                user_id=_USER_ID,
                organization_id=_ORGANIZATION_ID,
                role_name="ADMIN",
                granted_at=now,
                revoked_at=None,
            )
        )
        session.add(
            UserRoleAssignmentRecord(
                id=_SECURITY_OFFICER_ROLE_ID,
                user_id=_USER_ID,
                organization_id=_ORGANIZATION_ID,
                role_name="SECURITY_OFFICER",
                granted_at=now,
                revoked_at=None,
            )
        )
        session.add(
            UserAssetAssignmentRecord(
                id=_ASSIGNMENT_ID,
                user_id=_USER_ID,
                organization_id=_ORGANIZATION_ID,
                asset_id=_ASSET_ID,
                assigned_at=now,
                revoked_at=None,
            )
        )
    print(
        "DEV-LOCAL administrator and security-officer account with one synthetic "
        "asset assignment was created."
    )
    print("No username, password, MFA code or session secret was printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
