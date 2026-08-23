"""Authentication contracts shared by the API, persistence and tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class HumanRole(StrEnum):
    USER = "USER"
    SECURITY_OFFICER = "SECURITY_OFFICER"
    APPROVER = "APPROVER"
    ADMIN = "ADMIN"


class SessionPhase(StrEnum):
    PRE_AUTH = "PRE_AUTH"
    MFA_PENDING = "MFA_PENDING"
    AUTHENTICATED = "AUTHENTICATED"


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    user_id: UUID
    username: str
    display_name: str
    organization_id: UUID
    roles: frozenset[HumanRole]
    asset_ids: frozenset[UUID]
    auth_methods: frozenset[str]
    session_created_at: datetime
    reauthenticated_at: datetime

    @property
    def privileged(self) -> bool:
        return bool(
            self.roles
            & {
                HumanRole.SECURITY_OFFICER,
                HumanRole.APPROVER,
                HumanRole.ADMIN,
            }
        )


@dataclass(frozen=True, slots=True)
class SessionContext:
    token: str
    csrf_token: str
    phase: SessionPhase
    expires_at: datetime
    principal: AuthenticatedPrincipal | None = None


class AuthenticationCode(StrEnum):
    REQUIRED = "AUTHENTICATION_REQUIRED"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    MFA_REQUIRED = "MFA_REQUIRED"
    INVALID_MFA = "INVALID_MFA"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_REVOKED = "SESSION_REVOKED"
    CSRF_REJECTED = "CSRF_REJECTED"
    PROFILE_BLOCKED = "PROFILE_BLOCKED"


class AuthenticationError(ValueError):
    def __init__(self, code: AuthenticationCode, public_message: str) -> None:
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message
