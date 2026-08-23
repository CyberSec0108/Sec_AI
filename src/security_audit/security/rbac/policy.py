"""Central deny-by-default RBAC and organization/asset scope policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from security_audit.security.auth.contracts import (
    AuthenticatedPrincipal,
    HumanRole,
)


class Permission(StrEnum):
    PRODUCT_READ = "product.read"
    ASSET_READ = "asset.read"
    SWITCH_AUDIT_EXECUTE = "switch.audit.readonly.execute"
    EVIDENCE_DOWNLOAD = "evidence.original.download"
    SECURITY_EVENT_READ = "audit_event.security.read"
    PLATFORM_ADMIN = "system.config.read"
    SESSION_SELF_REVOKE = "session.self.revoke"


class AuthorizationOutcome(StrEnum):
    ALLOW = "ALLOW"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    outcome: AuthorizationOutcome
    permission: Permission
    reason_code: str

    @property
    def allowed(self) -> bool:
        return self.outcome is AuthorizationOutcome.ALLOW


_ROLE_PERMISSIONS = {
    HumanRole.USER: frozenset(
        {
            Permission.PRODUCT_READ,
            Permission.ASSET_READ,
            Permission.SWITCH_AUDIT_EXECUTE,
            Permission.SESSION_SELF_REVOKE,
        }
    ),
    HumanRole.SECURITY_OFFICER: frozenset(
        {
            Permission.PRODUCT_READ,
            Permission.ASSET_READ,
            Permission.SWITCH_AUDIT_EXECUTE,
            Permission.EVIDENCE_DOWNLOAD,
            Permission.SECURITY_EVENT_READ,
            Permission.SESSION_SELF_REVOKE,
        }
    ),
    HumanRole.APPROVER: frozenset(
        {
            Permission.PRODUCT_READ,
            Permission.SESSION_SELF_REVOKE,
        }
    ),
    HumanRole.ADMIN: frozenset(
        {
            Permission.PRODUCT_READ,
            Permission.PLATFORM_ADMIN,
            Permission.SWITCH_AUDIT_EXECUTE,
            Permission.SESSION_SELF_REVOKE,
        }
    ),
}


def authorize(
    principal: AuthenticatedPrincipal,
    permission: Permission,
    organization_id: UUID | None = None,
    asset_id: UUID | None = None,
) -> AuthorizationDecision:
    if organization_id is not None and organization_id != principal.organization_id:
        return AuthorizationDecision(
            AuthorizationOutcome.NOT_FOUND,
            permission,
            "ORGANIZATION_SCOPE_MISMATCH",
        )

    granted = any(
        permission in _ROLE_PERMISSIONS.get(role, frozenset())
        for role in principal.roles
    )
    if not granted:
        return AuthorizationDecision(
            AuthorizationOutcome.FORBIDDEN,
            permission,
            "PERMISSION_NOT_GRANTED",
        )

    if asset_id is not None:
        organization_wide = HumanRole.SECURITY_OFFICER in principal.roles
        if not organization_wide and asset_id not in principal.asset_ids:
            return AuthorizationDecision(
                AuthorizationOutcome.NOT_FOUND,
                permission,
                "ASSET_SCOPE_MISMATCH",
            )

    return AuthorizationDecision(
        AuthorizationOutcome.ALLOW,
        permission,
        "POLICY_ALLOWED",
    )
