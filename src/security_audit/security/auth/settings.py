"""Fail-closed authentication settings."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class AuthenticationSettings:
    enabled: bool
    profile: str
    canonical_origin: str
    cookie_name: str
    secure_cookie: bool
    session_index_key_file: str
    dev_mfa_code_file: str
    idle_timeout_minutes: int = 30
    privileged_idle_timeout_minutes: int = 15
    absolute_timeout_hours: int = 8
    pre_auth_timeout_minutes: int = 5

    @classmethod
    def from_environment(cls) -> AuthenticationSettings:
        enabled = os.getenv("SECAI_AUTH_ENABLED", "false").casefold() == "true"
        profile = os.getenv("SECAI_AUTH_PROFILE", "DISABLED")
        origin = os.getenv("SECAI_AUTH_CANONICAL_ORIGIN", "http://localhost:18480")
        parsed = urlsplit(origin)
        if enabled:
            if profile != "DEV-LOCAL":
                raise RuntimeError(
                    "Only the DEV-LOCAL authentication profile is implemented; "
                    "Pilot and production stay fail-closed."
                )
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise RuntimeError("SECAI_AUTH_CANONICAL_ORIGIN must be an exact origin.")
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise RuntimeError("Canonical origin cannot contain a path, query or fragment.")
        secure_cookie = parsed.scheme == "https"
        return cls(
            enabled=enabled,
            profile=profile,
            canonical_origin=origin.rstrip("/"),
            cookie_name=(
                "__Host-secai_session" if secure_cookie else "secai_dev_session"
            ),
            secure_cookie=secure_cookie,
            session_index_key_file=os.getenv(
                "SECAI_AUTH_SESSION_INDEX_KEY_FILE",
                "/run/secrets/auth_session_index_key",
            ),
            dev_mfa_code_file=os.getenv(
                "SECAI_AUTH_DEV_MFA_CODE_FILE",
                "/run/secrets/auth_dev_mfa_code",
            ),
        )
