"""Immutable contracts and stable failures for Finding construction."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from re import fullmatch
from uuid import UUID


class FindingBuildCode(StrEnum):
    """Stable fail-closed codes that never become Control result codes."""

    PACK_SCHEMA_INVALID = "PACK_SCHEMA_INVALID"
    PACK_NOT_APPROVED = "PACK_NOT_APPROVED"
    PACK_HASH_MISMATCH = "PACK_HASH_MISMATCH"
    EVIDENCE_SCHEMA_INVALID = "EVIDENCE_SCHEMA_INVALID"
    EVALUATION_SCOPE_MISMATCH = "EVALUATION_SCOPE_MISMATCH"
    FINDING_SCHEMA_INVALID = "FINDING_SCHEMA_INVALID"


class FindingBuildError(ValueError):
    """Reject invalid lineage or a malformed Finding before persistence."""

    def __init__(self, code: FindingBuildCode, message: str) -> None:
        super().__init__(message)
        self.code = code


def _require_utc_timestamp(value: str, field_name: str) -> None:
    if not value.endswith("Z"):
        raise ValueError(f"{field_name} must be an RFC 3339 UTC timestamp.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an RFC 3339 UTC timestamp.") from exc
    offset = parsed.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError(f"{field_name} must be an RFC 3339 UTC timestamp.")


@dataclass(frozen=True, slots=True)
class FindingBuildContext:
    """Explicit deterministic and execution metadata required by the builder."""

    organization_id: str
    evaluation_as_of: str
    evaluated_at: str
    engine_version: str
    engine_artifact_sha256: str

    def __post_init__(self) -> None:
        try:
            UUID(self.organization_id)
        except ValueError as exc:
            raise ValueError("organization_id must be a UUID.") from exc
        _require_utc_timestamp(self.evaluation_as_of, "evaluation_as_of")
        _require_utc_timestamp(self.evaluated_at, "evaluated_at")
        semver_pattern = (
            r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
            r"(?:[-+][0-9A-Za-z.-]+)?"
        )
        if fullmatch(semver_pattern, self.engine_version) is None:
            raise ValueError("engine_version must be semantic versioning text.")
        if fullmatch(r"[a-f0-9]{64}", self.engine_artifact_sha256) is None:
            raise ValueError("engine_artifact_sha256 must be lowercase SHA-256 hex.")
