"""Pure replay resolution contract for append-only Finding persistence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch
from typing import Any, NoReturn, cast
from uuid import UUID

from security_audit.common.canonical_json import JsonValue

from .builder import canonical_finding_output_sha256, deterministic_finding_id


class FindingReplayAction(StrEnum):
    """Repository action permitted by the pure idempotency decision."""

    CREATE = "CREATE"
    RETURN_EXISTING = "RETURN_EXISTING"


class FindingReplayCode(StrEnum):
    """Stable replay failures that must block an append or overwrite."""

    FINDING_INVALID = "FINDING_INVALID"
    OUTPUT_HASH_MISMATCH = "OUTPUT_HASH_MISMATCH"
    FINDING_ID_MISMATCH = "FINDING_ID_MISMATCH"
    IDEMPOTENCY_SCOPE_MISMATCH = "IDEMPOTENCY_SCOPE_MISMATCH"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"


class FindingReplayError(ValueError):
    """Reject malformed, conflicting or incorrectly scoped replay input."""

    def __init__(self, code: FindingReplayCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class FindingFingerprint:
    """Immutable identity used by a repository unique-key implementation."""

    idempotency_key: str
    finding_id: str
    output_sha256: str


@dataclass(frozen=True, slots=True)
class FindingReplayResolution:
    """Pure instruction to create once or return the existing Finding."""

    action: FindingReplayAction
    fingerprint: FindingFingerprint


def _reject(code: FindingReplayCode, message: str) -> NoReturn:
    raise FindingReplayError(code, message)


def _string(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        _reject(FindingReplayCode.FINDING_INVALID, f"Finding field is invalid: {key}.")
    return value


def _sha256(mapping: Mapping[str, Any], key: str) -> str:
    value = _string(mapping, key)
    if fullmatch(r"[a-f0-9]{64}", value) is None:
        _reject(FindingReplayCode.FINDING_INVALID, f"Finding hash is invalid: {key}.")
    return value


def finding_fingerprint(finding: Mapping[str, JsonValue]) -> FindingFingerprint:
    """Validate self-contained Finding identity and return its replay fingerprint."""

    finding_id = _string(finding, "id")
    try:
        UUID(finding_id)
    except ValueError as exc:
        raise FindingReplayError(
            FindingReplayCode.FINDING_INVALID,
            "Finding ID is not a UUID.",
        ) from exc

    rule_result_value = finding.get("rule_result")
    if not isinstance(rule_result_value, dict):
        _reject(FindingReplayCode.FINDING_INVALID, "Finding rule_result is invalid.")
    rule_result = cast(dict[str, Any], rule_result_value)
    input_sha256 = _sha256(rule_result, "input_sha256")
    output_sha256 = _sha256(rule_result, "output_sha256")
    if canonical_finding_output_sha256(finding) != output_sha256:
        _reject(
            FindingReplayCode.OUTPUT_HASH_MISMATCH,
            "Finding output hash does not match its canonical decision payload.",
        )
    if deterministic_finding_id(input_sha256, output_sha256) != finding_id:
        _reject(
            FindingReplayCode.FINDING_ID_MISMATCH,
            "Finding ID is not bound to its canonical input and output hashes.",
        )
    return FindingFingerprint(
        idempotency_key=input_sha256,
        finding_id=finding_id,
        output_sha256=output_sha256,
    )


def resolve_finding_replay(
    *,
    existing: Mapping[str, JsonValue] | None,
    candidate: Mapping[str, JsonValue],
) -> FindingReplayResolution:
    """Resolve one repository key without mutating or overwriting a Finding.

    ``rule_result.input_sha256`` is the logical idempotency key.  A repository
    must enforce it with an atomic unique constraint.  This pure function
    decides whether to create once, return the existing identity, or fail.
    """

    candidate_fingerprint = finding_fingerprint(candidate)
    if existing is None:
        return FindingReplayResolution(
            action=FindingReplayAction.CREATE,
            fingerprint=candidate_fingerprint,
        )

    existing_fingerprint = finding_fingerprint(existing)
    if existing_fingerprint.idempotency_key != candidate_fingerprint.idempotency_key:
        _reject(
            FindingReplayCode.IDEMPOTENCY_SCOPE_MISMATCH,
            "Existing Finding was loaded for a different idempotency key.",
        )
    if existing_fingerprint != candidate_fingerprint:
        _reject(
            FindingReplayCode.IDEMPOTENCY_CONFLICT,
            "The same canonical input produced a different Finding identity or output.",
        )
    return FindingReplayResolution(
        action=FindingReplayAction.RETURN_EXISTING,
        fingerprint=existing_fingerprint,
    )
