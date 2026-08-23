"""Immutable contracts for deterministic Control applicability evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class ApplicabilityStatus(StrEnum):
    """Machine-readable applicability states used before Finding creation."""

    APPLICABLE = "APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNDETERMINED = "UNDETERMINED"


@dataclass(frozen=True, slots=True, order=True)
class ExcludedSubject:
    """A subject excluded by an approved applicability rule and reason."""

    subject_id: str
    reason_code: str


@dataclass(frozen=True, slots=True)
class NormalizedEvidenceRecord:
    """Minimal normalized evidence view accepted by pure applicability rules."""

    evidence_id: str
    job_id: str
    asset_id: str
    package_id: str
    control_id: str
    subject_key: str
    probe_id: str
    probe_version: str
    collection_status: str
    error_code: str
    normalized_value: Mapping[str, object] | None


@dataclass(frozen=True, slots=True)
class ApplicabilityDecision:
    """Immutable result of selecting evaluated and excluded PC-07 subjects."""

    status: ApplicabilityStatus
    reason_code: str
    candidate_volume_ids: tuple[str, ...]
    excluded_volumes: tuple[ExcludedSubject, ...]
    error_codes: tuple[str, ...] = ()

