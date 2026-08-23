"""Approved deterministic PC-07 NTFS decision operator."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from security_audit.analysis.applicability import (
    ApplicabilityDecision,
    ApplicabilityStatus,
    NormalizedEvidenceRecord,
)

from .contracts import DecisionCandidate, DecisionStatus

_APPROVED_PARAMETERS: dict[str, object] = {
    "required_filesystem": "NTFS",
    "comparison_profile": "TRIM_CASE_INSENSITIVE_EXACT",
    "non_ntfs_status": "FAIL",
    "refs_status": "FAIL",
    "raw_status": "FAIL",
    "filesystem_unknown_status": "ERROR",
    "bitlocker_unknown_status": "ERROR",
    "aggregate_subject_scope": "VOLUME",
    "aggregate_subject_key": "pc07:evaluated-volume-set",
    "all_match_result_code": "ALL_EVALUATED_VOLUMES_NTFS",
    "non_match_result_code": "NON_NTFS_VOLUME_FOUND",
}


def pc07_evaluation_parameters_are_approved(parameters: Mapping[str, object]) -> bool:
    """Return whether parameters exactly match the approved operator version."""

    return set(parameters) == set(_APPROVED_PARAMETERS) and all(
        parameters[key] == value and type(parameters[key]) is type(value)
        for key, value in _APPROVED_PARAMETERS.items()
    )


def _records_by_subject(
    records: Sequence[NormalizedEvidenceRecord],
) -> dict[str, dict[str, NormalizedEvidenceRecord]]:
    grouped: dict[str, dict[str, NormalizedEvidenceRecord]] = {}
    for record in records:
        grouped.setdefault(record.subject_key, {})[record.probe_id] = record
    return grouped


def _error_decision(
    applicability: ApplicabilityDecision,
    result_code: str,
    error_codes: tuple[str, ...],
) -> DecisionCandidate:
    return DecisionCandidate(
        status=DecisionStatus.ERROR,
        applicability=applicability,
        subject_scope="VOLUME",
        subject_key="pc07:evaluated-volume-set",
        result_code=result_code,
        evaluated_volume_ids=(),
        violating_volume_ids=(),
        error_codes=error_codes,
        rationale_code=result_code,
    )


def evaluate_pc07_ntfs(
    applicability: ApplicabilityDecision,
    records: Sequence[NormalizedEvidenceRecord],
) -> DecisionCandidate:
    """Evaluate approved PC-07 candidate volumes without creating a Finding."""

    if applicability.status is ApplicabilityStatus.UNDETERMINED:
        result_code = applicability.reason_code
        if result_code == "VOLUME_EVIDENCE_INCOMPLETE":
            result_code = "VOLUME_COLLECTION_FAILED"
        return _error_decision(applicability, result_code, applicability.error_codes)

    grouped = _records_by_subject(records)
    filesystems: dict[str, str] = {}
    for subject_id in applicability.candidate_volume_ids:
        volume = grouped.get(subject_id, {}).get("win.storage.volumes")
        if (
            volume is None
            or volume.collection_status != "COLLECTED"
            or volume.normalized_value is None
        ):
            return _error_decision(
                applicability,
                "VOLUME_FILESYSTEM_UNAVAILABLE",
                ("EVIDENCE_INCOMPLETE",),
            )
        filesystem = volume.normalized_value.get("filesystem")
        bitlocker_state = volume.normalized_value.get("bitlocker_state")
        if not isinstance(filesystem, str) or bitlocker_state in {"LOCKED", "UNKNOWN"}:
            return _error_decision(
                applicability,
                "VOLUME_FILESYSTEM_UNAVAILABLE",
                ("EVIDENCE_INCOMPLETE",),
            )
        filesystems[subject_id] = filesystem

    evaluated = tuple(sorted(filesystems))
    violating = tuple(
        subject_id
        for subject_id in evaluated
        if filesystems[subject_id].strip().casefold() != "ntfs"
    )
    if not violating:
        return DecisionCandidate(
            status=DecisionStatus.COMPLIANT,
            applicability=applicability,
            subject_scope="VOLUME",
            subject_key="pc07:evaluated-volume-set",
            result_code="ALL_EVALUATED_VOLUMES_NTFS",
            evaluated_volume_ids=evaluated,
            violating_volume_ids=(),
            error_codes=(),
            rationale_code="ALL_EVALUATED_VOLUMES_NTFS",
        )

    violating_filesystems = {filesystems[subject_id].strip().casefold() for subject_id in violating}
    if violating_filesystems == {"refs"}:
        result_code = "NON_NTFS_REFS_FOUND"
        rationale_code = "REFS_KISA_NTFS_CONDITION_MISMATCH"
    elif violating_filesystems == {"raw"}:
        result_code = "NON_NTFS_RAW_VOLUME_FOUND"
        rationale_code = result_code
    else:
        result_code = "NON_NTFS_VOLUME_FOUND"
        rationale_code = result_code
    return DecisionCandidate(
        status=DecisionStatus.NONCOMPLIANT,
        applicability=applicability,
        subject_scope="VOLUME",
        subject_key="pc07:evaluated-volume-set",
        result_code=result_code,
        evaluated_volume_ids=evaluated,
        violating_volume_ids=violating,
        error_codes=(),
        rationale_code=rationale_code,
    )
