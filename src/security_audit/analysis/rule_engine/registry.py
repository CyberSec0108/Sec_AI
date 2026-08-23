"""Closed allowlist registry for deterministic Audit Pack rules."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Never, cast

from security_audit.analysis.applicability import (
    NormalizedEvidenceRecord,
    evaluate_pc07_applicability,
    pc07_applicability_parameters_are_approved,
)

from .contracts import DecisionCandidate, RuleEngineCode, RuleEngineError
from .pc07 import evaluate_pc07_ntfs, pc07_evaluation_parameters_are_approved

_PC07_APPLICABILITY = ("pc07.applicability", "0.1.0")
_PC07_EVALUATION = ("pc07.ntfs", "0.1.0")
_PC07_PROBES = frozenset(
    {"win.storage.disks", "win.storage.partitions", "win.storage.volumes"}
)


def _reject(code: RuleEngineCode, message: str) -> Never:
    raise RuleEngineError(code, message)


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(RuleEngineCode.EVALUATION_INPUT_INVALID, "Expected an object value.")
    return cast(Mapping[str, object], value)


def _string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        _reject(RuleEngineCode.EVALUATION_INPUT_INVALID, "Expected a non-empty string field.")
    return value


def _rule_reference(rule: Mapping[str, object]) -> tuple[tuple[str, str], Mapping[str, object]]:
    if set(rule) != {"rule_id", "rule_version", "parameters"}:
        _reject(RuleEngineCode.RULE_PARAMETERS_INVALID, "Rule reference fields are invalid.")
    identity = (_string(rule, "rule_id"), _string(rule, "rule_version"))
    parameters = _mapping(rule.get("parameters"))
    return identity, parameters


def _parse_evidence(
    control_id: str,
    evidence: Sequence[Mapping[str, object]],
) -> tuple[NormalizedEvidenceRecord, ...]:
    parsed: list[NormalizedEvidenceRecord] = []
    seen: set[tuple[str, str]] = set()
    context: tuple[str, str, str] | None = None

    for item in evidence:
        item_control_id = _string(item, "control_id")
        if item_control_id != control_id:
            _reject(RuleEngineCode.EVALUATION_INPUT_INVALID, "Evidence Control scope differs.")
        job_id = _string(item, "job_id")
        asset_id = _string(item, "asset_id")
        package_id = _string(item, "package_id")
        item_context = (job_id, asset_id, package_id)
        if context is None:
            context = item_context
        elif item_context != context:
            _reject(RuleEngineCode.EVALUATION_INPUT_INVALID, "Evidence package scope differs.")

        subject = _mapping(item.get("subject"))
        if _string(subject, "scope") != "VOLUME":
            _reject(RuleEngineCode.EVALUATION_INPUT_INVALID, "PC-07 requires VOLUME evidence.")
        subject_key = _string(subject, "subject_key")
        probe_id = _string(item, "probe_id")
        probe_version = _string(item, "probe_version")
        if probe_id not in _PC07_PROBES or probe_version != "0.1.0":
            _reject(RuleEngineCode.EVALUATION_INPUT_INVALID, "Evidence Probe is not allowed.")
        unique_key = (subject_key, probe_id)
        if unique_key in seen:
            _reject(RuleEngineCode.EVALUATION_INPUT_INVALID, "Duplicate subject Probe evidence.")
        seen.add(unique_key)

        collection_status = _string(item, "collection_status")
        error_code = _string(item, "error_code")
        if collection_status not in {"COLLECTED", "ERROR", "SKIPPED"}:
            _reject(RuleEngineCode.EVALUATION_INPUT_INVALID, "Collection status is invalid.")
        if (collection_status == "COLLECTED") != (error_code == "NONE"):
            _reject(RuleEngineCode.EVALUATION_INPUT_INVALID, "Collection error state is invalid.")
        normalized_value: Mapping[str, object] | None = None
        if collection_status == "COLLECTED":
            normalized_value = _mapping(item.get("normalized_value"))
            if normalized_value.get("volume_id") != subject_key:
                _reject(
                    RuleEngineCode.EVALUATION_INPUT_INVALID,
                    "Normalized volume ID differs from the subject.",
                )
        elif "normalized_value" in item:
            _reject(
                RuleEngineCode.EVALUATION_INPUT_INVALID,
                "Failed evidence cannot contain a normalized value.",
            )

        parsed.append(
            NormalizedEvidenceRecord(
                evidence_id=_string(item, "id"),
                job_id=job_id,
                asset_id=asset_id,
                package_id=package_id,
                control_id=item_control_id,
                subject_key=subject_key,
                probe_id=probe_id,
                probe_version=probe_version,
                collection_status=collection_status,
                error_code=error_code,
                normalized_value=normalized_value,
            )
        )
    if not parsed:
        _reject(RuleEngineCode.EVALUATION_INPUT_INVALID, "Evidence set is empty.")
    return tuple(
        sorted(parsed, key=lambda item: (item.subject_key, item.probe_id, item.evidence_id))
    )


class RuleRegistry:
    """Resolve only statically compiled, exact ID and version rule operators."""

    def evaluate(
        self,
        *,
        control_id: str,
        applicability_rule: Mapping[str, object],
        evaluation_rule: Mapping[str, object],
        evidence: Sequence[Mapping[str, object]],
    ) -> DecisionCandidate:
        """Evaluate the allowlisted PC-07 rules as a pure in-memory operation."""

        applicability_identity, applicability_parameters = _rule_reference(applicability_rule)
        evaluation_identity, evaluation_parameters = _rule_reference(evaluation_rule)
        if (
            control_id != "PC-07"
            or applicability_identity != _PC07_APPLICABILITY
            or evaluation_identity != _PC07_EVALUATION
        ):
            _reject(RuleEngineCode.RULE_NOT_ALLOWED, "Rule ID or version is not allowlisted.")
        if not pc07_applicability_parameters_are_approved(applicability_parameters):
            _reject(
                RuleEngineCode.RULE_PARAMETERS_INVALID,
                "Applicability parameters differ from the approved rule version.",
            )
        if not pc07_evaluation_parameters_are_approved(evaluation_parameters):
            _reject(
                RuleEngineCode.RULE_PARAMETERS_INVALID,
                "Evaluation parameters differ from the approved rule version.",
            )

        records = _parse_evidence(control_id, evidence)
        applicability = evaluate_pc07_applicability(records)
        return evaluate_pc07_ntfs(applicability, records)
