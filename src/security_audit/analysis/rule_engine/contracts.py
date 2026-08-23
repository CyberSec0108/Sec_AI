"""Immutable contracts and stable errors for the pure rule engine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from security_audit.analysis.applicability import ApplicabilityDecision


class RuleEngineCode(StrEnum):
    """Stable fail-closed codes that do not become Control Findings."""

    RULE_NOT_ALLOWED = "RULE_NOT_ALLOWED"
    RULE_PARAMETERS_INVALID = "RULE_PARAMETERS_INVALID"
    EVALUATION_INPUT_INVALID = "EVALUATION_INPUT_INVALID"


class RuleEngineError(ValueError):
    """Reject an untrusted rule reference or malformed evaluation input."""

    def __init__(self, code: RuleEngineCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class DecisionStatus(StrEnum):
    """Decision states produced before IMP-016 Finding construction."""

    COMPLIANT = "PASS"
    NONCOMPLIANT = "FAIL"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class DecisionCandidate:
    """Immutable PC-07 decision projection; this is not an official Finding."""

    status: DecisionStatus
    applicability: ApplicabilityDecision
    subject_scope: str
    subject_key: str
    result_code: str
    evaluated_volume_ids: tuple[str, ...]
    violating_volume_ids: tuple[str, ...]
    error_codes: tuple[str, ...]
    rationale_code: str
