"""Contracts for deterministic evidence normalization."""

from __future__ import annotations

from enum import StrEnum


class NormalizationCode(StrEnum):
    """Stable machine-readable rejection codes for the pure normalizer."""

    UNVALIDATED_PACKAGE = "UNVALIDATED_PACKAGE"
    DESCRIPTOR_BINDING_MISMATCH = "DESCRIPTOR_BINDING_MISMATCH"
    NORMALIZER_NOT_ALLOWED = "NORMALIZER_NOT_ALLOWED"
    NORMALIZATION_INPUT_INVALID = "NORMALIZATION_INPUT_INVALID"
    NORMALIZED_EVIDENCE_SCHEMA_INVALID = "NORMALIZED_EVIDENCE_SCHEMA_INVALID"


class NormalizationError(ValueError):
    """Fail-closed normalization error that never becomes a Control Finding."""

    def __init__(self, code: NormalizationCode, message: str) -> None:
        super().__init__(message)
        self.code = code
