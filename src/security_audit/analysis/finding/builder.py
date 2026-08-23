"""Schema-valid Finding construction and approved canonical hash profiles."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any, NoReturn, cast
from uuid import UUID, uuid5

from security_audit.analysis.package_validation import (
    PackageSchemaCatalog,
    PackageValidationCode,
    PackageValidationError,
)
from security_audit.analysis.rule_engine import DecisionCandidate
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256,
    canonical_sha256_without_fields,
)

from .contracts import FindingBuildCode, FindingBuildContext, FindingBuildError

_FINDING_NAMESPACE = UUID("9df956a5-ec7c-4b02-9570-33be0f59348b")
_OUTPUT_EXCLUDED_FIELDS = frozenset({"id", "created_at", "correlation_id", "evaluated_at"})


def _reject(code: FindingBuildCode, message: str) -> NoReturn:
    raise FindingBuildError(code, message)


def _object(value: object, *, code: FindingBuildCode) -> dict[str, Any]:
    if not isinstance(value, dict):
        _reject(code, "Expected a JSON object.")
    return cast(dict[str, Any], value)


def _string(mapping: Mapping[str, object], key: str, *, code: FindingBuildCode) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        _reject(code, f"Expected non-empty string field: {key}.")
    return value


def canonical_finding_output_sha256(finding: Mapping[str, JsonValue]) -> str:
    """Hash the decision while excluding execution metadata and the hash itself."""

    payload = copy.deepcopy(dict(finding))
    for field in _OUTPUT_EXCLUDED_FIELDS:
        payload.pop(field, None)
    rule_result = payload.get("rule_result")
    if not isinstance(rule_result, dict):
        _reject(FindingBuildCode.FINDING_SCHEMA_INVALID, "Finding rule_result is invalid.")
    rule_result.pop("output_sha256", None)
    return canonical_sha256(cast(JsonValue, payload))


def deterministic_finding_id(input_sha256: str, output_sha256: str) -> str:
    """Return the stable Finding UUID bound to canonical input and output hashes."""

    return str(uuid5(_FINDING_NAMESPACE, f"{input_sha256}:{output_sha256}"))


class FindingBuilder:
    """Build deterministic Finding JSON from validated evidence and a decision."""

    def __init__(self, schema_catalog: PackageSchemaCatalog) -> None:
        self._schemas = schema_catalog

    def _validate_schema(
        self,
        document: JsonValue,
        schema_filename: str,
        build_code: FindingBuildCode,
    ) -> None:
        try:
            self._schemas.validate(
                document,
                schema_filename,
                PackageValidationCode.DESCRIPTOR_SCHEMA_INVALID,
            )
        except PackageValidationError as exc:
            raise FindingBuildError(
                build_code,
                "Document failed its approved JSON Schema.",
            ) from exc

    def _pack_control(
        self,
        pack: Mapping[str, object],
        control_id: str,
        *,
        allow_draft: bool,
    ) -> dict[str, Any]:
        pack_document = cast(dict[str, JsonValue], copy.deepcopy(dict(pack)))
        self._validate_schema(
            pack_document,
            "audit_pack.schema.json",
            FindingBuildCode.PACK_SCHEMA_INVALID,
        )
        approval = _object(pack.get("approval"), code=FindingBuildCode.PACK_SCHEMA_INVALID)
        approval_status = _string(
            approval,
            "status",
            code=FindingBuildCode.PACK_SCHEMA_INVALID,
        )
        if approval_status != "APPROVED" and not (
            approval_status == "DRAFT" and allow_draft
        ):
            _reject(
                FindingBuildCode.PACK_NOT_APPROVED,
                "Only an approved Pack may create an official Finding.",
            )

        declared_hash = _string(
            pack,
            "content_sha256",
            code=FindingBuildCode.PACK_SCHEMA_INVALID,
        )
        actual_hash = canonical_sha256_without_fields(
            pack_document,
            {"content_sha256", "approval"},
        )
        if declared_hash != actual_hash:
            _reject(FindingBuildCode.PACK_HASH_MISMATCH, "Audit Pack content hash does not match.")

        controls = pack.get("controls")
        if not isinstance(controls, list):
            _reject(FindingBuildCode.PACK_SCHEMA_INVALID, "Pack controls are invalid.")
        matches = [
            _object(item, code=FindingBuildCode.PACK_SCHEMA_INVALID)
            for item in controls
            if isinstance(item, dict) and item.get("control_id") == control_id
        ]
        if len(matches) != 1:
            _reject(FindingBuildCode.PACK_SCHEMA_INVALID, "Control is not unique in the Pack.")
        return matches[0]

    def _validated_evidence(
        self,
        evidence: Sequence[Mapping[str, object]],
        control_id: str,
    ) -> tuple[list[dict[str, JsonValue]], str, str, str]:
        documents: list[dict[str, JsonValue]] = []
        for item in evidence:
            document = cast(dict[str, JsonValue], copy.deepcopy(dict(item)))
            self._validate_schema(
                document,
                "normalized_evidence.schema.json",
                FindingBuildCode.EVIDENCE_SCHEMA_INVALID,
            )
            documents.append(document)
        if not documents:
            _reject(FindingBuildCode.EVALUATION_SCOPE_MISMATCH, "Evidence set is empty.")

        job_ids = {
            _string(item, "job_id", code=FindingBuildCode.EVIDENCE_SCHEMA_INVALID)
            for item in documents
        }
        asset_ids = {
            _string(item, "asset_id", code=FindingBuildCode.EVIDENCE_SCHEMA_INVALID)
            for item in documents
        }
        control_ids = {
            _string(item, "control_id", code=FindingBuildCode.EVIDENCE_SCHEMA_INVALID)
            for item in documents
        }
        correlation_ids = {
            _string(item, "correlation_id", code=FindingBuildCode.EVIDENCE_SCHEMA_INVALID)
            for item in documents
        }
        evidence_ids = [
            _string(item, "id", code=FindingBuildCode.EVIDENCE_SCHEMA_INVALID)
            for item in documents
        ]
        if (
            len(job_ids) != 1
            or len(asset_ids) != 1
            or control_ids != {control_id}
            or len(correlation_ids) != 1
            or len(evidence_ids) != len(set(evidence_ids))
        ):
            _reject(
                FindingBuildCode.EVALUATION_SCOPE_MISMATCH,
                "Evidence does not belong to one job, asset, correlation and Control.",
            )
        documents.sort(
            key=lambda item: _string(
                item,
                "id",
                code=FindingBuildCode.EVIDENCE_SCHEMA_INVALID,
            )
        )
        return documents, next(iter(job_ids)), next(iter(asset_ids)), next(iter(correlation_ids))

    def build(
        self,
        *,
        pack: Mapping[str, object],
        control_id: str,
        evidence: Sequence[Mapping[str, object]],
        decision: DecisionCandidate,
        context: FindingBuildContext,
        allow_draft: bool = False,
    ) -> dict[str, JsonValue]:
        """Create a Finding, with explicit opt-in required for a DRAFT Pack."""

        control = self._pack_control(pack, control_id, allow_draft=allow_draft)
        documents, job_id, asset_id, correlation_id = self._validated_evidence(
            evidence,
            control_id,
        )
        evaluation_rule = _object(
            control.get("evaluation_rule"),
            code=FindingBuildCode.PACK_SCHEMA_INVALID,
        )
        evaluation_parameters = _object(
            evaluation_rule.get("parameters"),
            code=FindingBuildCode.PACK_SCHEMA_INVALID,
        )
        required_filesystem = _string(
            evaluation_parameters,
            "required_filesystem",
            code=FindingBuildCode.PACK_SCHEMA_INVALID,
        )

        volume_filesystems: dict[str, str] = {}
        for item in documents:
            if item.get("probe_id") != "win.storage.volumes":
                continue
            subject = _object(
                item.get("subject"),
                code=FindingBuildCode.EVIDENCE_SCHEMA_INVALID,
            )
            subject_key = _string(
                subject,
                "subject_key",
                code=FindingBuildCode.EVIDENCE_SCHEMA_INVALID,
            )
            normalized_value = item.get("normalized_value")
            if isinstance(normalized_value, dict):
                filesystem = normalized_value.get("filesystem")
                if isinstance(filesystem, str):
                    volume_filesystems[subject_key] = filesystem
        actual: dict[str, JsonValue] = {}
        for subject_key in sorted(decision.evaluated_volume_ids):
            filesystem = volume_filesystems.get(subject_key)
            if filesystem is None:
                _reject(
                    FindingBuildCode.EVALUATION_SCOPE_MISMATCH,
                    "An evaluated volume has no normalized filesystem value.",
                )
            actual[subject_key] = filesystem

        return self._assemble(
            pack=pack,
            control_id=control_id,
            control=control,
            documents=documents,
            job_id=job_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            context=context,
            subject={
                "scope": decision.subject_scope,
                "subject_key": decision.subject_key,
            },
            status=str(decision.status),
            applicability_status=str(decision.applicability.status),
            applicability_reason_code=decision.applicability.reason_code,
            actual=actual,
            expected=required_filesystem,
            result_code=decision.result_code,
            rationale_code=decision.rationale_code,
            error_codes=decision.error_codes,
        )

    def build_common(
        self,
        *,
        pack: Mapping[str, object],
        control_id: str,
        evidence: Sequence[Mapping[str, object]],
        decision: Mapping[str, object],
        context: FindingBuildContext,
        allow_draft: bool = False,
    ) -> dict[str, JsonValue]:
        """Build a non-PC-07 Finding from the common deterministic decision shape."""

        control = self._pack_control(pack, control_id, allow_draft=allow_draft)
        documents, job_id, asset_id, correlation_id = self._validated_evidence(
            evidence,
            control_id,
        )
        subjects = [
            _object(item.get("subject"), code=FindingBuildCode.EVIDENCE_SCHEMA_INVALID)
            for item in documents
        ]
        if any(subject != subjects[0] for subject in subjects[1:]):
            _reject(
                FindingBuildCode.EVALUATION_SCOPE_MISMATCH,
                "Common Finding evidence has more than one subject.",
            )
        status = _string(
            decision,
            "status",
            code=FindingBuildCode.EVALUATION_SCOPE_MISMATCH,
        )
        if status not in {"PASS", "FAIL", "ERROR", "REVIEW", "N/A"}:
            _reject(
                FindingBuildCode.EVALUATION_SCOPE_MISMATCH,
                "Decision status is not supported.",
            )
        error_codes_value = decision.get("error_codes")
        if not isinstance(error_codes_value, Sequence) or isinstance(
            error_codes_value,
            (str, bytes, bytearray),
        ):
            _reject(
                FindingBuildCode.EVALUATION_SCOPE_MISMATCH,
                "Decision error codes are invalid.",
            )
        error_codes = tuple(
            item
            for item in error_codes_value
            if isinstance(item, str) and item
        )
        if len(error_codes) != len(error_codes_value):
            _reject(
                FindingBuildCode.EVALUATION_SCOPE_MISMATCH,
                "Decision error codes are invalid.",
            )
        collection_failed = any(
            item.get("collection_status") != "COLLECTED" for item in documents
        )
        applicability_status = (
            "NOT_APPLICABLE"
            if status == "N/A"
            else "UNDETERMINED" if status == "ERROR" and collection_failed else "APPLICABLE"
        )
        return self._assemble(
            pack=pack,
            control_id=control_id,
            control=control,
            documents=documents,
            job_id=job_id,
            asset_id=asset_id,
            correlation_id=correlation_id,
            context=context,
            subject=cast(dict[str, JsonValue], copy.deepcopy(subjects[0])),
            status=status,
            applicability_status=applicability_status,
            applicability_reason_code=(
                "COLLECTION_UNDETERMINED"
                if applicability_status == "UNDETERMINED"
                else "CONTROL_NOT_APPLICABLE"
                if applicability_status == "NOT_APPLICABLE"
                else "CONTROL_APPLICABLE"
            ),
            actual=cast(
                JsonValue,
                copy.deepcopy(
                    decision.get("actual")
                    if decision.get("actual") is not None
                    else "확인하지 못함"
                ),
            ),
            expected=cast(
                JsonValue,
                copy.deepcopy(
                    decision.get("expected")
                    if decision.get("expected") is not None
                    else "승인된 점검 기준"
                ),
            ),
            result_code=_string(
                decision,
                "result_code",
                code=FindingBuildCode.EVALUATION_SCOPE_MISMATCH,
            ),
            rationale_code=_string(
                decision,
                "rationale_code",
                code=FindingBuildCode.EVALUATION_SCOPE_MISMATCH,
            ),
            error_codes=error_codes,
        )

    def _assemble(
        self,
        *,
        pack: Mapping[str, object],
        control_id: str,
        control: Mapping[str, object],
        documents: list[dict[str, JsonValue]],
        job_id: str,
        asset_id: str,
        correlation_id: str,
        context: FindingBuildContext,
        subject: dict[str, JsonValue],
        status: str,
        applicability_status: str,
        applicability_reason_code: str,
        actual: JsonValue,
        expected: JsonValue,
        result_code: str,
        rationale_code: str,
        error_codes: Sequence[str],
    ) -> dict[str, JsonValue]:
        applicability_rule = _object(
            control.get("applicability_rule"),
            code=FindingBuildCode.PACK_SCHEMA_INVALID,
        )
        evaluation_rule = _object(
            control.get("evaluation_rule"),
            code=FindingBuildCode.PACK_SCHEMA_INVALID,
        )
        evidence_refs: list[dict[str, JsonValue]] = [
            {
                "id": _string(
                    item,
                    "id",
                    code=FindingBuildCode.EVIDENCE_SCHEMA_INVALID,
                ),
                "sha256": _string(
                    item,
                    "evidence_sha256",
                    code=FindingBuildCode.EVIDENCE_SCHEMA_INVALID,
                ),
            }
            for item in documents
        ]
        evidence_set_sha256 = canonical_sha256(cast(JsonValue, evidence_refs))

        pack_approval = cast(JsonValue, copy.deepcopy(pack.get("approval")))
        canonical_input: dict[str, JsonValue] = {
            "schema": {
                "id": "https://schemas.sec-ai.local/v1/finding.schema.json",
                "version": "1.0.0",
            },
            "organization_id": context.organization_id,
            "job_id": job_id,
            "asset_id": asset_id,
            "control_id": control_id,
            "subject": copy.deepcopy(subject),
            "audit_pack": {
                "id": _string(pack, "id", code=FindingBuildCode.PACK_SCHEMA_INVALID),
                "version": _string(
                    pack,
                    "version",
                    code=FindingBuildCode.PACK_SCHEMA_INVALID,
                ),
                "sha256": _string(
                    pack,
                    "content_sha256",
                    code=FindingBuildCode.PACK_SCHEMA_INVALID,
                ),
                "approval": pack_approval,
            },
            "rules": {
                "applicability": cast(JsonValue, copy.deepcopy(applicability_rule)),
                "evaluation": cast(JsonValue, copy.deepcopy(evaluation_rule)),
            },
            "engine": {
                "name": "sec-ai-rule-engine",
                "version": context.engine_version,
                "artifact_sha256": context.engine_artifact_sha256,
            },
            "evidence": cast(JsonValue, documents),
            "evidence_refs": cast(JsonValue, evidence_refs),
            "evidence_set_sha256": evidence_set_sha256,
            "policy_refs": [],
            "reference_refs": [],
            "evaluation_as_of": context.evaluation_as_of,
        }
        input_sha256 = canonical_sha256(canonical_input)

        pack_guide = _object(pack.get("guide"), code=FindingBuildCode.PACK_SCHEMA_INVALID)
        citations = control.get("citations")
        if not isinstance(citations, list):
            _reject(FindingBuildCode.PACK_SCHEMA_INVALID, "Control citations are invalid.")

        finding: dict[str, JsonValue] = {
            "schema_version": "1.0.0",
            "id": "00000000-0000-4000-8000-000000000000",
            "created_at": context.evaluated_at,
            "source": "rule-engine",
            "producer_name": "sec-ai-rule-engine",
            "producer_version": context.engine_version,
            "correlation_id": correlation_id,
            "job_id": job_id,
            "asset_id": asset_id,
            "control_id": control_id,
            "guide_version": _string(
                pack_guide,
                "version",
                code=FindingBuildCode.PACK_SCHEMA_INVALID,
            ),
            "severity": _string(
                control,
                "severity",
                code=FindingBuildCode.PACK_SCHEMA_INVALID,
            ),
            "subject": copy.deepcopy(subject),
            "status": status,
            "applicability": {
                "status": applicability_status,
                "reason_code": applicability_reason_code,
                "rule_id": _string(
                    applicability_rule,
                    "rule_id",
                    code=FindingBuildCode.PACK_SCHEMA_INVALID,
                ),
            },
            "audit_pack": {
                "id": _string(pack, "id", code=FindingBuildCode.PACK_SCHEMA_INVALID),
                "version": _string(
                    pack,
                    "version",
                    code=FindingBuildCode.PACK_SCHEMA_INVALID,
                ),
                "sha256": _string(
                    pack,
                    "content_sha256",
                    code=FindingBuildCode.PACK_SCHEMA_INVALID,
                ),
            },
            "rule_result": {
                "rule_id": _string(
                    evaluation_rule,
                    "rule_id",
                    code=FindingBuildCode.PACK_SCHEMA_INVALID,
                ),
                "rule_version": _string(
                    evaluation_rule,
                    "rule_version",
                    code=FindingBuildCode.PACK_SCHEMA_INVALID,
                ),
                "result_code": result_code,
                "actual": actual,
                "expected": expected,
                "rationale_code": rationale_code,
                "citations": cast(JsonValue, copy.deepcopy(citations)),
                "input_sha256": input_sha256,
                "output_sha256": "0" * 64,
            },
            "evidence_refs": cast(JsonValue, evidence_refs),
            "evidence_set_sha256": evidence_set_sha256,
            "policy_refs": [],
            "error_codes": list(sorted(error_codes)),
            "evaluated_at": context.evaluated_at,
        }
        output_sha256 = canonical_finding_output_sha256(finding)
        finding["id"] = deterministic_finding_id(input_sha256, output_sha256)
        rule_result = cast(dict[str, JsonValue], finding["rule_result"])
        rule_result["output_sha256"] = output_sha256
        self._validate_schema(
            finding,
            "finding.schema.json",
            FindingBuildCode.FINDING_SCHEMA_INVALID,
        )
        return finding
