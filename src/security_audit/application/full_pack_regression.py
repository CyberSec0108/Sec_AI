"""IMP-026 whole-Pack fixture coverage and deterministic regression."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.analysis.rule_engine.account_policy import AccountPolicyRuleRegistry
from security_audit.analysis.rule_engine.endpoint_protection import (
    EndpointProtectionRuleRegistry,
)
from security_audit.analysis.rule_engine.patch_lifecycle import PatchLifecycleRuleRegistry
from security_audit.analysis.rule_engine.registry import RuleRegistry
from security_audit.analysis.rule_engine.service_management import (
    ServiceManagementRuleRegistry,
)
from security_audit.analysis.rule_engine.user_media_remote import (
    UserMediaRemoteRuleRegistry,
)
from security_audit.common.canonical_json import JsonValue, canonical_sha256

_CONTROL_IDS = tuple(f"PC-{number:02d}" for number in range(1, 19))
_REFERENCE_STATUS = {
    "pass": "PASS",
    "fail": "FAIL",
    "error": "ERROR",
    "review": "REVIEW",
    "not_applicable": "N/A",
}


class FullPackRegressionError(ValueError):
    """Reject an incomplete, inconsistent or non-deterministic integration set."""


@dataclass(frozen=True, slots=True)
class _Fixture:
    case_id: str
    control_id: str
    evidence: object
    organization_policy: Mapping[str, object] | None
    expected_status: str
    expected_result_code: str


class FullPackRegression:
    """Run every approved synthetic oracle against the final DRAFT Pack."""

    def __init__(self, project_root: Path) -> None:
        self._base = project_root / "audit_packs" / "kisa_2026_pc"
        self._fixture_root = self._base / "fixtures"
        self._pack = self._load_object(self._base / "src" / "pack-0.6.0.json")
        self._coverage = self._load_object(
            self._fixture_root / "full_pack" / "coverage.json"
        )
        self._snapshot = self._load_object(
            self._base
            / "reference_snapshots"
            / "microsoft_windows_11"
            / "2026-07-23.json"
        )
        self._adapter_catalog = self._load_object(
            self._base
            / "adapter_catalogs"
            / "endpoint_protection"
            / "0.1.0.json"
        )
        controls = cast(list[dict[str, Any]], self._pack["controls"])
        self._controls = {cast(str, item["control_id"]): item for item in controls}
        self._fixtures = self._load_fixtures()
        self._validate_coverage_contract(controls)

    @staticmethod
    def _load_object(path: Path) -> dict[str, Any]:
        value = load_strict_json(path.read_bytes())
        if not isinstance(value, dict):
            raise FullPackRegressionError(f"Expected an object: {path.name}")
        return cast(dict[str, Any], value)

    def _load_fixtures(self) -> tuple[_Fixture, ...]:
        fixtures: list[_Fixture] = []
        sources = cast(list[dict[str, str]], self._coverage["fixture_sources"])
        for source in sources:
            kind = source["kind"]
            if kind == "CASE_SET":
                document = self._load_object(self._fixture_root / source["path"])
                if document.get("synthetic") is not True:
                    raise FullPackRegressionError("Every fixture set must be synthetic.")
                for case in cast(list[dict[str, Any]], document["cases"]):
                    expected = cast(dict[str, str], case["expected"])
                    policy = case.get("organization_policy")
                    fixtures.append(
                        _Fixture(
                            case_id=case["case_id"],
                            control_id=case["control_id"],
                            evidence=case["evidence"],
                            organization_policy=(
                                cast(Mapping[str, object], policy)
                                if isinstance(policy, Mapping)
                                else None
                            ),
                            expected_status=expected["status"],
                            expected_result_code=expected["result_code"],
                        )
                    )
            elif kind == "PC07_PAIR_DIRECTORIES":
                input_directory = self._fixture_root / source["input_path"]
                expected_directory = self._fixture_root / source["expected_path"]
                input_paths = {path.stem: path for path in input_directory.glob("*.json")}
                expected_paths = {
                    path.stem: path for path in expected_directory.glob("*.json")
                }
                if input_paths.keys() != expected_paths.keys():
                    raise FullPackRegressionError(
                        "PC-07 input and expected fixture names differ."
                    )
                for case_id in sorted(input_paths):
                    input_document = self._load_object(input_paths[case_id])
                    expected = self._load_object(expected_paths[case_id])
                    if input_document.get("synthetic") is not True:
                        raise FullPackRegressionError(
                            "Every PC-07 fixture must be synthetic."
                        )
                    fixtures.append(
                        _Fixture(
                            case_id=case_id,
                            control_id="PC-07",
                            evidence=input_document["evidence"],
                            organization_policy=None,
                            expected_status=expected["expected_status"],
                            expected_result_code=expected["expected_result_code"],
                        )
                    )
            else:
                raise FullPackRegressionError(f"Unknown fixture source kind: {kind}")
        return tuple(
            sorted(
                fixtures,
                key=lambda item: (int(item.control_id.removeprefix("PC-")), item.case_id),
            )
        )

    def _validate_coverage_contract(self, controls: list[dict[str, Any]]) -> None:
        control_ids = [cast(str, item["control_id"]) for item in controls]
        expected_ids = cast(list[str], self._coverage["expected_control_ids"])
        if (
            self._pack.get("version") != self._coverage.get("pack_version")
            or self._pack.get("approval") != {"status": "DRAFT"}
        ):
            raise FullPackRegressionError("Coverage must target the exact DRAFT Pack.")
        if tuple(expected_ids) != _CONTROL_IDS or tuple(control_ids) != _CONTROL_IDS:
            raise FullPackRegressionError(
                "PC-01~18 must each occur exactly once and in numeric order."
            )
        if len(self._controls) != len(controls):
            raise FullPackRegressionError("Duplicate Control ID found in Pack.")

        case_ids = [item.case_id for item in self._fixtures]
        if len(case_ids) != len(set(case_ids)):
            raise FullPackRegressionError("Fixture case IDs must be globally unique.")
        if len(self._fixtures) != self._coverage["expected_fixture_count"]:
            raise FullPackRegressionError("Fixture count differs from Coverage contract.")
        if {item.control_id for item in self._fixtures} != set(_CONTROL_IDS):
            raise FullPackRegressionError("At least one Control has no fixture.")

        fixture_by_id = {item.case_id: item for item in self._fixtures}
        for control in controls:
            control_id = cast(str, control["control_id"])
            refs = cast(dict[str, str], control["fixture_refs"])
            for required in cast(
                list[str], self._coverage["required_reference_states"]
            ):
                if required not in refs:
                    raise FullPackRegressionError(
                        f"{control_id} has no required {required} fixture reference."
                    )
            for reference_name, case_id in refs.items():
                fixture = fixture_by_id.get(case_id)
                if (
                    fixture is None
                    or fixture.control_id != control_id
                    or fixture.expected_status != _REFERENCE_STATUS[reference_name]
                ):
                    raise FullPackRegressionError(
                        f"{control_id} fixture reference {reference_name} is invalid."
                    )

        actual_status_counts = Counter(item.expected_status for item in self._fixtures)
        expected_status_counts = cast(
            dict[str, int], self._coverage["expected_status_counts"]
        )
        if dict(sorted(actual_status_counts.items())) != dict(
            sorted(expected_status_counts.items())
        ):
            raise FullPackRegressionError("Fixture status counts differ.")

    def _evaluate_fixture(self, fixture: _Fixture) -> dict[str, JsonValue]:
        control = self._controls[fixture.control_id]
        applicability_rule = cast(Mapping[str, object], control["applicability_rule"])
        evaluation_rule = cast(Mapping[str, object], control["evaluation_rule"])

        if fixture.control_id == "PC-07":
            decision = RuleRegistry().evaluate(
                control_id=fixture.control_id,
                applicability_rule=applicability_rule,
                evaluation_rule=evaluation_rule,
                evidence=cast(Sequence[Mapping[str, object]], fixture.evidence),
            )
            status = str(decision.status)
            result_code = decision.result_code
            actual = (
                "평가 대상 볼륨이 모두 NTFS"
                if status == "PASS"
                else (
                    f"기준 위반 볼륨 {len(decision.violating_volume_ids)}개"
                    if status == "FAIL"
                    else "볼륨 증적을 완전하게 판정하지 못함"
                )
            )
            expected = "평가 대상 Windows 볼륨은 모두 NTFS"
        else:
            evidence = cast(Mapping[str, object], fixture.evidence)
            if fixture.control_id in {"PC-01", "PC-02", "PC-03"}:
                decision_value = AccountPolicyRuleRegistry().evaluate(
                    control_id=fixture.control_id,
                    applicability_rule=applicability_rule,
                    evaluation_rule=evaluation_rule,
                    evidence=evidence,
                    organization_policy=fixture.organization_policy,
                ).as_dict()
            elif fixture.control_id in {
                "PC-04",
                "PC-05",
                "PC-06",
                "PC-08",
                "PC-09",
            }:
                decision_value = ServiceManagementRuleRegistry().evaluate(
                    control_id=fixture.control_id,
                    applicability_rule=applicability_rule,
                    evaluation_rule=evaluation_rule,
                    evidence=evidence,
                    organization_policy=fixture.organization_policy,
                ).as_dict()
            elif fixture.control_id in {"PC-10", "PC-11"}:
                decision_value = PatchLifecycleRuleRegistry().evaluate(
                    control_id=fixture.control_id,
                    applicability_rule=applicability_rule,
                    evaluation_rule=evaluation_rule,
                    evidence=evidence,
                    reference_snapshot=self._snapshot,
                    organization_policy=fixture.organization_policy,
                ).as_dict()
            elif fixture.control_id in {"PC-12", "PC-13", "PC-14", "PC-15"}:
                decision_value = EndpointProtectionRuleRegistry().evaluate(
                    control_id=fixture.control_id,
                    applicability_rule=applicability_rule,
                    evaluation_rule=evaluation_rule,
                    evidence=evidence,
                    adapter_catalog=(
                        None
                        if fixture.control_id == "PC-12"
                        else self._adapter_catalog
                    ),
                    organization_policy=fixture.organization_policy,
                ).as_dict()
            else:
                decision_value = UserMediaRemoteRuleRegistry().evaluate(
                    control_id=fixture.control_id,
                    applicability_rule=applicability_rule,
                    evaluation_rule=evaluation_rule,
                    evidence=evidence,
                    organization_policy=fixture.organization_policy,
                ).as_dict()
            status = cast(str, decision_value["status"])
            result_code = cast(str, decision_value["result_code"])
            actual = cast(str, decision_value["actual"])
            expected = cast(str, decision_value["expected"])

        if (
            status != fixture.expected_status
            or result_code != fixture.expected_result_code
        ):
            raise FullPackRegressionError(
                f"Fixture oracle mismatch: {fixture.case_id}"
            )
        citation = cast(list[dict[str, JsonValue]], control["citations"])[0]
        return {
            "case_id": fixture.case_id,
            "control_id": fixture.control_id,
            "control_title": cast(str, control["title"]),
            "category": cast(str, control["category"]),
            "severity": cast(str, control["severity"]),
            "automation_type": cast(str, control["automation_type"]),
            "status": status,
            "result_code": result_code,
            "actual": actual,
            "expected": expected,
            "page_start": cast(int, citation["page_start"]),
            "page_end": cast(int, citation["page_end"]),
            "rule_id": cast(str, evaluation_rule["rule_id"]),
            "rule_version": cast(str, evaluation_rule["rule_version"]),
        }

    def evaluate_all(self) -> list[dict[str, JsonValue]]:
        """Evaluate all 92 cases in stable Control/case order."""

        return [self._evaluate_fixture(fixture) for fixture in self._fixtures]

    def coverage_report(self) -> dict[str, JsonValue]:
        """Return the immutable integration Coverage projection."""

        status_counts = Counter(item.expected_status for item in self._fixtures)
        per_control: list[dict[str, JsonValue]] = []
        for control_id in _CONTROL_IDS:
            cases = [item for item in self._fixtures if item.control_id == control_id]
            per_control.append(
                {
                    "control_id": control_id,
                    "fixture_count": len(cases),
                    "statuses": cast(
                        JsonValue,
                        sorted({item.expected_status for item in cases}),
                    ),
                    "reference_count": len(
                        cast(dict[str, str], self._controls[control_id]["fixture_refs"])
                    ),
                }
            )
        return {
            "control_count": len(_CONTROL_IDS),
            "fixture_count": len(self._fixtures),
            "status_counts": dict(sorted(status_counts.items())),
            "synthetic_only": True,
            "all_controls_exactly_once": True,
            "all_fixture_references_resolved": True,
            "all_oracles_matched": True,
            "per_control": cast(JsonValue, per_control),
        }

    def verify_determinism(self, iterations: int | None = None) -> dict[str, JsonValue]:
        """Prove that complete result serialization is stable across repeated runs."""

        run_count = (
            cast(int, self._coverage["determinism_iterations"])
            if iterations is None
            else iterations
        )
        if run_count < 2 or run_count > 1000:
            raise FullPackRegressionError("Determinism iterations must be 2~1000.")
        first = self.evaluate_all()
        fingerprint = canonical_sha256(cast(JsonValue, first))
        for _ in range(run_count - 1):
            if canonical_sha256(cast(JsonValue, self.evaluate_all())) != fingerprint:
                raise FullPackRegressionError("Whole-Pack result is not deterministic.")
        return {
            "iterations": run_count,
            "unique_fingerprint_count": 1,
            "result_fingerprint_sha256": fingerprint,
        }

    @property
    def pack_metadata(self) -> dict[str, JsonValue]:
        return {
            "name": cast(str, self._pack["name"]),
            "version": cast(str, self._pack["version"]),
            "approval_status": cast(dict[str, str], self._pack["approval"])["status"],
            "content_sha256": cast(str, self._pack["content_sha256"]),
        }
