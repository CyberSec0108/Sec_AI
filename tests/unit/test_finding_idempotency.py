from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, cast

import pytest

from security_audit.analysis.finding import (
    FindingBuildContext,
    FindingBuilder,
    FindingReplayAction,
    FindingReplayCode,
    FindingReplayError,
    canonical_finding_output_sha256,
    deterministic_finding_id,
    resolve_finding_replay,
)
from security_audit.analysis.package_validation import PackageSchemaCatalog
from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.analysis.rule_engine import RuleRegistry
from security_audit.common.canonical_json import JsonValue

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
PACK_PATH = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "src" / "pack.json"
INPUT_PATH = (
    PROJECT_ROOT
    / "audit_packs"
    / "kisa_2026_pc"
    / "fixtures"
    / "pc07"
    / "input"
    / "pc07-pass.json"
)


def _load_object(path: Path) -> dict[str, Any]:
    value = load_strict_json(path.read_bytes())
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _build(
    builder: FindingBuilder,
    pack: dict[str, Any],
    input_document: dict[str, Any],
    *,
    replay_number: int,
) -> dict[str, JsonValue]:
    control = cast(list[dict[str, Any]], pack["controls"])[0]
    evidence = cast(list[dict[str, Any]], input_document["evidence"])
    decision = RuleRegistry().evaluate(
        control_id="PC-07",
        applicability_rule=cast(dict[str, Any], control["applicability_rule"]),
        evaluation_rule=cast(dict[str, Any], control["evaluation_rule"]),
        evidence=evidence,
    )
    return builder.build(
        pack=pack,
        control_id="PC-07",
        evidence=evidence,
        decision=decision,
        context=FindingBuildContext(
            organization_id="70000000-0000-4000-8000-000000000001",
            evaluation_as_of="2026-07-22T08:00:00Z",
            evaluated_at=f"2026-07-22T09:{replay_number % 60:02d}:00Z",
            engine_version="0.1.0",
            engine_artifact_sha256="a" * 64,
        ),
        allow_draft=True,
    )


def test_same_input_replayed_100_times_has_one_result_and_no_duplicate_creation() -> None:
    pack = _load_object(PACK_PATH)
    original = _load_object(INPUT_PATH)
    builder = FindingBuilder(PackageSchemaCatalog(SCHEMA_ROOT))
    existing: dict[str, JsonValue] | None = None
    actions: list[FindingReplayAction] = []
    fingerprints: set[tuple[str, str, str]] = set()

    for replay_number in range(100):
        replay = copy.deepcopy(original)
        evidence = cast(list[dict[str, Any]], replay["evidence"])
        shift = replay_number % len(evidence)
        replay["evidence"] = evidence[shift:] + evidence[:shift]
        candidate = _build(
            builder,
            pack,
            replay,
            replay_number=replay_number,
        )
        resolution = resolve_finding_replay(existing=existing, candidate=candidate)
        actions.append(resolution.action)
        fingerprints.add(
            (
                resolution.fingerprint.idempotency_key,
                resolution.fingerprint.finding_id,
                resolution.fingerprint.output_sha256,
            )
        )
        if resolution.action is FindingReplayAction.CREATE:
            existing = candidate

    assert actions.count(FindingReplayAction.CREATE) == 1
    assert actions.count(FindingReplayAction.RETURN_EXISTING) == 99
    assert len(fingerprints) == 1


def test_replay_returns_the_existing_finding_identity_not_execution_metadata() -> None:
    pack = _load_object(PACK_PATH)
    input_document = _load_object(INPUT_PATH)
    builder = FindingBuilder(PackageSchemaCatalog(SCHEMA_ROOT))
    existing = _build(builder, pack, input_document, replay_number=0)
    candidate = _build(builder, pack, input_document, replay_number=59)

    resolution = resolve_finding_replay(existing=existing, candidate=candidate)

    assert resolution.action is FindingReplayAction.RETURN_EXISTING
    assert resolution.fingerprint.finding_id == existing["id"]
    assert existing["evaluated_at"] != candidate["evaluated_at"]


def test_same_idempotency_key_with_different_decision_is_a_conflict() -> None:
    pack = _load_object(PACK_PATH)
    input_document = _load_object(INPUT_PATH)
    builder = FindingBuilder(PackageSchemaCatalog(SCHEMA_ROOT))
    existing = _build(builder, pack, input_document, replay_number=0)
    conflicting = copy.deepcopy(existing)
    rule_result = cast(dict[str, JsonValue], conflicting["rule_result"])
    actual = cast(dict[str, JsonValue], rule_result["actual"])
    actual["vol-data"] = "FAT32"
    rule_result["output_sha256"] = canonical_finding_output_sha256(conflicting)
    conflicting["id"] = deterministic_finding_id(
        cast(str, rule_result["input_sha256"]),
        cast(str, rule_result["output_sha256"]),
    )

    with pytest.raises(FindingReplayError) as captured:
        resolve_finding_replay(existing=existing, candidate=conflicting)

    assert captured.value.code is FindingReplayCode.IDEMPOTENCY_CONFLICT


def test_declared_output_hash_tampering_is_rejected_before_replay_resolution() -> None:
    pack = _load_object(PACK_PATH)
    input_document = _load_object(INPUT_PATH)
    builder = FindingBuilder(PackageSchemaCatalog(SCHEMA_ROOT))
    finding = _build(builder, pack, input_document, replay_number=0)
    rule_result = cast(dict[str, JsonValue], finding["rule_result"])
    rule_result["output_sha256"] = "0" * 64

    with pytest.raises(FindingReplayError) as captured:
        resolve_finding_replay(existing=None, candidate=finding)

    assert captured.value.code is FindingReplayCode.OUTPUT_HASH_MISMATCH


def test_existing_record_for_another_idempotency_key_is_not_overwritten() -> None:
    pack = _load_object(PACK_PATH)
    input_document = _load_object(INPUT_PATH)
    changed_input = copy.deepcopy(input_document)
    changed_input["evidence"][0]["source_locator"]["locator"] += ":changed"
    builder = FindingBuilder(PackageSchemaCatalog(SCHEMA_ROOT))
    existing = _build(builder, pack, input_document, replay_number=0)
    candidate = _build(builder, pack, changed_input, replay_number=0)

    with pytest.raises(FindingReplayError) as captured:
        resolve_finding_replay(existing=existing, candidate=candidate)

    assert captured.value.code is FindingReplayCode.IDEMPOTENCY_SCOPE_MISMATCH
