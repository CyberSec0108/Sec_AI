from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from referencing import Registry, Resource

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.common.canonical_json import JsonValue, canonical_sha256_without_fields

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
BASE = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc"
PACK_PATH = BASE / "src" / "pack-0.6.0.json"
FIXTURE_PATH = BASE / "fixtures" / "user_media_remote" / "cases.json"


def _load_object(path: Path) -> dict[str, JsonValue]:
    value = load_strict_json(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _validator(schema_file: str) -> Draft202012Validator:
    catalog = _load_object(SCHEMA_ROOT / "schema-catalog.json")
    resources: list[tuple[str, Resource[Any]]] = []
    target: dict[str, JsonValue] | None = None
    for entry in cast(list[dict[str, str]], catalog["schemas"]):
        schema = _load_object(SCHEMA_ROOT / entry["file"])
        resources.append((entry["id"], Resource.from_contents(schema)))
        if entry["file"] == schema_file:
            target = schema
    assert target is not None
    return Draft202012Validator(
        target,
        registry=Registry().with_resources(resources),
        format_checker=FormatChecker(),
    )


def test_imp025_pack_is_schema_valid_and_contains_pc01_through_pc18() -> None:
    pack = _load_object(PACK_PATH)
    errors = sorted(
        _validator("audit_pack.schema.json").iter_errors(pack),
        key=lambda error: [str(part) for part in error.path],
    )

    assert [error.message for error in errors] == []
    assert pack["version"] == "0.6.0"
    assert pack["approval"] == {"status": "DRAFT"}
    assert pack["content_sha256"] == canonical_sha256_without_fields(
        pack, {"content_sha256", "approval"}
    )
    controls = cast(list[dict[str, JsonValue]], pack["controls"])
    assert [item["control_id"] for item in controls] == [
        f"PC-{number:02d}" for number in range(1, 19)
    ]
    assert [item["severity"] for item in controls[15:18]] == [
        "HIGH",
        "HIGH",
        "MEDIUM",
    ]
    assert [item["automation_type"] for item in controls[15:18]] == [
        "AUTO",
        "AUTO-CONDITIONAL",
        "AUTO",
    ]
    assert [
        cast(list[dict[str, JsonValue]], item["citations"])[0]["page_start"]
        for item in controls[15:18]
    ] == [587, 589, 591]


def test_imp025_fifteen_fixtures_are_schema_valid_and_cover_all_states() -> None:
    fixture_set = _load_object(FIXTURE_PATH)
    cases = cast(list[dict[str, JsonValue]], fixture_set["cases"])
    evidence_validator = _validator("normalized_evidence.schema.json")

    assert fixture_set["synthetic"] is True
    assert fixture_set["pack_version"] == "0.6.0"
    assert len(cases) == 15
    assert {case["control_id"] for case in cases} == {"PC-16", "PC-17", "PC-18"}
    assert {
        cast(dict[str, JsonValue], case["expected"])["status"] for case in cases
    } == {"PASS", "FAIL", "ERROR", "REVIEW"}
    for control_id in ("PC-16", "PC-17", "PC-18"):
        statuses = {
            cast(dict[str, JsonValue], case["expected"])["status"]
            for case in cases
            if case["control_id"] == control_id
        }
        assert {"PASS", "FAIL", "ERROR", "REVIEW"} <= statuses
    for case in cases:
        evidence = cast(dict[str, JsonValue], case["evidence"])
        errors = sorted(
            evidence_validator.iter_errors(evidence),
            key=lambda error: [str(part) for part in error.path],
        )
        assert [error.message for error in errors] == [], case["case_id"]


def test_imp025_fixtures_do_not_contain_real_identity_or_remote_scope_confusion() -> None:
    serialized = FIXTURE_PATH.read_text(encoding="utf-8").casefold()

    for forbidden in (
        '"user_name"',
        '"username"',
        '"display_name"',
        '"organization_name"',
        '"quick_assist_enabled"',
        '"remote_desktop_enabled"',
    ):
        assert forbidden not in serialized
