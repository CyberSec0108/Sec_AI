from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from referencing import Registry, Resource

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.common.canonical_json import JsonValue, canonical_sha256_without_fields

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
PACK_PATH = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "src" / "pack-0.3.0.json"
FIXTURE_PATH = (
    PROJECT_ROOT
    / "audit_packs"
    / "kisa_2026_pc"
    / "fixtures"
    / "service_management"
    / "cases.json"
)


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


def test_imp022_pack_is_schema_valid_versioned_draft() -> None:
    pack = _load_object(PACK_PATH)
    errors = sorted(
        _validator("audit_pack.schema.json").iter_errors(pack),
        key=lambda error: [str(part) for part in error.path],
    )

    assert [error.message for error in errors] == []
    assert pack["version"] == "0.3.0"
    assert pack["approval"] == {"status": "DRAFT"}
    assert pack["content_sha256"] == canonical_sha256_without_fields(
        pack, {"content_sha256", "approval"}
    )


def test_imp022_pack_contains_pc01_through_pc09_once() -> None:
    pack = _load_object(PACK_PATH)
    controls = cast(list[dict[str, JsonValue]], pack["controls"])

    assert [item["control_id"] for item in controls] == [
        "PC-01", "PC-02", "PC-03", "PC-04", "PC-05", "PC-06", "PC-07", "PC-08", "PC-09"
    ]
    controls_by_id = {str(item["control_id"]): item for item in controls}
    expected_pages = {
        "PC-04": (561, 565),
        "PC-05": (566, 569),
        "PC-06": (570, 570),
        "PC-08": (573, 574),
        "PC-09": (575, 576),
    }
    for control_id, pages in expected_pages.items():
        citation = cast(list[dict[str, JsonValue]], controls_by_id[control_id]["citations"])[0]
        assert (citation["page_start"], citation["page_end"]) == pages
    assert controls_by_id["PC-04"]["automation_type"] == "AUTO-CONDITIONAL"
    assert controls_by_id["PC-05"]["automation_type"] == "AUTO-CONDITIONAL"
    assert controls_by_id["PC-06"]["automation_type"] == "AUTO-CONDITIONAL"
    assert controls_by_id["PC-09"]["automation_type"] == "AUTO-APPLICABILITY"


def test_imp022_fixtures_are_synthetic_schema_valid_and_cover_all_boundaries() -> None:
    fixture_set = _load_object(FIXTURE_PATH)
    cases = cast(list[dict[str, JsonValue]], fixture_set["cases"])
    evidence_validator = _validator("normalized_evidence.schema.json")

    assert fixture_set["synthetic"] is True
    assert fixture_set["pack_version"] == "0.3.0"
    assert len(cases) == 20
    assert {case["control_id"] for case in cases} == {
        "PC-04", "PC-05", "PC-06", "PC-08", "PC-09"
    }
    assert {
        cast(dict[str, JsonValue], case["expected"])["status"] for case in cases
    } == {"PASS", "FAIL", "ERROR", "REVIEW", "N/A"}
    for control_id in {"PC-04", "PC-05", "PC-06", "PC-08", "PC-09"}:
        statuses = {
            cast(dict[str, JsonValue], case["expected"])["status"]
            for case in cases
            if case["control_id"] == control_id
        }
        assert {"PASS", "FAIL", "ERROR"} <= statuses
    for case in cases:
        evidence = cast(dict[str, JsonValue], case["evidence"])
        errors = sorted(
            evidence_validator.iter_errors(evidence),
            key=lambda error: [str(part) for part in error.path],
        )
        assert [error.message for error in errors] == [], case["case_id"]

    serialized = FIXTURE_PATH.read_text(encoding="utf-8").casefold()
    for forbidden in ("username", "display_name", "organization_name", "password_value"):
        assert forbidden not in serialized
