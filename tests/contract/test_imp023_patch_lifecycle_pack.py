from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from referencing import Registry, Resource

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.common.canonical_json import JsonValue, canonical_sha256_without_fields

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
PACK_PATH = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "src" / "pack-0.4.0.json"
FIXTURE_PATH = (
    PROJECT_ROOT
    / "audit_packs"
    / "kisa_2026_pc"
    / "fixtures"
    / "patch_lifecycle"
    / "cases.json"
)
SNAPSHOT_PATH = (
    PROJECT_ROOT
    / "audit_packs"
    / "kisa_2026_pc"
    / "reference_snapshots"
    / "microsoft_windows_11"
    / "2026-07-23.json"
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


def test_imp023_pack_is_schema_valid_and_contains_pc01_through_pc11() -> None:
    pack = _load_object(PACK_PATH)
    errors = sorted(
        _validator("audit_pack.schema.json").iter_errors(pack),
        key=lambda error: [str(part) for part in error.path],
    )

    assert [error.message for error in errors] == []
    assert pack["version"] == "0.4.0"
    assert pack["approval"] == {"status": "DRAFT"}
    assert pack["content_sha256"] == canonical_sha256_without_fields(
        pack, {"content_sha256", "approval"}
    )
    controls = cast(list[dict[str, JsonValue]], pack["controls"])
    assert [item["control_id"] for item in controls] == [
        f"PC-{number:02d}" for number in range(1, 12)
    ]
    pc10 = controls[9]
    pc11 = controls[10]
    assert pc10["category"] == "PATCH_MANAGEMENT"
    assert pc11["category"] == "PATCH_MANAGEMENT"
    assert pc10["automation_type"] == "AUTO-CONDITIONAL"
    assert pc11["automation_type"] == "AUTO-CONDITIONAL"
    assert cast(list[dict[str, JsonValue]], pc10["citations"])[0]["page_start"] == 577
    assert cast(list[dict[str, JsonValue]], pc11["citations"])[0]["page_end"] == 579


def test_imp023_reference_snapshot_is_integrity_bound_draft() -> None:
    snapshot = _load_object(SNAPSHOT_PATH)
    pack = _load_object(PACK_PATH)
    controls = cast(list[dict[str, JsonValue]], pack["controls"])

    assert snapshot["snapshot_id"] == "microsoft-windows-11-2026-07-23"
    assert snapshot["approval"] == {
        "status": "DRAFT",
        "usage": "SYNTHETIC_TEST_ONLY",
        "signature_present": False,
    }
    assert snapshot["content_sha256"] == canonical_sha256_without_fields(
        snapshot, {"content_sha256", "approval"}
    )
    assert snapshot["valid_until"] == "2026-08-10T23:59:59Z"
    for control in controls[9:11]:
        parameters = cast(dict[str, JsonValue], control["evaluation_rule"])["parameters"]
        assert cast(dict[str, JsonValue], parameters)["reference_snapshot_sha256"] == snapshot[
            "content_sha256"
        ]
    sources = cast(list[dict[str, JsonValue]], snapshot["sources"])
    assert len(sources) == 6
    assert all(
        str(source["url"]).startswith(("https://learn.microsoft.com/", "https://support.microsoft.com/"))
        for source in sources
    )


def test_imp023_fixtures_are_schema_valid_synthetic_and_cover_boundaries() -> None:
    fixture_set = _load_object(FIXTURE_PATH)
    cases = cast(list[dict[str, JsonValue]], fixture_set["cases"])
    evidence_validator = _validator("normalized_evidence.schema.json")

    assert fixture_set["synthetic"] is True
    assert fixture_set["pack_version"] == "0.4.0"
    assert len(cases) == 12
    assert {case["control_id"] for case in cases} == {"PC-10", "PC-11"}
    assert {
        cast(dict[str, JsonValue], case["expected"])["status"] for case in cases
    } == {"PASS", "FAIL", "ERROR", "REVIEW"}
    for control_id in ("PC-10", "PC-11"):
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

    serialized = FIXTURE_PATH.read_text(encoding="utf-8").casefold()
    for forbidden in ("username", "display_name", "organization_name", "password_value"):
        assert forbidden not in serialized
