from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from referencing import Registry, Resource

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
PACK_PATH = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "src" / "pack.json"


def _load_object(path: Path) -> dict[str, JsonValue]:
    value = load_strict_json(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _audit_pack_validator() -> Draft202012Validator:
    catalog = _load_object(SCHEMA_ROOT / "schema-catalog.json")
    catalog_entries = cast(list[dict[str, str]], catalog["schemas"])
    resources: list[tuple[str, Resource[Any]]] = []
    audit_pack_schema: dict[str, JsonValue] | None = None

    for entry in catalog_entries:
        schema = _load_object(SCHEMA_ROOT / entry["file"])
        resources.append((entry["id"], Resource.from_contents(schema)))
        if entry["file"] == "audit_pack.schema.json":
            audit_pack_schema = schema

    assert audit_pack_schema is not None
    registry = Registry().with_resources(resources)
    return Draft202012Validator(
        audit_pack_schema,
        registry=registry,
        format_checker=FormatChecker(),
    )


def _pc07_control(pack: dict[str, JsonValue]) -> dict[str, JsonValue]:
    controls = cast(list[dict[str, JsonValue]], pack["controls"])
    assert len(controls) == 1
    return controls[0]


def test_pc07_pack_source_is_schema_valid() -> None:
    pack = _load_object(PACK_PATH)
    errors = sorted(
        _audit_pack_validator().iter_errors(pack),
        key=lambda error: [str(part) for part in error.path],
    )

    assert [error.message for error in errors] == []


def test_pc07_pack_content_hash_matches_payload_projection() -> None:
    pack = _load_object(PACK_PATH)
    expected = canonical_sha256_without_fields(pack, {"content_sha256", "approval"})

    assert pack["content_sha256"] == expected


def test_pc07_pack_remains_draft_and_contains_only_pc07() -> None:
    pack = _load_object(PACK_PATH)
    approval = cast(dict[str, JsonValue], pack["approval"])
    control = _pc07_control(pack)

    assert approval == {"status": "DRAFT"}
    assert control["control_id"] == "PC-07"
    assert control["required_privileges"] == ["STANDARD_USER"]


def test_pc07_pack_encodes_imp010_edge_decisions() -> None:
    pack = _load_object(PACK_PATH)
    control = _pc07_control(pack)
    applicability = cast(dict[str, JsonValue], control["applicability_rule"])
    evaluation = cast(dict[str, JsonValue], control["evaluation_rule"])
    applicability_parameters = cast(dict[str, JsonValue], applicability["parameters"])
    evaluation_parameters = cast(dict[str, JsonValue], evaluation["parameters"])

    excluded = cast(list[str], applicability_parameters["exclude_volume_classes"])
    included = cast(list[str], applicability_parameters["include_volume_classes"])

    assert "EFI_SYSTEM_PARTITION" in excluded
    assert "WINDOWS_RECOVERY_PARTITION" in excluded
    assert "ATTACHED_VHD_VOLUME" in included
    assert "STORAGE_SPACES_LOGICAL_VOLUME" in included
    assert evaluation_parameters["required_filesystem"] == "NTFS"
    assert evaluation_parameters["refs_status"] == "FAIL"
    assert evaluation_parameters["bitlocker_unknown_status"] == "ERROR"
    assert evaluation_parameters["aggregate_subject_key"] == (
        "pc07:evaluated-volume-set"
    )
