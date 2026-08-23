from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from referencing import Registry, Resource

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.application.full_pack_regression import FullPackRegression
from security_audit.common.canonical_json import JsonValue, canonical_sha256_without_fields

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
PACK_PATH = (
    PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "src" / "pack-0.6.0.json"
)


def _load_object(path: Path) -> dict[str, JsonValue]:
    value = load_strict_json(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _pack_validator() -> Draft202012Validator:
    catalog = _load_object(SCHEMA_ROOT / "schema-catalog.json")
    resources: list[tuple[str, Resource[Any]]] = []
    target: dict[str, JsonValue] | None = None
    for entry in cast(list[dict[str, str]], catalog["schemas"]):
        schema = _load_object(SCHEMA_ROOT / entry["file"])
        resources.append((entry["id"], Resource.from_contents(schema)))
        if entry["file"] == "audit_pack.schema.json":
            target = schema
    assert target is not None
    return Draft202012Validator(
        target,
        registry=Registry().with_resources(resources),
        format_checker=FormatChecker(),
    )


def test_imp026_final_draft_pack_has_pc01_to_pc18_exactly_once() -> None:
    pack = _load_object(PACK_PATH)
    errors = sorted(
        _pack_validator().iter_errors(pack),
        key=lambda error: [str(part) for part in error.path],
    )
    controls = cast(list[dict[str, JsonValue]], pack["controls"])

    assert [error.message for error in errors] == []
    assert pack["version"] == "0.6.0"
    assert pack["approval"] == {"status": "DRAFT"}
    assert pack["content_sha256"] == canonical_sha256_without_fields(
        pack, {"content_sha256", "approval"}
    )
    assert [item["control_id"] for item in controls] == [
        f"PC-{number:02d}" for number in range(1, 19)
    ]
    assert len({item["control_id"] for item in controls}) == 18


def test_imp026_fixture_coverage_resolves_every_pack_reference_and_oracle() -> None:
    regression = FullPackRegression(PROJECT_ROOT)
    coverage = regression.coverage_report()
    results = regression.evaluate_all()

    assert coverage["control_count"] == 18
    assert coverage["fixture_count"] == 92
    assert coverage["all_controls_exactly_once"] is True
    assert coverage["all_fixture_references_resolved"] is True
    assert coverage["all_oracles_matched"] is True
    assert Counter(cast(str, item["status"]) for item in results) == {
        "PASS": 28,
        "FAIL": 26,
        "ERROR": 21,
        "REVIEW": 16,
        "N/A": 1,
    }
    assert {item["control_id"] for item in results} == {
        f"PC-{number:02d}" for number in range(1, 19)
    }


def test_imp026_whole_pack_results_are_deterministic_for_100_runs() -> None:
    report = FullPackRegression(PROJECT_ROOT).verify_determinism()

    assert report["iterations"] == 100
    assert report["unique_fingerprint_count"] == 1
    assert len(cast(str, report["result_fingerprint_sha256"])) == 64
