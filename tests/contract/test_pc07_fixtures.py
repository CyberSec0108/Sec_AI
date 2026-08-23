from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from referencing import Registry, Resource

from security_audit.analysis.package_validation.strict_json import load_strict_json
from security_audit.common.canonical_json import JsonValue, canonical_sha256

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
FIXTURE_ROOT = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "fixtures"
PACK_PATH = PROJECT_ROOT / "audit_packs" / "kisa_2026_pc" / "src" / "pack.json"
FIXTURE_SET_SHA256 = "74c7098bb08e63580bc10bfe99f514fb92341e256d6c7f21be503f7befb513e0"

APPROVED_CASES = (
    "pc07-pass",
    "pc07-fail-fat32",
    "pc07-fail-exfat",
    "pc07-error-collection",
    "pc07-error-filesystem-unknown",
    "pc07-error-no-evaluated-volume",
    "pc07-excluded-efi",
    "pc07-excluded-recovery",
    "pc07-edge-refs",
    "pc07-edge-vhd-ntfs",
    "pc07-edge-vhd-fat32",
    "pc07-edge-vhd-detached",
    "pc07-edge-storage-spaces-ntfs",
    "pc07-edge-storage-spaces-refs",
    "pc07-edge-bitlocker-ntfs",
    "pc07-edge-bitlocker-locked",
    "pc07-edge-mounted-folder",
)

EXPECTED_STATUS = {
    "pc07-pass": "PASS",
    "pc07-fail-fat32": "FAIL",
    "pc07-fail-exfat": "FAIL",
    "pc07-error-collection": "ERROR",
    "pc07-error-filesystem-unknown": "ERROR",
    "pc07-error-no-evaluated-volume": "ERROR",
    "pc07-excluded-efi": "PASS",
    "pc07-excluded-recovery": "PASS",
    "pc07-edge-refs": "FAIL",
    "pc07-edge-vhd-ntfs": "PASS",
    "pc07-edge-vhd-fat32": "FAIL",
    "pc07-edge-vhd-detached": "PASS",
    "pc07-edge-storage-spaces-ntfs": "PASS",
    "pc07-edge-storage-spaces-refs": "FAIL",
    "pc07-edge-bitlocker-ntfs": "PASS",
    "pc07-edge-bitlocker-locked": "ERROR",
    "pc07-edge-mounted-folder": "PASS",
}

EXPECTED_RESULT_CODE = {
    "pc07-pass": "ALL_EVALUATED_VOLUMES_NTFS",
    "pc07-fail-fat32": "NON_NTFS_VOLUME_FOUND",
    "pc07-fail-exfat": "NON_NTFS_VOLUME_FOUND",
    "pc07-error-collection": "VOLUME_COLLECTION_FAILED",
    "pc07-error-filesystem-unknown": "VOLUME_FILESYSTEM_UNAVAILABLE",
    "pc07-error-no-evaluated-volume": "NO_EVALUATED_VOLUME",
    "pc07-excluded-efi": "ALL_EVALUATED_VOLUMES_NTFS",
    "pc07-excluded-recovery": "ALL_EVALUATED_VOLUMES_NTFS",
    "pc07-edge-refs": "NON_NTFS_REFS_FOUND",
    "pc07-edge-vhd-ntfs": "ALL_EVALUATED_VOLUMES_NTFS",
    "pc07-edge-vhd-fat32": "NON_NTFS_VOLUME_FOUND",
    "pc07-edge-vhd-detached": "ALL_EVALUATED_VOLUMES_NTFS",
    "pc07-edge-storage-spaces-ntfs": "ALL_EVALUATED_VOLUMES_NTFS",
    "pc07-edge-storage-spaces-refs": "NON_NTFS_REFS_FOUND",
    "pc07-edge-bitlocker-ntfs": "ALL_EVALUATED_VOLUMES_NTFS",
    "pc07-edge-bitlocker-locked": "VOLUME_FILESYSTEM_UNAVAILABLE",
    "pc07-edge-mounted-folder": "ALL_EVALUATED_VOLUMES_NTFS",
}


def _load(path: Path) -> Any:
    return load_strict_json(path.read_bytes())


def _load_object(path: Path) -> dict[str, Any]:
    value = _load(path)
    assert isinstance(value, dict)
    return cast(dict[str, Any], value)


def _index() -> dict[str, Any]:
    return _load_object(FIXTURE_ROOT / "index.json")


def _case_entries() -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], _index()["cases"])


def _case_documents(entry: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    input_path = (FIXTURE_ROOT / cast(str, entry["input_path"])).resolve()
    expected_path = (FIXTURE_ROOT / cast(str, entry["expected_path"])).resolve()
    assert input_path.is_relative_to(FIXTURE_ROOT.resolve())
    assert expected_path.is_relative_to(FIXTURE_ROOT.resolve())
    return _load_object(input_path), _load_object(expected_path)


def _normalized_evidence_validator() -> Draft202012Validator:
    catalog = _load_object(SCHEMA_ROOT / "schema-catalog.json")
    entries = cast(list[dict[str, str]], catalog["schemas"])
    resources: list[tuple[str, Resource[Any]]] = []
    evidence_schema: dict[str, JsonValue] | None = None

    for entry in entries:
        schema = cast(dict[str, JsonValue], _load_object(SCHEMA_ROOT / entry["file"]))
        resources.append((entry["id"], Resource.from_contents(schema)))
        if entry["file"] == "normalized_evidence.schema.json":
            evidence_schema = schema

    assert evidence_schema is not None
    return Draft202012Validator(
        evidence_schema,
        registry=Registry().with_resources(resources),
        format_checker=FormatChecker(),
    )


def _find_evidence(
    input_document: dict[str, Any], subject_id: str, probe_id: str
) -> dict[str, Any]:
    evidence = cast(list[dict[str, Any]], input_document["evidence"])
    matches = [
        item
        for item in evidence
        if item["subject"]["subject_key"] == subject_id and item["probe_id"] == probe_id
    ]
    assert len(matches) == 1
    return matches[0]


def test_fixture_index_declares_exact_approved_case_set() -> None:
    index = _index()
    entries = _case_entries()

    assert index["fixture_set_version"] == "1.0.0"
    assert index["control_id"] == "PC-07"
    assert index["synthetic"] is True
    assert index["canonicalization"] == "RFC8785-JCS"
    assert index["case_count"] == 17
    assert tuple(entry["case_id"] for entry in entries) == APPROVED_CASES
    assert canonical_sha256(index) == FIXTURE_SET_SHA256


def test_fixture_paths_hashes_and_strict_json_are_valid() -> None:
    referenced: set[Path] = set()

    for entry in _case_entries():
        input_document, expected_document = _case_documents(entry)
        input_path = (FIXTURE_ROOT / entry["input_path"]).resolve()
        expected_path = (FIXTURE_ROOT / entry["expected_path"]).resolve()
        referenced.update((input_path, expected_path))

        assert entry["input_sha256"] == canonical_sha256(input_document)
        assert entry["expected_sha256"] == canonical_sha256(expected_document)
        assert input_document["case_id"] == entry["case_id"]
        assert expected_document["case_id"] == entry["case_id"]

    actual = {
        path.resolve()
        for path in (FIXTURE_ROOT / "pc07").rglob("*.json")
        if path.is_file()
    }
    assert actual == referenced


def test_every_input_contains_schema_valid_normalized_evidence() -> None:
    validator = _normalized_evidence_validator()

    for entry in _case_entries():
        input_document, _ = _case_documents(entry)
        evidence = cast(list[dict[str, Any]], input_document["evidence"])
        evidence_ids = [item["id"] for item in evidence]
        ordering = [
            (item["subject"]["subject_key"], item["probe_id"], item["id"])
            for item in evidence
        ]

        assert input_document["fixture_version"] == "1.0.0"
        assert input_document["synthetic"] is True
        assert input_document["control_id"] == "PC-07"
        assert len(evidence_ids) == len(set(evidence_ids))
        assert ordering == sorted(ordering)
        assert {item["probe_id"] for item in evidence} == {
            "win.storage.volumes",
            "win.storage.partitions",
            "win.storage.disks",
        }

        for item in evidence:
            errors = list(validator.iter_errors(item))
            assert [error.message for error in errors] == []
            assert item["control_id"] == "PC-07"


def test_expected_decisions_match_approved_status_and_result_codes() -> None:
    for entry in _case_entries():
        _, expected = _case_documents(entry)
        case_id = cast(str, entry["case_id"])
        status = cast(str, expected["expected_status"])
        error_codes = cast(list[str], expected["error_codes"])
        violations = cast(list[str], expected["violating_volume_ids"])

        assert status == EXPECTED_STATUS[case_id]
        assert expected["expected_result_code"] == EXPECTED_RESULT_CODE[case_id]
        assert expected["expected_subject"] == {
            "scope": "VOLUME",
            "subject_key": "pc07:evaluated-volume-set",
        }
        if status == "PASS":
            assert error_codes == []
            assert violations == []
        elif status == "FAIL":
            assert error_codes == []
            assert violations
        else:
            assert status == "ERROR"
            assert error_codes


def test_volume_sets_are_sorted_disjoint_and_traceable() -> None:
    for entry in _case_entries():
        _, expected = _case_documents(entry)
        candidate = cast(list[str], expected["candidate_volume_ids"])
        evaluated = cast(list[str], expected["evaluated_volume_ids"])
        violations = cast(list[str], expected["violating_volume_ids"])
        excluded = cast(list[dict[str, str]], expected["excluded_volumes"])
        excluded_ids = [item["subject_id"] for item in excluded]

        assert candidate == sorted(candidate)
        assert evaluated == sorted(evaluated)
        assert violations == sorted(violations)
        assert excluded_ids == sorted(excluded_ids)
        assert set(evaluated).issubset(candidate)
        assert set(violations).issubset(evaluated)
        assert set(candidate).isdisjoint(excluded_ids)


def test_edge_case_semantics_are_frozen() -> None:
    cases = {entry["case_id"]: _case_documents(entry) for entry in _case_entries()}

    _, efi = cases["pc07-excluded-efi"]
    assert efi["excluded_volumes"] == [
        {"subject_id": "vol-efi", "reason_code": "EXCLUDED_EFI_SYSTEM_PARTITION"}
    ]

    _, refs = cases["pc07-edge-refs"]
    assert refs["rationale_code"] == "REFS_KISA_NTFS_CONDITION_MISMATCH"

    _, detached = cases["pc07-edge-vhd-detached"]
    assert detached["excluded_volumes"] == [
        {"subject_id": "disk-image-01", "reason_code": "EXCLUDED_DETACHED_DISK_IMAGE"}
    ]

    locked_input, locked_expected = cases["pc07-edge-bitlocker-locked"]
    locked_volume = _find_evidence(
        locked_input, "vol-bitlocker", "win.storage.volumes"
    )["normalized_value"]
    assert locked_volume["filesystem"] is None
    assert locked_volume["bitlocker_state"] == "LOCKED"
    assert locked_expected["expected_status"] == "ERROR"

    mounted_input, mounted_expected = cases["pc07-edge-mounted-folder"]
    mounted_volume = _find_evidence(
        mounted_input, "vol-mounted", "win.storage.volumes"
    )["normalized_value"]
    assert mounted_volume["drive_letter"] is None
    assert mounted_volume["mount_kind"] == "FOLDER_MOUNT"
    assert mounted_expected["expected_status"] == "PASS"


def test_fixtures_are_synthetic_and_omit_sensitive_fields() -> None:
    forbidden_keys = {
        "password",
        "token",
        "cookie",
        "secret",
        "private_key",
        "username",
        "organization_name",
        "volume_label",
        "file_path",
        "vhd_path",
    }

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            assert forbidden_keys.isdisjoint(value)
            for nested in value.values():
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)
        elif isinstance(value, str):
            assert "E:\\" not in value
            assert "C:\\" not in value

    for entry in _case_entries():
        input_document, expected_document = _case_documents(entry)
        assert input_document["synthetic"] is True
        walk(input_document)
        walk(expected_document)


def test_pack_primary_fixture_references_exist() -> None:
    pack = _load_object(PACK_PATH)
    control = cast(list[dict[str, Any]], pack["controls"])[0]
    fixture_refs = cast(dict[str, str], control["fixture_refs"])
    case_ids = {entry["case_id"] for entry in _case_entries()}

    assert fixture_refs == {
        "pass": "pc07-pass",
        "fail": "pc07-fail-fat32",
        "error": "pc07-error-collection",
    }
    assert set(fixture_refs.values()).issubset(case_ids)
