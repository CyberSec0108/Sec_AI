from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from security_audit.analysis.package_validation import (
    PackageSchemaCatalog,
    PackageValidationCode,
    PackageValidationError,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
FIXTURE_CATALOG = (
    PROJECT_ROOT
    / "collectors"
    / "one_shot"
    / "fixtures"
    / "linux_oneshot_attack_catalog.json"
)


def _load(relative: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((SCHEMA_ROOT / "examples" / relative).read_text(encoding="utf-8")),
    )


@pytest.mark.parametrize(
    ("filename", "schema"),
    [
        ("valid/linux_collector_manifest.json", "linux_collector_manifest.schema.json"),
        ("valid/linux_collector_evidence.json", "linux_collector_evidence.schema.json"),
        ("valid/linux_audit_package.json", "linux_audit_package.schema.json"),
    ],
)
def test_linux_v2_contract_examples_are_valid(filename: str, schema: str) -> None:
    PackageSchemaCatalog(SCHEMA_ROOT).validate(
        _load(filename), schema, PackageValidationCode.DESCRIPTOR_SCHEMA_INVALID
    )


@pytest.mark.parametrize(
    ("filename", "schema"),
    [
        ("invalid/linux_collector_manifest.json", "linux_collector_manifest.schema.json"),
        ("invalid/linux_collector_evidence.json", "linux_collector_evidence.schema.json"),
        ("invalid/linux_audit_package.json", "linux_audit_package.schema.json"),
    ],
)
def test_linux_v2_contract_examples_fail_closed(filename: str, schema: str) -> None:
    with pytest.raises(PackageValidationError):
        PackageSchemaCatalog(SCHEMA_ROOT).validate(
            _load(filename), schema, PackageValidationCode.DESCRIPTOR_SCHEMA_INVALID
        )


def test_linux_manifest_rejects_unknown_user_command() -> None:
    value = _load("valid/linux_collector_manifest.json")
    value["user_command"] = ["/bin/sh", "-c", "whoami"]
    with pytest.raises(PackageValidationError):
        PackageSchemaCatalog(SCHEMA_ROOT).validate(
            value,
            "linux_collector_manifest.schema.json",
            PackageValidationCode.MANIFEST_SCHEMA_INVALID,
        )


def test_linux_manifest_rejects_unsupported_distribution() -> None:
    value = _load("valid/linux_collector_manifest.json")
    value["target"]["distribution"] = "DEBIAN_13"
    with pytest.raises(PackageValidationError):
        PackageSchemaCatalog(SCHEMA_ROOT).validate(
            value,
            "linux_collector_manifest.schema.json",
            PackageValidationCode.MANIFEST_SCHEMA_INVALID,
        )


def test_linux_attack_fixture_catalog_covers_required_fail_closed_cases() -> None:
    value = json.loads(FIXTURE_CATALOG.read_text(encoding="utf-8"))
    cases = cast(list[dict[str, str]], value["cases"])
    kinds = {item["kind"] for item in cases}

    assert len({item["id"] for item in cases}) == len(cases)
    assert {
        "VALID_UBUNTU_FULL",
        "VALID_ROCKY_FULL",
        "PARTIAL_PERMISSION_DENIED",
        "PROBE_TIMEOUT",
        "OUTPUT_LIMIT_EXCEEDED",
        "UNSUPPORTED_DISTRIBUTION",
        "EXPIRED_MANIFEST",
        "USER_ASSET_JOB_SCOPE_MISMATCH",
        "NONCE_REPLAY",
        "ARCHIVE_OR_MEMBER_HASH_TAMPER",
        "ZIP_PATH_TRAVERSAL",
        "ZIP_SYMLINK",
        "NESTED_ARCHIVE",
        "ZIP_BOMB_CANDIDATE",
    } <= kinds
    assert all(
        item["expected"] == "REJECT_BEFORE_RULE_ENGINE"
        for item in cases
        if item["kind"]
        not in {
            "VALID_UBUNTU_FULL",
            "VALID_ROCKY_FULL",
            "PARTIAL_PERMISSION_DENIED",
            "PROBE_TIMEOUT",
            "OUTPUT_LIMIT_EXCEEDED",
        }
    )
