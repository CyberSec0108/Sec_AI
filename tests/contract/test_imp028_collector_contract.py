from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from security_audit.analysis.package_validation import (
    PackageSchemaCatalog,
    PackageValidationCode,
)
from security_audit.collector import ProbeAllowlist
from security_audit.common.canonical_json import JsonValue, canonical_sha256_without_fields

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
ALLOWLIST_PATH = (
    PROJECT_ROOT / "collectors" / "one_shot" / "contracts" / "imp028_probe_allowlist.json"
)
MANIFEST_PATH = (
    PROJECT_ROOT / "collectors" / "one_shot" / "fixtures" / "imp028" / "valid_manifest.json"
)


def test_imp028_allowlist_has_only_pc07_mock_protocol() -> None:
    raw = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    allowlist = ProbeAllowlist.from_file(ALLOWLIST_PATH)

    assert raw["execution_mode"] == "MOCK_ONLY"
    assert raw["real_os_access"] is False
    assert allowlist.probe_ids == (
        "win.storage.disks",
        "win.storage.partitions",
        "win.storage.volumes",
    )
    assert all(probe["control_ids"] == ["PC-07"] for probe in raw["probes"])
    assert not any(
        forbidden in json.dumps(raw).casefold()
        for forbidden in ("powershell", "command", "script", "registry_path", "wmi_query")
    )


def test_imp028_manifest_fixture_is_schema_valid_and_hash_bound() -> None:
    manifest = cast(
        dict[str, JsonValue],
        json.loads(MANIFEST_PATH.read_text(encoding="utf-8")),
    )
    PackageSchemaCatalog(SCHEMA_ROOT).validate(
        manifest,
        "collector_manifest.schema.json",
        PackageValidationCode.MANIFEST_SCHEMA_INVALID,
    )
    expected_hash = canonical_sha256_without_fields(
        manifest,
        {"manifest_content_sha256", "authorization"},
    )
    authorization = cast(dict[str, Any], manifest["authorization"])
    signature = cast(dict[str, Any], authorization["signature"])

    assert manifest["manifest_content_sha256"] == expected_hash
    assert signature["signed_sha256"] == expected_hash
    assert signature["algorithm"] == "Ed25519"


def test_imp028_manifest_requests_only_exact_allowlist_contracts() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    catalog = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    expected = {
        item["probe_id"]: {
            "probe_version": item["probe_version"],
            "control_ids": item["control_ids"],
            "required_privilege": item["required_privilege"],
            "timeout_seconds": item["max_timeout_seconds"],
            "max_output_bytes": item["max_output_bytes"],
            "parameters": item["parameters"],
        }
        for item in catalog["probes"]
    }

    actual = {
        item["probe_id"]: {
            key: item[key]
            for key in expected[item["probe_id"]]
        }
        for item in manifest["probes"]
    }
    assert actual == expected
