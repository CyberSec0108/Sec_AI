from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from security_audit.collector.cli import verify_embedded_resources
from security_audit.supply_chain.collector_build import (
    ACCEPTANCE_NAME,
    ARTIFACT_NAME,
    AUTHENTICODE_NAME,
    CLAMAV_NAME,
    DEFENDER_NAME,
    MANIFEST_NAME,
    SBOM_NAME,
    VERSION,
    VULNERABILITY_NAME,
    finalize_imp034_build,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def test_imp034_policy_keeps_unsigned_build_inside_safe_boundary() -> None:
    policy = json.loads(
        (
            PROJECT_ROOT
            / "collectors"
            / "one_shot"
            / "contracts"
            / "imp034_native_build_policy.json"
        ).read_text(encoding="utf-8")
    )

    assert policy["artifact"]["name"] == ARTIFACT_NAME
    assert policy["builder"]["python"] == "3.14.6"
    assert policy["builder"]["pyinstaller"] == "6.21.0"
    assert policy["artifact"]["authenticode"] == "NOT_SIGNED_EXPECTED_UNTIL_IMP035"
    assert policy["output_boundary"]["production_release"] is False
    assert policy["output_boundary"]["portable_bundle_created"] is False
    assert policy["execution_boundary"]["actual_collection_cli_enabled"] is False


def test_embedded_resource_verifier_detects_tampering(tmp_path: Path) -> None:
    resource = tmp_path / "resources" / "contracts" / "sample.json"
    resource.parent.mkdir(parents=True)
    resource.write_bytes(b'{"approved":true}\n')
    _write_json(
        tmp_path / "resources" / "embedded-resources.json",
        {
            "files": [
                {
                    "path": "contracts/sample.json",
                    "bytes": resource.stat().st_size,
                    "sha256": _sha256_bytes(resource.read_bytes()),
                }
            ]
        },
    )

    verified, failures = verify_embedded_resources(tmp_path)
    assert verified == 1
    assert failures == []

    resource.write_bytes(b'{"approved":false}\n')
    verified, failures = verify_embedded_resources(tmp_path)
    assert verified == 0
    assert failures == ["RESOURCE_INTEGRITY_FAILED:contracts/sample.json"]


def _synthetic_output(tmp_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    project_root = tmp_path / "project"
    output = project_root / "runtime" / "imp034-artifacts" / "build-test"
    output.mkdir(parents=True)
    lock = project_root / "requirements" / "lock" / "collector-build.lock"
    lock.parent.mkdir(parents=True)
    lock.write_text(
        "alpha==1.0 \\\n"
        "    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        encoding="utf-8",
    )
    artifact = output / ARTIFACT_NAME
    artifact.write_bytes(b"MZ synthetic PE32+ AMD64 test fixture")
    artifact_hash = _sha256_bytes(artifact.read_bytes())
    lock_hash = _sha256_bytes(lock.read_bytes())
    embedded_name = f"SecAI-Collector-Windows-x64-{VERSION}.embedded-resources.json"
    _write_json(output / embedded_name, {"files": []})
    context: dict[str, Any] = {
        "artifact": {
            "name": ARTIFACT_NAME,
            "bytes": artifact.stat().st_size,
            "sha256": artifact_hash,
            "format": "PE32+",
            "machine": "AMD64",
        },
        "authenticode": "NOT_SIGNED_EXPECTED_UNTIL_IMP035",
        "builder": {
            "os": "Windows-11-test",
            "architecture": "AMD64",
            "python": "3.14.6",
            "pyinstaller": "6.21.0",
        },
        "dependency_lock": {"hash_install": "PASS", "sha256": lock_hash},
        "embedded_resources": {"file_count": 1},
        "self_check": {
            "status": "PASS",
            "frozen_runtime": True,
            "python_runtime": "3.14.6",
            "resource_failures": [],
            "embedded_resources_verified": 1,
            "settings_modified": False,
            "automatic_elevation": False,
            "actual_collection_started": False,
            "official_finding_created": False,
        },
        "source": {"snapshot_sha256": "b" * 64},
        "production_release": False,
    }
    _write_json(output / "imp034-build-context.json", context)
    _write_json(
        output / SBOM_NAME,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [{"name": "alpha", "version": "1.0"}],
        },
    )
    _write_json(
        output / VULNERABILITY_NAME,
        {"dependencies": [{"name": "alpha", "version": "1.0", "vulns": []}]},
    )
    for name, scanner, status in (
        (CLAMAV_NAME, "ClamAV", "CLEAN"),
        (DEFENDER_NAME, "Microsoft Defender", "CLEAN"),
        (AUTHENTICODE_NAME, "Get-AuthenticodeSignature", "NOT_SIGNED"),
    ):
        _write_json(
            output / name,
            {
                "scanner": scanner,
                "status": status,
                "artifact_sha256": artifact_hash,
            },
        )
    return project_root, output, context


def test_finalizer_accepts_matching_sbom_scans_and_lock(tmp_path: Path) -> None:
    project_root, output, _ = _synthetic_output(tmp_path)

    acceptance = finalize_imp034_build(project_root, output)

    assert acceptance["acceptance_status"] == "PASS"
    assert acceptance["known_vulnerabilities"] == 0
    assert acceptance["production_release"] is False
    assert acceptance["portable_bundle_created"] is False
    assert (output / ACCEPTANCE_NAME).is_file()
    assert (output / MANIFEST_NAME).is_file()
    assert (output / "SHA256SUMS.txt").is_file()


def test_finalizer_fails_closed_when_vulnerability_is_reported(
    tmp_path: Path,
) -> None:
    project_root, output, _ = _synthetic_output(tmp_path)
    _write_json(
        output / VULNERABILITY_NAME,
        {
            "dependencies": [
                {
                    "name": "alpha",
                    "version": "1.0",
                    "vulns": [{"id": "TEST-CVE"}],
                }
            ]
        },
    )

    with pytest.raises(ValueError, match="final acceptance failed"):
        finalize_imp034_build(project_root, output)

    acceptance = json.loads(
        (output / ACCEPTANCE_NAME).read_text(encoding="utf-8")
    )
    assert acceptance["acceptance_status"] == "FAIL"
