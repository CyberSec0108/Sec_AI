from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from security_audit.supply_chain.collector_release import (
    ACCEPTANCE_NAME,
    ARTIFACT_NAME,
    CLAMAV_NAME,
    DEFENDER_NAME,
    MANIFEST_NAME,
    SIGNING_CONTEXT_NAME,
    finalize_imp035_release,
    validate_revocation_status,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 23, 8, 0, tzinfo=UTC)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def test_imp035_policy_separates_dev_signature_from_production_release() -> None:
    policy = json.loads(
        (
            PROJECT_ROOT
            / "collectors"
            / "one_shot"
            / "contracts"
            / "imp035_release_policy.json"
        ).read_text(encoding="utf-8")
    )

    assert policy["development_profile"]["id"] == "DEV-EPHEMERAL-AUTHENTICODE"
    assert policy["development_profile"]["private_key_exportable"] is False
    assert policy["development_profile"]["timestamp_required"] is True
    assert policy["external_release_gates"]["organization_code_signing_certificate"]
    assert policy["external_release_gates"]["clean_windows_11_vm"]
    assert policy["output_boundary"]["production_release"] is False
    assert policy["output_boundary"]["download_enabled"] is False


def _synthetic_output(tmp_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    project_root = tmp_path / "project"
    output = project_root / "runtime" / "imp035-artifacts" / "acceptance-test"
    output.mkdir(parents=True)
    original_hash = "a" * 64
    artifact = output / ARTIFACT_NAME
    artifact.write_bytes(b"MZ signed synthetic collector fixture")
    signed_hash = _sha256(artifact.read_bytes())
    context: dict[str, Any] = {
        "pre_sign_sha256": original_hash,
        "post_sign_sha256": signed_hash,
        "signature": {
            "status_at_signing": "CryptographicallyValidUntrustedRoot",
            "digest_algorithm": "SHA256",
            "timestamp_present": True,
            "timestamp_subject": "CN=Test Timestamp",
        },
        "certificate": {
            "subject": "CN=Sec_AI IMP-035 DEV Publisher test",
            "issuer": "CN=Sec_AI IMP-035 DEV Root test",
            "key_algorithm": "RSA",
            "key_bits": 3072,
            "eku_oid": "1.3.6.1.5.5.7.3.3",
            "private_key_exportable": False,
        },
        "chain": {
            "valid_at_signing": True,
            "elements": 1,
            "root_pinned": True,
        },
        "revocation": {
            "profile": "EPHEMERAL_DEV_CA_POLICY",
            "status": "GOOD",
            "checked_at": (NOW - timedelta(minutes=5)).isoformat(),
        },
        "tamper_test": {
            "signature_status": "HashMismatch",
            "rejected": True,
        },
        "execution": {
            "self_check": "PASS",
            "frozen_runtime": True,
            "actual_collection_started": False,
            "settings_modified": False,
        },
        "trust_cleanup": {
            "root_store_removed": True,
            "publisher_store_removed": True,
            "private_keys_removed": True,
        },
        "production_release": False,
        "download_enabled": False,
        "official_finding_created": False,
        "portable_bundle_created": False,
    }
    _write_json(output / SIGNING_CONTEXT_NAME, context)
    _write_json(
        output / "imp034-acceptance.source.json",
        {
            "acceptance_status": "PASS",
            "artifact": {
                "release_channel": "DEV-UNSIGNED",
                "sha256": original_hash,
            },
        },
    )
    _write_json(
        output / "SecAI-Collector-Windows-x64-0.1.0.cdx.json",
        {"bomFormat": "CycloneDX"},
    )
    _write_json(
        output / "SecAI-Collector-Windows-x64-0.1.0.vulnerability.json",
        {"dependencies": [{"name": "alpha", "version": "1.0", "vulns": []}]},
    )
    for name, scanner in (
        (CLAMAV_NAME, "ClamAV"),
        (DEFENDER_NAME, "Microsoft Defender"),
    ):
        _write_json(
            output / name,
            {
                "scanner": scanner,
                "status": "CLEAN",
                "artifact_sha256": signed_hash,
            },
        )
    return project_root, output, context


def test_dev_signature_acceptance_passes_but_production_stays_blocked(
    tmp_path: Path,
) -> None:
    project_root, output, _ = _synthetic_output(tmp_path)

    acceptance = finalize_imp035_release(project_root, output, now=NOW)

    assert acceptance["acceptance_status"] == "PASS_WITH_DEFERRED_EXTERNAL_GATES"
    assert acceptance["implementation_complete"] is True
    assert acceptance["imp_complete"] is False
    assert acceptance["production_release_ready"] is False
    assert len(acceptance["implementation_checks"]) == 12
    assert all(check["passed"] for check in acceptance["implementation_checks"])
    assert {gate["status"] for gate in acceptance["external_gates"]} == {"DEFERRED"}
    assert acceptance["download_enabled"] is False
    assert (output / ACCEPTANCE_NAME).is_file()
    assert (output / MANIFEST_NAME).is_file()


def test_tampered_signature_fails_closed(tmp_path: Path) -> None:
    project_root, output, context = _synthetic_output(tmp_path)
    context["tamper_test"]["rejected"] = False
    _write_json(output / SIGNING_CONTEXT_NAME, context)

    with pytest.raises(ValueError, match="development acceptance failed"):
        finalize_imp035_release(project_root, output, now=NOW)

    acceptance = json.loads(
        (output / ACCEPTANCE_NAME).read_text(encoding="utf-8")
    )
    failed = {
        item["id"] for item in acceptance["implementation_checks"] if not item["passed"]
    }
    assert failed == {"IMP035-C07"}


@pytest.mark.parametrize("status", ["REVOKED", "UNAVAILABLE", "UNKNOWN"])
def test_revoked_or_unavailable_status_is_rejected(status: str) -> None:
    with pytest.raises(ValueError, match="must be GOOD"):
        validate_revocation_status(
            status,
            (NOW - timedelta(minutes=5)).isoformat(),
            now=NOW,
        )


@pytest.mark.parametrize(
    "checked_at",
    [
        NOW - timedelta(hours=24, seconds=1),
        NOW + timedelta(seconds=1),
    ],
)
def test_stale_or_future_revocation_status_is_rejected(
    checked_at: datetime,
) -> None:
    with pytest.raises(ValueError, match="stale or from the future"):
        validate_revocation_status("GOOD", checked_at.isoformat(), now=NOW)
