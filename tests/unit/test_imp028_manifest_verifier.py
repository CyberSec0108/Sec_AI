from __future__ import annotations

import copy
import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from security_audit.collector import (
    MAX_MANIFEST_BYTES,
    CollectorManifestVerifier,
    ExternalSignatureStatus,
    ManifestSignatureProof,
    ManifestVerificationCode,
    ManifestVerificationContext,
    ManifestVerificationError,
    MockCollectionCode,
    MockCollectionError,
    MockCollector,
    NonceStatus,
    ProbeAllowlist,
)
from security_audit.common.canonical_json import JsonValue, canonical_sha256_without_fields

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"
ALLOWLIST_PATH = (
    PROJECT_ROOT / "collectors" / "one_shot" / "contracts" / "imp028_probe_allowlist.json"
)
MANIFEST_PATH = (
    PROJECT_ROOT / "collectors" / "one_shot" / "fixtures" / "imp028" / "valid_manifest.json"
)
CHECKED_AT = datetime(2026, 7, 23, 6, 15, tzinfo=UTC)


def _manifest() -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], json.loads(MANIFEST_PATH.read_text(encoding="utf-8")))


def _context(**overrides: Any) -> ManifestVerificationContext:
    values: dict[str, Any] = {
        "expected_job_id": "28000000-0000-4000-8000-000000000003",
        "expected_asset_id": "28000000-0000-4000-8000-000000000004",
        "expected_endpoint_id": "imp028-mock-upload",
        "expected_nonce": "SU1QLTAyOC1ub25jZS0wMDAx",
        "checked_at": CHECKED_AT,
        "nonce_status": NonceStatus.FRESH,
    }
    values.update(overrides)
    return ManifestVerificationContext(**values)


def _proof(
    manifest: dict[str, JsonValue],
    status: ExternalSignatureStatus = ExternalSignatureStatus.VERIFIED,
) -> ManifestSignatureProof:
    authorization = cast(dict[str, Any], manifest["authorization"])
    signature = cast(dict[str, Any], authorization["signature"])
    return ManifestSignatureProof(
        status=status,
        manifest_sha256=cast(str, manifest["manifest_content_sha256"]),
        key_id=cast(str, signature["key_id"]),
    )


def _reseal(manifest: dict[str, JsonValue]) -> ManifestSignatureProof:
    digest = canonical_sha256_without_fields(
        manifest,
        {"manifest_content_sha256", "authorization"},
    )
    manifest["manifest_content_sha256"] = digest
    authorization = cast(dict[str, Any], manifest["authorization"])
    signature = cast(dict[str, Any], authorization["signature"])
    signature["signed_sha256"] = digest
    return _proof(manifest)


@pytest.fixture
def verifier() -> CollectorManifestVerifier:
    return CollectorManifestVerifier(
        SCHEMA_ROOT,
        ProbeAllowlist.from_file(ALLOWLIST_PATH),
    )


def _expect_code(
    verifier: CollectorManifestVerifier,
    manifest: dict[str, JsonValue],
    expected: ManifestVerificationCode,
    *,
    context: ManifestVerificationContext | None = None,
    proof: ManifestSignatureProof | None = None,
) -> None:
    with pytest.raises(ManifestVerificationError) as captured:
        verifier.verify(manifest, context or _context(), proof or _proof(manifest))
    assert captured.value.code is expected


def test_valid_manifest_creates_narrow_plan_and_mock_results_only(
    verifier: CollectorManifestVerifier,
) -> None:
    manifest = _manifest()
    plan = verifier.verify_bytes(MANIFEST_PATH.read_bytes(), _context(), _proof(manifest))
    collector = MockCollector()

    run = collector.execute(plan)

    assert tuple(probe.probe_id for probe in plan.probes) == (
        "win.storage.disks",
        "win.storage.partitions",
        "win.storage.volumes",
    )
    assert run.execution_mode == "MOCK_ONLY"
    assert run.real_os_access is False
    assert all(result.synthetic for result in run.results)
    assert all(result.collection_status is MockCollectionCode.COLLECTED for result in run.results)
    assert not hasattr(run, "finding")
    assert not hasattr(run, "status")


def test_mock_collector_rejects_same_nonce_twice(
    verifier: CollectorManifestVerifier,
) -> None:
    manifest = _manifest()
    plan = verifier.verify(manifest, _context(), _proof(manifest))
    collector = MockCollector()
    collector.execute(plan)

    with pytest.raises(MockCollectionError) as captured:
        collector.execute(plan)

    assert captured.value.code is MockCollectionCode.REPLAY_DETECTED


def test_manifest_hash_tamper_is_rejected(
    verifier: CollectorManifestVerifier,
) -> None:
    manifest = _manifest()
    manifest["expires_at"] = "2026-07-23T06:31:00Z"
    _expect_code(verifier, manifest, ManifestVerificationCode.HASH_MISMATCH)


def test_signature_digest_mismatch_is_rejected(
    verifier: CollectorManifestVerifier,
) -> None:
    manifest = _manifest()
    authorization = cast(dict[str, Any], manifest["authorization"])
    signature = cast(dict[str, Any], authorization["signature"])
    signature["signed_sha256"] = "0" * 64
    _expect_code(
        verifier,
        manifest,
        ManifestVerificationCode.SIGNATURE_HASH_MISMATCH,
    )


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (ExternalSignatureStatus.FAILED, ManifestVerificationCode.SIGNATURE_INVALID),
        (
            ExternalSignatureStatus.UNAVAILABLE,
            ManifestVerificationCode.SIGNATURE_UNAVAILABLE,
        ),
    ],
)
def test_external_signature_gate_fails_closed(
    verifier: CollectorManifestVerifier,
    status: ExternalSignatureStatus,
    expected: ManifestVerificationCode,
) -> None:
    manifest = _manifest()
    _expect_code(verifier, manifest, expected, proof=_proof(manifest, status))


@pytest.mark.parametrize(
    ("context", "expected"),
    [
        (
            _context(checked_at=datetime(2026, 7, 23, 5, 59, tzinfo=UTC)),
            ManifestVerificationCode.MANIFEST_NOT_YET_VALID,
        ),
        (
            _context(checked_at=datetime(2026, 7, 23, 6, 31, tzinfo=UTC)),
            ManifestVerificationCode.MANIFEST_EXPIRED,
        ),
        (
            _context(expected_asset_id="28000000-0000-4000-8000-000000000099"),
            ManifestVerificationCode.MANIFEST_SCOPE_MISMATCH,
        ),
        (
            _context(nonce_status=NonceStatus.REPLAYED),
            ManifestVerificationCode.NONCE_REPLAYED,
        ),
        (
            _context(nonce_status=NonceStatus.UNAVAILABLE),
            ManifestVerificationCode.NONCE_CHECK_UNAVAILABLE,
        ),
    ],
)
def test_time_scope_and_nonce_gates(
    verifier: CollectorManifestVerifier,
    context: ManifestVerificationContext,
    expected: ManifestVerificationCode,
) -> None:
    manifest = _manifest()
    _expect_code(verifier, manifest, expected, context=context)


def _mutate_unknown_probe(manifest: dict[str, JsonValue]) -> None:
    probes = cast(list[dict[str, Any]], manifest["probes"])
    probes[0]["probe_id"] = "win.untrusted.command"


def _mutate_probe_version(manifest: dict[str, JsonValue]) -> None:
    probes = cast(list[dict[str, Any]], manifest["probes"])
    probes[0]["probe_version"] = "9.9.9"


def _mutate_probe_privilege(manifest: dict[str, JsonValue]) -> None:
    probes = cast(list[dict[str, Any]], manifest["probes"])
    probes[0]["required_privilege"] = "ELEVATED_ADMIN"


def _mutate_probe_timeout(manifest: dict[str, JsonValue]) -> None:
    probes = cast(list[dict[str, Any]], manifest["probes"])
    probes[0]["timeout_seconds"] = 31


def _mutate_probe_output_limit(manifest: dict[str, JsonValue]) -> None:
    probes = cast(list[dict[str, Any]], manifest["probes"])
    probes[0]["max_output_bytes"] = 65537


def _mutate_probe_parameters(manifest: dict[str, JsonValue]) -> None:
    probes = cast(list[dict[str, Any]], manifest["probes"])
    probes[2]["parameters"] = {"include_fixed": False}


@pytest.mark.parametrize(
    ("mutator", "expected"),
    [
        (_mutate_unknown_probe, ManifestVerificationCode.PROBE_NOT_ALLOWED),
        (_mutate_probe_version, ManifestVerificationCode.PROBE_CONTRACT_MISMATCH),
        (_mutate_probe_privilege, ManifestVerificationCode.PROBE_CONTRACT_MISMATCH),
        (_mutate_probe_timeout, ManifestVerificationCode.PROBE_CONTRACT_MISMATCH),
        (_mutate_probe_output_limit, ManifestVerificationCode.PROBE_CONTRACT_MISMATCH),
        (_mutate_probe_parameters, ManifestVerificationCode.PROBE_CONTRACT_MISMATCH),
    ],
)
def test_probe_allowlist_is_exact(
    verifier: CollectorManifestVerifier,
    mutator: Callable[[dict[str, JsonValue]], None],
    expected: ManifestVerificationCode,
) -> None:
    manifest = _manifest()
    mutator(manifest)
    proof = _reseal(manifest)
    _expect_code(verifier, manifest, expected, proof=proof)


def test_duplicate_probe_is_rejected(
    verifier: CollectorManifestVerifier,
) -> None:
    manifest = _manifest()
    probes = cast(list[dict[str, Any]], manifest["probes"])
    probes.append(copy.deepcopy(probes[0]))
    proof = _reseal(manifest)
    _expect_code(
        verifier,
        manifest,
        ManifestVerificationCode.PROBE_DUPLICATED,
        proof=proof,
    )


def test_collector_version_and_channel_must_match_signed_constraint(
    verifier: CollectorManifestVerifier,
) -> None:
    manifest = _manifest()
    constraint = cast(dict[str, Any], manifest["collector_constraint"])
    constraint["release_channel"] = "SIGNED-PILOT"
    proof = _reseal(manifest)
    _expect_code(
        verifier,
        manifest,
        ManifestVerificationCode.COLLECTOR_CONSTRAINT_MISMATCH,
        proof=proof,
    )


def test_free_form_command_field_is_rejected_by_schema(
    verifier: CollectorManifestVerifier,
) -> None:
    manifest = _manifest()
    probes = cast(list[dict[str, Any]], manifest["probes"])
    probes[0]["command"] = "powershell.exe -Command arbitrary-input"
    _expect_code(verifier, manifest, ManifestVerificationCode.SCHEMA_INVALID)


def test_strict_bytes_reject_duplicate_keys_and_absolute_size_limit(
    verifier: CollectorManifestVerifier,
) -> None:
    manifest = _manifest()
    with pytest.raises(ManifestVerificationError) as duplicate:
        verifier.verify_bytes(
            b'{"schema_version":"1.0.0","schema_version":"9.9.9"}',
            _context(),
            _proof(manifest),
        )
    with pytest.raises(ManifestVerificationError) as oversized:
        verifier.verify_bytes(
            b"{" + (b" " * MAX_MANIFEST_BYTES) + b"}",
            _context(),
            _proof(manifest),
        )

    assert duplicate.value.code is ManifestVerificationCode.JSON_INVALID
    assert oversized.value.code is ManifestVerificationCode.INPUT_TOO_LARGE


def test_signature_proof_must_bind_digest_and_key(
    verifier: CollectorManifestVerifier,
) -> None:
    manifest = _manifest()
    proof = replace(_proof(manifest), key_id="another-key")
    _expect_code(
        verifier,
        manifest,
        ManifestVerificationCode.SIGNATURE_INVALID,
        proof=proof,
    )
