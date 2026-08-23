from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from security_audit.analysis.package_validation import (
    FullPackageValidator,
    PackageValidationCode,
    PackageValidationError,
)
from security_audit.application.online_submission_acceptance import (
    ORGANIZATION_ID,
    _gates,
    build_imp032_package,
)
from security_audit.common.canonical_json import JsonValue
from security_audit.security.auth import (
    CollectorCredentialCode,
    CollectorCredentialError,
    CollectorCredentialScope,
    CollectorCredentialService,
    InMemoryCollectorCredentialStore,
    OnlineCollectorSubmissionService,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 23, 7, 20, tzinfo=UTC)


def _service() -> tuple[
    InMemoryCollectorCredentialStore,
    CollectorCredentialService,
    OnlineCollectorSubmissionService,
]:
    store = InMemoryCollectorCredentialStore()
    credentials = CollectorCredentialService(
        store,
        hash_key=b"k" * 32,
        hash_key_version="unit-test-v1",
    )
    return (
        store,
        credentials,
        OnlineCollectorSubmissionService(
            credentials,
            FullPackageValidator(PROJECT_ROOT / "database" / "schemas"),
        ),
    )


def _scope(manifest: dict[str, JsonValue]) -> CollectorCredentialScope:
    return CollectorCredentialScope(
        organization_id=ORGANIZATION_ID,
        asset_id=cast(str, manifest["asset_id"]),
        job_id=cast(str, manifest["job_id"]),
        manifest_id=cast(str, manifest["id"]),
        manifest_sha256=cast(str, manifest["manifest_content_sha256"]),
        nonce=cast(str, manifest["nonce"]),
        endpoint_id="imp032-online-upload",
        content_type="application/zip",
        schema_version="1.0.0",
        max_archive_bytes=10 * 1024 * 1024,
    )


def test_credential_record_never_stores_bearer_and_ttl_is_bounded(
    tmp_path: Path,
) -> None:
    archive, _, manifest = build_imp032_package(PROJECT_ROOT, tmp_path)
    del archive
    store, credentials, _ = _service()
    issued = credentials.issue(_scope(manifest), issued_at=NOW)
    record = store.get(issued.credential_id)

    assert record is not None
    assert issued.token not in repr(record)
    assert len(record.token_hash) == 64
    assert issued.expires_at == NOW + timedelta(minutes=60)
    with pytest.raises(ValueError, match="at most two hours"):
        credentials.issue(
            _scope(manifest),
            issued_at=NOW,
            ttl=timedelta(hours=2, seconds=1),
        )


def test_valid_package_commits_once_and_creates_no_finding(tmp_path: Path) -> None:
    archive, descriptor, manifest = build_imp032_package(PROJECT_ROOT, tmp_path)
    _, credentials, submission = _service()
    scope = _scope(manifest)
    issued = credentials.issue(scope, issued_at=NOW - timedelta(minutes=5))
    digest = sha256(archive.read_bytes()).hexdigest()

    accepted = submission.submit(
        token=issued.token,
        archive_path=archive,
        descriptor_bytes=descriptor,
        trusted_manifest=manifest,
        content_type="application/zip",
        received_at=NOW,
        verifications=_gates(scope, digest, archive.stat().st_size),
    )

    assert accepted.receipt.asset_id == scope.asset_id
    assert accepted.receipt.job_id == scope.job_id
    assert accepted.official_finding_created is False
    with pytest.raises(CollectorCredentialError) as replay:
        submission.submit(
            token=issued.token,
            archive_path=archive,
            descriptor_bytes=descriptor,
            trusted_manifest=manifest,
            content_type="application/zip",
            received_at=NOW,
            verifications=_gates(scope, digest, archive.stat().st_size),
        )
    assert replay.value.code is CollectorCredentialCode.ALREADY_USED


def test_expired_revoked_malformed_and_wrong_secret_fail_closed(
    tmp_path: Path,
) -> None:
    _, _, manifest = build_imp032_package(PROJECT_ROOT, tmp_path)
    _, credentials, _ = _service()
    scope = _scope(manifest)
    expired = credentials.issue(
        scope,
        issued_at=NOW - timedelta(hours=2),
        ttl=timedelta(minutes=30),
    )
    revoked = credentials.issue(scope, issued_at=NOW - timedelta(minutes=5))
    credentials.revoke(revoked.credential_id, revoked_at=NOW - timedelta(minutes=1))
    replacement = "A" if revoked.token[-1] != "A" else "B"
    wrong_secret = revoked.token[:-1] + replacement

    cases = (
        (expired.token, CollectorCredentialCode.EXPIRED),
        (revoked.token, CollectorCredentialCode.REVOKED),
        ("not-a-token", CollectorCredentialCode.MALFORMED),
        (wrong_secret, CollectorCredentialCode.INVALID),
    )
    for token, expected in cases:
        with pytest.raises(CollectorCredentialError) as captured:
            credentials.authorize(token, received_at=NOW)
        assert captured.value.code is expected

    limited = credentials.issue(scope, issued_at=NOW - timedelta(minutes=5))
    replacement = "A" if limited.token[-1] != "A" else "B"
    wrong_limited = limited.token[:-1] + replacement
    for _ in range(5):
        with pytest.raises(CollectorCredentialError) as invalid:
            credentials.authorize(wrong_limited, received_at=NOW)
        assert invalid.value.code is CollectorCredentialCode.INVALID
    with pytest.raises(CollectorCredentialError) as locked:
        credentials.authorize(limited.token, received_at=NOW)
    assert locked.value.code is CollectorCredentialCode.ATTEMPTS_EXCEEDED


def test_manifest_and_asset_scope_mismatch_do_not_consume_credential(
    tmp_path: Path,
) -> None:
    archive, descriptor, manifest = build_imp032_package(PROJECT_ROOT, tmp_path)
    store, credentials, submission = _service()
    scope = _scope(manifest)
    issued = credentials.issue(scope, issued_at=NOW - timedelta(minutes=5))
    digest = sha256(archive.read_bytes()).hexdigest()
    other_manifest = copy.deepcopy(manifest)
    other_manifest["id"] = "32000000-0000-4000-8000-000000000099"

    with pytest.raises(CollectorCredentialError) as manifest_error:
        submission.submit(
            token=issued.token,
            archive_path=archive,
            descriptor_bytes=descriptor,
            trusted_manifest=other_manifest,
            content_type="application/zip",
            received_at=NOW,
            verifications=_gates(scope, digest, archive.stat().st_size),
        )
    assert manifest_error.value.code is CollectorCredentialCode.SCOPE_MISMATCH

    with pytest.raises(CollectorCredentialError) as media_type_error:
        submission.submit(
            token=issued.token,
            archive_path=archive,
            descriptor_bytes=descriptor,
            trusted_manifest=manifest,
            content_type="application/octet-stream",
            received_at=NOW,
            verifications=_gates(scope, digest, archive.stat().st_size),
        )
    assert media_type_error.value.code is CollectorCredentialCode.SCOPE_MISMATCH

    wrong_schema = json.loads(descriptor)
    wrong_schema["schema_version"] = "9.9.9"
    with pytest.raises(PackageValidationError) as schema_error:
        submission.submit(
            token=issued.token,
            archive_path=archive,
            descriptor_bytes=json.dumps(wrong_schema).encode(),
            trusted_manifest=manifest,
            content_type="application/zip",
            received_at=NOW,
            verifications=_gates(scope, digest, archive.stat().st_size),
        )
    assert schema_error.value.code is PackageValidationCode.DESCRIPTOR_SEMANTIC_INVALID

    wrong_asset = json.loads(descriptor)
    wrong_asset["asset_id"] = "32000000-0000-4000-8000-000000000099"
    with pytest.raises(PackageValidationError) as asset_error:
        submission.submit(
            token=issued.token,
            archive_path=archive,
            descriptor_bytes=json.dumps(wrong_asset).encode(),
            trusted_manifest=manifest,
            content_type="application/zip",
            received_at=NOW,
            verifications=_gates(scope, digest, archive.stat().st_size),
        )
    assert asset_error.value.code is PackageValidationCode.MANIFEST_SCOPE_MISMATCH
    record = store.get(issued.credential_id)
    assert record is not None and record.used_at is None


def test_same_nonce_cannot_commit_with_second_credential(tmp_path: Path) -> None:
    archive, descriptor, manifest = build_imp032_package(PROJECT_ROOT, tmp_path)
    _, credentials, submission = _service()
    scope = _scope(manifest)
    first = credentials.issue(scope, issued_at=NOW - timedelta(minutes=5))
    second = credentials.issue(scope, issued_at=NOW - timedelta(minutes=5))
    digest = sha256(archive.read_bytes()).hexdigest()
    gates = _gates(scope, digest, archive.stat().st_size)

    submission.submit(
        token=first.token,
        archive_path=archive,
        descriptor_bytes=descriptor,
        trusted_manifest=manifest,
        content_type="application/zip",
        received_at=NOW,
        verifications=gates,
    )
    with pytest.raises(CollectorCredentialError) as replay:
        submission.submit(
            token=second.token,
            archive_path=archive,
            descriptor_bytes=descriptor,
            trusted_manifest=manifest,
            content_type="application/zip",
            received_at=NOW,
            verifications=gates,
        )
    assert replay.value.code is CollectorCredentialCode.NONCE_REPLAYED


def test_policy_forbids_secret_leak_locations() -> None:
    policy = json.loads(
        (
            PROJECT_ROOT
            / "collectors"
            / "one_shot"
            / "contracts"
            / "imp032_online_submission_policy.json"
        ).read_text(encoding="utf-8")
    )
    assert policy["credential"]["successful_commits"] == 1
    assert set(policy["credential"]["forbidden_locations"]) == {
        "COMMAND_LINE",
        "PACKAGE",
        "SOURCE",
        "LOG",
        "BROWSER_STORAGE",
    }
    assert policy["implementation_boundary"]["credential_issue_http_endpoint"] is False
