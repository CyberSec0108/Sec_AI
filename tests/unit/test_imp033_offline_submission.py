from __future__ import annotations

import copy
import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from security_audit.application.offline_submission import (
    InMemoryOfflineReplayStore,
    OfflinePackageSubmissionService,
    OfflineSubmissionCode,
    OfflineSubmissionError,
)
from security_audit.application.offline_submission_acceptance import (
    RECEIVED_AT,
    _service,
    _user_context,
    _user_descriptor,
    build_imp033_case,
    run_offline_submission_acceptance,
)
from security_audit.security.signatures import (
    CertificateRevocationStatus,
    OfflineSignatureCode,
    OfflineSignatureError,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_signed_package_is_medium_assurance_and_creates_no_finding(
    tmp_path: Path,
) -> None:
    case = build_imp033_case(PROJECT_ROOT, tmp_path)

    result = _service(PROJECT_ROOT, case).submit_signed(
        archive_path=case.archive_path,
        descriptor_bytes=case.descriptor_bytes,
        trusted_manifest=case.manifest,
        signature_envelope_bytes=case.envelope_bytes,
        received_at=RECEIVED_AT,
        revocation=case.revocation,
        verifications=case.verifications,
    )

    assert result.receipt.profile == "OFFLINE-SIGNED"
    assert result.receipt.assurance_level == "MEDIUM"
    assert result.receipt.certificate_sha256 == case.revocation.certificate_sha256
    assert result.receipt.authenticated_subject_id is None
    assert result.official_finding_created is False


def test_signature_tampering_is_rejected(tmp_path: Path) -> None:
    case = build_imp033_case(PROJECT_ROOT, tmp_path)
    envelope = copy.deepcopy(case.envelope)
    signature = envelope["signature"]["value"]
    envelope["signature"]["value"] = (
        ("A" if signature[0] != "A" else "B") + signature[1:]
    )

    with pytest.raises(OfflineSignatureError) as captured:
        _service(PROJECT_ROOT, case).submit_signed(
            archive_path=case.archive_path,
            descriptor_bytes=case.descriptor_bytes,
            trusted_manifest=case.manifest,
            signature_envelope_bytes=json.dumps(envelope).encode(),
            received_at=RECEIVED_AT,
            revocation=case.revocation,
            verifications=case.verifications,
        )

    assert captured.value.code is OfflineSignatureCode.SIGNATURE_INVALID


@pytest.mark.parametrize(
    ("certificate_asset_id", "include_package_eku", "expected"),
    [
        (
            None,
            False,
            OfflineSignatureCode.CERTIFICATE_WRONG_EKU,
        ),
        (
            "33000000-0000-4000-8000-000000000099",
            True,
            OfflineSignatureCode.CERTIFICATE_SUBJECT_MISMATCH,
        ),
    ],
)
def test_wrong_eku_and_asset_certificate_are_rejected(
    tmp_path: Path,
    certificate_asset_id: str | None,
    include_package_eku: bool,
    expected: OfflineSignatureCode,
) -> None:
    case = build_imp033_case(
        PROJECT_ROOT,
        tmp_path,
        certificate_asset_id=certificate_asset_id,
        include_package_eku=include_package_eku,
    )

    with pytest.raises(OfflineSignatureError) as captured:
        _service(PROJECT_ROOT, case).submit_signed(
            archive_path=case.archive_path,
            descriptor_bytes=case.descriptor_bytes,
            trusted_manifest=case.manifest,
            signature_envelope_bytes=case.envelope_bytes,
            received_at=RECEIVED_AT,
            revocation=case.revocation,
            verifications=case.verifications,
        )

    assert captured.value.code is expected


def test_untrusted_root_and_revocation_fail_closed(tmp_path: Path) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    case = build_imp033_case(PROJECT_ROOT, first_dir)
    other = build_imp033_case(PROJECT_ROOT, second_dir)
    untrusted = _service(PROJECT_ROOT, other)

    with pytest.raises(OfflineSignatureError) as root_error:
        untrusted.submit_signed(
            archive_path=case.archive_path,
            descriptor_bytes=case.descriptor_bytes,
            trusted_manifest=case.manifest,
            signature_envelope_bytes=case.envelope_bytes,
            received_at=RECEIVED_AT,
            revocation=case.revocation,
            verifications=case.verifications,
        )
    assert root_error.value.code is OfflineSignatureCode.CERTIFICATE_UNTRUSTED

    for status, expected in (
        (
            CertificateRevocationStatus.REVOKED,
            OfflineSignatureCode.CERTIFICATE_REVOKED,
        ),
        (
            CertificateRevocationStatus.UNAVAILABLE,
            OfflineSignatureCode.REVOCATION_UNAVAILABLE,
        ),
    ):
        with pytest.raises(OfflineSignatureError) as revocation_error:
            _service(PROJECT_ROOT, case).submit_signed(
                archive_path=case.archive_path,
                descriptor_bytes=case.descriptor_bytes,
                trusted_manifest=case.manifest,
                signature_envelope_bytes=case.envelope_bytes,
                received_at=RECEIVED_AT,
                revocation=replace(case.revocation, status=status),
                verifications=case.verifications,
            )
        assert revocation_error.value.code is expected

    with pytest.raises(OfflineSignatureError) as stale_error:
        _service(PROJECT_ROOT, case).submit_signed(
            archive_path=case.archive_path,
            descriptor_bytes=case.descriptor_bytes,
            trusted_manifest=case.manifest,
            signature_envelope_bytes=case.envelope_bytes,
            received_at=RECEIVED_AT,
            revocation=replace(
                case.revocation,
                checked_at=RECEIVED_AT - timedelta(hours=24, seconds=1),
            ),
            verifications=case.verifications,
        )
    assert stale_error.value.code is OfflineSignatureCode.REVOCATION_UNAVAILABLE


def test_user_submission_is_low_assurance_and_bound_to_uploader(
    tmp_path: Path,
) -> None:
    case = build_imp033_case(PROJECT_ROOT, tmp_path)

    result = _service(PROJECT_ROOT, case).submit_user(
        archive_path=case.archive_path,
        descriptor_bytes=_user_descriptor(case),
        trusted_manifest=case.manifest,
        user=_user_context(case),
        verifications=case.verifications,
    )

    assert result.receipt.profile == "OFFLINE-USER-SUBMITTED"
    assert result.receipt.assurance_level == "LOW"
    assert result.receipt.authenticated_subject_id is not None
    assert result.receipt.certificate_sha256 is None
    assert result.official_finding_created is False


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"session_active": False}, OfflineSubmissionCode.USER_AUTH_REQUIRED),
        ({"csrf_verified": False}, OfflineSubmissionCode.CSRF_REQUIRED),
        ({"authorized_for_asset": False}, OfflineSubmissionCode.USER_SCOPE_MISMATCH),
    ],
)
def test_user_submission_requires_login_csrf_and_asset_scope(
    tmp_path: Path,
    overrides: dict[str, object],
    expected: OfflineSubmissionCode,
) -> None:
    case = build_imp033_case(PROJECT_ROOT, tmp_path)

    with pytest.raises(OfflineSubmissionError) as captured:
        _service(PROJECT_ROOT, case).submit_user(
            archive_path=case.archive_path,
            descriptor_bytes=_user_descriptor(case),
            trusted_manifest=case.manifest,
            user=_user_context(case, **overrides),
            verifications=case.verifications,
        )

    assert captured.value.code is expected


def test_same_nonce_is_rejected_across_offline_profiles(tmp_path: Path) -> None:
    case = build_imp033_case(PROJECT_ROOT, tmp_path)
    replay_store = InMemoryOfflineReplayStore()
    service: OfflinePackageSubmissionService = _service(
        PROJECT_ROOT,
        case,
        replay_store=replay_store,
    )
    service.submit_signed(
        archive_path=case.archive_path,
        descriptor_bytes=case.descriptor_bytes,
        trusted_manifest=case.manifest,
        signature_envelope_bytes=case.envelope_bytes,
        received_at=RECEIVED_AT,
        revocation=case.revocation,
        verifications=case.verifications,
    )

    with pytest.raises(OfflineSubmissionError) as captured:
        service.submit_user(
            archive_path=case.archive_path,
            descriptor_bytes=_user_descriptor(case),
            trusted_manifest=case.manifest,
            user=_user_context(case),
            verifications=case.verifications,
        )

    assert captured.value.code is OfflineSubmissionCode.REPLAYED


def test_acceptance_report_exposes_no_key_certificate_or_evidence() -> None:
    report = run_offline_submission_acceptance(PROJECT_ROOT)
    serialized = json.dumps(report)

    assert report["acceptance_status"] == "PASS"
    assert report["private_key_persisted"] is False
    assert report["real_certificate_issued"] is False
    assert report["original_evidence_persisted"] is False
    assert report["production_upload_endpoint_enabled"] is False
    assert report["official_finding_created"] is False
    assert "BEGIN PRIVATE KEY" not in serialized
    assert "leaf_certificate_der_base64url" not in serialized
