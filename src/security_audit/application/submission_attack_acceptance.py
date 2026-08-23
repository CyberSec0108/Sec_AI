"""IMP-039 synthetic submission and signature attack regression."""

from __future__ import annotations

import copy
import json
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

from security_audit.analysis.package_validation import (
    DigestVerification,
    ExternalVerificationStatus,
    FullPackageValidator,
    PackageValidationCode,
    PackageValidationError,
)
from security_audit.application.offline_submission import (
    InMemoryOfflineReplayStore,
    OfflinePackageSubmissionService,
    OfflineSubmissionCode,
    OfflineSubmissionError,
)
from security_audit.application.offline_submission_acceptance import (
    RECEIVED_AT as OFFLINE_RECEIVED_AT,
)
from security_audit.application.offline_submission_acceptance import (
    OfflineAcceptanceCase,
    _user_context,
    _user_descriptor,
    build_imp033_case,
)
from security_audit.application.offline_submission_acceptance import (
    _service as offline_service,
)
from security_audit.application.online_submission_acceptance import (
    RECEIVED_AT as ONLINE_RECEIVED_AT,
)
from security_audit.application.online_submission_acceptance import (
    _gates,
    _scope,
    build_imp032_package,
)
from security_audit.common.canonical_json import JsonValue
from security_audit.security.auth import (
    CollectorCredentialCode,
    CollectorCredentialError,
    CollectorCredentialService,
    InMemoryCollectorCredentialStore,
    OnlineCollectorSubmissionService,
    OnlineExternalVerifications,
)
from security_audit.security.signatures import (
    CertificateRevocationStatus,
    OfflineSignatureCode,
    OfflineSignatureError,
)

OTHER_ORGANIZATION_ID = "39000000-0000-4000-8000-000000000001"
OTHER_ASSET_ID = "39000000-0000-4000-8000-000000000002"
OTHER_JOB_ID = "39000000-0000-4000-8000-000000000003"
OTHER_MANIFEST_ID = "39000000-0000-4000-8000-000000000004"

_USER_MESSAGES = {
    "PACKAGE_TAMPER": "점검 자료가 변경되어 접수를 중단했습니다.",
    "EXPIRY": "사용 시간이 지난 요청이므로 다시 점검해야 합니다.",
    "REPLAY": "이미 처리된 요청이므로 중복 접수를 차단했습니다.",
    "SCOPE": "허용된 PC와 작업 범위가 일치하지 않아 접수를 중단했습니다.",
    "SIGNATURE": "서명 또는 인증서 확인에 실패하여 접수를 중단했습니다.",
    "USER_AUTH": "로그인·화면 요청·PC 접근 권한을 확인할 수 없어 접수를 중단했습니다.",
}


@dataclass(slots=True)
class _DownstreamRecorder:
    """Count only attack submissions that escape the acceptance boundary."""

    attack_submissions_accepted: int = 0
    objects_persisted: int = 0
    normalizer_runs: int = 0
    rule_runs: int = 0
    finding_writes: int = 0
    official_findings_created: int = 0

    def escaped(self) -> None:
        self.attack_submissions_accepted += 1
        self.objects_persisted += 1
        self.normalizer_runs += 1
        self.rule_runs += 1
        self.finding_writes += 1

    def as_dict(self) -> dict[str, int]:
        return {
            "attack_submissions_accepted": self.attack_submissions_accepted,
            "objects_persisted": self.objects_persisted,
            "normalizer_runs": self.normalizer_runs,
            "rule_runs": self.rule_runs,
            "finding_writes": self.finding_writes,
            "official_findings_created": self.official_findings_created,
        }


@dataclass(slots=True)
class _OnlineBundle:
    archive_path: Path
    descriptor_bytes: bytes
    manifest: dict[str, JsonValue]
    store: InMemoryCollectorCredentialStore
    credentials: CollectorCredentialService
    submission: OnlineCollectorSubmissionService
    verifications: OnlineExternalVerifications

    def issue(self, *, expired: bool = False) -> str:
        issued_at = (
            ONLINE_RECEIVED_AT - timedelta(hours=2)
            if expired
            else ONLINE_RECEIVED_AT - timedelta(minutes=5)
        )
        ttl = timedelta(minutes=30) if expired else timedelta(minutes=60)
        return self.credentials.issue(
            _scope(self.manifest, 10 * 1024 * 1024),
            issued_at=issued_at,
            ttl=ttl,
        ).token

    def submit(
        self,
        token: str,
        *,
        archive_path: Path | None = None,
        descriptor_bytes: bytes | None = None,
        manifest: dict[str, JsonValue] | None = None,
        content_type: str = "application/zip",
        received_at: datetime = ONLINE_RECEIVED_AT,
        verifications: OnlineExternalVerifications | None = None,
    ) -> object:
        return self.submission.submit(
            token=token,
            archive_path=archive_path or self.archive_path,
            descriptor_bytes=descriptor_bytes or self.descriptor_bytes,
            trusted_manifest=manifest or self.manifest,
            content_type=content_type,
            received_at=received_at,
            verifications=verifications or self.verifications,
        )


def _online_bundle(project_root: Path, directory: Path) -> _OnlineBundle:
    directory.mkdir(parents=True)
    archive_path, descriptor_bytes, manifest = build_imp032_package(
        project_root,
        directory,
    )
    store = InMemoryCollectorCredentialStore()
    credentials = CollectorCredentialService(
        store,
        hash_key=sha256(b"Sec_AI IMP-039 attack-only hash key").digest(),
        hash_key_version="imp039-attack-v1",
    )
    scope = _scope(manifest, 10 * 1024 * 1024)
    return _OnlineBundle(
        archive_path=archive_path,
        descriptor_bytes=descriptor_bytes,
        manifest=manifest,
        store=store,
        credentials=credentials,
        submission=OnlineCollectorSubmissionService(
            credentials,
            FullPackageValidator(project_root / "database" / "schemas"),
        ),
        verifications=_gates(
            scope,
            sha256(archive_path.read_bytes()).hexdigest(),
            archive_path.stat().st_size,
        ),
    )


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def _attack(
    *,
    attack_id: str,
    surface: str,
    category: str,
    title: str,
    expected_codes: tuple[str, ...],
    action: Callable[[], object],
    recorder: _DownstreamRecorder,
) -> dict[str, object]:
    actual_code = "ATTACK_ACCEPTED"
    try:
        action()
    except (
        CollectorCredentialError,
        PackageValidationError,
        OfflineSignatureError,
        OfflineSubmissionError,
    ) as exc:
        actual_code = exc.code.value
    except Exception:
        # 내부 예외의 종류나 내용을 보고서에 노출하지 않는다.
        actual_code = "UNEXPECTED_REJECTION"
    else:
        recorder.escaped()
    return {
        "id": attack_id,
        "surface": surface,
        "category": category,
        "title": title,
        "expected_codes": list(expected_codes),
        "actual_code": actual_code,
        "blocked": actual_code in expected_codes,
        "user_message": _USER_MESSAGES[category],
    }


def _online_attacks(
    project_root: Path,
    temporary: Path,
    recorder: _DownstreamRecorder,
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []

    def record(
        suffix: str,
        category: str,
        title: str,
        expected: tuple[str, ...],
        action: Callable[[], object],
    ) -> None:
        results.append(
            _attack(
                attack_id=f"IMP039-ON-{suffix}",
                surface="ONLINE",
                category=category,
                title=title,
                expected_codes=expected,
                action=action,
                recorder=recorder,
            )
        )

    bundle = _online_bundle(project_root, temporary / "online-archive")
    tampered_archive = temporary / "online-archive" / "tampered.zip"
    tampered_archive.write_bytes(bundle.archive_path.read_bytes() + b"tampered")
    record(
        "01",
        "PACKAGE_TAMPER",
        "압축 자료 내용 변경",
        (PackageValidationCode.ARCHIVE_HASH_MISMATCH.value,),
        lambda: bundle.submit(bundle.issue(), archive_path=tampered_archive),
    )

    bundle = _online_bundle(project_root, temporary / "online-descriptor")
    descriptor = cast(dict[str, Any], json.loads(bundle.descriptor_bytes))
    descriptor["archive"]["archive_sha256"] = "0" * 64
    record(
        "02",
        "PACKAGE_TAMPER",
        "자료 설명서의 압축 확인값 변경",
        (PackageValidationCode.ARCHIVE_HASH_MISMATCH.value,),
        lambda: bundle.submit(bundle.issue(), descriptor_bytes=_json_bytes(descriptor)),
    )

    bundle = _online_bundle(project_root, temporary / "online-manifest")
    manifest = copy.deepcopy(bundle.manifest)
    manifest["producer_version"] = "0.1.1"
    record(
        "03",
        "PACKAGE_TAMPER",
        "점검 지시서 내용 변경",
        (PackageValidationCode.MANIFEST_HASH_MISMATCH.value,),
        lambda: bundle.submit(bundle.issue(), manifest=manifest),
    )

    bundle = _online_bundle(project_root, temporary / "online-signature")
    verification = replace(
        bundle.verifications,
        manifest_signature=DigestVerification(
            ExternalVerificationStatus.FAILED,
            cast(str, bundle.manifest["manifest_content_sha256"]),
        ),
    )
    record(
        "04",
        "SIGNATURE",
        "점검 지시서 서명 실패",
        (PackageValidationCode.MANIFEST_SIGNATURE_INVALID.value,),
        lambda: bundle.submit(bundle.issue(), verifications=verification),
    )

    bundle = _online_bundle(project_root, temporary / "online-expired-credential")
    record(
        "05",
        "EXPIRY",
        "만료된 온라인 접수 권한",
        (CollectorCredentialCode.EXPIRED.value,),
        lambda: bundle.submit(bundle.issue(expired=True)),
    )

    bundle = _online_bundle(project_root, temporary / "online-expired-manifest")
    record(
        "06",
        "EXPIRY",
        "만료된 점검 지시서",
        (PackageValidationCode.MANIFEST_EXPIRED.value,),
        lambda: bundle.submit(
            bundle.credentials.issue(
                _scope(bundle.manifest, 10 * 1024 * 1024),
                issued_at=ONLINE_RECEIVED_AT + timedelta(minutes=55),
            ).token,
            received_at=ONLINE_RECEIVED_AT + timedelta(hours=1),
        ),
    )

    bundle = _online_bundle(project_root, temporary / "online-token-replay")
    token = bundle.issue()
    bundle.submit(token)
    record(
        "07",
        "REPLAY",
        "처리된 온라인 접수 권한 재사용",
        (CollectorCredentialCode.ALREADY_USED.value,),
        lambda: bundle.submit(token),
    )

    bundle = _online_bundle(project_root, temporary / "online-nonce-replay")
    bundle.submit(bundle.issue())
    record(
        "08",
        "REPLAY",
        "새 접수 권한으로 같은 요청 번호 재전송",
        (CollectorCredentialCode.NONCE_REPLAYED.value,),
        lambda: bundle.submit(bundle.issue()),
    )

    bundle = _online_bundle(project_root, temporary / "online-manifest-scope")
    manifest = copy.deepcopy(bundle.manifest)
    manifest["id"] = OTHER_MANIFEST_ID
    record(
        "09",
        "SCOPE",
        "다른 점검 지시서로 접수",
        (CollectorCredentialCode.SCOPE_MISMATCH.value,),
        lambda: bundle.submit(bundle.issue(), manifest=manifest),
    )

    bundle = _online_bundle(project_root, temporary / "online-asset-scope")
    descriptor = cast(dict[str, Any], json.loads(bundle.descriptor_bytes))
    descriptor["asset_id"] = OTHER_ASSET_ID
    record(
        "10",
        "SCOPE",
        "다른 PC 번호로 접수",
        (PackageValidationCode.MANIFEST_SCOPE_MISMATCH.value,),
        lambda: bundle.submit(bundle.issue(), descriptor_bytes=_json_bytes(descriptor)),
    )

    bundle = _online_bundle(project_root, temporary / "online-job-scope")
    descriptor = cast(dict[str, Any], json.loads(bundle.descriptor_bytes))
    descriptor["job_id"] = OTHER_JOB_ID
    record(
        "11",
        "SCOPE",
        "다른 점검 작업 번호로 접수",
        (PackageValidationCode.MANIFEST_SCOPE_MISMATCH.value,),
        lambda: bundle.submit(bundle.issue(), descriptor_bytes=_json_bytes(descriptor)),
    )

    bundle = _online_bundle(project_root, temporary / "online-org-scope")
    staged = replace(
        bundle.verifications.staged_object,
        organization_id=OTHER_ORGANIZATION_ID,
    )
    verification = replace(bundle.verifications, staged_object=staged)
    record(
        "12",
        "SCOPE",
        "다른 조직 저장 영역으로 접수",
        (PackageValidationCode.ATTESTATION_BINDING_MISMATCH.value,),
        lambda: bundle.submit(bundle.issue(), verifications=verification),
    )

    bundle = _online_bundle(project_root, temporary / "online-content-type")
    record(
        "13",
        "SCOPE",
        "허용되지 않은 자료 형식으로 접수",
        (CollectorCredentialCode.SCOPE_MISMATCH.value,),
        lambda: bundle.submit(bundle.issue(), content_type="application/octet-stream"),
    )
    return results


def _offline_attacks(
    project_root: Path,
    temporary: Path,
    recorder: _DownstreamRecorder,
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []

    def case(
        name: str,
        *,
        certificate_asset_id: str | None = None,
        include_package_eku: bool = True,
    ) -> OfflineAcceptanceCase:
        directory = temporary / name
        directory.mkdir(parents=True)
        return build_imp033_case(
            project_root,
            directory,
            certificate_asset_id=certificate_asset_id,
            include_package_eku=include_package_eku,
        )

    def record(
        suffix: str,
        category: str,
        title: str,
        expected: tuple[str, ...],
        action: Callable[[], object],
    ) -> None:
        results.append(
            _attack(
                attack_id=f"IMP039-OFF-{suffix}",
                surface="OFFLINE",
                category=category,
                title=title,
                expected_codes=expected,
                action=action,
                recorder=recorder,
            )
        )

    signed = case("offline-signature")
    envelope = copy.deepcopy(signed.envelope)
    signature = cast(str, envelope["signature"]["value"])
    envelope["signature"]["value"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    record(
        "01",
        "SIGNATURE",
        "오프라인 서명값 변경",
        (OfflineSignatureCode.SIGNATURE_INVALID.value,),
        lambda: offline_service(project_root, signed).submit_signed(
            archive_path=signed.archive_path,
            descriptor_bytes=signed.descriptor_bytes,
            trusted_manifest=signed.manifest,
            signature_envelope_bytes=_json_bytes(envelope),
            received_at=OFFLINE_RECEIVED_AT,
            revocation=signed.revocation,
            verifications=signed.verifications,
        ),
    )

    wrong_eku = case("offline-eku", include_package_eku=False)
    record(
        "02",
        "SIGNATURE",
        "점검 자료 서명 권한이 없는 인증서",
        (OfflineSignatureCode.CERTIFICATE_WRONG_EKU.value,),
        lambda: offline_service(project_root, wrong_eku).submit_signed(
            archive_path=wrong_eku.archive_path,
            descriptor_bytes=wrong_eku.descriptor_bytes,
            trusted_manifest=wrong_eku.manifest,
            signature_envelope_bytes=wrong_eku.envelope_bytes,
            received_at=OFFLINE_RECEIVED_AT,
            revocation=wrong_eku.revocation,
            verifications=wrong_eku.verifications,
        ),
    )

    wrong_asset = case("offline-san", certificate_asset_id=OTHER_ASSET_ID)
    record(
        "03",
        "SCOPE",
        "다른 PC에 발급된 인증서",
        (OfflineSignatureCode.CERTIFICATE_SUBJECT_MISMATCH.value,),
        lambda: offline_service(project_root, wrong_asset).submit_signed(
            archive_path=wrong_asset.archive_path,
            descriptor_bytes=wrong_asset.descriptor_bytes,
            trusted_manifest=wrong_asset.manifest,
            signature_envelope_bytes=wrong_asset.envelope_bytes,
            received_at=OFFLINE_RECEIVED_AT,
            revocation=wrong_asset.revocation,
            verifications=wrong_asset.verifications,
        ),
    )

    untrusted = case("offline-untrusted-source")
    other = case("offline-untrusted-root")
    record(
        "04",
        "SIGNATURE",
        "신뢰 목록에 없는 발급기관",
        (OfflineSignatureCode.CERTIFICATE_UNTRUSTED.value,),
        lambda: offline_service(project_root, other).submit_signed(
            archive_path=untrusted.archive_path,
            descriptor_bytes=untrusted.descriptor_bytes,
            trusted_manifest=untrusted.manifest,
            signature_envelope_bytes=untrusted.envelope_bytes,
            received_at=OFFLINE_RECEIVED_AT,
            revocation=untrusted.revocation,
            verifications=untrusted.verifications,
        ),
    )

    revoked = case("offline-revoked")
    revoked_status = replace(
        revoked.revocation,
        status=CertificateRevocationStatus.REVOKED,
    )
    record(
        "05",
        "SIGNATURE",
        "폐기된 인증서",
        (OfflineSignatureCode.CERTIFICATE_REVOKED.value,),
        lambda: offline_service(project_root, revoked).submit_signed(
            archive_path=revoked.archive_path,
            descriptor_bytes=revoked.descriptor_bytes,
            trusted_manifest=revoked.manifest,
            signature_envelope_bytes=revoked.envelope_bytes,
            received_at=OFFLINE_RECEIVED_AT,
            revocation=revoked_status,
            verifications=revoked.verifications,
        ),
    )

    stale = case("offline-revocation-stale")
    stale_status = replace(
        stale.revocation,
        checked_at=OFFLINE_RECEIVED_AT - timedelta(hours=24, seconds=1),
    )
    record(
        "06",
        "SIGNATURE",
        "오래되거나 확인할 수 없는 폐기 상태",
        (OfflineSignatureCode.REVOCATION_UNAVAILABLE.value,),
        lambda: offline_service(project_root, stale).submit_signed(
            archive_path=stale.archive_path,
            descriptor_bytes=stale.descriptor_bytes,
            trusted_manifest=stale.manifest,
            signature_envelope_bytes=stale.envelope_bytes,
            received_at=OFFLINE_RECEIVED_AT,
            revocation=stale_status,
            verifications=stale.verifications,
        ),
    )

    expired = case("offline-expired")
    record(
        "07",
        "EXPIRY",
        "만료된 오프라인 서명 자료",
        (OfflineSignatureCode.TIME_INVALID.value,),
        lambda: offline_service(project_root, expired).submit_signed(
            archive_path=expired.archive_path,
            descriptor_bytes=expired.descriptor_bytes,
            trusted_manifest=expired.manifest,
            signature_envelope_bytes=expired.envelope_bytes,
            received_at=OFFLINE_RECEIVED_AT + timedelta(hours=1),
            revocation=replace(
                expired.revocation,
                checked_at=OFFLINE_RECEIVED_AT + timedelta(hours=1),
            ),
            verifications=expired.verifications,
        ),
    )

    archive_case = case("offline-archive")
    tampered_archive = temporary / "offline-archive" / "tampered.zip"
    tampered_archive.write_bytes(archive_case.archive_path.read_bytes() + b"tampered")
    record(
        "08",
        "PACKAGE_TAMPER",
        "서명 후 압축 자료 내용 변경",
        (PackageValidationCode.ARCHIVE_HASH_MISMATCH.value,),
        lambda: offline_service(project_root, archive_case).submit_signed(
            archive_path=tampered_archive,
            descriptor_bytes=archive_case.descriptor_bytes,
            trusted_manifest=archive_case.manifest,
            signature_envelope_bytes=archive_case.envelope_bytes,
            received_at=OFFLINE_RECEIVED_AT,
            revocation=archive_case.revocation,
            verifications=archive_case.verifications,
        ),
    )

    descriptor_case = case("offline-descriptor")
    descriptor = copy.deepcopy(descriptor_case.descriptor)
    descriptor["asset_id"] = OTHER_ASSET_ID
    record(
        "09",
        "PACKAGE_TAMPER",
        "서명 후 자료 설명서 변경",
        (OfflineSubmissionCode.SIGNED_SCOPE_MISMATCH.value,),
        lambda: offline_service(project_root, descriptor_case).submit_signed(
            archive_path=descriptor_case.archive_path,
            descriptor_bytes=_json_bytes(descriptor),
            trusted_manifest=descriptor_case.manifest,
            signature_envelope_bytes=descriptor_case.envelope_bytes,
            received_at=OFFLINE_RECEIVED_AT,
            revocation=descriptor_case.revocation,
            verifications=descriptor_case.verifications,
        ),
    )

    manifest_case = case("offline-manifest")
    manifest = copy.deepcopy(manifest_case.manifest)
    manifest["producer_version"] = "0.1.1"
    record(
        "10",
        "PACKAGE_TAMPER",
        "서명 후 점검 지시서 변경",
        (PackageValidationCode.MANIFEST_HASH_MISMATCH.value,),
        lambda: offline_service(project_root, manifest_case).submit_signed(
            archive_path=manifest_case.archive_path,
            descriptor_bytes=manifest_case.descriptor_bytes,
            trusted_manifest=manifest,
            signature_envelope_bytes=manifest_case.envelope_bytes,
            received_at=OFFLINE_RECEIVED_AT,
            revocation=manifest_case.revocation,
            verifications=manifest_case.verifications,
        ),
    )

    session_case = case("offline-session")
    record(
        "11",
        "USER_AUTH",
        "로그인하지 않은 사용자의 수동 제출",
        (OfflineSubmissionCode.USER_AUTH_REQUIRED.value,),
        lambda: offline_service(project_root, session_case).submit_user(
            archive_path=session_case.archive_path,
            descriptor_bytes=_user_descriptor(session_case),
            trusted_manifest=session_case.manifest,
            user=_user_context(session_case, session_active=False),
            verifications=session_case.verifications,
        ),
    )

    csrf_case = case("offline-csrf")
    record(
        "12",
        "USER_AUTH",
        "화면 요청 확인값이 없는 수동 제출",
        (OfflineSubmissionCode.CSRF_REQUIRED.value,),
        lambda: offline_service(project_root, csrf_case).submit_user(
            archive_path=csrf_case.archive_path,
            descriptor_bytes=_user_descriptor(csrf_case),
            trusted_manifest=csrf_case.manifest,
            user=_user_context(csrf_case, csrf_verified=False),
            verifications=csrf_case.verifications,
        ),
    )

    user_scope = case("offline-user-scope")
    record(
        "13",
        "USER_AUTH",
        "권한이 없는 PC의 수동 제출",
        (OfflineSubmissionCode.USER_SCOPE_MISMATCH.value,),
        lambda: offline_service(project_root, user_scope).submit_user(
            archive_path=user_scope.archive_path,
            descriptor_bytes=_user_descriptor(user_scope),
            trusted_manifest=user_scope.manifest,
            user=_user_context(user_scope, authorized_for_asset=False),
            verifications=user_scope.verifications,
        ),
    )

    organization = case("offline-organization")
    record(
        "14",
        "SCOPE",
        "다른 조직으로 바꾼 사용자 제출",
        (PackageValidationCode.ATTESTATION_BINDING_MISMATCH.value,),
        lambda: offline_service(project_root, organization).submit_user(
            archive_path=organization.archive_path,
            descriptor_bytes=_user_descriptor(organization),
            trusted_manifest=organization.manifest,
            user=_user_context(organization, organization_id=OTHER_ORGANIZATION_ID),
            verifications=organization.verifications,
        ),
    )

    replay = case("offline-profile-replay")
    replay_store = InMemoryOfflineReplayStore()
    service: OfflinePackageSubmissionService = offline_service(
        project_root,
        replay,
        replay_store=replay_store,
    )
    service.submit_signed(
        archive_path=replay.archive_path,
        descriptor_bytes=replay.descriptor_bytes,
        trusted_manifest=replay.manifest,
        signature_envelope_bytes=replay.envelope_bytes,
        received_at=OFFLINE_RECEIVED_AT,
        revocation=replay.revocation,
        verifications=replay.verifications,
    )
    record(
        "15",
        "REPLAY",
        "서명 제출 후 사용자 제출로 바꾼 재전송",
        (OfflineSubmissionCode.REPLAYED.value,),
        lambda: service.submit_user(
            archive_path=replay.archive_path,
            descriptor_bytes=_user_descriptor(replay),
            trusted_manifest=replay.manifest,
            user=_user_context(replay),
            verifications=replay.verifications,
        ),
    )

    return results


def run_submission_attack_acceptance(project_root: Path) -> dict[str, object]:
    """Run the complete synthetic attack matrix and return a safe report."""

    recorder = _DownstreamRecorder()
    with tempfile.TemporaryDirectory(prefix="secai-imp039-") as temporary:
        temporary_path = Path(temporary)
        attacks = [
            *_online_attacks(project_root, temporary_path, recorder),
            *_offline_attacks(project_root, temporary_path, recorder),
        ]

    blocked_count = sum(1 for attack in attacks if attack["blocked"] is True)
    report: dict[str, object] = {
        "imp": "IMP-039",
        "acceptance_status": (
            "PASS"
            if blocked_count == len(attacks)
            and recorder.attack_submissions_accepted == 0
            else "FAIL"
        ),
        "scope": "합성 Package의 제출·서명 공격 회귀",
        "summary": {
            "attack_count": len(attacks),
            "blocked_count": blocked_count,
            "escaped_count": len(attacks) - blocked_count,
            "online_count": sum(1 for attack in attacks if attack["surface"] == "ONLINE"),
            "offline_count": sum(1 for attack in attacks if attack["surface"] == "OFFLINE"),
        },
        "attacks": attacks,
        "downstream_boundary": recorder.as_dict(),
        "safe_reporting": {
            "credential_exposed": False,
            "private_key_exposed": False,
            "certificate_body_exposed": False,
            "raw_evidence_exposed": False,
            "temporary_path_exposed": False,
            "exception_message_exposed": False,
        },
        "test_data_only": True,
        "production_upload_endpoint_enabled": False,
        "original_evidence_persisted": False,
        "official_finding_created": False,
        "limitations": [
            "개인정보가 없는 합성 Package와 메모리 저장소로 수행한 개발 공격시험입니다.",
            "운영 업로드 endpoint와 조직 인증서는 활성화하지 않았습니다.",
            "clean Windows VM·조직 서명·SmartScreen 검증은 단계 J에서 수행합니다.",
        ],
        "next_imp": "IMP-040",
    }
    return report
