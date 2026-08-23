"""일반 사용자의 Linux 원샷 자가 점검 생성·제출·업로드 API."""

from __future__ import annotations

import base64
import os
import secrets
import tempfile
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, cast
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import (
    APIRouter,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from apps.api.auth_support import auth_enabled, current_principal
from apps.api.browser_csrf import browser_csrf_token, verify_browser_csrf
from apps.api.dev_signed_downloads import dev_signed_artifact_status
from security_audit.analysis.package_validation import (
    DigestVerification,
    ExternalVerificationStatus,
    MalwareScanStatus,
    MalwareScanVerification,
    NonceVerification,
    NonceVerificationStatus,
    PackageAuthenticationKind,
    PackageAuthenticationVerification,
    PackageGateVerifications,
    PackageSchemaCatalog,
    PackageValidationCode,
    PackageValidationContext,
    PackageValidationError,
    StagedObjectVerification,
    inspect_package_archive,
    load_strict_json,
)
from security_audit.application.linux_oneshot_processing import (
    ProcessedLinuxOneShotPackage,
    inspect_linux_package_content_policy,
    process_linux_oneshot_package,
)
from security_audit.collector.linux_connection import (
    DeviceCodeError,
    InMemoryDeviceCodeStore,
    InMemoryExchangeRateLimiter,
    LinuxOneShotConnectionService,
)
from security_audit.collector.linux_manifest import (
    build_linux_collector_manifest,
    verify_linux_collector_manifest,
)
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.linux_oneshot_repository import (
    LinuxOneShotRunRecord,
    bind_linux_oneshot_platform,
    commit_linux_oneshot_result,
    create_linux_oneshot_run,
    find_pending_linux_oneshot_run,
    load_linux_oneshot_run,
    mark_linux_oneshot_deleted,
    nonce_is_fresh,
)
from security_audit.platforms import (
    LinuxDistribution,
    current_platform_support_catalog,
    discover_linux_platform,
)
from security_audit.platforms.linux_kisa import KisaUnixAssessmentProfile
from security_audit.security.auth import (
    AuthenticatedPrincipal,
    CollectorCredentialError,
    CollectorCredentialScope,
    InMemoryCollectorCredentialStore,
)
from security_audit.security.malware import scan_file_with_clamav
from security_audit.supply_chain.dev_signed_download import DevArtifactPlatform

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")
SCHEMA_ROOT = Path("database/schemas")
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_DESCRIPTOR_BYTES = 2 * 1024 * 1024


class CreateLinuxOneShotBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    criteria: dict[str, object] | None = None


class ExchangeLinuxOneShotBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=20, max_length=24)
    os_release: str = Field(min_length=1, max_length=8192)
    machine: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")


class _Runtime:
    def __init__(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.connection = LinuxOneShotConnectionService(
            code_store=InMemoryDeviceCodeStore(),
            credential_store=InMemoryCollectorCredentialStore(),
            hash_key=secrets.token_bytes(32),
            hash_key_version="dev-ephemeral-v1",
        )
        self.exchange_rate_limiter = InMemoryExchangeRateLimiter()

    @property
    def public_key_b64(self) -> str:
        value = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    def sign(self, digest: bytes) -> tuple[str, str]:
        signature = self.private_key.sign(digest)
        return (
            "linux-oneshot-dev-ephemeral",
            base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        )

    def verify(self, key_id: str, digest: bytes, signature: str) -> bool:
        if key_id != "linux-oneshot-dev-ephemeral":
            return False
        try:
            decoded = base64.urlsafe_b64decode(signature + ("=" * (-len(signature) % 4)))
            self.private_key.public_key().verify(decoded, digest)
        except (InvalidSignature, ValueError):
            return False
        return True


@lru_cache(maxsize=1)
def _runtime() -> _Runtime:
    # DEV 전용 key는 process memory에만 존재하며 운영 배포에는 사용하지 않습니다.
    return _Runtime()


@lru_cache(maxsize=1)
def _engine() -> Engine:
    return create_engine(ServiceSettings.from_environment().postgres_url(), pool_pre_ping=True)


def _public_feature_enabled() -> None:
    if os.getenv("SECAI_DEV_DEMO_ENABLED", "false").casefold() != "true":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")


def _require_feature(request: Request) -> AuthenticatedPrincipal:
    _public_feature_enabled()
    if not auth_enabled():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Authentication required.")
    return current_principal(request)


def _pending_run_action(expires_at: datetime | None, now: datetime) -> str:
    """만료됐거나 만료 시각을 알 수 없는 대기 실행은 새 점검으로 대체합니다."""

    if expires_at is None or expires_at <= now:
        return "REPLACE"
    return "CONFLICT"


def _pending_conflict_error(pending_run_id: UUID) -> HTTPException:
    return HTTPException(
        status.HTTP_409_CONFLICT,
        {
            "code": "LINUX_ONESHOT_ALREADY_WAITING",
            "message": (
                "이미 제출을 기다리는 Linux 자가 점검이 있습니다. "
                "기존 점검을 취소한 뒤 다시 만드세요."
            ),
            "pending_run_id": str(pending_run_id),
        },
    )


def _safe_error(code: str, http_status: int = status.HTTP_400_BAD_REQUEST) -> HTTPException:
    return HTTPException(
        http_status,
        {"code": code, "message": "제출 자료를 확인할 수 없습니다."},
    )


def _bearer(value: str | None) -> str:
    if value is None or not value.startswith("Bearer ") or len(value) > 1024:
        raise _safe_error("COLLECTOR_CREDENTIAL_REQUIRED", status.HTTP_401_UNAUTHORIZED)
    return value.removeprefix("Bearer ")


async def _stage_upload(upload: UploadFile) -> Path:
    if upload.content_type != "application/zip":
        raise _safe_error("PACKAGE_MEDIA_TYPE_INVALID", status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)
    handle = tempfile.NamedTemporaryFile(prefix="secai-linux-upload-", suffix=".zip", delete=False)
    path = Path(handle.name)
    measured = 0
    try:
        with handle:
            while chunk := await upload.read(64 * 1024):
                measured += len(chunk)
                if measured > MAX_ARCHIVE_BYTES:
                    raise _safe_error(
                        "PACKAGE_TOO_LARGE",
                        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    )
                handle.write(chunk)
        if measured == 0:
            raise _safe_error("PACKAGE_EMPTY")
        os.chmod(path, 0o600)
        return path
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _manifest_scope(manifest: dict[str, Any]) -> CollectorCredentialScope:
    submission = cast(dict[str, Any], manifest["submission"])
    return CollectorCredentialScope(
        organization_id=str(manifest["organization_id"]),
        asset_id=str(manifest["asset_id"]),
        job_id=str(manifest["job_id"]),
        manifest_id=str(manifest["id"]),
        manifest_sha256=str(manifest["manifest_content_sha256"]),
        nonce=str(manifest["nonce"]),
        endpoint_id=str(submission["endpoint_id"]),
        content_type="application/zip",
        schema_version="2.0.0",
        max_archive_bytes=int(submission["max_archive_bytes"]),
    )


def _validate_and_commit(
    *,
    archive_path: Path,
    descriptor_bytes: bytes,
    record: LinuxOneShotRunRecord,
    authentication_kind: PackageAuthenticationKind,
    received_at: datetime,
) -> tuple[ProcessedLinuxOneShotPackage, bool]:
    if len(descriptor_bytes) > MAX_DESCRIPTOR_BYTES:
        raise _safe_error("DESCRIPTOR_TOO_LARGE", status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
    descriptor_value = load_strict_json(descriptor_bytes)
    if not isinstance(descriptor_value, dict):
        raise _safe_error("DESCRIPTOR_INVALID")
    descriptor = cast(dict[str, Any], descriptor_value)
    PackageSchemaCatalog(SCHEMA_ROOT).validate(
        descriptor,
        "linux_audit_package.schema.json",
        PackageValidationCode.DESCRIPTOR_SCHEMA_INVALID,
    )
    expected_scope = {
        "organization_id": str(record.organization_id),
        "subject_user_id": str(record.owner_user_id),
        "job_id": str(record.run_id),
        "asset_id": str(record.asset_id),
        "manifest_id": str(record.manifest["id"]),
        "manifest_hash": record.manifest_sha256,
        "nonce": str(record.manifest["nonce"]),
        "execution_attempt_id": str(record.manifest["execution_attempt_id"]),
    }
    if any(descriptor.get(key) != value for key, value in expected_scope.items()):
        raise _safe_error("SUBMISSION_SCOPE_MISMATCH", status.HTTP_403_FORBIDDEN)
    expected_profile = (
        "ONLINE-AUTHENTICATED"
        if authentication_kind is PackageAuthenticationKind.ONLINE_TRANSPORT
        else "OFFLINE-USER-SUBMITTED"
    )
    authentication = cast(dict[str, Any], descriptor["authentication"])
    if authentication.get("profile") != expected_profile:
        raise _safe_error("SUBMISSION_AUTHENTICATION_MISMATCH")
    try:
        expected_distribution = LinuxDistribution(record.distribution)
    except ValueError as exc:
        raise _safe_error("PLATFORM_NOT_IDENTIFIED", status.HTTP_409_CONFLICT) from exc
    verify_linux_collector_manifest(
        record.manifest,
        schema_root=SCHEMA_ROOT,
        expected_distribution=expected_distribution,
        now=received_at,
        verify_signature=_runtime().verify,
    )
    inspection = inspect_package_archive(archive_path)
    if inspection.archive_sha256 != inspect_linux_package_content_policy(
        archive_path,
        schema_root=SCHEMA_ROOT,
    ):
        raise _safe_error("CONTENT_POLICY_BINDING_MISMATCH")
    try:
        malware = scan_file_with_clamav(
            archive_path,
            host=os.getenv("SECAI_CLAMAV_HOST", "clamav"),
            port=int(os.getenv("SECAI_CLAMAV_PORT", "3310")),
        )
    except (OSError, ValueError) as exc:
        raise _safe_error(
            "MALWARE_SCAN_UNAVAILABLE",
            status.HTTP_503_SERVICE_UNAVAILABLE,
        ) from exc
    if not malware.accepted or malware.source_sha256 != inspection.archive_sha256:
        raise _safe_error("MALWARE_SCAN_REJECTED")
    with Session(_engine()) as session:
        fresh = nonce_is_fresh(
            session,
            organization_id=record.organization_id,
            owner_user_id=record.owner_user_id,
            run_id=record.run_id,
            nonce=str(record.manifest["nonce"]),
        )
    context = PackageValidationContext(
        organization_id=str(record.organization_id),
        asset_id=str(record.asset_id),
        job_id=str(record.run_id),
        endpoint_id=str(cast(dict[str, Any], record.manifest["submission"])["endpoint_id"]),
        received_at=received_at,
    )
    verifications = PackageGateVerifications(
        manifest_signature=DigestVerification(
            ExternalVerificationStatus.VERIFIED,
            record.manifest_sha256,
        ),
        nonce=NonceVerification(
            NonceVerificationStatus.FRESH_RESERVED
            if fresh
            else NonceVerificationStatus.REPLAYED,
            str(record.manifest["nonce"]),
        ),
        package_authentication=PackageAuthenticationVerification(
            ExternalVerificationStatus.VERIFIED,
            authentication_kind,
        ),
        malware_scan=MalwareScanVerification(
            MalwareScanStatus.CLEAN,
            inspection.archive_sha256,
        ),
        content_policy=DigestVerification(
            ExternalVerificationStatus.VERIFIED,
            inspection.archive_sha256,
        ),
        staged_object=StagedObjectVerification(
            ExternalVerificationStatus.VERIFIED,
            str(record.organization_id),
            str(record.asset_id),
            str(record.run_id),
            inspection.archive_sha256,
            inspection.compressed_bytes,
        ),
    )
    processed = process_linux_oneshot_package(
        archive_path=archive_path,
        descriptor_bytes=descriptor_bytes,
        expected_manifest=record.manifest,
        context=context,
        verifications=verifications,
        expected_subject_user_id=str(record.owner_user_id),
        schema_root=SCHEMA_ROOT,
    )
    with Session(_engine()) as session, session.begin():
        committed = commit_linux_oneshot_result(
            session,
            record=record,
            descriptor=descriptor,
            descriptor_sha256=processed.validated_package.descriptor_sha256,
            archive_sha256=inspection.archive_sha256,
            submission_profile=processed.submission_profile,
            assurance_level=processed.assurance_level,
            evidence=processed.evidence,
            result_json=processed.result_json,
            received_at=received_at,
        )
    return processed, committed


@router.get("/ui/linux-self-scan", response_class=HTMLResponse)
def linux_self_scan_page(request: Request) -> HTMLResponse:
    _require_feature(request)
    return templates.TemplateResponse(
        request=request,
        name="pages/linux_self_scan.html",
        context={
            "csrf_token": browser_csrf_token(request),
            "default_criteria": KisaUnixAssessmentProfile().public_values(),
        },
    )


@router.post("/api/v1/linux/one-shot/runs", status_code=status.HTTP_201_CREATED)
def create_linux_self_scan(
    request: Request,
    body: CreateLinuxOneShotBody,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, object]:
    principal = _require_feature(request)
    verify_browser_csrf(request, csrf_token)
    try:
        criteria = KisaUnixAssessmentProfile.from_values(body.criteria).public_values()
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Linux criteria invalid.",
        ) from exc
    now = datetime.now(UTC)
    run_id = uuid4()
    asset_id = uuid4()
    manifests = {
        distribution: build_linux_collector_manifest(
            organization_id=principal.organization_id,
            subject_user_id=principal.user_id,
            job_id=run_id,
            asset_id=asset_id,
            manifest_id=uuid4(),
            execution_attempt_id=uuid4(),
            correlation_id=uuid4(),
            distribution=distribution,
            issued_at=now,
            expires_at=now + timedelta(minutes=60),
            nonce=secrets.token_urlsafe(24),
            criteria_values=criteria,
            sign=_runtime().sign,
        )
        for distribution in LinuxDistribution
    }
    placeholder_manifest = manifests[LinuxDistribution.UBUNTU_24_04]
    try:
        with Session(_engine()) as session, session.begin():
            pending = find_pending_linux_oneshot_run(
                session,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                asset_key="self-auto",
            )
            if pending is not None:
                pending_run_id, pending_expires_at = pending
                if _pending_run_action(pending_expires_at, now) == "CONFLICT":
                    raise _pending_conflict_error(pending_run_id)
                mark_linux_oneshot_deleted(
                    session,
                    organization_id=principal.organization_id,
                    owner_user_id=principal.user_id,
                    run_id=pending_run_id,
                )
            create_linux_oneshot_run(
                session,
                run_id=run_id,
                organization_id=principal.organization_id,
                owner_user_id=principal.user_id,
                asset_id=asset_id,
                distribution="AUTO",
                manifest=placeholder_manifest,
            )
    except IntegrityError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "이미 제출을 기다리는 같은 종류의 Linux 자가 점검이 있습니다.",
        ) from exc
    issued = _runtime().connection.issue_choices(
        {
            distribution.value: (_manifest_scope(manifest), manifest)
            for distribution, manifest in manifests.items()
        },
        subject_user_id=str(principal.user_id),
        issued_at=now,
        ttl=timedelta(minutes=10),
    )
    return {
        "run_id": str(run_id),
        "asset_id": str(asset_id),
        "device_code": issued.code,
        "code_expires_at": issued.expires_at.isoformat(),
        "manifest_expires_at": placeholder_manifest["expires_at"],
        "draft": True,
        "official_certification": False,
        "artifact": dev_signed_artifact_status(DevArtifactPlatform.LINUX_AUTO_X64),
    }


@router.post("/api/v1/linux/one-shot/exchange")
def exchange_linux_self_scan(
    request: Request,
    body: ExchangeLinuxOneShotBody,
) -> dict[str, object]:
    _public_feature_enabled()
    remote = request.client.host if request.client is not None else "unknown"
    received_at = datetime.now(UTC)
    if not _runtime().exchange_rate_limiter.allow(remote, received_at=received_at):
        raise _safe_error("DEVICE_CODE_RATE_LIMITED", status.HTTP_429_TOO_MANY_REQUESTS)
    try:
        fingerprint = discover_linux_platform(
            body.os_release.encode("utf-8"),
            machine=body.machine,
        )
        selection = current_platform_support_catalog().resolve(fingerprint)
        distribution = {
            "secai.linux.ubuntu22.readonly.v1": LinuxDistribution.UBUNTU_22_04,
            "secai.linux.ubuntu24.readonly.v1": LinuxDistribution.UBUNTU_24_04,
            "secai.linux.debian12.readonly.v1": LinuxDistribution.DEBIAN_12,
            "secai.linux.rocky9.readonly.v1": LinuxDistribution.ROCKY_9,
            "secai.linux.rhel9.readonly.v1": LinuxDistribution.RHEL_9,
            "secai.linux.alma9.readonly.v1": LinuxDistribution.ALMALINUX_9,
        }.get(selection.adapter_id)
        if distribution is None:
            raise ValueError("LINUX_ONESHOT_ADAPTER_NOT_MAPPED")
        exchanged = _runtime().connection.exchange(
            body.code,
            selection_key=distribution.value,
            received_at=received_at,
        )
    except (DeviceCodeError, CollectorCredentialError) as exc:
        raise _safe_error(str(exc.code), status.HTTP_401_UNAUTHORIZED) from exc
    except ValueError as exc:
        raise _safe_error("PLATFORM_UNSUPPORTED") from exc
    scope = exchanged.credential.scope
    try:
        with Session(_engine()) as session, session.begin():
            bind_linux_oneshot_platform(
                session,
                organization_id=UUID(scope.organization_id),
                owner_user_id=UUID(exchanged.subject_user_id),
                run_id=UUID(scope.job_id),
                distribution=distribution.value,
                manifest=exchanged.manifest,
                discovery={
                    "fingerprint": fingerprint.to_json(),
                    "selection": selection.to_json(),
                },
            )
    except ValueError as exc:
        raise _safe_error("PLATFORM_BIND_CONFLICT", status.HTTP_409_CONFLICT) from exc
    return {
        "manifest": exchanged.manifest,
        "credential": exchanged.credential.token,
        "credential_expires_at": exchanged.credential.expires_at.isoformat(),
        "transport_receipt_id": exchanged.transport_receipt_id,
        "manifest_public_key": _runtime().public_key_b64,
        "manifest_key_id": "linux-oneshot-dev-ephemeral",
    }


@router.post("/api/v1/linux/one-shot/submit")
async def submit_linux_self_scan(
    package: Annotated[UploadFile, File()],
    descriptor: Annotated[str, Form(max_length=MAX_DESCRIPTOR_BYTES)],
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> dict[str, object]:
    _public_feature_enabled()
    token = _bearer(authorization)
    received_at = datetime.now(UTC)
    try:
        connection = _runtime().connection.authorize_connection(
            token,
            received_at=received_at,
        )
    except (DeviceCodeError, CollectorCredentialError) as exc:
        raise _safe_error(str(exc.code), status.HTTP_401_UNAUTHORIZED) from exc
    scope = connection.credential.scope
    with Session(_engine()) as session:
        record = load_linux_oneshot_run(
            session,
            organization_id=UUID(scope.organization_id),
            owner_user_id=UUID(connection.subject_user_id),
            run_id=UUID(scope.job_id),
        )
    if record is None or str(record.asset_id) != scope.asset_id:
        raise _safe_error("SUBMISSION_SCOPE_MISMATCH", status.HTTP_403_FORBIDDEN)
    staged = await _stage_upload(package)
    try:
        processed, committed = _validate_and_commit(
            archive_path=staged,
            descriptor_bytes=descriptor.encode("utf-8"),
            record=record,
            authentication_kind=PackageAuthenticationKind.ONLINE_TRANSPORT,
            received_at=received_at,
        )
        receipt = _runtime().connection.commit(
            token,
            received_at=received_at,
            package_id=processed.validated_package.package_id,
            archive_sha256=processed.validated_package.inspection.archive_sha256,
        )
        return {
            "run_id": str(record.run_id),
            "receipt_id": receipt.receipt_id,
            "committed": committed,
            "result_url": f"/ui/linux-results?run_id={record.run_id}",
            "assurance_level": processed.assurance_level,
        }
    except PackageValidationError as exc:
        raise _safe_error(exc.code.value) from exc
    finally:
        staged.unlink(missing_ok=True)


@router.post("/api/v1/linux/one-shot/runs/{run_id}/upload")
async def upload_linux_self_scan(
    request: Request,
    run_id: UUID,
    package: Annotated[UploadFile, File()],
    descriptor: Annotated[str, Form(max_length=MAX_DESCRIPTOR_BYTES)],
    csrf_token: Annotated[str, Form()],
) -> dict[str, object]:
    principal = _require_feature(request)
    verify_browser_csrf(request, csrf_token)
    with Session(_engine()) as session:
        record = load_linux_oneshot_run(
            session,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
            run_id=run_id,
        )
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Linux self scan not found.")
    staged = await _stage_upload(package)
    try:
        processed, committed = _validate_and_commit(
            archive_path=staged,
            descriptor_bytes=descriptor.encode("utf-8"),
            record=record,
            authentication_kind=PackageAuthenticationKind.OFFLINE_SUBMITTER,
            received_at=datetime.now(UTC),
        )
        return {
            "run_id": str(run_id),
            "committed": committed,
            "result_url": f"/ui/linux-results?run_id={run_id}",
            "assurance_level": processed.assurance_level,
            "device_identity_verified": False,
        }
    except PackageValidationError as exc:
        raise _safe_error(exc.code.value) from exc
    finally:
        staged.unlink(missing_ok=True)


@router.get("/api/v1/linux/one-shot/runs/{run_id}")
def linux_self_scan_status(request: Request, run_id: UUID) -> dict[str, object]:
    principal = _require_feature(request)
    with Session(_engine()) as session:
        record = load_linux_oneshot_run(
            session,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
            run_id=run_id,
        )
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Linux self scan not found.")
    return {
        "run_id": str(record.run_id),
        "status": record.status,
        "distribution": record.distribution,
        "submission_profile": record.submission_profile,
        "assurance_level": record.assurance_level,
        "result_sha256": record.result_sha256,
        "draft": True,
        "official_certification": False,
    }


@router.delete("/api/v1/linux/one-shot/runs/{run_id}")
def delete_linux_self_scan(
    request: Request,
    run_id: UUID,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict[str, bool]:
    principal = _require_feature(request)
    verify_browser_csrf(request, csrf_token)
    with Session(_engine()) as session, session.begin():
        deleted = mark_linux_oneshot_deleted(
            session,
            organization_id=principal.organization_id,
            owner_user_id=principal.user_id,
            run_id=run_id,
        )
    return {"deleted": deleted}
