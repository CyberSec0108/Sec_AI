"""Sec_AI Linux 원샷 프로그램의 사용자용 CLI."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import os
import shutil
import signal
import socket
import sys
import tempfile
import time
import webbrowser
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any, cast
from uuid import uuid4

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from security_audit.analysis.package_validation import PackageValidationError
from security_audit.collector.linux_local import (
    LinuxLocalCollectionBatch,
    LocalProcessSupervisor,
    collect_linux_plan_locally,
    current_linux_runtime_identity,
)
from security_audit.collector.linux_manifest import (
    ManifestSignatureVerifier,
    verify_linux_collector_manifest,
)
from security_audit.collector.linux_package import (
    BuiltLinuxAuditPackage,
    build_linux_audit_package,
    replace_linux_package_authentication,
    write_linux_offline_descriptor,
)
from security_audit.collector.scan_handshake import (
    GrantedScan,
    perform_scan_handshake,
)
from security_audit.collector.scan_sidecar import (
    ScanSidecar,
    device_name,
    existing_sidecar_path,
)
from security_audit.collector.scan_sidecar_keys import (
    ScanSidecarKeyError,
    load_verified_sidecar,
)
from security_audit.platforms import LinuxDistribution, linux_adapter_for
from security_audit.platforms.readonly_plan import ReadOnlyCommandPlan

COLLECTOR_NOTICE = "자가 점검 DRAFT · 공식 인증 결과가 아닙니다."


def _bundle_root() -> Path:
    frozen_root = getattr(sys, "_MEIPASS", None)
    if isinstance(frozen_root, str):
        return Path(frozen_root)
    return Path(__file__).resolve().parents[3]


def _schema_root() -> Path:
    return _bundle_root() / "database" / "schemas"


def _build_sha256() -> str:
    source = Path(sys.executable) if getattr(sys, "frozen", False) else Path(__file__)
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _server_url(value: str) -> str:
    parsed = httpx.URL(value)
    localhost = parsed.host in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and localhost):
        raise ValueError("중앙 UI 주소는 HTTPS여야 합니다. 개발용 localhost만 HTTP를 허용합니다.")
    if parsed.userinfo or parsed.query or parsed.fragment:
        raise ValueError("중앙 UI 주소에 계정·query·fragment를 넣을 수 없습니다.")
    return str(parsed).rstrip("/")


@contextmanager
def _single_instance_lock() -> Iterator[None]:
    import fcntl

    lock_path = Path(tempfile.gettempdir()) / f"secai-linux-one-shot-{os.getuid()}.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("이미 Linux 자가 점검 프로그램이 실행 중입니다.") from exc
        yield
    finally:
        os.close(descriptor)


def _manifest_verifier(
    public_key_b64: str,
    expected_key_id: str,
) -> ManifestSignatureVerifier:
    raw = base64.urlsafe_b64decode(public_key_b64 + ("=" * (-len(public_key_b64) % 4)))
    public_key = Ed25519PublicKey.from_public_bytes(raw)

    def verify(key_id: str, digest: bytes, signature: str) -> bool:
        if key_id != expected_key_id:
            return False
        try:
            decoded = base64.urlsafe_b64decode(signature + ("=" * (-len(signature) % 4)))
            public_key.verify(decoded, digest)
        except (InvalidSignature, ValueError):
            return False
        return True

    return verify


def _collect(
    distribution: LinuxDistribution,
    *,
    cancelled: Event,
    supervisor: LocalProcessSupervisor,
    approved_consent: bool | None = None,
) -> LinuxLocalCollectionBatch:
    plan = linux_adapter_for(distribution).plan
    standard_plan = ReadOnlyCommandPlan(
        platform="LINUX",
        commands=tuple(item for item in plan.commands if item.privilege == "STANDARD_USER"),
    )
    elevated_plan = ReadOnlyCommandPlan(
        platform="LINUX",
        commands=tuple(item for item in plan.commands if item.privilege != "STANDARD_USER"),
    )

    def progress(probe_id: str, state: str) -> None:
        if state == "STARTED":
            print(f"  확인 중: {probe_id}")

    print("\n[1/2] 일반 권한 자료 3개를 먼저 확인합니다.")
    standard = collect_linux_plan_locally(
        standard_plan,
        include_elevated=False,
        elevated_consent=False,
        should_cancel=cancelled.is_set,
        on_probe=progress,
        process_supervisor=supervisor,
    )
    if standard.cancelled:
        return standard
    print("\n[2/2] 추가 권한 자료 39개는 계정 정책, SSH, 파일 권한, 서비스 상태를 읽습니다.")
    print("설정을 바꾸지 않으며 비밀번호는 Linux sudo가 직접 처리합니다.")
    if approved_consent is None:
        consent = input("추가 권한 점검을 계속할까요? [y/N]: ").strip().casefold() == "y"
    else:
        # 승인 화면의 체크박스가 이미 같은 동의를 받았습니다.
        consent = approved_consent
        print(f"승인 화면에서 받은 동의: {'예' if consent else '아니오'}")
    elevated = collect_linux_plan_locally(
        elevated_plan,
        include_elevated=consent,
        elevated_consent=consent,
        should_cancel=cancelled.is_set,
        on_probe=progress,
        process_supervisor=supervisor,
    )
    return LinuxLocalCollectionBatch(
        outcomes=standard.outcomes + elevated.outcomes,
        cancelled=standard.cancelled or elevated.cancelled,
    )


def _save_offline(
    package: BuiltLinuxAuditPackage,
    output_directory: Path,
) -> tuple[Path, Path]:
    output_directory.mkdir(parents=True, exist_ok=True)
    suffix = str(uuid4())[:8]
    archive_output = output_directory / f"secai-linux-result-{suffix}.zip"
    descriptor_output = output_directory / f"secai-linux-result-{suffix}.descriptor.json"
    with package.archive_path.open("rb") as source, archive_output.open("xb") as destination:
        shutil.copyfileobj(source, destination, length=64 * 1024)
    os.chmod(archive_output, 0o600)
    write_linux_offline_descriptor(package, descriptor_output)
    return archive_output, descriptor_output


def _request_approval(sidecar: ScanSidecar) -> GrantedScan:
    """브라우저 승인을 받고 실행 코드를 받아옵니다. 사용자는 코드를 보지 않습니다."""

    target_name = device_name(socket.gethostname())
    print(f"\n점검 대상: {device_name}")
    print("웹 화면에서 [점검 승인]을 눌러주세요. 승인 전에는 아무것도 수집하지 않습니다.")
    with httpx.Client(timeout=httpx.Timeout(30, read=60), follow_redirects=False) as client:

        def _post(url: str, payload: dict[str, object]) -> dict[str, Any]:
            response = client.post(url, json=payload, headers={"Accept": "application/json"})
            response.raise_for_status()
            return cast(dict[str, Any], response.json())

        def _get(url: str) -> dict[str, Any]:
            response = client.get(url, headers={"Accept": "application/json"})
            response.raise_for_status()
            return cast(dict[str, Any], response.json())

        def _open(url: str) -> bool:
            print(f"승인 주소: {url}")
            try:
                return bool(webbrowser.open(url))
            except OSError:
                return False

        return perform_scan_handshake(
            sidecar,
            device_name=target_name,
            register=_post,
            poll=_get,
            grant=_post,
            open_browser=_open,
            sleep=time.sleep,
        )


def run(
    *,
    server_url: str,
    distribution: LinuxDistribution | None,
    output_directory: Path,
    sidecar: ScanSidecar | None = None,
) -> int:
    print("Sec_AI Linux 원샷 보안 점검")
    print(COLLECTOR_NOTICE)
    print("설정·서비스·계정·방화벽을 변경하지 않습니다. 예상 시간은 약 5~15분입니다.\n")
    identity = current_linux_runtime_identity(distribution)
    selected_distribution = identity.distribution
    adapter = linux_adapter_for(selected_distribution)
    print(f"자동 확인: {adapter.display_name} · x86_64")
    approved_consent: bool | None = None
    if sidecar is not None:
        granted = _request_approval(sidecar)
        if granted.grant_code is None:
            print("승인은 되었지만 실행 코드를 받지 못했습니다.", file=sys.stderr)
            return 1
        code = granted.grant_code
        server_url = sidecar.server_origin
        approved_consent = granted.elevated_consent
        print("승인을 확인했습니다.")
    else:
        code = getpass.getpass("중앙 UI에 표시된 일회용 코드: ").strip()
    credential = ""
    supervisor = LocalProcessSupervisor()
    cancelled = Event()

    def stop(_signal: int, _frame: object) -> None:
        cancelled.set()
        supervisor.cancel()

    previous_int = signal.signal(signal.SIGINT, stop)
    previous_term = signal.signal(signal.SIGTERM, stop)
    try:
        with httpx.Client(timeout=httpx.Timeout(30, read=120), follow_redirects=False) as client:
            exchange = client.post(
                f"{server_url}/api/v1/linux/one-shot/exchange",
                json={
                    "code": code,
                    "os_release": identity.os_release.decode("utf-8", errors="strict"),
                    "machine": identity.machine,
                },
                headers={"Accept": "application/json"},
            )
            exchange.raise_for_status()
            connection = cast(dict[str, Any], exchange.json())
            credential = str(connection["credential"])
            manifest = cast(dict[str, Any], connection["manifest"])
            verify_linux_collector_manifest(
                manifest,
                schema_root=_schema_root(),
                expected_distribution=selected_distribution,
                now=datetime.now(UTC),
                verify_signature=_manifest_verifier(
                    str(connection["manifest_public_key"]),
                    str(connection["manifest_key_id"]),
                ),
            )
            batch = _collect(
                selected_distribution,
                cancelled=cancelled,
                supervisor=supervisor,
                approved_consent=approved_consent,
            )
            if batch.cancelled:
                print("사용자 요청으로 안전하게 중단했습니다.")
                return 130
            collected = sum(item.collection_status == "COLLECTED" for item in batch.outcomes)
            errors = sum(item.collection_status == "ERROR" for item in batch.outcomes)
            skipped = sum(item.collection_status == "SKIPPED" for item in batch.outcomes)
            print(f"\n수집 완료: 성공 {collected}개 · 오류 {errors}개 · 건너뜀 {skipped}개")
            with tempfile.TemporaryDirectory(prefix="secai-linux-result-") as temporary:
                archive_path = Path(temporary) / "result.zip"
                online = build_linux_audit_package(
                    manifest=manifest,
                    outcomes=batch.outcomes,
                    archive_path=archive_path,
                    package_id=uuid4(),
                    collected_at=datetime.now(UTC),
                    build_sha256=_build_sha256(),
                    host_version=identity.version,
                    authentication={
                        "profile": "ONLINE-AUTHENTICATED",
                        "assurance_level": "MEDIUM",
                        "authenticated_subject_id": str(manifest["subject_user_id"]),
                        "transport_receipt_id": str(connection["transport_receipt_id"]),
                    },
                )
                try:
                    with online.archive_path.open("rb") as stream:
                        submitted = client.post(
                            f"{server_url}/api/v1/linux/one-shot/submit",
                            headers={"Authorization": f"Bearer {credential}"},
                            data={"descriptor": online.descriptor_bytes.decode("utf-8")},
                            files={"package": ("result.zip", stream, "application/zip")},
                            timeout=180,
                        )
                    submitted.raise_for_status()
                    response = cast(dict[str, Any], submitted.json())
                    print("온라인 제출과 서버 검증을 완료했습니다.")
                    print(f"결과 주소: {server_url}{response['result_url']}")
                    return 0
                except (httpx.HTTPError, ValueError):
                    offline = replace_linux_package_authentication(
                        online,
                        {
                            "profile": "OFFLINE-USER-SUBMITTED",
                            "assurance_level": "LOW",
                        },
                    )
                    archive_output, descriptor_output = _save_offline(
                        offline,
                        output_directory,
                    )
                    print("자동 제출에 실패해 검증 가능한 오프라인 파일을 저장했습니다.")
                    print(f"ZIP: {archive_output}")
                    print(f"Descriptor: {descriptor_output}")
                    print("중앙 UI의 '오프라인 결과 수동 업로드'에서 두 파일을 선택하세요.")
                    return 2
    finally:
        credential = ""
        code = ""
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)


def main(
    argv: list[str] | None = None,
    *,
    forced_distribution: LinuxDistribution | None = None,
) -> int:
    parser = argparse.ArgumentParser(description="Sec_AI Linux 원샷 자가 점검")
    parser.add_argument(
        "--server-url",
        default=os.getenv("SECAI_SERVER_URL", "http://localhost:18480"),
        help="Sec_AI 중앙 UI 주소; credential이나 token을 넣지 않습니다.",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path.cwd(),
        help="자동 제출 실패 시 새 오프라인 Package를 저장할 위치입니다.",
    )
    parser.add_argument(
        "--sidecar",
        type=Path,
        default=existing_sidecar_path(Path(sys.argv[0]).resolve()),
        help="다운로드 시 함께 받은 실행 파일 옆의 사이드카 파일 위치입니다.",
    )
    arguments = parser.parse_args(argv)
    try:
        with _single_instance_lock():
            sidecar = load_verified_sidecar(arguments.sidecar, _bundle_root())
            return run(
                server_url=_server_url(arguments.server_url),
                distribution=forced_distribution,
                output_directory=arguments.output_directory,
                sidecar=sidecar,
            )
    except (
        OSError,
        RuntimeError,
        ValueError,
        PackageValidationError,
        ScanSidecarKeyError,
        httpx.HTTPError,
    ) as exc:
        code = getattr(exc, "code", type(exc).__name__)
        print(f"점검을 시작하거나 완료하지 못했습니다. 오류 코드: {code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
