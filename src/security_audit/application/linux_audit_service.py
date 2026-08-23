"""Allowlisted multi-distribution KISA U-01~U-67 collection orchestration."""

from __future__ import annotations

import os
import shutil
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from security_audit.application.device_ai_token_stream import (
    enrich_linux_audit_history_result,
)
from security_audit.application.linux_asset_management import (
    LinuxPlatformVerification,
    LinuxVerificationTarget,
)
from security_audit.common.canonical_json import JsonValue, canonical_sha256
from security_audit.persistence.database.linux_audit_repository import (
    append_linux_audit_event,
    finish_linux_audit_run,
    load_linux_audit_run,
    mark_linux_audit_running,
)
from security_audit.platforms import (
    AssetContext,
    DeviceAuditResult,
    LinuxDistribution,
    SshReadOnlyTarget,
    collect_plan_over_ssh,
    current_platform_support_catalog,
    detect_linux_distribution,
    discover_linux_platform,
    evaluate_kisa_unix,
    linux_adapter_for,
)
from security_audit.platforms.linux_kisa import (
    KISA_2026_UNIX_CONTROLS,
    KisaUnixAssessmentProfile,
    control_ids_for_probe,
    probe_ids_for_control,
)
from security_audit.platforms.readonly_plan import ReadOnlyCommand, ReadOnlyCommandPlan


@dataclass(frozen=True, slots=True)
class LinuxLabTarget:
    key: str
    label: str
    distribution: LinuxDistribution
    host: str
    username: str
    private_key: Path
    known_hosts: Path
    asset_id: UUID
    port: int = 22

    def public_view(self) -> dict[str, str]:
        return {
            "key": self.key,
            "label": self.label,
            "connection_label": "등록된 SSH 서버",
            "platform_hint": "운영체제는 연결 후 자동 확인",
            "benchmark": "KISA UNIX U-01~U-67",
        }


def linux_lab_targets() -> dict[str, LinuxLabTarget]:
    runtime = Path(os.getenv("SECAI_LINUX_RUNTIME_ROOT", "/run/secai-vmware"))
    values = (
        (
            "ubuntu24",
            os.getenv("SECAI_LINUX_UBUNTU_LABEL", "Linux 시험 서버 A"),
            LinuxDistribution.UBUNTU_24_04,
            os.getenv("SECAI_LINUX_UBUNTU_HOST", "192.168.110.146"),
            "secai-ubuntu-lab-ed25519",
        ),
        (
            "rocky9",
            os.getenv("SECAI_LINUX_ROCKY_LABEL", "Linux 시험 서버 B"),
            LinuxDistribution.ROCKY_9,
            os.getenv("SECAI_LINUX_ROCKY_HOST", "192.168.110.148"),
            "secai-rocky-lab-ed25519",
        ),
    )
    return {
        key: LinuxLabTarget(
            key=key,
            label=label,
            distribution=distribution,
            host=host,
            username=os.getenv("SECAI_LINUX_SSH_USER", "secai-lab"),
            private_key=runtime / key_file,
            known_hosts=runtime / "known_hosts",
            asset_id=uuid5(NAMESPACE_URL, f"secai-linux-lab:{key}"),
            port=22,
        )
        for key, label, distribution, host, key_file in values
    }


_CANCELLATIONS: dict[UUID, threading.Event] = {}
_CANCELLATIONS_LOCK = threading.Lock()
_PREFLIGHT_ATTEMPTS = 2


def request_running_linux_audit_cancel(run_id: UUID) -> None:
    with _CANCELLATIONS_LOCK:
        event = _CANCELLATIONS.get(run_id)
    if event is not None:
        event.set()


def _criteria_sha256(profile: KisaUnixAssessmentProfile) -> str:
    return canonical_sha256(
        {
            "benchmark": "KISA-2026-UNIX-U01-U67",
            "controls": [
                {
                    "control_id": item.control_id,
                    "severity": item.severity,
                    "category": item.category,
                    "title": item.title,
                    "page_start": item.page_start,
                    "page_end": item.page_end,
                }
                for item in KISA_2026_UNIX_CONTROLS
            ],
            "profile": profile.public_values(),
        }
    )


def _validate_target_distribution(
    os_release: bytes | None,
    expected: LinuxDistribution,
) -> LinuxDistribution:
    """수집 실패와 실제 배포판 불일치를 서로 다른 안전 오류로 구분합니다."""

    if not os_release:
        raise RuntimeError("LINUX_PREFLIGHT_COLLECTION_FAILED")
    try:
        detected = detect_linux_distribution(os_release)
    except ValueError as exc:
        raise RuntimeError("LINUX_DISTRIBUTION_UNSUPPORTED") from exc
    if detected != expected:
        raise RuntimeError("LINUX_DISTRIBUTION_MISMATCH")
    return detected


def verify_linux_connection(target: LinuxVerificationTarget) -> LinuxPlatformVerification:
    """고정된 두 명령으로 등록 서버의 연결과 지원 플랫폼을 확인합니다."""

    detection = ReadOnlyCommandPlan(
        platform="LINUX",
        commands=(
            ReadOnlyCommand(
                "linux.os-release",
                ("/usr/bin/cat", "/etc/os-release"),
                "STANDARD_USER",
                10,
                8192,
            ),
            ReadOnlyCommand(
                "linux.architecture",
                ("/usr/bin/uname", "-m"),
                "STANDARD_USER",
                10,
                128,
            ),
        ),
    )
    collected = collect_plan_over_ssh(
        detection,
        SshReadOnlyTarget(
            host=target.host,
            username=target.username,
            private_key=target.private_key,
            known_hosts=target.known_hosts,
            port=target.port,
        ),
    )
    os_release = collected.outputs.get("linux.os-release")
    architecture = collected.outputs.get("linux.architecture")
    if os_release is None or architecture is None:
        raise RuntimeError("LINUX_REGISTRATION_CONNECTION_FAILED")
    detected = detect_linux_distribution(os_release)
    fingerprint = discover_linux_platform(
        os_release,
        machine=architecture.decode("ascii", errors="strict").strip(),
    )
    current_platform_support_catalog().resolve(fingerprint)
    return LinuxPlatformVerification(
        distribution=detected,
        version=fingerprint.version,
        architecture=fingerprint.architecture,
    )


def _secured_ssh_material(target: LinuxLabTarget) -> tuple[Path, Path]:
    """Docker Desktop bind 파일을 OpenSSH가 허용하는 tmpfs 권한으로 복사합니다."""

    secure_root = Path("/tmp/secai-linux-ssh") / target.key  # noqa: S108 - 전용 tmpfs
    secure_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    secure_root.chmod(0o700)
    private_key = secure_root / "identity"
    known_hosts = secure_root / "known_hosts"
    shutil.copyfile(target.private_key, private_key)
    shutil.copyfile(target.known_hosts, known_hosts)
    private_key.chmod(0o600)
    known_hosts.chmod(0o600)
    return private_key, known_hosts


def start_linux_audit_thread(
    engine: Engine,
    *,
    run_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    target: LinuxLabTarget,
    criteria_profile: KisaUnixAssessmentProfile,
) -> None:
    cancel = threading.Event()
    with _CANCELLATIONS_LOCK:
        _CANCELLATIONS[run_id] = cancel
    thread = threading.Thread(
        target=_run_linux_audit,
        kwargs={
            "engine": engine,
            "run_id": run_id,
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "target": target,
            "criteria_profile": criteria_profile,
            "cancel": cancel,
        },
        name=f"linux-audit-{run_id}",
        daemon=True,
    )
    thread.start()


def _event(
    engine: Engine,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    event_type: str,
    payload: dict[str, object],
) -> None:
    with Session(engine) as session, session.begin():
        append_linux_audit_event(
            session,
            organization_id=organization_id,
            owner_user_id=owner_user_id,
            run_id=run_id,
            event_type=event_type,
            payload=payload,
        )


def _run_linux_audit(
    *,
    engine: Engine,
    run_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    target: LinuxLabTarget,
    criteria_profile: KisaUnixAssessmentProfile,
    cancel: threading.Event,
) -> None:
    started_at = datetime.now(UTC)
    try:
        with Session(engine) as session, session.begin():
            mark_linux_audit_running(
                session, organization_id=organization_id, owner_user_id=owner_user_id, run_id=run_id
            )
        _event(
            engine,
            organization_id,
            owner_user_id,
            run_id,
            "RUN_STARTED",
            {"asset": target.public_view(), "total_controls": 67},
        )
        private_key, known_hosts = _secured_ssh_material(target)
        ssh_target = SshReadOnlyTarget(
            host=target.host,
            username=target.username,
            private_key=private_key,
            known_hosts=known_hosts,
            port=target.port,
        )

        def should_cancel() -> bool:
            if cancel.is_set():
                return True
            with Session(engine) as session:
                record = load_linux_audit_run(
                    session,
                    organization_id=organization_id,
                    owner_user_id=owner_user_id,
                    run_id=run_id,
                )
            return record is None or record.cancellation_requested

        detection = ReadOnlyCommandPlan(
            platform="LINUX",
            commands=(
                ReadOnlyCommand(
                    "linux.os-release",
                    ("/usr/bin/cat", "/etc/os-release"),
                    "STANDARD_USER",
                    10,
                    8192,
                ),
                ReadOnlyCommand(
                    "linux.architecture",
                    ("/usr/bin/uname", "-m"),
                    "STANDARD_USER",
                    10,
                    128,
                ),
            ),
        )
        os_release: bytes | None = None
        architecture: bytes | None = None
        for attempt in range(1, _PREFLIGHT_ATTEMPTS + 1):
            preflight = collect_plan_over_ssh(
                detection,
                ssh_target,
                should_cancel=should_cancel,
            )
            if preflight.cancelled:
                raise InterruptedError
            os_release = preflight.outputs.get("linux.os-release")
            architecture = preflight.outputs.get("linux.architecture")
            if os_release and architecture:
                break
            if attempt < _PREFLIGHT_ATTEMPTS:
                _event(
                    engine,
                    organization_id,
                    owner_user_id,
                    run_id,
                    "PREFLIGHT_RETRY",
                    {
                        "next_attempt": attempt + 1,
                        "maximum_attempts": _PREFLIGHT_ATTEMPTS,
                    },
                )
        detected = _validate_target_distribution(os_release, target.distribution)
        if architecture is None or os_release is None:
            raise RuntimeError("LINUX_PREFLIGHT_COLLECTION_FAILED")
        fingerprint = discover_linux_platform(
            os_release,
            machine=architecture.decode("ascii", errors="strict").strip(),
        )
        selection = current_platform_support_catalog().resolve(fingerprint)
        _event(
            engine,
            organization_id,
            owner_user_id,
            run_id,
            "PLATFORM_IDENTIFIED",
            {
                "fingerprint": fingerprint.to_json(),
                "selection": selection.to_json(),
            },
        )
        adapter = linux_adapter_for(detected)
        command_count = len(adapter.plan.commands)
        completed_commands = 0
        completed_probe_ids: set[str] = set()

        def on_command(command_id: str, state: str) -> None:
            nonlocal completed_commands
            if state in {"COMPLETED", "FAILED"}:
                completed_commands += 1
                completed_probe_ids.add(command_id)
            affected_control_ids = control_ids_for_probe(command_id)
            ready_control_ids = tuple(
                control_id
                for control_id in affected_control_ids
                if set(probe_ids_for_control(control_id)).issubset(completed_probe_ids)
            )
            _event(
                engine,
                organization_id,
                owner_user_id,
                run_id,
                "PROBE_PROGRESS",
                {
                    "probe_id": command_id,
                    "state": state,
                    "completed_probes": completed_commands,
                    "total_probes": command_count,
                    "affected_control_ids": list(affected_control_ids),
                    "ready_control_ids": list(ready_control_ids),
                },
            )

        batch = collect_plan_over_ssh(
            adapter.plan,
            ssh_target,
            on_command=on_command,
            should_cancel=should_cancel,
        )
        if batch.cancelled or cancel.is_set():
            raise InterruptedError
        captured_at = datetime.now(UTC)
        results = evaluate_kisa_unix(
            batch.outputs,
            captured_at=captured_at,
            distribution=detected,
            profile=criteria_profile,
        )
        for index, control in enumerate(results, start=1):
            _event(
                engine,
                organization_id,
                owner_user_id,
                run_id,
                "CONTROL_COMPLETED",
                {
                    "control_index": index,
                    "total_controls": len(results),
                    "control_id": control.control_id,
                    "title": control.title,
                    "status": control.status,
                    "observed_summary": control.observed_summary,
                },
            )
        result = DeviceAuditResult(
            schema_version="1.0.0",
            run_id=run_id,
            asset=AssetContext(
                asset_id=target.asset_id,
                asset_type="LINUX_SERVER",
                platform="LINUX",
                platform_version=fingerprint.version,
                vendor=adapter.vendor,
                product_family=adapter.display_name,
            ),
            benchmark_id="KISA-2026-UNIX-U01-U67",
            benchmark_version="2026-DRAFT",
            criteria_profile_id=None,
            criteria_sha256=_criteria_sha256(criteria_profile),
            started_at=started_at,
            completed_at=datetime.now(UTC),
            controls=results,
            criteria_summary={
                "name": "KISA·SecAI Linux 안전 기본 기준",
                "source": (
                    "KISA_SECAI_DEFAULT"
                    if criteria_profile == KisaUnixAssessmentProfile()
                    else "USER_ADJUSTED"
                ),
                "values": cast(JsonValue, criteria_profile.public_values()),
                "review_display": "CHECK_REQUIRED",
            },
        )
        result_json = enrich_linux_audit_history_result(result.to_json())
        result_sha = str(result_json["result_sha256"])
        with Session(engine) as session, session.begin():
            finish_linux_audit_run(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                run_id=run_id,
                status="COMPLETED",
                result_json=result_json,
                result_sha256=result_sha,
            )
        _event(
            engine,
            organization_id,
            owner_user_id,
            run_id,
            "RUN_COMPLETED",
            {"result_sha256": result_sha, "collection_failures": batch.failures},
        )
    except InterruptedError:
        with Session(engine) as session, session.begin():
            finish_linux_audit_run(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                run_id=run_id,
                status="CANCELLED",
            )
        _event(engine, organization_id, owner_user_id, run_id, "RUN_CANCELLED", {})
    except Exception as exc:  # 안전한 오류 코드만 저장하고 원문 출력은 보관하지 않습니다.
        code = str(exc) if str(exc).isupper() and len(str(exc)) <= 80 else "LINUX_AUDIT_FAILED"
        with Session(engine) as session, session.begin():
            finish_linux_audit_run(
                session,
                organization_id=organization_id,
                owner_user_id=owner_user_id,
                run_id=run_id,
                status="FAILED",
            )
        _event(engine, organization_id, owner_user_id, run_id, "RUN_FAILED", {"code": code})
    finally:
        with _CANCELLATIONS_LOCK:
            _CANCELLATIONS.pop(run_id, None)
