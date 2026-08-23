"""Owner-scoped PostgreSQL persistence for Linux one-shot self scans."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from .linux_audit_repository import append_linux_audit_event, set_linux_audit_scope


@dataclass(frozen=True, slots=True)
class LinuxOneShotRunRecord:
    run_id: UUID
    organization_id: UUID
    owner_user_id: UUID
    asset_id: UUID
    distribution: str
    status: str
    manifest: dict[str, Any]
    manifest_sha256: str
    package_sha256: str | None
    submission_profile: str | None
    assurance_level: str | None
    result_json: dict[str, Any] | None
    result_sha256: str | None


def create_linux_oneshot_run(
    session: Session,
    *,
    run_id: UUID,
    organization_id: UUID,
    owner_user_id: UUID,
    asset_id: UUID,
    distribution: str,
    manifest: dict[str, Any],
) -> None:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    asset_key = {
        "UBUNTU_22_04": "self-ubuntu22",
        "UBUNTU_24_04": "self-ubuntu24",
        "DEBIAN_12": "self-debian12",
        "ROCKY_9": "self-rocky9",
        "RHEL_9": "self-rhel9",
        "ALMALINUX_9": "self-alma9",
        "AUTO": "self-auto",
    }.get(distribution)
    if asset_key is None:
        raise ValueError("LINUX_ONESHOT_DISTRIBUTION_INVALID")
    session.execute(
        text(
            """
            INSERT INTO linux_audit_runs (
                id, organization_id, owner_user_id, asset_key, asset_id,
                distribution, benchmark_id, status, run_mode, manifest_id,
                manifest_json, manifest_sha256, execution_attempt_id
            ) VALUES (
                :id, :organization_id, :owner_user_id, :asset_key, :asset_id,
                :distribution, 'KISA-2026-UNIX-U01-U67', 'WAITING_UPLOAD',
                'ONESHOT_SELF', :manifest_id, CAST(:manifest AS jsonb),
                :manifest_sha256, :execution_attempt_id
            )
            """
        ),
        {
            "id": run_id,
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "asset_key": asset_key,
            "asset_id": asset_id,
            "distribution": distribution,
            "manifest_id": manifest["id"],
            "manifest": json.dumps(manifest, ensure_ascii=False),
            "manifest_sha256": manifest["manifest_content_sha256"],
            "execution_attempt_id": manifest["execution_attempt_id"],
        },
    )
    append_linux_audit_event(
        session,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
        run_id=run_id,
        event_type="WAITING_FOR_PACKAGE",
        payload={"mode": "ONESHOT_SELF", "draft": True},
    )


def find_pending_linux_oneshot_run(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    asset_key: str,
) -> tuple[UUID, datetime | None] | None:
    """활성 slot을 잡고 있는 자가 점검과 그 manifest 만료 시각을 찾습니다."""

    set_linux_audit_scope(session, organization_id, owner_user_id)
    row = session.execute(
        text(
            """
            SELECT id, manifest_json ->> 'expires_at' AS expires_at
            FROM linux_audit_runs
            WHERE organization_id = :organization_id
              AND owner_user_id = :owner_user_id
              AND asset_key = :asset_key
              AND run_mode = 'ONESHOT_SELF'
              AND deleted_at IS NULL
              AND status IN ('WAITING_UPLOAD', 'VALIDATING')
            """
        ),
        {
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "asset_key": asset_key,
        },
    ).first()
    if row is None:
        return None
    raw_expires_at = row[1]
    if not raw_expires_at:
        return UUID(str(row[0])), None
    try:
        expires_at = datetime.fromisoformat(str(raw_expires_at).replace("Z", "+00:00"))
    except ValueError:
        return UUID(str(row[0])), None
    return UUID(str(row[0])), expires_at


def bind_linux_oneshot_platform(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    distribution: str,
    manifest: dict[str, Any],
    discovery: dict[str, Any],
) -> None:
    """일회용 코드 교환 시 AUTO 실행을 감지된 한 배포판에 원자적으로 묶습니다."""

    asset_key = {
        "UBUNTU_22_04": "self-ubuntu22",
        "UBUNTU_24_04": "self-ubuntu24",
        "DEBIAN_12": "self-debian12",
        "ROCKY_9": "self-rocky9",
        "RHEL_9": "self-rhel9",
        "ALMALINUX_9": "self-alma9",
    }.get(distribution)
    if asset_key is None:
        raise ValueError("LINUX_ONESHOT_DISTRIBUTION_INVALID")
    set_linux_audit_scope(session, organization_id, owner_user_id)
    updated = session.execute(
        text(
            """
            UPDATE linux_audit_runs
            SET asset_key = :asset_key, distribution = :distribution,
                manifest_id = :manifest_id,
                manifest_json = CAST(:manifest AS jsonb),
                manifest_sha256 = :manifest_sha256,
                execution_attempt_id = :execution_attempt_id
            WHERE id = :run_id
              AND organization_id = :organization_id
              AND owner_user_id = :owner_user_id
              AND run_mode = 'ONESHOT_SELF'
              AND status = 'WAITING_UPLOAD'
              AND distribution = 'AUTO'
            """
        ),
        {
            "run_id": run_id,
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "asset_key": asset_key,
            "distribution": distribution,
            "manifest_id": manifest["id"],
            "manifest": json.dumps(manifest, ensure_ascii=False),
            "manifest_sha256": manifest["manifest_content_sha256"],
            "execution_attempt_id": manifest["execution_attempt_id"],
        },
    )
    if int(getattr(updated, "rowcount", 0)) != 1:
        raise ValueError("LINUX_ONESHOT_AUTO_BIND_CONFLICT")
    append_linux_audit_event(
        session,
        organization_id=organization_id,
        owner_user_id=owner_user_id,
        run_id=run_id,
        event_type="PLATFORM_IDENTIFIED",
        payload=discovery,
    )


def load_linux_oneshot_run(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
) -> LinuxOneShotRunRecord | None:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    row = (
        session.execute(
            text(
                """
                SELECT id, organization_id, owner_user_id, asset_id, distribution,
                       status, manifest_json, manifest_sha256, package_sha256,
                       submission_profile, assurance_level, result_json, result_sha256
                FROM linux_audit_runs
                WHERE id = :run_id AND run_mode = 'ONESHOT_SELF' AND deleted_at IS NULL
                """
            ),
            {"run_id": run_id},
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    return LinuxOneShotRunRecord(
        run_id=row["id"],
        organization_id=row["organization_id"],
        owner_user_id=row["owner_user_id"],
        asset_id=row["asset_id"],
        distribution=str(row["distribution"]),
        status=str(row["status"]),
        manifest=dict(row["manifest_json"]),
        manifest_sha256=str(row["manifest_sha256"]),
        package_sha256=str(row["package_sha256"]) if row["package_sha256"] else None,
        submission_profile=(
            str(row["submission_profile"]) if row["submission_profile"] else None
        ),
        assurance_level=str(row["assurance_level"]) if row["assurance_level"] else None,
        result_json=dict(row["result_json"]) if row["result_json"] is not None else None,
        result_sha256=str(row["result_sha256"]) if row["result_sha256"] else None,
    )


def nonce_is_fresh(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
    nonce: str,
) -> bool:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    return (
        session.execute(
            text(
                "SELECT 1 FROM linux_oneshot_submissions "
                "WHERE run_id = :run_id AND nonce = :nonce"
            ),
            {"run_id": run_id, "nonce": nonce},
        ).scalar_one_or_none()
        is None
    )


def commit_linux_oneshot_result(
    session: Session,
    *,
    record: LinuxOneShotRunRecord,
    descriptor: dict[str, Any],
    descriptor_sha256: str,
    archive_sha256: str,
    submission_profile: str,
    assurance_level: str,
    evidence: tuple[dict[str, Any], ...],
    result_json: dict[str, Any],
    received_at: datetime,
) -> bool:
    """Package·Evidence·결과를 한 transaction에서 정확히 한 번 확정합니다."""

    set_linux_audit_scope(session, record.organization_id, record.owner_user_id)
    existing = session.execute(
        text(
            "SELECT archive_sha256 FROM linux_oneshot_submissions "
            "WHERE run_id = :run_id"
        ),
        {"run_id": record.run_id},
    ).scalar_one_or_none()
    if existing is not None:
        if str(existing) == archive_sha256:
            return False
        raise ValueError("LINUX_ONESHOT_DIFFERENT_PACKAGE_ALREADY_COMMITTED")
    locked = session.execute(
        text(
            "SELECT status FROM linux_audit_runs WHERE id = :run_id FOR UPDATE"
        ),
        {"run_id": record.run_id},
    ).scalar_one()
    if str(locked) != "WAITING_UPLOAD":
        raise ValueError("LINUX_ONESHOT_RUN_NOT_WAITING")
    session.execute(
        text(
            """
            INSERT INTO linux_oneshot_submissions (
                run_id, organization_id, owner_user_id, asset_id, package_id,
                manifest_id, execution_attempt_id, nonce, archive_sha256,
                descriptor_sha256, descriptor_json, submission_profile,
                assurance_level, created_at
            ) VALUES (
                :run_id, :organization_id, :owner_user_id, :asset_id, :package_id,
                :manifest_id, :execution_attempt_id, :nonce, :archive_sha256,
                :descriptor_sha256, CAST(:descriptor AS jsonb), :submission_profile,
                :assurance_level, :received_at
            )
            """
        ),
        {
            "run_id": record.run_id,
            "organization_id": record.organization_id,
            "owner_user_id": record.owner_user_id,
            "asset_id": record.asset_id,
            "package_id": descriptor["id"],
            "manifest_id": descriptor["manifest_id"],
            "execution_attempt_id": descriptor["execution_attempt_id"],
            "nonce": descriptor["nonce"],
            "archive_sha256": archive_sha256,
            "descriptor_sha256": descriptor_sha256,
            "descriptor": json.dumps(descriptor, ensure_ascii=False),
            "submission_profile": submission_profile,
            "assurance_level": assurance_level,
            "received_at": received_at,
        },
    )
    for item in evidence:
        session.execute(
            text(
                """
                INSERT INTO linux_oneshot_evidence (
                    evidence_id, run_id, organization_id, owner_user_id, probe_id,
                    collection_status, error_code, raw_output_sha256,
                    normalized_sha256, redaction_applied, normalized_value, collected_at
                ) VALUES (
                    :evidence_id, :run_id, :organization_id, :owner_user_id, :probe_id,
                    :collection_status, :error_code, :raw_output_sha256,
                    :normalized_sha256, :redaction_applied, :normalized_value, :collected_at
                )
                """
            ),
            {
                "evidence_id": item["evidence_id"],
                "run_id": record.run_id,
                "organization_id": record.organization_id,
                "owner_user_id": record.owner_user_id,
                "probe_id": item["probe_id"],
                "collection_status": item["collection_status"],
                "error_code": item["error_code"],
                "raw_output_sha256": item["raw_output_sha256"],
                "normalized_sha256": item["normalized_sha256"],
                "redaction_applied": item["redaction_applied"],
                "normalized_value": item["normalized_value"],
                "collected_at": item["collected_at"],
            },
        )
    result_sha256 = str(result_json["result_sha256"])
    updated = session.execute(
        text(
            """
            UPDATE linux_audit_runs
            SET status = 'COMPLETED', package_sha256 = :archive_sha256,
                submission_profile = :submission_profile,
                assurance_level = :assurance_level,
                result_json = CAST(:result_json AS jsonb), result_sha256 = :result_sha256,
                received_at = :received_at, completed_at = :received_at
            WHERE id = :run_id AND status = 'WAITING_UPLOAD' AND result_json IS NULL
            """
        ),
        {
            "archive_sha256": archive_sha256,
            "submission_profile": submission_profile,
            "assurance_level": assurance_level,
            "result_json": json.dumps(result_json, ensure_ascii=False),
            "result_sha256": result_sha256,
            "received_at": received_at,
            "run_id": record.run_id,
        },
    )
    if int(getattr(updated, "rowcount", 0)) != 1:
        raise ValueError("LINUX_ONESHOT_RESULT_COMMIT_CONFLICT")
    append_linux_audit_event(
        session,
        organization_id=record.organization_id,
        owner_user_id=record.owner_user_id,
        run_id=record.run_id,
        event_type="RUN_COMPLETED",
        payload={
            "result_sha256": result_sha256,
            "archive_sha256": archive_sha256,
            "assurance_level": assurance_level,
            "draft": True,
        },
    )
    return True


def mark_linux_oneshot_deleted(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    run_id: UUID,
) -> bool:
    set_linux_audit_scope(session, organization_id, owner_user_id)
    result = session.execute(
        text(
            "UPDATE linux_audit_runs SET deleted_at = now() "
            "WHERE id = :run_id AND run_mode = 'ONESHOT_SELF' AND deleted_at IS NULL"
        ),
        {"run_id": run_id},
    )
    return int(getattr(result, "rowcount", 0)) == 1
