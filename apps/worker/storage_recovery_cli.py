"""Internal-only IMP-045 synthetic backup and restore verification CLI."""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from minio import Minio
from minio.commonconfig import ENABLED
from minio.versioningconfig import VersioningConfig
from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from security_audit.common.canonical_json import (
    JsonValue,
    canonicalize_json,
)
from security_audit.common.secret_files import read_required_secret
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.models import EvidenceArtifactRecord
from security_audit.persistence.database.storage_recovery_repository import (
    add_synthetic_artifact,
    alembic_version,
    complete_recovery_run,
    database_inventory,
    mark_artifact_restored,
    mark_backup_created,
    mark_component,
    prepare_storage_recovery_run,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = (
    PROJECT_ROOT / "database" / "schemas" / "storage_recovery_manifest.schema.json"
)
PRIMARY_BUCKET = "secai-imp045-synthetic"
RESTORE_BUCKET = "secai-imp045-synthetic-restore"
IMAGE_REF = "RELEASE.2026-06-06T02-44-06Z"


def _utc(value: datetime | None = None) -> str:
    return (value or datetime.now(UTC)).isoformat().replace("+00:00", "Z")


def _recovery_root() -> Path:
    root = Path(os.getenv("SECAI_RECOVERY_ROOT", "/recovery")).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _engine() -> Engine:
    return create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )


def _aistor_client() -> Minio:
    endpoint = os.getenv(
        "SECAI_RECOVERY_AISTOR_ENDPOINT",
        ServiceSettings.from_environment().aistor_endpoint,
    )
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {
        "",
        "/",
    }:
        raise RuntimeError("AIStor recovery endpoint is invalid.")
    access_key = read_required_secret(
        os.getenv(
            "SECAI_AISTOR_ACCESS_KEY_FILE",
            "/run/secrets/aistor_root_user",
        )
    )
    secret_key = read_required_secret(
        os.getenv(
            "SECAI_AISTOR_SECRET_KEY_FILE",
            "/run/secrets/aistor_root_password",
        )
    )
    return Minio(
        parsed.netloc,
        access_key=access_key,
        secret_key=secret_key,
        secure=parsed.scheme == "https",
    )


def _ensure_versioned_bucket(client: Minio, bucket: str) -> None:
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)
    client.set_bucket_versioning(bucket, VersioningConfig(ENABLED))
    status = client.get_bucket_versioning(bucket)
    if status.status != ENABLED:
        raise RuntimeError("Recovery bucket versioning is not enabled.")


def _read_object(
    client: Minio,
    bucket: str,
    object_key: str,
    version_id: str,
) -> bytes:
    response = client.get_object(bucket, object_key, version_id=version_id)
    try:
        return response.read()
    finally:
        response.close()
        response.release_conn()


def _load_schema() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
    )


def _validate_manifest(manifest: dict[str, JsonValue]) -> None:
    validator = Draft202012Validator(_load_schema(), format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(manifest), key=lambda item: list(item.path))
    if errors:
        raise RuntimeError("Storage recovery manifest validation failed.")


def _manifest_path(root: Path) -> Path:
    return root / "storage-recovery-manifest.json"


def _load_manifest() -> dict[str, JsonValue]:
    value = json.loads(_manifest_path(_recovery_root()).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("Storage recovery manifest is invalid.")
    manifest = cast(dict[str, JsonValue], value)
    _validate_manifest(manifest)
    return manifest


def _object_entry(manifest: dict[str, JsonValue]) -> dict[str, JsonValue]:
    inventory = manifest["object_inventory"]
    if not isinstance(inventory, list) or len(inventory) != 1:
        raise RuntimeError("Storage recovery object inventory is invalid.")
    entry = inventory[0]
    if not isinstance(entry, dict):
        raise RuntimeError("Storage recovery object entry is invalid.")
    return entry


def _backup_file(entry: dict[str, JsonValue]) -> Path:
    relative = entry["backup_file"]
    if not isinstance(relative, str):
        raise RuntimeError("Storage recovery backup file is invalid.")
    root = _recovery_root()
    path = (root / relative).resolve()
    if root not in path.parents:
        raise RuntimeError("Storage recovery backup path escaped its root.")
    return path


def _prepare() -> dict[str, object]:
    started = time.monotonic()
    engine = _engine()
    try:
        with Session(engine) as session, session.begin():
            reference = prepare_storage_recovery_run(session)
        artifact_id = uuid4()
        object_key = f"synthetic/{artifact_id}/artifact.bin"
        content = canonicalize_json(
            {
                "classification": "SYNTHETIC_DEV_ONLY",
                "purpose": "IMP-045 storage recovery rehearsal",
                "recovery_run_id": str(reference.run_id),
            }
        )
        object_sha256 = sha256(content).hexdigest()
        client = _aistor_client()
        _ensure_versioned_bucket(client, PRIMARY_BUCKET)
        result = client.put_object(
            PRIMARY_BUCKET,
            object_key,
            io.BytesIO(content),
            len(content),
            content_type="application/octet-stream",
            metadata={
                "secai-classification": "SYNTHETIC_DEV_ONLY",
                "secai-sha256": object_sha256,
            },
        )
        source_version_id = result.version_id
        if not source_version_id:
            raise RuntimeError("AIStor did not return an exact object version.")
        downloaded = _read_object(
            client,
            PRIMARY_BUCKET,
            object_key,
            source_version_id,
        )
        if sha256(downloaded).hexdigest() != object_sha256:
            raise RuntimeError("AIStor source object hash mismatch.")
        backup_relative = f"objects/{artifact_id}.bin"
        backup_path = (_recovery_root() / backup_relative).resolve()
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        backup_path.write_bytes(downloaded)
        if sha256(backup_path.read_bytes()).hexdigest() != object_sha256:
            raise RuntimeError("Recovery backup copy hash mismatch.")
        with Session(engine) as session, session.begin():
            add_synthetic_artifact(
                session,
                reference,
                artifact_id=artifact_id,
                bucket_name=PRIMARY_BUCKET,
                object_key=object_key,
                source_version_id=source_version_id,
                object_sha256=object_sha256,
                size_bytes=len(content),
            )
        checkpoint_at = datetime.now(UTC)
        with Session(engine) as session:
            inventory = database_inventory(session)
            migration = alembic_version(session)
        manifest: dict[str, JsonValue] = {
            "schema_version": "1.0",
            "backup_id": str(reference.run_id),
            "created_at": _utc(checkpoint_at),
            "classification": "SYNTHETIC_DEV_ONLY",
            "source_checkpoint": {
                "alembic_version": migration,
                "postgres_checkpoint_at": _utc(checkpoint_at),
                "aistor_image_ref": IMAGE_REF,
                "redis_is_business_truth": False,
            },
            "database_inventory": inventory,
            "object_inventory": [
                {
                    "artifact_id": str(artifact_id),
                    "bucket": PRIMARY_BUCKET,
                    "object_key": object_key,
                    "source_version_id": source_version_id,
                    "sha256": object_sha256,
                    "size_bytes": len(content),
                    "backup_file": backup_relative,
                }
            ],
            "recovery_targets": {
                "postgres_rpo_seconds": 900,
                "postgres_rto_seconds": 14400,
                "evidence_rpo_seconds": 3600,
                "evidence_rto_seconds": 28800,
                "independent_failure_domain_required": True,
            },
        }
        _validate_manifest(manifest)
        _manifest_path(_recovery_root()).write_bytes(canonicalize_json(manifest))
        elapsed = max(0, int(time.monotonic() - started))
        with Session(engine) as session, session.begin():
            mark_backup_created(
                session,
                reference.run_id,
                evidence_rpo_seconds=elapsed,
            )
        return {
            "run_id": str(reference.run_id),
            "status": "BACKUP_CREATED",
            "evidence_rpo_seconds": elapsed,
            "object_count": 1,
            "classification": "SYNTHETIC_DEV_ONLY",
        }
    finally:
        engine.dispose()


def _verify_primary(run_id: UUID) -> dict[str, object]:
    engine = _engine()
    try:
        with Session(engine) as session:
            artifact = session.scalar(
                select(EvidenceArtifactRecord).where(
                    EvidenceArtifactRecord.recovery_run_id == run_id
                )
            )
            if artifact is None:
                raise RuntimeError("Synthetic recovery artifact is unavailable.")
        client = _aistor_client()
        content = _read_object(
            client,
            artifact.bucket_name,
            artifact.object_key,
            artifact.source_version_id,
        )
        matches = sha256(content).hexdigest() == artifact.object_sha256
        if not matches:
            raise RuntimeError("Recovered primary object hash mismatch.")
        return {"status": "PRIMARY_RECOVERED", "object_hash_matches": True}
    finally:
        engine.dispose()


def _restore_object(run_id: UUID) -> dict[str, object]:
    manifest = _load_manifest()
    if manifest["backup_id"] != str(run_id):
        raise RuntimeError("Storage recovery run binding is invalid.")
    entry = _object_entry(manifest)
    backup_file = _backup_file(entry)
    content = backup_file.read_bytes()
    expected_sha256 = entry["sha256"]
    if not isinstance(expected_sha256, str):
        raise RuntimeError("Storage recovery object hash is invalid.")
    if sha256(content).hexdigest() != expected_sha256:
        raise RuntimeError("Storage recovery backup object hash mismatch.")
    client = _aistor_client()
    _ensure_versioned_bucket(client, RESTORE_BUCKET)
    source_version_id = entry["source_version_id"]
    if not isinstance(source_version_id, str):
        raise RuntimeError("Storage recovery source version is invalid.")
    result = client.put_object(
        RESTORE_BUCKET,
        str(entry["object_key"]),
        io.BytesIO(content),
        len(content),
        content_type="application/octet-stream",
        metadata={
            "secai-classification": "SYNTHETIC_DEV_ONLY",
            "secai-source-version": source_version_id,
            "secai-sha256": expected_sha256,
        },
    )
    restored_version_id = result.version_id
    if not restored_version_id:
        raise RuntimeError("AIStor restore did not return an exact version.")
    restored = _read_object(
        client,
        RESTORE_BUCKET,
        str(entry["object_key"]),
        restored_version_id,
    )
    if sha256(restored).hexdigest() != expected_sha256:
        raise RuntimeError("Restored AIStor object hash mismatch.")
    engine = _engine()
    try:
        with Session(engine) as session, session.begin():
            mark_artifact_restored(
                session,
                run_id,
                restored_version_id=restored_version_id,
            )
    finally:
        engine.dispose()
    return {
        "status": "AISTOR_RESTORED",
        "object_hash_matches": True,
        "source_version_mapped": True,
    }


def _verify_database(run_id: UUID) -> dict[str, object]:
    manifest = _load_manifest()
    if manifest["backup_id"] != str(run_id):
        raise RuntimeError("Storage recovery run binding is invalid.")
    expected = manifest["database_inventory"]
    if not isinstance(expected, dict):
        raise RuntimeError("Storage recovery database inventory is invalid.")
    engine = _engine()
    try:
        with Session(engine) as session:
            actual = database_inventory(session)
            migration = alembic_version(session)
    finally:
        engine.dispose()
    checkpoint = manifest["source_checkpoint"]
    if not isinstance(checkpoint, dict):
        raise RuntimeError("Storage recovery checkpoint is invalid.")
    if actual != expected or migration != checkpoint["alembic_version"]:
        raise RuntimeError("Restored PostgreSQL inventory does not match.")
    return {
        "status": "POSTGRES_RESTORED",
        "finding_lineage_matches": True,
        "artifact_inventory_matches": True,
        "migration_matches": True,
    }


def _mark(
    run_id: UUID,
    component: str,
    status: str,
    seconds: int | None,
) -> dict[str, object]:
    engine = _engine()
    try:
        with Session(engine) as session, session.begin():
            mark_component(
                session,
                run_id,
                component=component,
                status=status,
                seconds=seconds,
            )
    finally:
        engine.dispose()
    return {"status": "RECORDED", "component": component}


def _complete(args: argparse.Namespace) -> dict[str, object]:
    run_id = UUID(args.run_id)
    engine = _engine()
    try:
        with Session(engine) as session, session.begin():
            complete_recovery_run(
                session,
                run_id,
                postgres_rpo_seconds=args.postgres_rpo,
                postgres_rto_seconds=args.postgres_rto,
                evidence_rpo_seconds=args.evidence_rpo,
                evidence_rto_seconds=args.evidence_rto,
                redis_rebuild_seconds=args.redis_rebuild,
            )
    finally:
        engine.dispose()
    return {
        "status": "SUCCEEDED",
        "finding_lineage_reproduced": True,
        "object_hash_reproduced": True,
        "pending_outbox_reconciled": True,
        "production_gate_complete": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("prepare")
    for command in ("verify-primary", "restore-object", "verify-database"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("run_id")
    mark_parser = subparsers.add_parser("mark")
    mark_parser.add_argument("run_id")
    mark_parser.add_argument(
        "component",
        choices=("postgres", "redis", "aistor"),
    )
    mark_parser.add_argument("status")
    mark_parser.add_argument("--seconds", type=int)
    complete_parser = subparsers.add_parser("complete")
    complete_parser.add_argument("run_id")
    complete_parser.add_argument("--postgres-rpo", type=int, required=True)
    complete_parser.add_argument("--postgres-rto", type=int, required=True)
    complete_parser.add_argument("--evidence-rpo", type=int, required=True)
    complete_parser.add_argument("--evidence-rto", type=int, required=True)
    complete_parser.add_argument("--redis-rebuild", type=int, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "prepare":
            result = _prepare()
        elif args.command == "verify-primary":
            result = _verify_primary(UUID(args.run_id))
        elif args.command == "restore-object":
            result = _restore_object(UUID(args.run_id))
        elif args.command == "verify-database":
            result = _verify_database(UUID(args.run_id))
        elif args.command == "mark":
            result = _mark(
                UUID(args.run_id),
                args.component,
                args.status,
                args.seconds,
            )
        elif args.command == "complete":
            result = _complete(args)
        else:
            raise RuntimeError("Unsupported storage recovery command.")
    except Exception as exc:  # noqa: BLE001 - internal CLI returns a generalized error
        print(
            json.dumps(
                {
                    "status": "FAILED",
                    "error_code": "STORAGE_RECOVERY_COMMAND_FAILED",
                },
                separators=(",", ":"),
            )
        )
        print(type(exc).__name__, file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
