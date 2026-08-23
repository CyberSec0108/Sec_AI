"""Internal IMP-044 recovery acceptance controls; no HTTP exposure."""

from __future__ import annotations

import argparse
import json
import os
import signal
from collections.abc import Sequence
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from apps.worker.celery_app import celery_app
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.queue_repository import (
    QueueRecoveryCode,
    QueueRecoveryError,
    mark_event_published,
    mark_event_retry_pending,
    pending_event_payload,
    prepare_recovery_probe,
    record_event_publish_attempt,
    recovery_probe_status,
)


def _engine() -> Engine:
    return create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )


def _prepare() -> dict[str, object]:
    engine = _engine()
    try:
        with Session(engine) as session, session.begin():
            reference = prepare_recovery_probe(session)
    finally:
        engine.dispose()
    return {
        "status": "PREPARED",
        "job_id": str(reference.job_id),
        "step_id": str(reference.step_id),
        "outbox_event_id": str(reference.outbox_event_id),
        "baseline_finding_count": reference.baseline_finding_count,
    }


def _dispatch(event_id: UUID, simulate_publish_crash: bool) -> dict[str, object]:
    engine = _engine()
    try:
        with Session(engine) as session:
            payload, task_name, queue_name = pending_event_payload(
                session,
                event_id,
            )
        with Session(engine) as session, session.begin():
            record_event_publish_attempt(session, event_id)
        delivery_id = uuid4()
        try:
            celery_app.send_task(
                task_name,
                args=[str(event_id)],
                task_id=str(delivery_id),
                queue=queue_name,
                serializer="json",
            )
        except Exception:
            with Session(engine) as session, session.begin():
                mark_event_retry_pending(session, event_id)
            raise
        if not simulate_publish_crash:
            with Session(engine) as session, session.begin():
                mark_event_published(session, event_id)
    finally:
        engine.dispose()
    return {
        "status": (
            "PUBLISHED_NOT_ACKNOWLEDGED"
            if simulate_publish_crash
            else "PUBLISHED"
        ),
        "delivery_id": str(delivery_id),
        "payload_field_count": len(payload),
        "raw_payload_logged": False,
    }


def _status(job_id: UUID) -> dict[str, object]:
    engine = _engine()
    try:
        with Session(engine) as session:
            return recovery_probe_status(session, job_id)
    finally:
        engine.dispose()


def _kill_child(job_id: UUID) -> dict[str, object]:
    status = _status(job_id)
    pid = status.get("active_worker_pid")
    if not isinstance(pid, int) or pid <= 1 or pid == os.getpid():
        raise QueueRecoveryError(
            QueueRecoveryCode.ACTIVE_WORKER_INVALID,
            "An exact active worker child is unavailable.",
        )
    command_line_path = Path(f"/proc/{pid}/cmdline")
    try:
        command_line = command_line_path.read_bytes().replace(b"\0", b" ")
    except OSError as exc:
        raise QueueRecoveryError(
            QueueRecoveryCode.ACTIVE_WORKER_INVALID,
            "The recorded worker child no longer exists.",
        ) from exc
    if b"celery" not in command_line:
        raise QueueRecoveryError(
            QueueRecoveryCode.ACTIVE_WORKER_INVALID,
            "The recorded PID is not a Celery worker child.",
        )
    os.kill(pid, signal.SIGKILL)
    return {
        "status": "WORKER_CHILD_KILLED",
        "exact_recorded_pid": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="IMP-044 internal recovery verifier")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("prepare")
    dispatch = subparsers.add_parser("dispatch")
    dispatch.add_argument("event_id")
    dispatch.add_argument("--simulate-publish-crash", action="store_true")
    status = subparsers.add_parser("status")
    status.add_argument("job_id")
    kill = subparsers.add_parser("kill-child")
    kill.add_argument("job_id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "prepare":
            result = _prepare()
        elif arguments.command == "dispatch":
            result = _dispatch(
                UUID(arguments.event_id),
                bool(arguments.simulate_publish_crash),
            )
        elif arguments.command == "status":
            result = _status(UUID(arguments.job_id))
        else:
            result = _kill_child(UUID(arguments.job_id))
    except (ValueError, QueueRecoveryError):
        print(
            json.dumps(
                {
                    "status": "FAILED",
                    "error_code": "IMP044_RECOVERY_COMMAND_FAILED",
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
