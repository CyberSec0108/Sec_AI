"""Registered identifier-only Celery tasks for IMP-044."""

from __future__ import annotations

import time
from uuid import UUID

from celery import Task
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from apps.worker.celery_app import celery_app
from security_audit.common.service_settings import ServiceSettings
from security_audit.persistence.database.queue_repository import (
    begin_recovery_attempt,
    complete_recovery_attempt,
)

_FIRST_ATTEMPT_HOLD_SECONDS = 45


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    name="secai.maintenance.verify_delivery",
    acks_late=True,
    reject_on_worker_lost=True,
    soft_time_limit=120,
    time_limit=150,
)
def verify_delivery(self: Task, outbox_event_id: str) -> None:
    """Prove worker-loss redelivery without creating an official Finding."""

    event_id = UUID(outbox_event_id)
    delivery_id = UUID(str(self.request.id))
    engine = create_engine(
        ServiceSettings.from_environment().postgres_url(),
        pool_pre_ping=True,
    )
    try:
        with Session(engine) as session, session.begin():
            attempt = begin_recovery_attempt(
                session,
                event_id=event_id,
                delivery_id=delivery_id,
            )
        if attempt.result_already_exists:
            return
        if attempt.should_hold_for_worker_loss:
            time.sleep(_FIRST_ATTEMPT_HOLD_SECONDS)
        with Session(engine) as session, session.begin():
            complete_recovery_attempt(
                session,
                execution_id=attempt.execution_id,
            )
    finally:
        engine.dispose()
