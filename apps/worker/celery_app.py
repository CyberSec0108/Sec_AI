from __future__ import annotations

from celery import Celery

from security_audit.common.service_settings import ServiceSettings

settings = ServiceSettings.from_environment()
celery_app = Celery(
    "secai-core",
    broker=settings.redis_url(),
    include=["apps.worker.tasks"],
)
celery_app.conf.update(
    accept_content=["json"],
    broker_connection_retry_on_startup=True,
    broker_transport_options={"visibility_timeout": 3600},
    enable_utc=True,
    result_backend=None,
    task_acks_late=True,
    task_acks_on_failure_or_timeout=True,
    task_default_queue="core.validation",
    task_ignore_result=True,
    task_protocol=2,
    task_reject_on_worker_lost=True,
    task_routes={
        "secai.maintenance.verify_delivery": {"queue": "maintenance"},
    },
    task_send_sent_event=False,
    task_serializer="json",
    task_store_errors_even_if_ignored=False,
    timezone="UTC",
    worker_enable_remote_control=False,
    worker_prefetch_multiplier=1,
    worker_send_task_events=False,
    worker_soft_shutdown_timeout=30.0,
)
