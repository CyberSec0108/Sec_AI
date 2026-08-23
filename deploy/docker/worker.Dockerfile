# syntax=docker/dockerfile:1.7

ARG PYTHON_BASE=docker.io/library/python:3.14.6-slim-bookworm@sha256:f70215e5dbe2a47dee6d23f9c6d358bf3c148f59cce2fd165b61118e9d80f2bb
FROM ${PYTHON_BASE}

ARG SECAI_COMPONENT=worker
LABEL org.opencontainers.image.title="Sec_AI MVP Background Service" \
      org.opencontainers.image.description="Celery worker or scheduler skeleton for the Sec_AI audit service" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="Sec_AI Project" \
      io.sec-ai-mvp.project="Sec_AI" \
      io.sec-ai-mvp.component="${SECAI_COMPONENT}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src:/app \
    HOME=/tmp/secai-home

WORKDIR /app

COPY requirements/lock/worker.lock /tmp/secai-worker.lock
RUN python -m pip install \
      --require-hashes \
      --no-deps \
      --no-compile \
      -r /tmp/secai-worker.lock \
    && python -m pip check \
    && rm -f /tmp/secai-worker.lock \
    && groupadd --gid 10001 secai \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin secai

COPY --chown=10001:10001 src /app/src
COPY --chown=10001:10001 apps /app/apps

USER 10001:10001

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=6 \
    CMD ["python", "-m", "apps.worker.container_health"]

ENTRYPOINT ["python"]
