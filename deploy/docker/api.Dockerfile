# syntax=docker/dockerfile:1.7

ARG PYTHON_BASE=docker.io/library/python:3.14.6-slim-bookworm@sha256:f70215e5dbe2a47dee6d23f9c6d358bf3c148f59cce2fd165b61118e9d80f2bb
FROM ${PYTHON_BASE}

LABEL org.opencontainers.image.title="Sec_AI MVP Audit API" \
      org.opencontainers.image.description="FastAPI audit API and development Web UI for Sec_AI" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="Sec_AI Project" \
      io.sec-ai-mvp.project="Sec_AI" \
      io.sec-ai-mvp.component="audit-api"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src:/app

WORKDIR /app

COPY requirements/lock/api.lock /tmp/secai-api.lock
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install \
      --require-hashes \
      --no-deps \
      --no-compile \
      -r /tmp/secai-api.lock \
    && python -m pip check \
    && rm -f /tmp/secai-api.lock \
    && groupadd --gid 10001 secai \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin secai

COPY --chown=10001:10001 src /app/src
COPY --chown=10001:10001 apps /app/apps
COPY --chown=10001:10001 database /app/database
COPY --chown=10001:10001 audit_packs /app/audit_packs
COPY --chown=10001:10001 guides /app/guides
COPY --chown=10001:10001 collectors /app/collectors
COPY --chown=10001:10001 alembic.ini /app/alembic.ini

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD ["python", "-m", "apps.api.container_health"]

ENTRYPOINT ["python"]
CMD ["-m", "uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
