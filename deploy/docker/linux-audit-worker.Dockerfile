# syntax=docker/dockerfile:1.7

ARG PYTHON_BASE=docker.io/library/python:3.14.6-slim-bookworm@sha256:f70215e5dbe2a47dee6d23f9c6d358bf3c148f59cce2fd165b61118e9d80f2bb
FROM ${PYTHON_BASE}

LABEL org.opencontainers.image.title="Sec_AI Linux Audit Worker" \
      org.opencontainers.image.description="Read-only SSH collector for KISA UNIX U-01 through U-67" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="Sec_AI Project" \
      io.sec-ai-mvp.project="Sec_AI" \
      io.sec-ai-mvp.component="linux-audit-worker"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src:/app \
    HOME=/tmp/secai-home

WORKDIR /app

COPY requirements/lock/api.lock /tmp/secai-linux-audit.lock
RUN apt-get update \
    && apt-get install --yes --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install \
      --require-hashes \
      --no-deps \
      --no-compile \
      -r /tmp/secai-linux-audit.lock \
    && python -m pip check \
    && rm -f /tmp/secai-linux-audit.lock \
    && groupadd --gid 10001 secai \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /tmp/secai-home --shell /usr/sbin/nologin secai

COPY --chown=10001:10001 src /app/src
COPY --chown=10001:10001 tools/check-linux-kisa.py /app/tools/check-linux-kisa.py

USER 10001:10001

ENTRYPOINT ["python", "/app/tools/check-linux-kisa.py"]
