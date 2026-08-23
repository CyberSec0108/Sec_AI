# syntax=docker/dockerfile:1.7

ARG PYTHON_BASE=docker.io/library/python:3.14.6-slim-bookworm@sha256:f70215e5dbe2a47dee6d23f9c6d358bf3c148f59cce2fd165b61118e9d80f2bb
FROM ${PYTHON_BASE}

LABEL org.opencontainers.image.title="Sec_AI MVP Development Tools" \
      org.opencontainers.image.description="Locked development and verification tools for the Sec_AI security audit project" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="Sec_AI Project" \
      org.opencontainers.image.source="E:/Sec_AI" \
      io.sec-ai-mvp.project="Sec_AI" \
      io.sec-ai-mvp.component="development-tools"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/workspace/src:/workspace

WORKDIR /workspace

COPY requirements/lock/dev.lock /tmp/secai-dev.lock

RUN python -m pip install \
      --require-hashes \
      --no-deps \
      --no-compile \
      -r /tmp/secai-dev.lock \
    && python -m pip check \
    && rm -f /tmp/secai-dev.lock \
    && groupadd --gid 10001 secai \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin secai

USER 10001:10001

ENTRYPOINT ["python"]
CMD ["--version"]
