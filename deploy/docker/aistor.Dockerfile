# syntax=docker/dockerfile:1.7
ARG AISTOR_BASE=quay.io/minio/aistor/minio:RELEASE.2026-06-06T02-44-06Z@sha256:5dbb753c0dbe6a987dd30ce564f66c0042e291e464d10e792443451d4fec2120
FROM ${AISTOR_BASE}

LABEL org.opencontainers.image.title="Sec_AI MVP AIStor" \
      org.opencontainers.image.description="Sec_AI-labelled AIStor runtime based on the approved immutable upstream image" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="Sec_AI Project" \
      io.sec-ai-mvp.project="Sec_AI" \
      io.sec-ai-mvp.component="aistor" \
      io.sec-ai-mvp.upstream.repository="quay.io/minio/aistor/minio" \
      io.sec-ai-mvp.upstream.version="RELEASE.2026-06-06T02-44-06Z" \
      io.sec-ai-mvp.upstream.digest="sha256:5dbb753c0dbe6a987dd30ce564f66c0042e291e464d10e792443451d4fec2120"
