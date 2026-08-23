# syntax=docker/dockerfile:1.7
ARG REDIS_BASE=docker.io/library/redis:8.8.0@sha256:5d2c689b4b55fc3fab4b0cc8aaa950f85b508c76c1e0f35a90d8f411d55a8b2b
FROM ${REDIS_BASE}

LABEL org.opencontainers.image.title="Sec_AI MVP Redis" \
      org.opencontainers.image.description="Sec_AI-labelled Redis runtime based on the approved immutable upstream image" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="Sec_AI Project" \
      io.sec-ai-mvp.project="Sec_AI" \
      io.sec-ai-mvp.component="redis" \
      io.sec-ai-mvp.upstream.repository="docker.io/library/redis" \
      io.sec-ai-mvp.upstream.version="8.8.0" \
      io.sec-ai-mvp.upstream.digest="sha256:5d2c689b4b55fc3fab4b0cc8aaa950f85b508c76c1e0f35a90d8f411d55a8b2b"
