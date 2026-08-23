# syntax=docker/dockerfile:1.7
ARG VLLM_BASE=docker.io/vllm/vllm-openai:v0.23.0@sha256:3a1e7f5904e1a1192a02aa0086ceaffc33985d7044c7bb25b3a43d61bdbe3ac0
FROM ${VLLM_BASE}

LABEL org.opencontainers.image.title="Sec_AI Local vLLM GPU Runtime"
LABEL org.opencontainers.image.description="Prepared NVIDIA GPU vLLM runtime without model weights"
LABEL org.opencontainers.image.version="0.23.0"
LABEL org.opencontainers.image.vendor="Sec_AI Project"
LABEL io.sec-ai-mvp.project="Sec_AI"
LABEL io.sec-ai-mvp.component=vllm
