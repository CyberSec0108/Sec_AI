# syntax=docker/dockerfile:1.7

ARG PYTHON_BASE=docker.io/library/python:3.14.6-alpine3.23@sha256:e10f6e0f219a81c65c518e339e7e9bf2f8c63b6ba1bf112e1bb2d1e395ed0c17
FROM ${PYTHON_BASE}

LABEL org.opencontainers.image.title="Sec_AI Model Gateway" \
      org.opencontainers.image.description="Internal OpenAI-compatible connector for OpenRouter now and local vLLM later" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="Sec_AI Project" \
      io.sec-ai-mvp.project="Sec_AI" \
      io.sec-ai-mvp.component="model-gateway"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src:/app

WORKDIR /app

COPY requirements/lock/api.lock /tmp/secai-api.lock
RUN python -m pip install \
      --require-hashes \
      --no-deps \
      --no-compile \
      -r /tmp/secai-api.lock \
    && python -m pip check \
    && rm -f /tmp/secai-api.lock

# CPython 3.14 official backport for CVE-2026-15308.
# The checksum pins commit 07efb08123ba9367a7107325adb9d5626dca1ca9 exactly.
ADD --checksum=sha256:5c5ed245889135564e75dfed9a47aeb6b4d3e5a2e9614d918a986767e3747539 \
    https://raw.githubusercontent.com/python/cpython/07efb08123ba9367a7107325adb9d5626dca1ca9/Lib/html/parser.py \
    /tmp/secai-cpython-html-parser.py
RUN python -c "from pathlib import Path; target=Path('/usr/local/lib/python3.14/html/parser.py'); source=Path('/tmp/secai-cpython-html-parser.py'); target.write_bytes(source.read_bytes())" \
    && python -c "import hashlib, html.parser, inspect; expected='5c5ed245889135564e75dfed9a47aeb6b4d3e5a2e9614d918a986767e3747539'; actual=hashlib.sha256(inspect.getsourcefile(html.parser.HTMLParser) and open(inspect.getsourcefile(html.parser.HTMLParser), 'rb').read()).hexdigest(); assert actual == expected; assert hasattr(html.parser.HTMLParser(), '_parse_threshold')" \
    && rm -f /tmp/secai-cpython-html-parser.py

COPY --chown=10001:10001 src /app/src
COPY --chown=10001:10001 apps/model_gateway /app/apps/model_gateway
COPY --chown=10001:10001 apps/__init__.py /app/apps/__init__.py

USER 10001:10001
EXPOSE 8010

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=6 \
    CMD ["python", "-m", "apps.model_gateway.container_health"]

ENTRYPOINT ["python"]
CMD ["-m", "uvicorn", "apps.model_gateway.main:app", "--host", "0.0.0.0", "--port", "8010", "--no-access-log"]
