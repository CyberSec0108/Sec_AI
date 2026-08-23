ARG PYTHON_BUILD_BASE=quay.io/pypa/manylinux_2_34_x86_64@sha256:29b6458a44228fdca16762e2139f15189784ff17c6196507d79f3af95e81112a
ARG BUILDER_RUNTIME_BASE=registry.access.redhat.com/ubi9-minimal@sha256:31648959f2cf4e3fdd14801905e4339fef1d4457763e80094ed30f69562f0a63

FROM ${PYTHON_BUILD_BASE} AS python-build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SOURCE_DATE_EPOCH=1785945600 \
    PATH=/opt/secai-python/bin:/opt/python/cp314-cp314/bin:${PATH} \
    LD_LIBRARY_PATH=/opt/secai-python/lib

WORKDIR /workspace

ARG PYTHON_SOURCE_SHA256=143b1dddefaec3bd2e21e3b839b34a2b7fb9842272883c576420d605e9f30c63
ARG CVE_2026_11940_COMMIT=79c06bd5c6afa3c440d50faf7ee1b147c8832b4c
ARG CVE_2026_11940_PATCH_SHA256=b5622f0fe9eb0aee7b6f018963f8c702d70dc803e3c8a0f342f6ee5eeba9c642
ARG CVE_2026_11972_COMMIT=e86666c9dd256d52d0fbef6feb1ea4a51768fdec
ARG CVE_2026_11972_PATCH_SHA256=6af7f4f986c90b0c5e445459775f92d606f1bc40695f3818cc3caa4ee006b868
ARG CVE_2026_15308_COMMIT=07efb08123ba9367a7107325adb9d5626dca1ca9
ARG CVE_2026_15308_PATCH_SHA256=35063144d2126f2bcecb1297f2ea58af8ea9c6918538f4d073c6aa3e74cb583b
RUN dnf install --assumeyes --setopt=install_weak_deps=False \
      bzip2-devel-1.0.8-11.el9 \
      openssl-devel-3.5.5-6.el9_8 \
      readline-devel-8.1-4.el9 \
      xz-devel-5.2.5-8.el9_0 \
    && dnf clean all \
    && curl --fail --location --proto '=https' --tlsv1.2 \
      --output /tmp/Python-3.14.6.tar.xz \
      https://www.python.org/ftp/python/3.14.6/Python-3.14.6.tar.xz \
    && echo "${PYTHON_SOURCE_SHA256}  /tmp/Python-3.14.6.tar.xz" | sha256sum --check --strict \
    && tar --directory /tmp --extract --file /tmp/Python-3.14.6.tar.xz \
    && curl --fail --location --proto '=https' --tlsv1.2 \
      --output /tmp/CVE-2026-11940.patch \
      "https://github.com/python/cpython/commit/${CVE_2026_11940_COMMIT}.patch" \
    && curl --fail --location --proto '=https' --tlsv1.2 \
      --output /tmp/CVE-2026-11972.patch \
      "https://github.com/python/cpython/commit/${CVE_2026_11972_COMMIT}.patch" \
    && curl --fail --location --proto '=https' --tlsv1.2 \
      --output /tmp/CVE-2026-15308.patch \
      "https://github.com/python/cpython/commit/${CVE_2026_15308_COMMIT}.patch" \
    && echo "${CVE_2026_11940_PATCH_SHA256}  /tmp/CVE-2026-11940.patch" | sha256sum --check --strict \
    && echo "${CVE_2026_11972_PATCH_SHA256}  /tmp/CVE-2026-11972.patch" | sha256sum --check --strict \
    && echo "${CVE_2026_15308_PATCH_SHA256}  /tmp/CVE-2026-15308.patch" | sha256sum --check --strict \
    && patch --directory /tmp/Python-3.14.6 --strip=1 --input /tmp/CVE-2026-11940.patch \
    && patch --directory /tmp/Python-3.14.6 --strip=1 --input /tmp/CVE-2026-11972.patch \
    && patch --directory /tmp/Python-3.14.6 --strip=1 --input /tmp/CVE-2026-15308.patch \
    && cd /tmp/Python-3.14.6 \
    && ./configure \
      --prefix=/opt/secai-python \
      --enable-shared \
      --with-ensurepip=install \
      --without-static-libpython \
    && make --jobs=2 \
    && make install \
    && ln --symbolic /opt/secai-python/bin/python3.14 /opt/secai-python/bin/python \
    && python -m test --timeout 60 test_tarfile test_htmlparser \
    && rm --recursive --force \
      /tmp/Python-3.14.6 \
      /tmp/Python-3.14.6.tar.xz \
      /tmp/CVE-2026-11940.patch \
      /tmp/CVE-2026-11972.patch \
      /tmp/CVE-2026-15308.patch \
    && python --version

COPY requirements/lock/linux-collector-build.lock /workspace/requirements/lock/linux-collector-build.lock
RUN python -m pip install --no-cache-dir --require-hashes \
    -r /workspace/requirements/lock/linux-collector-build.lock \
    && python -m pip check

FROM ${BUILDER_RUNTIME_BASE}

LABEL org.opencontainers.image.title="Sec_AI Linux Collector builder" \
      org.opencontainers.image.version="0.1.0" \
      io.sec-ai-mvp.component="linux-collector-builder"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SOURCE_DATE_EPOCH=1785945600 \
    PATH=/opt/secai-python/bin:/opt/python/cp314-cp314/bin:${PATH} \
    LD_LIBRARY_PATH=/opt/secai-python/lib

WORKDIR /workspace

RUN microdnf install --assumeyes --setopt=install_weak_deps=0 \
      binutils-2.35.2-72.el9 \
    && microdnf clean all \
    && rpm --erase --nodeps curl-minimal libcurl-minimal microdnf \
    && rm --recursive --force /var/cache/dnf /var/cache/yum \
    && test ! -e /usr/bin/curl \
    && test ! -e /usr/bin/microdnf

COPY --from=python-build /opt/secai-python /opt/secai-python
RUN python --version \
    && python -m pip check \
    && objcopy --version

COPY pyproject.toml /workspace/pyproject.toml
COPY src /workspace/src
COPY collectors /workspace/collectors
COPY database/schemas /workspace/database/schemas
COPY deploy/security/linux-collector-builder.openvex.json /workspace/deploy/security/linux-collector-builder.openvex.json
COPY requirements /workspace/requirements
COPY tools/build_linux_oneshot_collector.py /workspace/tools/build_linux_oneshot_collector.py

ENV PYTHONPATH=/workspace/src

ENTRYPOINT ["python", "/workspace/tools/build_linux_oneshot_collector.py"]
