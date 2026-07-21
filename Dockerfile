FROM docker.io/library/python:3.12-slim-bookworm@sha256:72d3d75f2639ab82b34b29390ad3d6e0827c775befee94edda8e9976818f488d AS builder

ARG UV_VERSION=0.10.2

ENV PATH="/opt/build/bin:${PATH}" \
    UV_NO_CONFIG=1 \
    UV_NO_PROGRESS=1

WORKDIR /build

RUN python -m venv /opt/build \
    && python -m venv /opt/shisad \
    && /opt/build/bin/python -m pip install --no-cache-dir \
        "hatchling==1.29.0" \
        "uv==${UV_VERSION}"

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src

RUN uv export \
        --frozen \
        --no-dev \
        --extra assistant \
        --no-emit-project \
        --format requirements-txt \
        --output-file /tmp/requirements.txt \
    && uv pip install \
        --python /opt/shisad/bin/python \
        --require-hashes \
        --no-deps \
        --requirements /tmp/requirements.txt \
    && uv build \
        --wheel \
        --no-build-isolation \
        --out-dir /tmp/dist \
    && uv pip install \
        --python /opt/shisad/bin/python \
        --no-deps \
        /tmp/dist/shisad-*.whl

FROM docker.io/library/python:3.12-slim-bookworm@sha256:72d3d75f2639ab82b34b29390ad3d6e0827c775befee94edda8e9976818f488d

LABEL org.opencontainers.image.source="https://github.com/shisa-ai/shisad" \
      org.opencontainers.image.title="shisad" \
      org.opencontainers.image.description="Security-first AI agent daemon"

ENV HOME=/home/shisad \
    PATH="/opt/shisad/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    XDG_RUNTIME_DIR=/run/shisad \
    SHISAD_DATA_DIR=/var/lib/shisad \
    SHISAD_SOCKET_PATH=/run/shisad/control.sock \
    SHISAD_ASSISTANT_FS_ROOTS="[\"/workspace\"]"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        bubblewrap \
        ca-certificates \
        git \
        iptables \
        passt \
        tini \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 shisad \
    && useradd \
        --uid 10001 \
        --gid 10001 \
        --home-dir /home/shisad \
        --shell /usr/sbin/nologin \
        shisad \
    && install -d -o 10001 -g 10001 -m 0700 \
        /etc/shisad \
        /home/shisad \
        /run/shisad \
        /var/lib/shisad \
        /workspace

COPY --from=builder /opt/shisad /opt/shisad
COPY scripts/clean_artifact_smoke.py /usr/local/bin/shisad-container-entrypoint

RUN chmod 0755 /usr/local/bin/shisad-container-entrypoint \
    && ln -s /usr/local/bin/shisad-container-entrypoint /usr/local/bin/bwrap

VOLUME ["/var/lib/shisad", "/workspace"]
WORKDIR /workspace
USER 10001:10001

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["shisad", "status"]

STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/shisad-container-entrypoint"]
CMD ["shisad", "start", "--foreground"]
