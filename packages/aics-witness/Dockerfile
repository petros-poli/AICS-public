# syntax=docker/dockerfile:1
#
# aics-witness for a second host (Oracle Always Free Ampere/arm64 or a small
# amd64 VPS). The build context is the directory that holds aics-tlog/ and
# aics-witness/ side by side (the repository's packages/ directory), which
# compose.witness.yml sets up:
#
#   cd packages/aics-witness && docker compose -f compose.witness.yml build
#
# Dependencies come from uv.lock exactly (the build fails if the lock is
# stale). The container runs as an unprivileged user, keeps its config, key
# and SQLite database in the /data volume, and logs no client addresses.

FROM ghcr.io/astral-sh/uv:0.12.6 AS uv

FROM python:3.12-slim AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/aics-witness
COPY aics-tlog /src/aics-tlog
COPY aics-witness /src/aics-witness
WORKDIR /src/aics-witness
RUN uv sync --locked --no-dev --no-editable --python /usr/local/bin/python3.12 \
    && /opt/aics-witness/bin/aics-witness --version

FROM python:3.12-slim
RUN useradd --system --uid 10001 --user-group --home-dir /data --no-create-home \
        --shell /usr/sbin/nologin witness \
    && mkdir -p /data \
    && chown witness:witness /data \
    && chmod 0700 /data
COPY --from=build /opt/aics-witness /opt/aics-witness
ENV PATH=/opt/aics-witness/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AICS_WITNESS_CONFIG=/data/witness.json
USER witness
WORKDIR /data
VOLUME ["/data"]
# Keep "listen" at 0.0.0.0:7380 in /data/witness.json (the init default);
# the health check and compose.witness.yml assume it.
EXPOSE 7380
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7380/healthz', timeout=4)"]
ENTRYPOINT ["aics-witness"]
CMD ["serve"]
