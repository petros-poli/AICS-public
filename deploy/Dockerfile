# The aics-server image: the HTTP app and the TCP text gate in one process (see CMD).
#
# Reproducible and narrow:
# * the base image is pinned by digest (python:3.12.15-slim-trixie, its multi-platform
#   index digest); to move it, resolve the new tag's digest and change both together;
# * third-party packages are exactly those packages/aics-server/uv.lock pins, each checked
#   against its SHA-256 (deploy/requirements.txt is `uv export` of that lock, see its first
#   lines; deploy/deploy-vps.sh refuses to deploy when it differs from the lock), installed
#   with --no-deps so nothing else is resolved;
# * the four local packages are built with the build backend pinned by hash in
#   deploy/build-requirements.txt (--no-build-isolation: nothing unpinned is fetched), and
#   the backend is removed again. aics-witness is one of them: it is not a dependency of
#   aics-server, but the checkpoint feeder imports aics_witness.feeder as soon as
#   AICS_WITNESSES names a witness, and a server without it refuses to start (its own
#   dependencies, aics-tlog and cryptography, are already pinned here). deploy/deploy-vps.sh
#   checks that the built image imports it before any container is replaced;
# * the app runs as the unprivileged user aics (uid and gid 10001), which owns /data and
#   /data/tiles. A volume an older image created as root is handed over once with
#   `docker compose run --rm --no-deps --name aics-chown --user 0 --entrypoint chown aics-server -R 10001:10001 /data`
#   (ops/RUNBOOK-first-deploy.md step 4).
FROM python:3.12.15-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    AICS_DB_PATH=/data/aics.db \
    AICS_HOST=0.0.0.0 \
    AICS_PORT=8080

WORKDIR /app

COPY deploy/requirements.txt deploy/build-requirements.txt /app/
RUN pip install --no-deps --require-hashes -r /app/requirements.txt -r /app/build-requirements.txt

COPY packages/aics-identity /app/packages/aics-identity
COPY packages/aics-tlog /app/packages/aics-tlog
COPY packages/aics-witness /app/packages/aics-witness
COPY packages/aics-server /app/packages/aics-server

RUN pip install --no-deps --no-build-isolation \
        /app/packages/aics-identity \
        /app/packages/aics-tlog \
        /app/packages/aics-witness \
        /app/packages/aics-server \
    && pip uninstall -y uv-build \
    && pip check \
    && python -c "import aics_server.witness_feed, aics_witness.feeder" \
    && groupadd --system --gid 10001 aics \
    && useradd --system --uid 10001 --gid aics --home-dir /data --no-create-home --shell /usr/sbin/nologin aics \
    && mkdir -p /data/tiles \
    && chown -R aics:aics /data

USER aics:aics
VOLUME ["/data"]
# 8080: HTTP behind Caddy. 7701: the text gate, plain TCP. 7700: the text gate over TLS
# (only once AICS_GATE_TLS_CERT and AICS_GATE_TLS_KEY name a certificate: deploy/gate-tls.yml).
EXPOSE 8080 7700 7701

# The aics-server CLI (aics_server.cli), not bare uvicorn: it serves the HTTP app AND the
# TCP text gate (7701 plain, 7700 TLS) in one process and event loop over one database
# object, so the single writer stays single (docs/DESIGN.md §4.1); it refuses
# AICS_WORKERS other than 1, runs one worker with no access log (client addresses,
# docs/DESIGN.md §2, §8), no Server header, proxy headers trusted from
# AICS_FORWARDED_ALLOW_IPS (default *: port 8080 is reachable only through Caddy), and
# runs housekeeping (retention, daily count reports) on a timer.
CMD ["aics-server"]
