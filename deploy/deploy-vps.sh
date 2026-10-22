#!/usr/bin/env bash
# shellcheck disable=SC2029
# (SC2029: REMOTE_DIR is expanded on this side on purpose; it is a constant without spaces.)
#
# Deploy WeSupport-AI (wesupport-ai.com) to the VPS with Docker Compose.
#
# Usage: deploy/deploy-vps.sh <ssh-user@vps-host>
#
# The configuration is the VPS's own /opt/wesupport-ai/deploy/.env. Create it
# there once from deploy/.env.example. Without it this script stops before
# building anything; it never creates one from the example and never sends a
# local deploy/.env.
#
# Steps: check that deploy/requirements.txt is the export of
# packages/aics-server/uv.lock (the image installs exactly those pins, by hash;
# needs uv here), sync packages/, deploy/, ops/ and .dockerignore from the repository
# this script lives in (the remote copies are made identical to the local ones;
# dev data, .env files other than .env.example, virtualenvs and caches are never
# sent), check the remote .env and required Caddy token, build and validate Caddy,
# and when the TLS gate is on
# (deploy/gate-tls.yml through COMPOSE_FILE in the remote .env) copy the gate
# certificate and require that the app's user can read it inside an app
# container, and check that the image imports aics_witness.feeder (the
# checkpoint feeder needs it once AICS_WITNESSES is set), before anything
# running is replaced; then start the containers,
# check the app and the text gate from inside its container (plain TCP 7701
# always, TLS 7700 once deploy/gate-tls.yml is on, with certificate and hostname
# validation), then check https://wesupport-ai.com/healthz and
# gate.wesupport-ai.com:7701 from here.
#
# Exit status: 0 deployed and answering on the public URL and the public gate
# port; 1 not deployed, or the app or the gate does not answer inside its
# container; 2 deployed and healthy inside the container, but the public URL or
# the public gate port did not answer (DNS not pointing here yet, ports
# 80/443/7700/7701 closed, or the certificate not issued yet).
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <ssh-user@vps-host>" >&2
  exit 1
fi

TARGET="$1"
REMOTE_DIR="/opt/wesupport-ai"
PUBLIC_URL="https://wesupport-ai.com"
GATE_HOST="gate.wesupport-ai.com"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"

for path in packages deploy ops .dockerignore; do
  if [ ! -e "${SRC_DIR}/${path}" ]; then
    echo "ERROR: ${SRC_DIR}/${path} is missing; ${SRC_DIR} is not the repository root." >&2
    exit 1
  fi
done
if [ -e "${SRC_DIR}/deploy/.env" ]; then
  echo "Note: ${SRC_DIR}/deploy/.env is not sent; the VPS uses its own ${REMOTE_DIR}/deploy/.env."
fi

# The image installs exactly what packages/aics-server/uv.lock pins, each package checked by
# hash (deploy/Dockerfile): deploy/requirements.txt must be that lock's export, byte for byte.
EXPORT_CMD="uv export --frozen --no-dev --no-emit-project --no-emit-package aics-identity --no-emit-package aics-tlog --format requirements.txt"
if ! command -v uv >/dev/null 2>&1; then
  echo "ERROR: uv is not installed here; it is needed to check deploy/requirements.txt against packages/aics-server/uv.lock (https://docs.astral.sh/uv/). Nothing was sent." >&2
  exit 1
fi
# shellcheck disable=SC2086  # EXPORT_CMD is a fixed word list
if ! (cd "${SRC_DIR}/packages/aics-server" && ${EXPORT_CMD} 2>/dev/null) | cmp -s - "${SRC_DIR}/deploy/requirements.txt"; then
  cat >&2 <<EOF
ERROR: deploy/requirements.txt is not the export of packages/aics-server/uv.lock. Nothing was sent.
Regenerate it, review the difference and commit it:
  (cd packages/aics-server && ${EXPORT_CMD}) > deploy/requirements.txt
EOF
  exit 1
fi

# The published documents: deploy/docs-public is gitignored, made in this checkout by ops/sync-docs.sh. The app
# mounts four of its files with create_host_path false (deploy/docker-compose.yml) and the sync below runs with
# --delete, so a checkout without the export (a fresh worktree) would delete the VPS's copies and the app could not
# start. Refuse before anything is sent.
for published in charter.md terms.md retention.md secret-patterns.json; do
  if [ ! -s "${SRC_DIR}/deploy/docs-public/legal/${published}" ]; then
    echo "ERROR: ${SRC_DIR}/deploy/docs-public/legal/${published} is missing. Run bash ops/sync-docs.sh deploy/docs-public in this checkout first; the sync would otherwise delete the VPS's copy, which the app mounts. Nothing was sent." >&2
    exit 1
  fi
done

echo "==> [1/6] Syncing packages/, deploy/, ops/ and .dockerignore from ${SRC_DIR} to ${TARGET}:${REMOTE_DIR} ..."
ssh "${TARGET}" "sudo mkdir -p ${REMOTE_DIR} && sudo chown -R \$(whoami) ${REMOTE_DIR}"
# Recovery files are VPS-local and may still be mounted by the running proxy.
# Excluding them also protects them from --delete; retire them explicitly only
# after the canonical DNS-01 configuration has been validated and activated.
# The reviewed card body deploy/card/card-unsigned.json is gitignored (card/README.md
# "Placeholders"): a checkout without it must not delete the VPS's copy (--filter P protects
# it from --delete; a copy present here still replaces it). --inplace asks rsync to keep the inode of
# every synced file (openrsync on macOS ignores it, so nothing relies on it); -i lists what changed so
# the remote step can recreate Caddy and restart the app when only a bind-mounted file changed.
# Local tool caches and build output (.ruff_cache, .mypy_cache, dist, build, *.egg-info) are never sent:
# .dockerignore keeps them out of the image too, so the image of a working checkout is the image of a clean
# worktree of the same commit. Published evidence (deploy/docs-public/docs/evidence/) is added, never removed:
# a card names it by hash, so a local export that lacks a file (a fresh worktree of an older commit) must not
# delete the VPS's copy (--filter P), while a file present here still replaces it.
RSYNC_CHANGES="$(mktemp)"
trap 'rm -f "${RSYNC_CHANGES}"' EXIT
rsync -azi --inplace --delete \
  --exclude '.venv/' --exclude '__pycache__/' --exclude '.pytest_cache/' --exclude '.hypothesis/' \
  --exclude '.ruff_cache/' --exclude '.mypy_cache/' --exclude 'dist/' --exclude 'build/' --exclude '*.egg-info/' \
  --exclude 'data/' --exclude '.DS_Store' --exclude '.zenodo-staging/' \
  --exclude '*.seed' --exclude '*.key' --exclude 'rclone.conf' \
  --exclude '/deploy/Caddyfile.recovery' --exclude '/deploy/docker-compose.recovery.yml' \
  --filter 'P /deploy/card/card-unsigned.json' \
  --filter 'P /deploy/docs-public/docs/evidence/**' \
  --include '.env.example' --exclude '.env' --exclude '.env.*' \
  "${SRC_DIR}/packages" "${SRC_DIR}/deploy" "${SRC_DIR}/ops" "${SRC_DIR}/.dockerignore" \
  "${TARGET}:${REMOTE_DIR}/" > "${RSYNC_CHANGES}"
# Itemized lines: "<f.st...... path" (GNU rsync, 11 flag characters) or ">f..t.... path" (openrsync
# on macOS, 9); "*deleting path" for a deletion.
grep -E '^[<>ch*][^ ]* deploy/(Caddyfile|card/|docs-public/)' "${RSYNC_CHANGES}" || true
CADDYFILE_CHANGED=0; CARD_CHANGED=0
grep -qE '^[<>ch]f[^ ]* deploy/Caddyfile$' "${RSYNC_CHANGES}" && CADDYFILE_CHANGED=1
grep -qE '^[<>ch]f[^ ]* deploy/card/' "${RSYNC_CHANGES}" && CARD_CHANGED=1

echo "==> [2/6] Checking that ${REMOTE_DIR}/deploy/.env exists on the VPS ..."
if ! ssh "${TARGET}" "test -f ${REMOTE_DIR}/deploy/.env"; then
  cat >&2 <<EOF
ERROR: ${REMOTE_DIR}/deploy/.env does not exist on ${TARGET}. Nothing was built or started.
Create it on the VPS from the example, fill it in, then run this script again:
  ssh ${TARGET}
  cp ${REMOTE_DIR}/deploy/.env.example ${REMOTE_DIR}/deploy/.env
  chmod 600 ${REMOTE_DIR}/deploy/.env
  \$EDITOR ${REMOTE_DIR}/deploy/.env
This script never creates it from the example.
EOF
  exit 1
fi

echo "==> [3/6] Checking configuration; building and validating Caddy; checking the gate certificate; starting ..."
if ! ssh "${TARGET}" sh -s -- "${REMOTE_DIR}" "${CADDYFILE_CHANGED}" "${CARD_CHANGED}" <<'REMOTE'
set -eu
cd "$1/deploy" || exit 1
caddyfile_changed="${2:-0}"; card_changed="${3:-0}"
# rsync -a keeps the laptop's modes: a worktree made under umask 077 ships directories the app's user cannot
# traverse (the 2026-10-22 outage: PermissionError on /etc/aics/card). Make the synced tree readable, and keep
# the env files private.
chmod -R go+rX "$1/packages" "$1/deploy" "$1/ops" "$1/.dockerignore" 2>/dev/null || true
chmod 600 .env 2>/dev/null || true
for envf in .env.*; do [ "$envf" = ".env.example" ] || [ ! -e "$envf" ] || chmod 600 "$envf"; done
# The reviewed card body: when deploy/.env names AICS_CARD_FILE (runbook step 5), the file it
# names must exist under deploy/card (mounted as /etc/aics/card), or the app would stop at start
# (FileNotFoundError) and crash-loop. Check before anything is built or replaced.
card_file="$(sed -n 's/^AICS_CARD_FILE=//p' .env 2>/dev/null | tail -n 1)"
if [ -n "${card_file}" ] && [ ! -s "card/$(basename "${card_file}")" ]; then
  echo "deploy/.env sets AICS_CARD_FILE=${card_file} but deploy/card/$(basename "${card_file}") is missing or empty on the VPS; restore the reviewed card body (card/README.md \"Placeholders\") before deploying. Nothing was built or replaced." >&2
  exit 1
fi
# Inspect the effective configuration without ever printing it: it contains secrets.
# Fail before building or replacing a running container when DNS-01 cannot start.
docker compose config --format json 2>/dev/null | python3 -c '
import json
import sys

try:
    config = json.load(sys.stdin)
except (ValueError, TypeError):
    sys.exit("Invalid Compose configuration; run docker compose config --quiet on the VPS.")
token = config.get("services", {}).get("caddy", {}).get("environment", {}).get("CLOUDFLARE_API_TOKEN", "")
if not isinstance(token, str) or not token.strip():
    sys.exit("CLOUDFLARE_API_TOKEN is missing from Caddy. Set the scoped Zone Read + DNS Edit token in deploy/.env; running containers were not replaced.")
'
docker compose build </dev/null
# Use the same Cloudflare-module image and mounts as the live service. Suppress
# validator output because provisioner errors may include resolved configuration.
if ! docker compose run --rm --no-deps caddy caddy validate \
    --config /etc/caddy/Caddyfile --adapter caddyfile </dev/null >/dev/null 2>&1; then
  echo "Caddy configuration validation failed; running containers were not replaced. Check deploy/Caddyfile and the scoped Cloudflare token on the VPS." >&2
  exit 1
fi
if docker compose config --services </dev/null | grep -qx gate-cert; then
  # deploy/gate-tls.yml is on (COMPOSE_FILE in .env): copy the gate certificate and key out of
  # Caddy's store, then require that the app's user can read both inside an app container with
  # the same mounts, before the running service is replaced. A missing or unreadable file would
  # otherwise stop the gate's TLS listener, and with it the whole process, at start.
  docker compose run --rm gate-cert </dev/null
  # --name: a one-off container must not take the service's container_name.
  if ! docker compose run --rm --no-deps --name "aics-gate-check-$$" --entrypoint sh aics-server -c \
      'test -r "$AICS_GATE_TLS_CERT" && test -r "$AICS_GATE_TLS_KEY" && echo "gate certificate readable: $AICS_GATE_TLS_CERT"' \
      </dev/null; then
    echo "the TLS gate is on (deploy/gate-tls.yml), but the app cannot read AICS_GATE_TLS_CERT and AICS_GATE_TLS_KEY" >&2
    exit 1
  fi
fi
# The checkpoint feeder (aics_server.witness_feed) imports aics_witness.feeder as soon as
# AICS_WITNESSES names a witness, and a server that cannot import it refuses to start: check the
# built image, and that the setting parses, before the running service is replaced.
if ! docker compose run --rm --no-deps --name "aics-witness-check-$$" --entrypoint python aics-server -c \
    'import os, aics_witness.feeder; from aics_server.witness_feed import parse_witnesses; parse_witnesses(os.environ.get("AICS_WITNESSES", ""))' \
    </dev/null >/dev/null; then
  echo "the built aics-server image cannot import aics_witness.feeder (packages/aics-witness, deploy/Dockerfile), or AICS_WITNESSES does not parse; running containers were not replaced" >&2
  exit 1
fi
app_before="$(docker compose ps -q aics-server </dev/null 2>/dev/null || true)"
docker compose up -d </dev/null
# A changed bind-mounted file does not recreate its container: reload Caddy gracefully when the
# Caddyfile changed, and restart the app when the card body changed but up -d kept the container.
if [ "${caddyfile_changed}" = 1 ]; then
  # The Caddyfile is a read-only bind mount of one file: rsync may give the host path a new inode (openrsync
  # on macOS ignores --inplace), and the container keeps the old one, so a reload would re-read the old
  # bytes. Recreating the container mounts the new file (a few seconds without Caddy).
  echo "deploy/Caddyfile changed: recreating Caddy so it mounts the new file"
  docker compose up -d --force-recreate --no-deps caddy </dev/null
fi
app_after="$(docker compose ps -q aics-server </dev/null 2>/dev/null || true)"
if [ "${card_changed}" = 1 ] && [ -n "${app_after}" ] && [ "${app_after}" = "${app_before}" ]; then
  echo "deploy/card changed and the app container was kept: restarting aics-server so it reads the new card"
  docker compose restart aics-server </dev/null
fi
REMOTE
then
  echo "ERROR: configuration preflight, image build, Caddy validation, gate certificate check, or container startup failed (output above). If the TLS gate is on and Caddy has not issued the gate certificate yet, remove only gate-tls.yml from COMPOSE_FILE in ${REMOTE_DIR}/deploy/.env, preserving any pilot override, and deploy again." >&2
  exit 1
fi

echo "==> [4/6] Checking the app and the text gate inside the container (8080/healthz, TCP 7701, TLS 7700) ..."
# The remote script reads its own lines from stdin, so every docker command in
# it gets </dev/null (or a here-document of its own) and cannot swallow the rest
# of the script.
if ! ssh "${TARGET}" sh -s -- "${REMOTE_DIR}" <<'REMOTE'
set -u
cd "$1/deploy" || exit 1
tries=0
healthy=0
while [ "$tries" -lt 30 ]; do
  if docker compose exec -T aics-server python3 -c \
      "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=5)" \
      </dev/null >/dev/null 2>&1; then
    healthy=1
    break
  fi
  tries=$((tries + 1))
  sleep 2
done
docker compose ps </dev/null
if [ "$healthy" -ne 1 ]; then
  docker compose logs --tail 40 aics-server </dev/null
  exit 1
fi
# The text gate (docs/PROTOCOL-TEXT.md section 1) runs in the same process: 7701 must
# print the session line and the banner; 7700 must too once a certificate is wired,
# over TLS validated for the gate hostname (the same check an agent's openssl makes).
if ! docker compose exec -T aics-server python3 - <<'PY'
import os
import socket
import ssl
import sys


def first_turn(sock):
    sock.settimeout(10)
    data = b""
    while b"\n>\n" not in data and len(data) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    sock.sendall(b"quit\n")
    sock.close()
    return data


if not first_turn(socket.create_connection(("127.0.0.1", 7701), timeout=10)).startswith(b"session "):
    sys.exit("gate 7701 answered without its session line and banner")
print("gate 7701 (plain TCP): session line and banner received")
if os.environ.get("AICS_GATE_TLS_CERT", "").strip():
    host = os.environ.get("AICS_GATE_HOSTNAME", "").strip() or "gate.wesupport-ai.com"
    context = ssl.create_default_context()
    tls = context.wrap_socket(socket.create_connection(("127.0.0.1", 7700), timeout=10), server_hostname=host)
    if not first_turn(tls).startswith(b"session "):
        sys.exit("gate 7700 answered without its session line and banner")
    print(f"gate 7700 (TLS): certificate valid for {host}; session line and banner received")
else:
    print("gate 7700 (TLS): dark, deploy/gate-tls.yml is not enabled yet (runbook step 4)")
PY
then
  docker compose logs --tail 40 aics-server </dev/null
  exit 1
fi
exit 0
REMOTE
then
  echo "ERROR: aics-server does not answer /healthz or its text gate inside its container (status and last log lines above)." >&2
  echo "If the log shows a PermissionError under /data, the volumes were created by an older image that ran as root: hand them to the app's user once with 'docker compose run --rm --no-deps --name aics-chown --user 0 --entrypoint chown aics-server -R 10001:10001 /data' and deploy again." >&2
  exit 1
fi

echo "==> [5/6] Checking ${PUBLIC_URL}/healthz from here ..."
tries=0
while :; do
  rc=0
  body="$(curl -fsS --max-time 10 "${PUBLIC_URL}/healthz" 2>&1)" || rc=$?
  if [ "${rc}" -eq 0 ]; then
    break
  fi
  tries=$((tries + 1))
  # curl exit 6: the name does not resolve, so retrying will not help.
  if [ "${rc}" -eq 6 ] || [ "${tries}" -ge 12 ]; then
    cat >&2 <<EOF
WARNING: deployed and healthy inside the container, but ${PUBLIC_URL}/healthz did not answer:
  ${body}
Check that DNS for the service hostnames points at this VPS, that ports 80 and 443 are open,
and Caddy's certificate log: ssh ${TARGET} 'cd ${REMOTE_DIR}/deploy && docker compose logs caddy'
Cloudflare proxy and TLS mode per hostname: see docs/DECISIONS.md #10.
EOF
    exit 2
  fi
  sleep 5
done
printf '%s\n' "${body:0:400}"

echo "==> [6/6] Checking the public text gate ${GATE_HOST}:7701 from here ..."
if ! python3 - "${GATE_HOST}" <<'PY'
import socket
import sys

try:
    with socket.create_connection((sys.argv[1], 7701), timeout=10) as sock:
        sock.settimeout(10)
        data = b""
        while b"\n>\n" not in data and len(data) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.sendall(b"quit\n")
except OSError as exc:
    sys.exit(f"{sys.argv[1]}:7701: {exc}")
if not data.startswith(b"session "):
    sys.exit(f"{sys.argv[1]}:7701 answered without the gate's session line")
print(f"{sys.argv[1]}:7701 answers with the gate banner")
PY
then
  cat >&2 <<WARN
WARNING: deployed, and the gate answers inside the container, but ${GATE_HOST}:7701 did not answer from here.
Check the DNS record for ${GATE_HOST} (DNS-only) and that TCP 7700 and 7701 are open in the OVH firewall.
WARN
  exit 2
fi
echo "==> Deployed; ${PUBLIC_URL}/healthz and ${GATE_HOST}:7701 answer. Cloudflare proxy and TLS mode per hostname: see docs/DECISIONS.md #10."
