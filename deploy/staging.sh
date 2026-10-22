#!/usr/bin/env bash
# Start, check or stop ONLY the disposable staging instance (aics-staging), on the VPS.
#
# Usage (on the VPS, in /opt/wesupport-ai/deploy, after deploy/docker-compose.staging.yml
# is in COMPOSE_FILE of deploy/.env):
#   deploy/staging.sh check   refuse unless staging is configured and shares no key with production
#   deploy/staging.sh up      check, then build and (re)start aics-staging alone and reload Caddy; with
#                             deploy/gate-tls-staging.yml in COMPOSE_FILE it first copies the test.*
#                             certificate for staging's TLS gate on 7800 (`up --no-deps` starts no dependency)
#   deploy/staging.sh stop    stop aics-staging alone (its volumes stay; wipe: ops/RUNBOOK-first-deploy.md)
#
# Unlike deploy/deploy-vps.sh, this never builds, restarts or replaces production's containers:
# `docker compose build aics-staging` and `docker compose up -d --no-deps aics-staging` touch
# only the staging service, and Caddy picks up the test.* block with a configuration reload
# (no restart, production's sites keep serving). The code it builds is whatever is in
# /opt/wesupport-ai on the VPS (synced by the last deploy-vps.sh run).
#
# The check reads the resolved configuration (`docker compose config --format json`) and never
# prints a value: staging's seed must not equal production's AICS_SERVER_SEED_HEX, and staging's
# owner key must not equal production's AICS_OWNER_PUBKEY (staging keys derived from
# production's seed would sign checkpoints for another origin with production's key material).
#
# Exit status: 0 done; 1 refused or failed.
set -euo pipefail

cd "$(dirname "$0")"
ACTION="${1:-}"
case "${ACTION}" in
  check|up|stop) ;;
  *) echo "Usage: $0 check|up|stop" >&2; exit 1 ;;
esac

check() {
  docker compose config --format json 2>/dev/null | python3 -c '
import json
import sys

try:
    config = json.load(sys.stdin)
except (ValueError, TypeError):
    sys.exit("Invalid Compose configuration; run docker compose config --quiet. Nothing was started.")
services = config.get("services", {})
staging = services.get("aics-staging")
if staging is None:
    sys.exit("aics-staging is not configured: add docker-compose.staging.yml to COMPOSE_FILE in deploy/.env. Nothing was started.")
production = services.get("aics-server", {})

def env(service):
    value = service.get("environment") or {}
    if isinstance(value, list):
        value = dict(item.split("=", 1) if "=" in item else (item, "") for item in value)
    return {k: ("" if v is None else str(v)).strip() for k, v in value.items()}

s, p = env(staging), env(production)
problems = []
for name, label in (("AICS_SERVER_SEED_HEX", "seed (AICS_STAGING_SEED_HEX)"), ("AICS_OWNER_PUBKEY", "owner key (AICS_STAGING_OWNER_PUBKEY)")):
    if s.get(name) and s.get(name).lower() == p.get(name, "").lower():
        problems.append(f"the staging {label} equals production\x27s {name}")
if s.get("AICS_PRODUCTION"):
    problems.append("AICS_PRODUCTION is set for aics-staging")
if not s.get("AICS_ORIGIN", "").startswith("test."):
    problems.append("the staging origin is not test.*")
if problems:
    sys.exit("Refusing: " + "; ".join(problems) + ". Nothing was started; values not shown.")
print("staging configuration: separate seed, owner key and origin")
'
}

# Whether deploy/gate-tls-staging.yml is in COMPOSE_FILE (its one-shot staging-gate-cert service exists).
staging_tls() {
  docker compose config --format json 2>/dev/null | python3 -c '
import json
import sys

try:
    services = json.load(sys.stdin).get("services", {})
except (ValueError, TypeError, AttributeError):
    sys.exit(1)
sys.exit(0 if "staging-gate-cert" in services else 1)
'
}

check
case "${ACTION}" in
  check)
    ;;
  up)
    docker compose build aics-staging </dev/null
    if staging_tls; then
      # Copy test.wesupport-ai.com's certificate out of Caddy's store for the TLS gate on 7800, before the
      # start: a missing copy stops the app at start (fail closed, as production's gate does).
      docker compose run --rm staging-gate-cert </dev/null
    fi
    docker compose up -d --no-deps aics-staging </dev/null
    docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile </dev/null
    echo "aics-staging started; check: curl -fsS https://test.wesupport-ai.com/healthz"
    if staging_tls; then
      echo "TLS gate: openssl s_client -quiet -verify_return_error -verify_hostname test.wesupport-ai.com -connect test.wesupport-ai.com:7800"
    fi
    ;;
  stop)
    docker compose stop aics-staging </dev/null
    echo "aics-staging stopped; production untouched"
    ;;
esac
