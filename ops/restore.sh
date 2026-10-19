#!/usr/bin/env bash
# Restore the SQLite database and the tiles mirror from a backup made by
# ops/backup.sh — and verify BEFORE applying anything.
#
# Usage (run on the VPS as root):
#   ops/restore.sh --stamp 20261018-033000 [--remote r2|b2|local] [--vkey-file FILE] [--yes]
#   ops/restore.sh --archive /var/backups/aics/20261018-033000 [--vkey-file FILE] [--yes]
#   ops/restore.sh --db aics-20261018-033000.db.gz --tiles tiles-20261018-033000.tar.gz \
#                  [--vkey-file FILE] [--yes]
#
# Sources: --stamp downloads aics-backup/<stamp>/ from an rclone remote (r2 by
# default); --stamp with --remote local, or --archive DIR, reads a backup
# directory that ops/backup.sh wrote locally (AICS_BACKUP_LOCAL_DIR, default
# /var/backups/aics; or a directory copied off the box); --db/--tiles name the
# two archive files directly. When a SHA256SUMS file sits with the archives
# (backup.sh writes one), both archives must match it before anything else runs.
#
# What it does:
#   1. stages the backup (downloaded with rclone from the chosen remote, or the
#      local backup directory or the two local files given) and checks
#      SHA256SUMS when present;
#   2. runs SQLite's PRAGMA integrity_check on the database;
#   3. verifies the staged tiles with the aics-tlog CLI (see below);
#   4. only then (after --yes or a prompt) stops aics-server, saves the current
#      live data aside (database with its -wal/-shm sidecars, and tiles), deletes
#      the old sidecars FIRST (SQLite must never replay a foreign write-ahead log
#      into the restored database), copies the restored db in, empties the tiles
#      volume and copies the restored tiles in, hands both to the app's user, runs
#      integrity_check and the tile verification once more on the applied files,
#      and tells you how to bring it back up.
#
# Every file operation runs in a one-off container of the aics-server service
# (`docker compose run --rm --no-deps`, the same image and volumes, the staging
# directory mounted read-only at /restore), never with `exec` in the service's
# own container: that works whether the service runs or not (step 4 stops it, and
# the scratch drill of runbook step 7.5 never starts it), and the one-off
# container serves nothing and signs nothing. /data/tiles is a volume mount point,
# so it is emptied with `find -mindepth 1 -delete`, never removed.
#
# Verification command (steps 3 and 4), in such a one-off container:
#   aics-tlog verify-checkpoint --tiles /restore/unpack/tiles --vkey-file /restore/log.vkey
# `verify-checkpoint` with --tiles reads the signed checkpoint note that sits in
# the tile directory, checks the note's signature against the out-of-band log
# key, recomputes the Merkle tree root from the staged tiles and compares it
# with the root in that checkpoint — exactly "recomputed tree root equals the
# latest checkpoint". --vkey-file must point at a LOCAL file holding the log
# vkey line obtained out of band (the _aics.wesupport-ai.com DNS TXT record /
# the aics package / the public README; format: "log name+8hex+base64", plain
# text). The CLI refuses a key fetched from the server being verified, on
# purpose. TODO(verify against live mirror too): once restored and running,
# also run `aics-tlog verify-checkpoint --tiles https://tiles.wesupport-ai.com/tiles
# --vkey-file ...` from an outside machine to confirm the mirror serves the
# same root agents can verify.
#
# WARNING: restoring a checkpoint OLDER than ones agents have already saved is
# a rollback; verifiers flag it as a consistency break (docs/DESIGN.md G5/G8 —
# gossip evidence, saved checkpoints). Never resume this origin from a shorter
# backup. Before applying, establish that recovered state reaches the newest
# acknowledged history, including receipts; this script's snapshot checks alone
# do not establish that. If it cannot be recovered, preserve evidence, stop
# signing and declare an availability incident. Disclosure cannot authorize rollback.
#
# The server seed is never part of a backup and is never touched here. If the
# seed is gone, the log keys are gone: regenerate nothing, stop, and follow the
# hand-written offline-seed procedure instead.
set -euo pipefail

COMPOSE_DIR="${AICS_COMPOSE_DIR:-/opt/wesupport-ai/deploy}"
COMPOSE_FILE="${COMPOSE_DIR}/docker-compose.yml"
RCLONE_CONF="${RCLONE_CONFIG:-/root/.config/rclone/rclone.conf}"
LOCAL_DIR="${AICS_BACKUP_LOCAL_DIR:-/var/backups/aics}"

log() { printf '[restore %s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { printf '[restore] ERROR: %s\n' "$*" >&2; exit 1; }

STAMP="" REMOTE="r2" ARCHIVE_DIR="" DB_IN="" TILES_IN="" VKEY_FILE="${AICS_LOG_VKEY_FILE:-}" ASSUME_YES=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --stamp)     STAMP="${2:?}"; shift 2 ;;
    --remote)    REMOTE="${2:?}"; shift 2 ;;
    --archive)   ARCHIVE_DIR="${2:?}"; shift 2 ;;
    --db)        DB_IN="${2:?}"; shift 2 ;;
    --tiles)     TILES_IN="${2:?}"; shift 2 ;;
    --vkey-file) VKEY_FILE="${2:?}"; shift 2 ;;
    --yes|-y)    ASSUME_YES=1; shift ;;
    *)           die "unknown argument: $1 (see header comment for usage)" ;;
  esac
done

[ -f "$COMPOSE_FILE" ] || die "compose file not found: $COMPOSE_FILE (set AICS_COMPOSE_DIR)"
[ -n "$VKEY_FILE" ] && [ -f "$VKEY_FILE" ] || die "need --vkey-file FILE (or AICS_LOG_VKEY_FILE): the out-of-band log vkey, from the _aics DNS TXT record / the aics package / the README. Without it the tree root cannot be verified."

compose() { docker compose --project-directory "$COMPOSE_DIR" -f "$COMPOSE_FILE" "$@"; }

STAGING="$(mktemp -d /tmp/aics-restore.XXXXXX)"
PRESERVE="/root/pre-restore-$(date -u +%Y%m%d-%H%M%S)"
trap 'rm -rf "$STAGING"' EXIT

# A one-off container of the aics-server service with its volumes (/data and the
# /data/tiles mount) and the staging directory read-only at /restore, run as root so
# it can hand the files to the app's user. --name: a one-off container must not take
# the service's container_name. Extra arguments go before the service name.
RUN_N=0
oneoff() {
  local entry="$1"; shift
  RUN_N=$((RUN_N + 1))
  compose run --rm --no-deps -T --user 0:0 --name "aics-restore-$$-$RUN_N" \
    -v "$STAGING:/restore:ro" ${ONEOFF_ARGS[@]+"${ONEOFF_ARGS[@]}"} --entrypoint "$entry" aics-server "$@" </dev/null
}
ONEOFF_ARGS=()

# PRAGMA integrity_check on a database file inside the one-off container.
integrity() {
  oneoff python3 -c '
import sqlite3, sys
conn = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro&immutable=1", uri=True)
ok = conn.execute("PRAGMA integrity_check").fetchone()[0]
conn.close()
print("integrity_check:", ok)
sys.exit(0 if ok == "ok" else 1)
' "$1"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# --- 1. Stage -----------------------------------------------------------------
if [ -n "$STAMP" ] && [ "$REMOTE" = local ]; then
  [ -z "$ARCHIVE_DIR" ] || die "give either --stamp with --remote local or --archive, not both"
  ARCHIVE_DIR="${LOCAL_DIR%/}/${STAMP}"
  STAMP=""
fi
if [ -n "$ARCHIVE_DIR" ]; then
  [ -z "$STAMP" ] && [ -z "$DB_IN" ] && [ -z "$TILES_IN" ] || die "--archive cannot be combined with --stamp, --db or --tiles"
  [ -d "$ARCHIVE_DIR" ] || die "backup directory not found: $ARCHIVE_DIR"
  for f in "$ARCHIVE_DIR"/aics-*.db.gz; do
    if [ -e "$f" ]; then
      [ -z "$DB_IN" ] || die "more than one aics-*.db.gz in $ARCHIVE_DIR"
      DB_IN="$f"
    fi
  done
  for f in "$ARCHIVE_DIR"/tiles-*.tar.gz; do
    if [ -e "$f" ]; then
      [ -z "$TILES_IN" ] || die "more than one tiles-*.tar.gz in $ARCHIVE_DIR"
      TILES_IN="$f"
    fi
  done
  [ -n "$DB_IN" ] && [ -n "$TILES_IN" ] || die "$ARCHIVE_DIR does not hold an aics-*.db.gz and a tiles-*.tar.gz"
  log "using the local backup directory $ARCHIVE_DIR"
elif [ -n "$STAMP" ]; then
  command -v rclone >/dev/null 2>&1 || die "rclone is not installed"
  [ -f "$RCLONE_CONF" ] || die "rclone config not found: $RCLONE_CONF"
  log "downloading aics-backup/${STAMP}/ from ${REMOTE}"
  rclone --config "$RCLONE_CONF" copy "${REMOTE}:aics-backup/${STAMP}" "$STAGING" \
    || die "download failed from ${REMOTE}:aics-backup/${STAMP} (try the other remote: --remote b2 / --remote r2)"
  DB_IN="$STAGING/aics-${STAMP}.db.gz"
  TILES_IN="$STAGING/tiles-${STAMP}.tar.gz"
fi
[ -n "$DB_IN" ] && [ -n "$TILES_IN" ] || die "give --stamp STAMP [--remote r2|b2|local] | --archive DIR | (--db FILE --tiles FILE); see header comment"
[ -f "$DB_IN" ] || die "database archive not found: $DB_IN"
[ -f "$TILES_IN" ] || die "tiles archive not found: $TILES_IN"

# SHA256SUMS written by backup.sh, when it sits with both archives.
SUMS_DIR="$(dirname "$DB_IN")"
if [ "$(dirname "$TILES_IN")" = "$SUMS_DIR" ] && [ -f "$SUMS_DIR/SHA256SUMS" ]; then
  for f in "$DB_IN" "$TILES_IN"; do
    name="${f##*/}"
    want="$(awk -v f="$name" '$2 == f { print $1 }' "$SUMS_DIR/SHA256SUMS")"
    [ -n "$want" ] || die "$name is not listed in $SUMS_DIR/SHA256SUMS; refusing an unlisted archive."
    [ "$want" = "$(sha256_of "$f")" ] || die "SHA256 mismatch on $f against $SUMS_DIR/SHA256SUMS; the archive is damaged or was altered. Nothing was applied."
  done
  log "SHA256SUMS match for both archives"
else
  log "no SHA256SUMS beside the archives; skipping the checksum check (integrity_check and the tree-root verification still run)"
fi

log "staged: $DB_IN, $TILES_IN"
gunzip -c "$DB_IN" > "$STAGING/aics.db"
# Only tiles/ may come out of the tiles archive (no absolute or ../ paths, no
# stray files), and never a seed or .env.
tar -tzf "$TILES_IN" > "$STAGING/tiles.list" || die "cannot list $TILES_IN"
if grep -vE '^(\./)?tiles(/|$)' "$STAGING/tiles.list" | grep -q . || grep -qE '(^|/)\.\.(/|$)' "$STAGING/tiles.list"; then
  die "$TILES_IN holds entries outside tiles/; refusing it."
fi
if grep -E '(^|/)([^/]*\.seed|\.env(\.[^/]*)?)/?$' "$STAGING/tiles.list" >&2; then
  die "the tiles archive contains a *.seed or .env file; refusing to apply it."
fi
mkdir -p "$STAGING/unpack"
tar -xzf "$TILES_IN" -C "$STAGING/unpack"
[ -d "$STAGING/unpack/tiles" ] || die "tiles archive does not contain a tiles/ directory"
cp "$VKEY_FILE" "$STAGING/log.vkey"

# Seed guard, same as backup.sh: nothing matching *.seed or .env may be applied.
if find "$STAGING" \( -name '*.seed' -o -name '.env' -o -name '.env.*' \) -print -quit | grep -q .; then
  die "a *.seed or .env file is in the staged backup; refusing to apply it."
fi

# --- 2. SQLite integrity ------------------------------------------------------
log "PRAGMA integrity_check on the staged database"
integrity /restore/aics.db || die "integrity_check failed on the staged database; do not apply this backup."

# --- 3. Verify the recomputed tree root equals the signed checkpoint -----------
log "verifying tiles with aics-tlog verify-checkpoint (out-of-band vkey)"
if ! oneoff aics-tlog verify-checkpoint --tiles /restore/unpack/tiles --vkey-file /restore/log.vkey \
     | tee "$STAGING/verify-report.json"; then
  die "aics-tlog verify-checkpoint FAILED: the recomputed root does not match the signed checkpoint (or the key/origin is wrong). Nothing was applied."
fi
log "tree root matches the signed checkpoint; report saved in $STAGING/verify-report.json"

# --- 4. Apply -----------------------------------------------------------------
if [ "$ASSUME_YES" -ne 1 ]; then
  printf 'Apply this restore (stop aics-server, replace db + tiles, keep the current data aside)? [type YES] '
  read -r answer
  [ "$answer" = "YES" ] || die "aborted; nothing was changed."
fi

log "stopping aics-server and preserving current live data in $PRESERVE"
compose stop aics-server
mkdir -p "$PRESERVE"
ONEOFF_ARGS=(-v "$PRESERVE:/preserve")
# shellcheck disable=SC2016  # the script runs in the container's shell
oneoff sh -euc '
for f in /data/aics.db /data/aics.db-wal /data/aics.db-shm; do
  if [ -e "$f" ]; then cp -a "$f" /preserve/; fi
done
mkdir -p /preserve/tiles
cp -a /data/tiles/. /preserve/tiles/
' || die "could not preserve the current data in $PRESERVE; nothing was replaced."
ONEOFF_ARGS=()

log "replacing the database and the tiles in the volumes"
# Order matters: the old -wal/-shm go first, so no write-ahead log of the previous
# database can be replayed into the restored one; the database is copied under a
# temporary name and renamed into place; the tiles volume is emptied in place.
oneoff sh -euc '
rm -f /data/aics.db-wal /data/aics.db-shm
cp /restore/aics.db /data/aics.db.restoring
mv -f /data/aics.db.restoring /data/aics.db
find /data/tiles -mindepth 1 -delete
cp -R /restore/unpack/tiles/. /data/tiles/
if id aics >/dev/null 2>&1; then chown -R aics:aics /data/aics.db /data/tiles; fi
' || die "applying the restore failed part way; the previous data is in $PRESERVE. Do not start aics-server; fix and run this script again."

log "verifying the applied files once more (integrity_check and the tree root)"
integrity /data/aics.db || die "integrity_check failed on the applied database; do not start aics-server (previous data: $PRESERVE)."
oneoff aics-tlog verify-checkpoint --tiles /data/tiles --vkey-file /restore/log.vkey >/dev/null \
  || die "the applied tiles do not verify against the signed checkpoint; do not start aics-server (previous data: $PRESERVE)."

log "restore applied. Next:"
cat <<'NEXT'
  1. cd /opt/wesupport-ai/deploy && docker compose up -d
  2. check https://api.wesupport-ai.com/healthz
  3. verify byte-identical signed notes at /tiles/checkpoint and /checkpoint
     on https://api.wesupport-ai.com against the pinned log key and saved heads;
  4. from an OUTSIDE machine, verify the live mirror serves the same root:
       aics-tlog verify-checkpoint --tiles https://tiles.wesupport-ai.com/tiles --vkey-file <log-vkey-file>
  5. never resume signing from a state shorter than any acknowledged history;
     if recovery cannot reach it, remain stopped and declare an availability incident.
NEXT
