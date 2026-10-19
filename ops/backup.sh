#!/usr/bin/env bash
# Nightly off-box backup for WeSupport-AI (wesupport-ai.com).
# Run on the VPS (ops/systemd/aics-backup.timer does it at 03:30 UTC).
#
# What it backs up — an explicit allowlist, nothing else is ever read into the
# staging directory:
#   1. the SQLite database, via sqlite3's ONLINE backup API (the same one
#      behind the `.backup` dot-command): safe against the concurrently writing
#      WAL database, no filesystem copy of a live db, no service stop;
#   2. the tlog-tiles mirror (/data/tiles), which plus the database is
#      everything an independent verifier needs.
#
# NEVER INCLUDED: the server seed file (/data/server_master.seed, or the value
# of AICS_SERVER_SEED_HEX). The seed derives the log and policy signing keys,
# which are the log itself: anyone holding it can forge future checkpoints and
# administrative leaves (tombstones, refusals, suspensions, the assurance card),
# so one leaked backup would end the log's entire trust story
# (docs/DESIGN.md §10). The seed is backed up only to an offline medium, by
# hand, never with the nightly dump. The script enforces this twice: it stages
# exactly the two named paths above, and it refuses to continue if any staged
# file (or anything inside the tiles archive) matches *.seed.
#
# Uploads go to TWO remotes ("r2" and "b2", see ops/rclone.conf.example) under
# aics-backup/<UTC-stamp>/ and are kept RETENTION_DAYS (30) only. Upload
# corruption is caught at restore time, where the tiles are verified
# cryptographically against the signed checkpoint (ops/restore.sh).
set -euo pipefail

COMPOSE_DIR="${AICS_COMPOSE_DIR:-/opt/wesupport-ai/deploy}"
COMPOSE_FILE="${COMPOSE_DIR}/docker-compose.yml"
RCLONE_CONF="${RCLONE_CONFIG:-/root/.config/rclone/rclone.conf}"
RCLONE_REMOTES="${AICS_BACKUP_REMOTES:-r2 b2}"
RETENTION_DAYS="${AICS_BACKUP_RETENTION_DAYS:-30}"

log() { printf '[backup %s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { printf '[backup] ERROR: %s\n' "$*" >&2; exit 1; }

command -v rclone >/dev/null 2>&1 || die "rclone is not installed (apt install rclone or curl the stock binary)"
[ -f "$COMPOSE_FILE" ] || die "compose file not found: $COMPOSE_FILE (set AICS_COMPOSE_DIR if the checkout lives elsewhere)"
[ -f "$RCLONE_CONF" ] || die "rclone config not found: $RCLONE_CONF (copy ops/rclone.conf.example and fill it in)"

compose() { docker compose --project-directory "$COMPOSE_DIR" -f "$COMPOSE_FILE" "$@"; }

# One instance at a time; a second invocation exits quietly (systemd timer). Under
# ops/systemd/aics-backup.service, /run is read-only (ProtectSystem=strict) and systemd
# creates /run/aics-backup for the unit (RuntimeDirectory=, exported as
# RUNTIME_DIRECTORY); run by hand as root, the same directory is made here.
LOCK_DIR="${RUNTIME_DIRECTORY:-/run/aics-backup}"
mkdir -p "$LOCK_DIR" || die "cannot create the lock directory $LOCK_DIR"
exec 9>"$LOCK_DIR/lock" || die "cannot open the lock file $LOCK_DIR/lock"
flock -n 9 || { log "another backup is running; exiting."; exit 0; }

STAMP="$(date -u +%Y%m%d-%H%M%S)"
STAGING="$(mktemp -d /tmp/aics-backup.XXXXXX)"
trap 'rm -rf "$STAGING"' EXIT

log "staging into $STAGING"

# --- 1. SQLite database: online backup, executed inside the container ---------
# The image has no sqlite3 CLI; python3's sqlite3 module exposes the same online
# backup API the `.backup` dot-command uses. Destination is container /tmp, then
# `compose cp` pulls it out (works while the writer is running).
if ! compose exec -T aics-server python3 -c '
import sqlite3
src = sqlite3.connect("/data/aics.db", timeout=120)
dst = sqlite3.connect("/tmp/aics-backup.db")
with dst:
    src.backup(dst)   # online page-by-page copy; WAL-safe, no service stop
dst.close(); src.close()
'; then
  die "online backup of /data/aics.db failed (is the aics-server container running?)"
fi
compose cp aics-server:/tmp/aics-backup.db "$STAGING/aics.db" >/dev/null
compose exec -T aics-server rm -f /tmp/aics-backup.db
gzip -9 "$STAGING/aics.db"

# --- 2. Tiles: copy the shared volume's contents out of the container ---------
# The newest partial tile may be mid-rewrite during the copy; harmless — tiles
# are derived data, and restore.sh re-verifies the tree root against the signed
# checkpoint before applying anything.
compose cp aics-server:/data/tiles "$STAGING/tiles" >/dev/null
tar -C "$STAGING" -czf "$STAGING/tiles.tar.gz" tiles
rm -rf "$STAGING/tiles"

# --- 3. Seed guard -------------------------------------------------------------
# Belt and braces: the allowlist above never touches it, but refuse to ship any
# *.seed file if one somehow ended up staged (the seed is the log and policy key).
if find "$STAGING" -name '*.seed' -print -quit | grep -q .; then
  die "a *.seed file reached the staging area; aborting so it is never uploaded."
fi
if tar -tzf "$STAGING/tiles.tar.gz" | grep -E '(^|/)[^/]*\.seed$'; then
  die "the tiles archive contains a *.seed file; aborting so it is never uploaded."
fi

# --- 4. Upload to both remotes, then trim to retention ------------------------
DB_ARCHIVE="aics-${STAMP}.db.gz"
TILES_ARCHIVE="tiles-${STAMP}.tar.gz"
for remote in $RCLONE_REMOTES; do
  log "uploading to ${remote}:aics-backup/${STAMP}/"
  rclone --config "$RCLONE_CONF" copyto "$STAGING/$DB_ARCHIVE"   "${remote}:aics-backup/${STAMP}/${DB_ARCHIVE}"
  rclone --config "$RCLONE_CONF" copyto "$STAGING/tiles.tar.gz"  "${remote}:aics-backup/${STAMP}/${TILES_ARCHIVE}"
  log "pruning ${remote}:aics-backup/ older than ${RETENTION_DAYS} days"
  # rclone delete removes files (recursively) older than the bound; empty date
  # directories are swept afterwards.
  rclone --config "$RCLONE_CONF" delete "${remote}:aics-backup" --min-age "${RETENTION_DAYS}d"
  rclone --config "$RCLONE_CONF" rmdirs "${remote}:aics-backup" --leave-root 2>/dev/null || true
done

log "done: ${DB_ARCHIVE} + ${TILES_ARCHIVE} on: $RCLONE_REMOTES"
