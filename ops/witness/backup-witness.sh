#!/usr/bin/env bash
# Daily backup of the founder-run witness's state, on the witness host
# (ops/witness/README.md, "Backups"; optional: ops/witness/systemd/ runs it at
# 04:10 UTC once you install the timer).
#
# What it writes, one directory <UTC-stamp>/ per run:
#   witness-<stamp>.db.gz     the SQLite database, copied with SQLite's online
#                             backup API inside the running witness container
#                             (WAL-safe, no stop), streamed out over stdout
#   witness-<stamp>.json      the config (cosigner name, trusted logs and their
#                             public vkeys; no secret)
#   status-<stamp>.json       `aics-witness status --json`: size, root and last
#                             cosignature time per log, evidence counts
#   SHA256SUMS
#
# NEVER INCLUDED: the witness key (/data/witness.key). Its one backup is the
# offline copy made by hand once (README); an online copy of it in a cloud
# remote would let its holder cosign forks under this witness's name. The
# script stages exactly the files above and refuses to continue if any staged
# name looks like a key, seed or .env.
#
# What the backup is FOR. A witness must never be restored from an older
# database into service: it would have forgotten what it cosigned after the
# backup, and could then be led to cosign a fork (packages/aics-witness/README.md,
# "Operations"). So these archives are evidence and a record, not a restore
# path: they keep the log-signed requests the witness refused (proof of a split
# view, if one ever happens) and the last cosigned head per log, should the
# host and its volume be lost. Losing the volume means retiring the identity,
# whatever this backup holds. To move hosts, copy the stopped volume (README).
#
# Where the archives go, the pattern of ops/backup.sh:
#   - LOCAL: WITNESS_BACKUP_LOCAL_DIR (default /var/backups/aics-witness, mode
#     0700), kept WITNESS_BACKUP_KEEP_DAYS (default 30) days. Same disk as the
#     volume: protects against a broken database file, not a lost host.
#   - REMOTE: every rclone remote named in WITNESS_BACKUP_REMOTES (default
#     empty: local only), with the rclone config at RCLONE_CONFIG (default
#     /root/.config/rclone/rclone.conf, never in git; ops/rclone.conf.example
#     shows r2/b2, ops/witness/README.md a Google Drive remote). Each run goes
#     to <remote>:aics-witness-backup/<stamp>/; remote copies older than the
#     keep days are deleted. Set WITNESS_BACKUP_REQUIRE_REMOTES=1 to fail when
#     no remote is usable.
#
# Every archive is verified before it counts: SHA256SUMS, gzip -t, PRAGMA
# integrity_check on the decompressed database, and the database's recorded
# witness vkey against the running witness's. Any failure exits non-zero and
# removes the partial directory.
set -euo pipefail
umask 077

DIR="${AICS_WITNESS_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
LOCAL_DIR="${WITNESS_BACKUP_LOCAL_DIR-/var/backups/aics-witness}"
KEEP_DAYS="${WITNESS_BACKUP_KEEP_DAYS:-30}"
REMOTES_TEXT="${WITNESS_BACKUP_REMOTES:-}"
REQUIRE_REMOTES="${WITNESS_BACKUP_REQUIRE_REMOTES:-0}"
RCLONE_CONF="${RCLONE_CONFIG:-/root/.config/rclone/rclone.conf}"
PREFIX=aics-witness-backup

log()  { printf '[witness-backup %s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
warn() { printf '[witness-backup] WARNING: %s\n' "$*" >&2; }
die()  { printf '[witness-backup] ERROR: %s\n' "$*" >&2; exit 1; }

case "$KEEP_DAYS" in ''|*[!0-9]*) die "WITNESS_BACKUP_KEEP_DAYS must be a whole number of days" ;; esac
KEEP_DAYS=$((10#$KEEP_DAYS))
[ "$KEEP_DAYS" -ge 1 ] || die "WITNESS_BACKUP_KEEP_DAYS must be at least 1"
[ -f "$DIR/compose.yml" ] || die "no compose.yml in $DIR (set AICS_WITNESS_DIR to ~/aics/ops/witness)"
command -v docker >/dev/null 2>&1 || die "docker is not installed"
command -v python3 >/dev/null 2>&1 || die "python3 is not installed"

REMOTES=()
read -r -a REMOTES <<< "$REMOTES_TEXT" || true
for remote in ${REMOTES[@]+"${REMOTES[@]}"}; do
    [[ "$remote" =~ ^[A-Za-z0-9_.-]+$ ]] || die "invalid rclone remote name in WITNESS_BACKUP_REMOTES: '$remote'"
done
USE_REMOTES=0
if [ "${#REMOTES[@]}" -gt 0 ] && [ -f "$RCLONE_CONF" ]; then
    command -v rclone >/dev/null 2>&1 || die "rclone is not installed, but remotes are configured: ${REMOTES[*]}"
    USE_REMOTES=1
elif [ "$REQUIRE_REMOTES" = 1 ]; then
    die "no usable remote (WITNESS_BACKUP_REMOTES='${REMOTES_TEXT}', rclone config $RCLONE_CONF) and WITNESS_BACKUP_REQUIRE_REMOTES=1"
else
    warn "no remote configured: LOCAL MODE, the backup stays on this host only"
fi
[ "$USE_REMOTES" = 1 ] || [ -n "$LOCAL_DIR" ] || die "local mode needs WITNESS_BACKUP_LOCAL_DIR"
if [ -n "$LOCAL_DIR" ]; then
    case "$LOCAL_DIR" in /?*) ;; *) die "WITNESS_BACKUP_LOCAL_DIR must be an absolute path other than /" ;; esac
    LOCAL_DIR="${LOCAL_DIR%/}"
fi

compose() { docker compose --project-directory "$DIR" -f "$DIR/compose.yml" "$@"; }
[ -n "$(compose ps --status running -q aics-witness 2>/dev/null)" ] \
    || die "the aics-witness container is not running (docker compose up -d in $DIR)"

STAMP="$(date -u +%Y%m%d-%H%M%S)"
STAGING="$(mktemp -d /tmp/aics-witness-backup.XXXXXX)"
trap 'rm -rf "$STAGING"' EXIT
DB_ARCHIVE="witness-$STAMP.db.gz"
CONFIG_COPY="witness-$STAMP.json"
STATUS_COPY="status-$STAMP.json"

# -- 1. stage exactly three things ----------------------------------------------
compose exec -T aics-witness python3 -c '
import sqlite3, sys
from aics_witness.config import load_config
cfg = load_config("/data/witness.json")
src = sqlite3.connect(f"file:{cfg.db_path}?mode=ro", uri=True, timeout=30)
dst = sqlite3.connect(":memory:")
src.backup(dst)
src.close()
sys.stdout.buffer.write(dst.serialize())
' | gzip -9 > "$STAGING/$DB_ARCHIVE"
compose exec -T aics-witness cat /data/witness.json > "$STAGING/$CONFIG_COPY"
compose exec -T aics-witness aics-witness status --json > "$STAGING/$STATUS_COPY"

for f in "$STAGING"/*; do
    case "${f##*/}" in
        *.key|*.seed|.env|.env.*|*witness.key*) die "refusing to back up ${f##*/}: keys never go into this backup" ;;
    esac
done

# -- 2. verify ------------------------------------------------------------------
(cd "$STAGING" && { sha256sum "$DB_ARCHIVE" "$CONFIG_COPY" "$STATUS_COPY" > SHA256SUMS; sha256sum -c --quiet SHA256SUMS; }) \
    || die "SHA256SUMS check failed"
gzip -t "$STAGING/$DB_ARCHIVE" || die "gzip -t failed"
gzip -dc "$STAGING/$DB_ARCHIVE" > "$STAGING/verify.db"
python3 -I - "$STAGING/verify.db" "$STAGING/$STATUS_COPY" "$STAGING/$CONFIG_COPY" <<'PY' || die "verification failed"
import json, sqlite3, sys
db, status_path, config_path = sys.argv[1:]
conn = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)
rows = conn.execute("PRAGMA integrity_check").fetchall()
if rows != [("ok",)]:
    sys.exit(f"integrity_check: {rows}")
bound = conn.execute("SELECT value FROM meta WHERE key = 'witness_vkey'").fetchone()
logs = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
conn.close()
status = json.load(open(status_path, encoding="utf-8"))
json.load(open(config_path, encoding="utf-8"))
if bound is None or bound[0] != status["witness"]["vkey"]:
    sys.exit("the database's witness vkey differs from the running witness's")
print(f"verified: integrity ok, {logs} log(s), vkey {bound[0]}")
PY
rm -f "$STAGING/verify.db"

# -- 3. local copy ----------------------------------------------------------------
if [ -n "$LOCAL_DIR" ]; then
    install -d -m 0700 "$LOCAL_DIR"
    cp -R "$STAGING" "$LOCAL_DIR/.incoming-$STAMP"
    mv "$LOCAL_DIR/.incoming-$STAMP" "$LOCAL_DIR/$STAMP"
    log "local: $LOCAL_DIR/$STAMP"
    cutoff="$(date -u -d "-$KEEP_DAYS days" +%Y%m%d-%H%M%S)"
    for d in "$LOCAL_DIR"/*; do
        name="${d##*/}"
        [[ -d "$d" && "$name" =~ ^[0-9]{8}-[0-9]{6}$ && "$name" < "$cutoff" ]] || continue
        rm -rf "$d" && log "local: removed $name (older than $KEEP_DAYS days)"
    done
fi

# -- 4. remotes -------------------------------------------------------------------
failed=0
if [ "$USE_REMOTES" = 1 ]; then
    for remote in "${REMOTES[@]}"; do
        if rclone --config "$RCLONE_CONF" copy "$STAGING" "$remote:$PREFIX/$STAMP"; then
            log "remote: $remote:$PREFIX/$STAMP"
            rclone --config "$RCLONE_CONF" delete "$remote:$PREFIX" --min-age "${KEEP_DAYS}d" || warn "pruning $remote failed"
            rclone --config "$RCLONE_CONF" rmdirs "$remote:$PREFIX" --leave-root 2>/dev/null || true
        else
            warn "upload to $remote failed"; failed=1
        fi
    done
fi
[ "$failed" = 0 ] || die "at least one remote upload failed"
log "done: $STAMP"
