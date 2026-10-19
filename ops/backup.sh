#!/usr/bin/env bash
# Nightly backup for WeSupport-AI (wesupport-ai.com).
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
# of AICS_SERVER_SEED_HEX), nor deploy/.env. The seed derives the log and
# policy signing keys, which are the log itself: anyone holding it can forge
# future checkpoints and administrative leaves (tombstones, refusals,
# suspensions, the assurance card), so one leaked backup would end the log's
# entire trust story (docs/DESIGN.md §10). The seed is backed up only to an
# offline medium, by hand, never with the nightly dump. The script enforces
# this three times: it stages exactly the two named paths above, it refuses to
# continue if any staged file matches *.seed, .env or .env.*, and it refuses an
# archive whose listing holds such a name or anything outside tiles/.
#
# Where the archives go. Each run writes one directory <UTC-stamp>/ holding
# aics-<stamp>.db.gz, tiles-<stamp>.tar.gz and SHA256SUMS:
#   - LOCAL: under AICS_BACKUP_LOCAL_DIR (default /var/backups/aics, mode 0700),
#     kept AICS_BACKUP_KEEP_DAYS (default 30) by the date in the stamp. This is
#     the only copy while no remote is configured, and it is ON THE SAME BOX:
#     it protects against a broken database or a bad deploy, not against
#     losing the VPS. Set AICS_BACKUP_LOCAL_DIR= (empty) to keep no local copy
#     once remotes work.
#   - REMOTE: when AICS_BACKUP_REMOTES (default "r2 b2", see
#     ops/rclone.conf.example) is non-empty AND the rclone config exists, the
#     same directory is uploaded to every remote under aics-backup/<stamp>/ and
#     remote copies older than AICS_BACKUP_KEEP_DAYS are deleted. With no
#     rclone config the script runs in local mode and says so on stderr; set
#     AICS_BACKUP_REQUIRE_REMOTES=1 to make that a failure instead.
#
# Every archive is verified after it is written, before it counts: SHA256SUMS,
# gzip -t, tar -tzf (plus the name guard above), and PRAGMA integrity_check on
# the database decompressed from the written file (host python3, else the
# sqlite3 CLI, else inside the aics-server container; AICS_BACKUP_INTEGRITY_TOOL
# = python3|sqlite3|container forces one). A failed verification removes the
# partial directory. Before writing locally the script keeps
# AICS_BACKUP_MIN_FREE_MB (default 5120) free on the backup filesystem, which
# is the log's own disk: it deletes the oldest local backups (never the newest
# one) to make room, and fails without writing if that is not enough. Any
# failure exits non-zero. Upload corruption is also caught at restore time,
# where the tiles are verified cryptographically against the signed checkpoint
# (ops/restore.sh).
set -euo pipefail
umask 077

COMPOSE_DIR="${AICS_COMPOSE_DIR:-/opt/wesupport-ai/deploy}"
COMPOSE_FILE="${COMPOSE_DIR}/docker-compose.yml"
RCLONE_CONF="${RCLONE_CONFIG:-/root/.config/rclone/rclone.conf}"
RCLONE_REMOTES="${AICS_BACKUP_REMOTES-r2 b2}"
LOCAL_DIR="${AICS_BACKUP_LOCAL_DIR-/var/backups/aics}"
# AICS_BACKUP_RETENTION_DAYS is the older name of the same setting.
KEEP_DAYS="${AICS_BACKUP_KEEP_DAYS:-${AICS_BACKUP_RETENTION_DAYS:-30}}"
MIN_FREE_MB="${AICS_BACKUP_MIN_FREE_MB:-5120}"
REQUIRE_REMOTES="${AICS_BACKUP_REQUIRE_REMOTES:-0}"
INTEGRITY_TOOL="${AICS_BACKUP_INTEGRITY_TOOL:-auto}"

log()  { printf '[backup %s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
warn() { printf '[backup] WARNING: %s\n' "$*" >&2; }
die()  { printf '[backup] ERROR: %s\n' "$*" >&2; exit 1; }

# Names that must never be in a backup: the seed, deploy/.env and its variants.
FORBIDDEN_RE='(^|/)([^/]*\.seed|\.env(\.[^/]*)?)/?$'
STAMP_RE='^[0-9]{8}-[0-9]{6}$'

# --- 0. Settings and mode -------------------------------------------------------
case "$KEEP_DAYS" in ''|*[!0-9]*) die "AICS_BACKUP_KEEP_DAYS must be a whole number of days (got '$KEEP_DAYS')" ;; esac
KEEP_DAYS=$((10#$KEEP_DAYS))
[ "$KEEP_DAYS" -ge 1 ] || die "AICS_BACKUP_KEEP_DAYS must be at least 1"
case "$MIN_FREE_MB" in ''|*[!0-9]*) die "AICS_BACKUP_MIN_FREE_MB must be a whole number (got '$MIN_FREE_MB')" ;; esac
MIN_FREE_MB=$((10#$MIN_FREE_MB))
case "$INTEGRITY_TOOL" in auto|python3|sqlite3|container) ;; *) die "AICS_BACKUP_INTEGRITY_TOOL must be auto, python3, sqlite3 or container" ;; esac

REMOTES=()
read -r -a REMOTES <<< "$RCLONE_REMOTES" || true
for remote in ${REMOTES[@]+"${REMOTES[@]}"}; do
  [[ "$remote" =~ ^[A-Za-z0-9_.-]+$ ]] || die "invalid rclone remote name in AICS_BACKUP_REMOTES: '$remote'"
done

if [ "${#REMOTES[@]}" -gt 0 ] && [ -f "$RCLONE_CONF" ]; then
  MODE=remote
  command -v rclone >/dev/null 2>&1 || die "rclone is not installed (apt install rclone or curl the stock binary), but remotes are configured: ${REMOTES[*]}"
else
  MODE=local
  if [ "${#REMOTES[@]}" -gt 0 ]; then
    [ "$REQUIRE_REMOTES" = 1 ] && die "rclone config not found: $RCLONE_CONF (AICS_BACKUP_REQUIRE_REMOTES=1; copy ops/rclone.conf.example and fill it in)"
    warn "rclone config not found at $RCLONE_CONF: LOCAL MODE, the backup stays on this machine only (not off-box)."
  else
    [ "$REQUIRE_REMOTES" = 1 ] && die "AICS_BACKUP_REMOTES is empty but AICS_BACKUP_REQUIRE_REMOTES=1"
    warn "no remotes configured (AICS_BACKUP_REMOTES is empty): LOCAL MODE, the backup stays on this machine only (not off-box)."
  fi
  [ -n "$LOCAL_DIR" ] || die "local mode needs AICS_BACKUP_LOCAL_DIR (default /var/backups/aics); it is set empty"
fi
if [ -n "$LOCAL_DIR" ]; then
  case "$LOCAL_DIR" in /?*) ;; *) die "AICS_BACKUP_LOCAL_DIR must be an absolute path other than / (got '$LOCAL_DIR')" ;; esac
  LOCAL_DIR="${LOCAL_DIR%/}"
fi

command -v docker >/dev/null 2>&1 || die "docker is not installed"
command -v flock >/dev/null 2>&1 || die "flock is not installed (util-linux)"
[ -f "$COMPOSE_FILE" ] || die "compose file not found: $COMPOSE_FILE (set AICS_COMPOSE_DIR if the checkout lives elsewhere)"

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
DB_ARCHIVE="aics-${STAMP}.db.gz"
TILES_ARCHIVE="tiles-${STAMP}.tar.gz"
STAGING="$(mktemp -d /tmp/aics-backup.XXXXXX)"
INCOMING=""
cleanup() {
  rm -rf "$STAGING"
  if [ -n "$INCOMING" ]; then rm -rf "$INCOMING"; fi
}
trap cleanup EXIT

# --- helpers --------------------------------------------------------------------
stamp_at() {  # epoch seconds -> UTC stamp (GNU date, then BSD date)
  date -u -d "@$1" +%Y%m%d-%H%M%S 2>/dev/null || date -u -r "$1" +%Y%m%d-%H%M%S
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

free_mb() { df -Pk "$1" | awk 'NR == 2 { print int($4 / 1024) }'; }

# Stamp directories under LOCAL_DIR, oldest first (stamps sort as text).
local_stamps() {
  local d name
  for d in "$LOCAL_DIR"/*; do
    [ -d "$d" ] || continue
    name="${d##*/}"
    [[ "$name" =~ $STAMP_RE ]] && printf '%s\n' "$name"
  done | LC_ALL=C sort
}

INTEGRITY_PY='
import sqlite3, sys
conn = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro&immutable=1", uri=True)
rows = conn.execute("PRAGMA integrity_check").fetchall()
conn.close()
print("\n".join(str(r[0]) for r in rows))
sys.exit(0 if rows == [("ok",)] else 1)
'

# PRAGMA integrity_check on an uncompressed database file. Prints the result;
# returns 0 only when SQLite answers exactly "ok".
db_integrity() {
  local f="$1" tool="$INTEGRITY_TOOL" out
  if [ "$tool" = auto ]; then
    if command -v python3 >/dev/null 2>&1; then tool=python3
    elif command -v sqlite3 >/dev/null 2>&1; then tool=sqlite3
    else tool=container; fi
  fi
  case "$tool" in
    python3)
      out="$(python3 -I -c "$INTEGRITY_PY" "$f" 2>&1)" || { printf '%s\n' "$out"; return 1; } ;;
    sqlite3)
      out="$(sqlite3 "file:${f}?mode=ro&immutable=1" 'PRAGMA integrity_check;' 2>&1)" || { printf '%s\n' "$out"; return 1; } ;;
    container)
      compose cp "$f" aics-server:/tmp/aics-verify.db >/dev/null || { echo "could not copy the database into aics-server"; return 1; }
      out="$(compose exec -T -u 0 aics-server python3 -c "$INTEGRITY_PY" /tmp/aics-verify.db 2>&1)" \
        || { compose exec -T -u 0 aics-server rm -f /tmp/aics-verify.db || true; printf '%s\n' "$out"; return 1; }
      compose exec -T -u 0 aics-server rm -f /tmp/aics-verify.db || true ;;
  esac
  printf '%s\n' "$out"
  [ "$out" = ok ]
}

# Verify one written backup directory; dies on any failure.
verify_set() {
  local dir="$1" db="$1/$DB_ARCHIVE" tiles="$1/$TILES_ARCHIVE" list="$STAGING/verify-tiles.list" name want got result
  [ -s "$db" ] && [ -s "$tiles" ] && [ -s "$dir/SHA256SUMS" ] || die "archive missing or empty in $dir"
  for name in "$DB_ARCHIVE" "$TILES_ARCHIVE"; do
    want="$(awk -v f="$name" '$2 == f { print $1 }' "$dir/SHA256SUMS")"
    got="$(sha256_of "$dir/$name")"
    [ -n "$want" ] && [ "$want" = "$got" ] || die "SHA256 mismatch on $dir/$name after writing"
  done
  gzip -t "$db" || die "gzip -t failed on $db"
  tar -tzf "$tiles" > "$list" || die "tar -tzf failed on $tiles"
  grep -qE '^(\./)?tiles(/|$)' "$list" || die "$tiles has no tiles/ directory"
  if grep -vE '^(\./)?tiles(/|$)' "$list" | grep -q .; then
    die "$tiles holds entries outside tiles/; refusing it."
  fi
  if grep -E "$FORBIDDEN_RE" "$list" >&2; then
    die "the tiles archive contains a *.seed or .env file; aborting so it is never kept or uploaded."
  fi
  gunzip -c "$db" > "$STAGING/verify.db" || die "gunzip failed on $db"
  if ! result="$(db_integrity "$STAGING/verify.db")"; then
    die "PRAGMA integrity_check failed on $db: $result"
  fi
  rm -f "$STAGING/verify.db" "$list"
  log "verified $dir: sha256, gzip, tar listing, integrity_check $result"
}

log "staging into $STAGING (mode: $MODE)"

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
compose cp aics-server:/tmp/aics-backup.db "$STAGING/aics.db" >/dev/null || die "could not copy the database backup out of aics-server"
compose exec -T aics-server rm -f /tmp/aics-backup.db || warn "could not remove /tmp/aics-backup.db inside aics-server"
gzip -9 "$STAGING/aics.db"

# --- 2. Tiles: copy the shared volume's contents out of the container ---------
# The newest partial tile may be mid-rewrite during the copy; harmless — tiles
# are derived data, and restore.sh re-verifies the tree root against the signed
# checkpoint before applying anything.
compose cp aics-server:/data/tiles "$STAGING/tiles" >/dev/null || die "could not copy /data/tiles out of aics-server"

# --- 3. Seed guard -------------------------------------------------------------
# Belt and braces: the allowlist above never touches them, but refuse to keep or
# ship any *.seed or .env file if one somehow ended up staged.
if [ -n "$(find "$STAGING" \( -name '*.seed' -o -name '.env' -o -name '.env.*' \) -print)" ]; then
  find "$STAGING" \( -name '*.seed' -o -name '.env' -o -name '.env.*' \) -print >&2
  die "a *.seed or .env file reached the staging area; aborting so it is never kept or uploaded."
fi
# COPYFILE_DISABLE: no AppleDouble ._* members when this runs on macOS (a drill).
COPYFILE_DISABLE=1 tar -C "$STAGING" -czf "$STAGING/tiles.tar.gz" tiles
rm -rf "$STAGING/tiles"

# --- 4. Write the backup directory and verify it ------------------------------
if [ -n "$LOCAL_DIR" ]; then
  mkdir -p "$LOCAL_DIR" || die "cannot create $LOCAL_DIR"
  chmod 0700 "$LOCAL_DIR" || die "cannot chmod 0700 $LOCAL_DIR"
  [ -e "$LOCAL_DIR/$STAMP" ] && die "$LOCAL_DIR/$STAMP already exists"
  # Stale partial directories from an interrupted run (the lock rules out a live one).
  for d in "$LOCAL_DIR"/.incoming-*; do
    if [ -d "$d" ]; then rm -rf "$d"; log "removed stale partial $d"; fi
  done
  # Keep MIN_FREE_MB free on the log's own disk: drop the oldest local backups
  # (never the newest one) if needed, and write nothing if that is not enough.
  need_mb=$(( ( $(wc -c < "$STAGING/aics.db.gz") + $(wc -c < "$STAGING/tiles.tar.gz") ) / 1048576 + 1 ))
  while [ $(( $(free_mb "$LOCAL_DIR") - need_mb )) -lt "$MIN_FREE_MB" ]; do
    count="$(local_stamps | wc -l | tr -d ' ')"
    oldest="$(local_stamps | sed -n 1p)"
    if [ "$count" -le 1 ]; then
      die "not enough disk space in $LOCAL_DIR: need ${need_mb} MB plus ${MIN_FREE_MB} MB free (AICS_BACKUP_MIN_FREE_MB), have $(free_mb "$LOCAL_DIR") MB; nothing was written."
    fi
    warn "low disk space: deleting the oldest local backup $LOCAL_DIR/$oldest"
    rm -rf "${LOCAL_DIR:?}/$oldest"
  done
  INCOMING="$LOCAL_DIR/.incoming-$STAMP"
  TARGET="$INCOMING"
else
  TARGET="$STAGING/out"
fi
mkdir -p "$TARGET"
mv "$STAGING/aics.db.gz" "$TARGET/$DB_ARCHIVE"
mv "$STAGING/tiles.tar.gz" "$TARGET/$TILES_ARCHIVE"
printf '%s  %s\n%s  %s\n' \
  "$(sha256_of "$TARGET/$DB_ARCHIVE")" "$DB_ARCHIVE" \
  "$(sha256_of "$TARGET/$TILES_ARCHIVE")" "$TILES_ARCHIVE" > "$TARGET/SHA256SUMS"
verify_set "$TARGET"

if [ -n "$LOCAL_DIR" ]; then
  FINAL="$LOCAL_DIR/$STAMP"
  mv "$INCOMING" "$FINAL"
  INCOMING=""
  log "kept locally: $FINAL"
  # Retention by the date in the stamp: keep the last KEEP_DAYS days.
  cutoff="$(stamp_at $(( $(date -u +%s) - KEEP_DAYS * 86400 )))"
  while IFS= read -r s; do
    [ -n "$s" ] || continue
    if [ "$s" != "$STAMP" ] && [[ "$s" < "$cutoff" ]]; then
      rm -rf "${LOCAL_DIR:?}/$s"
      log "pruned local backup $s (older than ${KEEP_DAYS} days)"
    fi
  done < <(local_stamps)
else
  FINAL="$TARGET"
fi

# --- 5. Upload to every remote, then trim to retention ------------------------
if [ "$MODE" = remote ]; then
  failed=""
  for remote in "${REMOTES[@]}"; do
    log "uploading to ${remote}:aics-backup/${STAMP}/"
    if rclone --config "$RCLONE_CONF" copyto "$FINAL/$DB_ARCHIVE"    "${remote}:aics-backup/${STAMP}/${DB_ARCHIVE}" \
       && rclone --config "$RCLONE_CONF" copyto "$FINAL/$TILES_ARCHIVE" "${remote}:aics-backup/${STAMP}/${TILES_ARCHIVE}" \
       && rclone --config "$RCLONE_CONF" copyto "$FINAL/SHA256SUMS"     "${remote}:aics-backup/${STAMP}/SHA256SUMS"; then
      log "pruning ${remote}:aics-backup/ older than ${KEEP_DAYS} days"
      # rclone delete removes files (recursively) older than the bound; empty date
      # directories are swept afterwards.
      rclone --config "$RCLONE_CONF" delete "${remote}:aics-backup" --min-age "${KEEP_DAYS}d" \
        || { warn "pruning ${remote}:aics-backup failed"; failed="$failed ${remote}(prune)"; }
      rclone --config "$RCLONE_CONF" rmdirs "${remote}:aics-backup" --leave-root 2>/dev/null || true
    else
      warn "upload to ${remote} failed"
      failed="$failed ${remote}"
    fi
  done
  if [ -n "$failed" ]; then
    [ -n "$LOCAL_DIR" ] && warn "the verified local copy is in $FINAL"
    die "remote step failed for:$failed"
  fi
  log "done: ${DB_ARCHIVE} + ${TILES_ARCHIVE} on: ${REMOTES[*]}${LOCAL_DIR:+ and in $FINAL}"
else
  log "done: ${DB_ARCHIVE} + ${TILES_ARCHIVE} in $FINAL (local only, not off-box)"
fi
