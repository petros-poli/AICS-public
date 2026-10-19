#!/usr/bin/env bash
# Uptime + freshness probe for api.wesupport-ai.com (DNS-only, straight to the
# VPS and Caddy — never through Cloudflare, per decision 10).
#
# Checks:
#   1. GET /healthz answers HTTP 200;
#   2. the transparency-log checkpoint note is reachable and parses, and is not
#      older than MAX_AGE seconds (default 600 = 10 minutes);
#   3. disk usage on the data volume (decision 16 follow-up): each run records
#      the volume's used bytes in a small state file, and the probe fails when
#      growth over the last hour exceeds AICS_DISK_GROWTH_PCT percent of the
#      volume (default 2) or free space drops under AICS_DISK_FREE_FLOOR_PCT
#      percent (default 15). This is the early warning before disk pressure
#      forces the expiry of DM/capsule ciphertext bodies — which must be at
#      least 90 days old first and never takes leaves — or a storage expansion;
#   4. what the server itself stores outside the log (GET /v2/limits, aggregate
#      counts only): the notice register, i.e. the open rows of the notices
#      table, which only the owner empties by closing notices (each close is a
#      permanent report leaf), against its published caps limits.open_notices
#      and limits.open_notice_bytes (fails at AICS_NOTICE_FILL_PCT percent of
#      either, default 80; at 100 the server refuses new notices with 503); and
#      the resource exhaustion of AICS-1 section 8.2 (stored ciphertext above
#      retention.ciphertext_budget_bytes with nothing old enough to evict).
#      Set AICS_LIMITS_CHECK=0 to skip it.
#
# Exit codes: 0 ok; 1 /healthz failed; 2 checkpoint unreachable or unparseable;
# 3 checkpoint older than MAX_AGE (or dated implausibly far ahead); 4 checkpoint
# age could not be determined at all; 5 hourly disk growth above threshold;
# 6 free disk below floor; 7 disk sample failed (bad AICS_DATA_PATH?);
# 8 the notice register (notices table) is near or at its cap; 9 the server
# reports ciphertext resource exhaustion; 10 /v2/limits unreachable or
# unparseable.
#
# Freshness source, in order (see the python below):
#   a. cosignature/v1 lines inside the signed checkpoint note: their signature
#      blob is key-id(4) + big-endian POSIX seconds(8) + signature(64) = 76
#      bytes, so a 76-byte blob yields a timestamp (the plain log signature is
#      68 bytes and carries none). Until the witness feeder is wired
#      (docs/internal/followups.md) the note carries no cosignature;
#   b. a numeric timestamp field in the JSON envelope, should one be added;
#   c. neither -> exit 4 with a clear message. A monitor must not report "ok"
#      when it cannot actually verify the thing it monitors; a silent freeze
#      that still answers /healthz is exactly what this probe exists to catch.
#
# Endpoints (DECISIONS row 17a, reconciled in the server): /checkpoint and
# /tiles/checkpoint serve the C2SP tlog-checkpoint note as text/plain;
# /v2/tlog/checkpoint serves a JSON envelope whose signed_checkpoint member is
# the same note. The probe reads the note first and falls back to the envelope.
set -euo pipefail

BASE_URL="${AICS_API_BASE_URL:-https://api.wesupport-ai.com}"
MAX_AGE="${AICS_CHECKPOINT_MAX_AGE:-600}"

# Disk-growth alert (check 3). AICS_DATA_PATH: any directory on the volume that
# holds the server's /data — default /var/lib/docker, the docker volume store
# on the single-disk VPS. On a monitoring host whose own disk is not the data
# volume, either point AICS_DATA_PATH at the right filesystem or set
# AICS_DISK_CHECK=0. AICS_DISK_STATE: where samples are kept (default under
# XDG_STATE_HOME). Percentages are integers.
DATA_PATH="${AICS_DATA_PATH:-/var/lib/docker}"
DISK_CHECK="${AICS_DISK_CHECK:-1}"
STATE_FILE="${AICS_DISK_STATE:-${XDG_STATE_HOME:-${HOME:-/tmp}/.local/state}/aics/uptime-check-disk.state}"
GROWTH_PCT="${AICS_DISK_GROWTH_PCT:-2}"
FREE_FLOOR_PCT="${AICS_DISK_FREE_FLOOR_PCT:-15}"
LIMITS_CHECK="${AICS_LIMITS_CHECK:-1}"
NOTICE_FILL_PCT="${AICS_NOTICE_FILL_PCT:-80}"

rc=0
if ! curl -fsS --max-time 15 -o /dev/null "$BASE_URL/healthz"; then
  rc=$?
  printf 'FAIL: %s/healthz did not answer (curl exit %d)\n' "$BASE_URL" "$rc" >&2
  exit 1
fi
printf 'ok: /healthz\n'

cp_body=""
for path in /checkpoint /tiles/checkpoint /v2/tlog/checkpoint; do
  if cp_body="$(curl -fsS --max-time 15 "$BASE_URL$path" 2>/dev/null)" && [ -n "$cp_body" ]; then
    printf 'ok: checkpoint at %s\n' "$path"
    break
  fi
done
if [ -z "$cp_body" ]; then
  printf 'FAIL: no checkpoint at %s (tried /checkpoint, /tiles/checkpoint, /v2/tlog/checkpoint)\n' "$BASE_URL" >&2
  exit 2
fi

cp_body="$cp_body" MAX_AGE="$MAX_AGE" python3 - <<'PY'
import base64, json, os, sys, time

body = os.environ["cp_body"]
doc = None
try:
    maybe = json.loads(body)
    if isinstance(maybe, dict) and isinstance(maybe.get("tree_size"), int):
        doc = maybe
except ValueError:
    pass

if doc is not None:                       # JSON envelope (/v2/tlog/checkpoint)
    size = doc["tree_size"]
    note = doc.get("signed_checkpoint") or ""
    if not isinstance(note, str) or not note:
        print("FAIL: JSON checkpoint envelope has no signed_checkpoint note", file=sys.stderr); sys.exit(2)
else:                                     # C2SP tlog-checkpoint note (/checkpoint, /tiles/checkpoint)
    note = body

# Parse the note: origin line, decimal size, base64 root (32 bytes), optional
# extension lines, one blank line, then at least one "— <name> <base64>" line.
lines = note.split("\n")
try:
    blank = lines.index("")
except ValueError:
    print("FAIL: checkpoint note has no blank separator line", file=sys.stderr); sys.exit(2)
head, sigs = lines[:blank], [l for l in lines[blank + 1:] if l]
if len(head) < 3 or not head[0].strip():
    print("FAIL: checkpoint note is missing origin, size or root", file=sys.stderr); sys.exit(2)
try:
    note_size = int(head[1])
    root = base64.b64decode(head[2], validate=True)
except (ValueError, TypeError):
    print("FAIL: checkpoint note has a malformed size or root line", file=sys.stderr); sys.exit(2)
if note_size < 0 or len(root) != 32:
    print("FAIL: checkpoint note has a malformed size or root line", file=sys.stderr); sys.exit(2)
if doc is not None and doc["tree_size"] != note_size:
    print(f"FAIL: envelope tree_size {doc['tree_size']} differs from the note's {note_size}", file=sys.stderr); sys.exit(2)
size = note_size
if not sigs or not all(l.startswith("\N{EM DASH} ") for l in sigs):
    print("FAIL: checkpoint note carries no signature lines", file=sys.stderr); sys.exit(2)
print(f"ok: origin={head[0]} tree_size={size}")

max_age = int(os.environ["MAX_AGE"])
now = time.time()
ts = None

# (a) cosignature timestamps from the note (76-byte sig blobs).
for line in sigs:
    parts = line.split()
    if len(parts) < 3:
        continue
    try:
        blob = base64.b64decode(parts[-1], validate=True)
    except (ValueError, TypeError):
        continue
    if len(blob) == 76:  # key-id 4 + timestamp 8 + signature 64
        ts = max(ts or 0, int.from_bytes(blob[4:12], "big"))

# (b) numeric timestamp field in the envelope, should the server add one.
if ts is None and doc is not None:
    for k in ("ts", "timestamp", "generated_at", "checkpoint_ts", "signed_at", "updated_at"):
        v = doc.get(k)
        if isinstance(v, (int, float)) and v > 1_500_000_000:  # plausible POSIX seconds
            ts = v
            break

if ts is None:
    print("FAIL: cannot determine checkpoint age: the note carries no cosignature "
          "(witness feeder not wired yet?) and the envelope has no timestamp field.",
          file=sys.stderr)
    sys.exit(4)

age = now - ts
if age > max_age:
    print(f"FAIL: checkpoint is {int(age)}s old (limit {max_age}s)", file=sys.stderr)
    sys.exit(3)
if -age > 300:  # dated more than 5 minutes in the future
    print(f"FAIL: checkpoint is dated {-int(age)}s in the future (clock skew?)", file=sys.stderr)
    sys.exit(3)
print(f"ok: checkpoint age {int(age)}s (limit {max_age}s)")
PY

# --- 3. Disk-usage growth on the data volume (decision 16) ------------------
# The log never shrinks and leaves are never deleted; the first disk-pressure
# valve is expiring DM/capsule ciphertext bodies, allowed only once they are at
# least 90 days old (decisions 4 and 16). A fast-growth alert is the warning
# that that decision point — or a disk expansion — is coming, with time to act.
if [ "$DISK_CHECK" = "1" ]; then
  if ! df_line="$(df -Pk "$DATA_PATH" 2>/dev/null | tail -n 1)" || [ -z "$df_line" ]; then
    printf 'FAIL: cannot sample disk usage of %s (set AICS_DATA_PATH to a directory on the data volume, or AICS_DISK_CHECK=0 on a host that is not the VPS)\n' "$DATA_PATH" >&2
    exit 7
  fi
  set -- $df_line
  total_kb=$2 used_kb=$3 avail_kb=$4

  now="$(date +%s)"
  used_b=$((used_kb * 1024))
  total_b=$((total_kb * 1024))
  free_pct=$((avail_kb * 100 / total_kb))
  limit_b=$((total_b * GROWTH_PCT / 100))

  mkdir -p "$(dirname "$STATE_FILE")"
  touch "$STATE_FILE"

  # Append this run's sample; keep the last 24h of samples plus the most
  # recent older sample as the 24h baseline. One sample per line:
  # "<epoch-seconds> <used-bytes>".
  tmp="$STATE_FILE.tmp"
  awk -v now="$now" -v used="$used_b" '
    NF == 2 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ { t[++n] = $1; u[n] = $2 }
    END {
      base = 0
      for (i = 1; i <= n; i++)
        if (t[i] <= now - 86400 && t[i] > base) base = t[i]
      for (i = 1; i <= n; i++)
        if (t[i] > now - 86400 || t[i] == base) print t[i], u[i]
      print now, used
    }' "$STATE_FILE" > "$tmp" && mv "$tmp" "$STATE_FILE"

  # Growth over the last hour and the last 24h: used-now minus the most recent
  # sample at least 1h / 24h old. "na" while no baseline exists yet.
  stats="$(awk -v now="$now" -v used="$used_b" '
    $1 <= now - 3600  && (!h || $1 > h) { h = $1; hu = $2 }
    $1 <= now - 86400 && (!d || $1 > d) { d = $1; du = $2 }
    END { printf "%s %s\n", (h ? used - hu : "na"), (d ? used - du : "na") }' \
    "$STATE_FILE")" || stats="na na"
  hour_g="${stats%% *}"
  day_g="${stats##* }"

  printf 'ok: disk %s: %d%% free, %d bytes used; growth last 1h %s B, last 24h %s B\n' \
    "$DATA_PATH" "$free_pct" "$used_b" "$hour_g" "$day_g"

  if [ "$hour_g" != "na" ] && [ "$hour_g" -gt "$limit_b" ]; then
    printf 'FAIL: %s grew by %d bytes in the last hour, above the %s%% threshold (%d bytes): investigate now — sustained growth at this rate brings disk pressure, and the only valve is expiring ciphertext bodies that are at least 90 days old (decision 16); leaves are never deleted. Look first at the notice register (the open rows of the notices table, check 4 / GET /v2/limits notice_register) and at the stored ciphertext (resource_exhaustion)\n' \
      "$DATA_PATH" "$hour_g" "$GROWTH_PCT" "$limit_b" >&2
    exit 5
  fi
  if [ "$free_pct" -lt "$FREE_FLOOR_PCT" ]; then
    printf 'FAIL: only %d%% free on %s (floor %d%%): free space before ciphertext-body expiry (bodies >= 90 days old only) or storage expansion has to be decided (decision 16)\n' \
      "$free_pct" "$DATA_PATH" "$FREE_FLOOR_PCT" >&2
    exit 6
  fi
fi

# --- 4. The notice register and ciphertext exhaustion (GET /v2/limits) --------
# Keyless POST /notice fills the notices table until the owner closes notices; the
# server caps the open ones (limits.open_notices, limits.open_notice_bytes) and
# refuses more with 503 at the cap. Warn well before that, naming the table.
if [ "$LIMITS_CHECK" = "1" ]; then
  if ! limits_body="$(curl -fsS --max-time 15 "$BASE_URL/v2/limits" 2>/dev/null)" || [ -z "$limits_body" ]; then
    printf 'FAIL: %s/v2/limits did not answer\n' "$BASE_URL" >&2
    exit 10
  fi
  limits_body="$limits_body" NOTICE_FILL_PCT="$NOTICE_FILL_PCT" python3 - <<'PY'
import json, os, sys

try:
    doc = json.loads(os.environ["limits_body"])
    register = doc["notice_register"]
    open_count, open_bytes = int(register["open"]), int(register["bytes"])
    max_open, max_bytes = int(register["max_open"]), int(register["max_bytes"])
    exhaustion = doc.get("resource_exhaustion")
except (ValueError, KeyError, TypeError) as exc:
    print(f"FAIL: /v2/limits is not the expected document ({exc})", file=sys.stderr)
    sys.exit(10)
pct = int(os.environ["NOTICE_FILL_PCT"])
print(f"ok: notice register {open_count}/{max_open} open notices, {open_bytes}/{max_bytes} bytes")
if open_count * 100 >= max_open * pct or open_bytes * 100 >= max_bytes * pct:
    full = open_count >= max_open or open_bytes >= max_bytes
    print(f"FAIL: the notice register (open rows of the notices table) holds {open_count} of {max_open} notices and "
          f"{open_bytes} of {max_bytes} bytes, {'at its cap: new notices are refused with 503' if full else f'above {pct}%'}; "
          "the owner closes notices with their outcomes (aics_client.py owner notices / close-notice), each one a "
          "permanent report leaf", file=sys.stderr)
    sys.exit(8)
if exhaustion is not None:
    print(f"FAIL: the server reports resource exhaustion of stored ciphertext (AICS-1 section 8.2): "
          f"{json.dumps(exhaustion, sort_keys=True)}; nothing is old enough to evict, so decide on more disk or a "
          "budget change (a policy leaf) now", file=sys.stderr)
    sys.exit(9)
PY
fi
