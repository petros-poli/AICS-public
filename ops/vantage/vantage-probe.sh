#!/usr/bin/env bash
# The second-vantage probes: run the public read-only probes from a host that is
# not the VPS (the founder-run witness host) and push phone notifications
# through ntfy, the same path as ops/first-contact-watch.sh.
#
# Usage: vantage-probe.sh uptime | mirror | status
#
#   uptime  (every 5 minutes) GET /healthz from here, then ops/uptime-check.sh
#           (AICS_DISK_CHECK=0: this host's disk is not the data volume;
#           AICS_UPTIME_KEEP_GOING=1: every check runs; AICS_CHECKPOINT_MAX_AGE
#           240 s by default: the card's max_checkpoint_age is 300 s, and the
#           margin covers the 5-minute probe interval; with a witness vkey file
#           only that witness's cosignature dates the checkpoint, verified with
#           aics-tlog under the pinned log and witness keys). Alerts: API down,
#           UNAVAILABLE (log diverged from its tiles), DEGRADED, checkpoint
#           unreachable, checkpoint stale (only once cosignatures give it an age;
#           until then "age unknown" is recorded, not alerted, and becomes an
#           alert only after an age has been seen once), notice register near
#           its cap, ciphertext resource exhaustion, /v2/limits not answering.
#   mirror  (hourly) ops/mirror-check.sh (api.* against tiles.*, signatures
#           under the pinned log vkey, consistency proof), then the witness's
#           view: the latest checkpoint the local witness cosigned
#           (GET <witness>/<sha256(origin)>/checkpoint) is verified under the
#           same vkey and compared with the api checkpoint, fetched after the
#           witness's so that an honest witness is never ahead of it: same size
#           must mean same root, the api must not be behind the witness (twice
#           in a row, so a cache or a race cannot raise it alone), and a smaller
#           witness tree must be proved consistent with the api tree from the
#           api tiles. Alerts: a split (any of these), an invalid signature,
#           consistency unproven for 3 runs, witness down, witness lost its
#           state, witness not cosigning while the log grows.
#   status  (daily) ops/status.sh output, the open alerts and the witness's
#           view, as one low-priority notification.
#
# Dedup: each check group keeps one state file under $AICS_VANTAGE_STATE/groups.
# A failure alerts once, when it first reaches its confirmation count (1 run
# for most, 2 or 3 for the ones that ordinary propagation lag or one lost
# packet can cause), and once more when it clears ("recovered"). A failure that
# changes into another one alerts the new one at once. A notification that
# could not be sent is retried on the next run. A group whose inputs could not
# be fetched this run (the API is down, so its checkpoint cannot be judged) is
# left as it was: it neither recovers nor alerts.
#
# Configuration (EnvironmentFile /etc/default/aics-vantage, mode 0600):
#   NTFY_TOPIC                  the phone's ntfy topic (secret; required unless
#                               AICS_VANTAGE_DRY_RUN=1)
#   NTFY_URL                    default https://ntfy.sh
#   AICS_API_BASE_URL           default https://api.wesupport-ai.com
#   AICS_TILES_BASE             mirror tile prefix, default
#                               https://tiles.wesupport-ai.com/tiles
#   AICS_LOG_VKEY_FILE          pinned log vkey, obtained out of band (DNS TXT
#                               _aics, the README, PyPI), default
#                               /etc/aics-vantage/log.vkey
#   AICS_LOG_ORIGIN             optional origin pin from the trust bundle
#   AICS_VANTAGE_WITNESS_URL    default http://127.0.0.1:7380 (compose.witness.yml);
#                               set it empty to skip the witness's view
#   AICS_VANTAGE_WITNESS_VKEY_FILE  optional witness vkey (public), default
#                               /etc/aics-vantage/witness.vkey if it exists:
#                               then the witness's cosignature is verified too
#   AICS_VANTAGE_WITNESS_MAX_LAG  seconds (default 1800) the witness may go
#                               without cosigning while the log is ahead of it
#   AICS_CHECKPOINT_MAX_AGE     the uptime probe's checkpoint age limit (240)
#   AICS_VANTAGE_STATE          default /var/lib/aics-vantage
#   AICS_VANTAGE_RETRY_DELAY    seconds between the two /healthz attempts (20)
#   AICS_VANTAGE_DRY_RUN=1      print notifications instead of sending them
# Public data only: nothing here reads a body, an address or a key other than
# the public log and witness vkeys. Exit 0 after any probe outcome (the phone,
# not the unit state, is the alert channel); exit 2 on a usage error.
set -u
set -o pipefail

MODE="${1:-}"
case "$MODE" in uptime|mirror|status) ;; *)
  printf 'usage: %s uptime|mirror|status\n' "$0" >&2; exit 2 ;;
esac

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
OPS_DIR="${AICS_VANTAGE_OPS_DIR:-$(dirname -- "$HERE")}"
API="${AICS_API_BASE_URL:-https://api.wesupport-ai.com}"
API="${API%/}"
TILES="${AICS_TILES_BASE:-https://tiles.wesupport-ai.com/tiles}"
TILES="${TILES%/}"
VKEY_FILE="${AICS_LOG_VKEY_FILE:-/etc/aics-vantage/log.vkey}"
WITNESS_URL="${AICS_VANTAGE_WITNESS_URL-http://127.0.0.1:7380}"
WITNESS_URL="${WITNESS_URL%/}"
WITNESS_VKEY_FILE="${AICS_VANTAGE_WITNESS_VKEY_FILE:-/etc/aics-vantage/witness.vkey}"
WITNESS_MAX_LAG="${AICS_VANTAGE_WITNESS_MAX_LAG:-1800}"
# The card's max_checkpoint_age is 300 s (card-content.json G5): agents treat an older cosignature as stale, so the
# phone hears of it before that, less a margin for the probe interval.
CHECKPOINT_MAX_AGE="${AICS_CHECKPOINT_MAX_AGE:-240}"
STATE="${AICS_VANTAGE_STATE:-/var/lib/aics-vantage}"
RETRY_DELAY="${AICS_VANTAGE_RETRY_DELAY:-20}"
DRY_RUN="${AICS_VANTAGE_DRY_RUN:-0}"
NTFY_URL="${NTFY_URL:-https://ntfy.sh}"
NTFY_TOPIC="${NTFY_TOPIC:-}"
if [ "$DRY_RUN" != "1" ] && [ -z "$NTFY_TOPIC" ]; then
  printf 'vantage-probe: NTFY_TOPIC is required (see /etc/default/aics-vantage)\n' >&2; exit 2
fi
umask 077
mkdir -p "$STATE/groups" "$STATE/markers" || exit 2
WORK=$(mktemp -d "${TMPDIR:-/tmp}/aics-vantage.XXXXXX") || exit 2
trap 'rm -rf "$WORK"' EXIT

now() { date +%s; }
iso() { date -u -d "@$1" +%FT%TZ 2>/dev/null || date -u -r "$1" +%FT%TZ 2>/dev/null || printf '%s' "$1"; }
dur() { # seconds -> "3h 05m"
  local s=$1; if [ "$s" -ge 3600 ]; then printf '%dh %02dm' $((s / 3600)) $((s % 3600 / 60)); else printf '%dm' $((s / 60)); fi
}
log() { printf 'vantage-probe %s: %s\n' "$MODE" "$*"; }

notify() { # title, body, priority(1-5), tags; 0 when sent
  local body
  body=$(printf '%s' "$2" | head -c 3500)
  if [ "$DRY_RUN" = "1" ]; then
    printf 'NOTIFY [p%s %s] %s\n%s\n' "${3:-3}" "${4:-robot}" "$1" "$body"; return 0
  fi
  # -4: ntfy.sh counts an IPv6 visitor by a provider-shared prefix (the VPS was refused for two days over IPv6
  # on 2026-10-20 while IPv4 published at once).
  if curl -4 -fsS --max-time 15 -o /dev/null -H "Title: $1" -H "Priority: ${3:-3}" -H "Tags: ${4:-robot}" \
      -d "$body" "$NTFY_URL/$NTFY_TOPIC"; then
    log "notified: $1"; return 0
  fi
  printf 'vantage-probe: notification failed, will retry next run: %s\n' "$1" >&2; return 1
}

# meta KEY -> PRIO TAGS CONFIRM TITLE (sets globals)
meta() {
  CONFIRM=1
  case "$1" in
    api_down)             PRIO=5 TAGS=rotating_light TITLE="API not answering" ;;
    health_unavailable)   PRIO=5 TAGS=rotating_light TITLE="log UNAVAILABLE (diverged from its tiles)" ;;
    health_degraded)      PRIO=4 TAGS=warning        TITLE="health DEGRADED" ;;
    checkpoint_unreachable) PRIO=4 TAGS=warning      TITLE="checkpoint unreachable or malformed" ;;
    checkpoint_stale)     PRIO=5 TAGS=hourglass      TITLE="checkpoint stale" ;;
    checkpoint_age_lost)  PRIO=4 TAGS=warning        TITLE="checkpoint age unknown again (cosignature gone)"; CONFIRM=2 ;;
    limits_unreachable)   PRIO=3 TAGS=warning        TITLE="/v2/limits not answering"; CONFIRM=2 ;;
    notice_register)      PRIO=4 TAGS=inbox_tray     TITLE="notice register near its cap" ;;
    resource_exhaustion)  PRIO=5 TAGS=rotating_light TITLE="ciphertext resource exhaustion" ;;
    uptime_error)         PRIO=3 TAGS=warning        TITLE="uptime probe error" ;;
    mirror_setup)         PRIO=3 TAGS=wrench         TITLE="mirror check cannot run" ;;
    mirror_fetch)         PRIO=3 TAGS=warning        TITLE="mirror check cannot fetch checkpoints"; CONFIRM=2 ;;
    mirror_bad_signature) PRIO=5 TAGS=rotating_light TITLE="checkpoint signature INVALID under the pinned log key" ;;
    mirror_split)         PRIO=5 TAGS=rotating_light TITLE="SPLIT: api and tiles checkpoints disagree" ;;
    mirror_unproven)      PRIO=3 TAGS=warning        TITLE="mirror consistency unproven"; CONFIRM=3 ;;
    witness_down)         PRIO=4 TAGS=warning        TITLE="witness not answering"; CONFIRM=2 ;;
    witness_lost_state)   PRIO=5 TAGS=rotating_light TITLE="witness lost its state (nothing cosigned any more)" ;;
    witness_bad_note)     PRIO=5 TAGS=rotating_light TITLE="witness checkpoint fails verification" ;;
    witness_split)        PRIO=5 TAGS=rotating_light TITLE="SPLIT: witness and api disagree" ;;
    witness_ahead)        PRIO=5 TAGS=rotating_light TITLE="SPLIT: witness and api disagree"; CONFIRM=2 ;;
    witness_unproven)     PRIO=3 TAGS=warning        TITLE="witness consistency unproven"; CONFIRM=3 ;;
    witness_stalled)      PRIO=3 TAGS=hourglass      TITLE="witness not cosigning new checkpoints" ;;
    *)                    PRIO=3 TAGS=warning        TITLE="$1" ;;
  esac
}

field() { sed -n "s/^$1=//p" "$2" 2>/dev/null | head -n 1; }

# group GROUP KEY BODY: KEY empty means the group is fine this run.
group() {
  local g=$1 key=$2 body=${3:-} f="$STATE/groups/$1" t
  local p_state="" p_count=0 p_since="" p_alerted=0 p_owed=0 p_title=""
  t=$(now)
  if [ -f "$f" ]; then
    p_state=$(field state "$f"); p_count=$(field count "$f"); p_since=$(field since "$f")
    p_alerted=$(field alerted "$f"); p_owed=$(field owed "$f"); p_title=$(field title "$f")
    p_count=${p_count:-0}; p_since=${p_since:-$t}; p_alerted=${p_alerted:-0}; p_owed=${p_owed:-0}
  fi
  if [ -z "$key" ]; then
    [ -n "$p_state" ] || { rm -f "$f"; return 0; }
    if [ "$p_alerted" = 1 ] || [ "$p_owed" = 1 ]; then
      notify "wesupport-ai: recovered: $p_title" \
        "ok again at $(iso "$t") from this vantage; failing since $(iso "$p_since") ($(dur $((t - p_since))), runs: $p_count)" \
        3 white_check_mark || return 0   # keep the state: the recovery is retried
    else
      log "$g: $p_state cleared before it was confirmed ($p_count run(s))"
    fi
    rm -f "$f"; return 0
  fi
  meta "$key"
  local count since alerted owed need=$CONFIRM was=""
  if [ "$key" = "$p_state" ]; then
    count=$((p_count + 1)); since=$p_since; alerted=$p_alerted; owed=$p_owed
  else
    count=1; since=$t; alerted=0; owed=0
    if [ -n "$p_state" ] && { [ "$p_alerted" = 1 ] || [ "$p_owed" = 1 ]; }; then
      owed=1; need=1; was=" (was: $p_title)"
    fi
  fi
  [ "$owed" = 1 ] && need=1
  if [ "$alerted" != 1 ] && [ "$count" -ge "$need" ]; then
    if notify "wesupport-ai: $TITLE$was" "$body" "$PRIO" "$TAGS"; then alerted=1; owed=0; fi
  elif [ "$alerted" != 1 ]; then
    log "$g: $key seen $count of $need run(s) needed to alert"
  fi
  printf 'state=%s\ncount=%s\nsince=%s\nalerted=%s\nowed=%s\ntitle=%s\n' \
    "$key" "$count" "$since" "$alerted" "$owed" "$TITLE" > "$f.tmp" && mv "$f.tmp" "$f"
}

group_state() { field state "$STATE/groups/$1"; }
mark() { date -u +%FT%TZ > "$STATE/markers/$1"; }
marked() { [ -f "$STATE/markers/$1" ]; }
fails() { grep -E 'FAIL|mirror-check:|error' "$1" 2>/dev/null | head -n 8 | cut -c1-400; }

# --- uptime ------------------------------------------------------------------
probe_health() { # sets H_KIND (ok|degraded|unavailable|down) and H_DETAIL
  local code rc
  code=$(curl -sS --max-time 15 -o "$WORK/healthz" -w '%{http_code}' "$API/healthz" 2>"$WORK/healthz.err"); rc=$?
  local st
  st=$(python3 - "$WORK/healthz" <<'PY' 2>/dev/null
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("?|unparseable /healthz body"); raise SystemExit
bits = [f"{k}={json.dumps(d.get(k))}" for k in ("tree_size", "published_size", "tiles_error", "diverged",
        "frozen", "agent_writes_held", "resource_exhaustion") if d.get(k) not in (None, False)]
print(f"{d.get('status', '?')}|" + ", ".join(bits))
PY
)
  local status=${st%%|*}
  H_DETAIL=${st#*|}
  if [ "$rc" -ne 0 ] || [ "$code" = "000" ]; then
    H_KIND=down; H_DETAIL="GET $API/healthz failed: $(head -c 200 "$WORK/healthz.err")"
  elif [ "$code" = "200" ] && [ "$status" = "OPERATIONAL" ]; then H_KIND=ok
  elif [ "$code" = "200" ]; then H_KIND=degraded; H_DETAIL="status $status: $H_DETAIL"
  elif [ "$code" = "503" ] && [ "$status" = "UNAVAILABLE" ]; then H_KIND=unavailable
  else H_KIND=down; H_DETAIL="GET $API/healthz answered HTTP $code"
  fi
}

run_uptime() {
  probe_health
  if [ "$H_KIND" = down ]; then sleep "$RETRY_DELAY"; probe_health; fi
  case "$H_KIND" in
    ok)          group health "" ;;
    degraded)    group health health_degraded "$H_DETAIL (checked $(date -u +%FT%TZ))" ;;
    unavailable) group health health_unavailable "/healthz 503 UNAVAILABLE: the log diverged from its tiles and refuses new leaves. $H_DETAIL" ;;
    down)        group health api_down "$H_DETAIL at $(date -u +%FT%TZ) (two attempts, $RETRY_DELAY s apart)" ;;
  esac
  case "$H_KIND" in ok|degraded) ;; *) log "health $H_KIND: other checks not judged this run"; return 0 ;; esac

  local rc codes out="$WORK/uptime.out" wkey=""
  [ -r "$WITNESS_VKEY_FILE" ] && wkey=$WITNESS_VKEY_FILE
  AICS_API_BASE_URL="$API" AICS_DISK_CHECK=0 AICS_UPTIME_KEEP_GOING=1 \
    AICS_CHECKPOINT_MAX_AGE="$CHECKPOINT_MAX_AGE" AICS_WITNESS_VKEY_FILE="$wkey" AICS_LOG_VKEY_FILE="$VKEY_FILE" \
    bash "$OPS_DIR/uptime-check.sh" >"$out" 2>&1; rc=$?
  codes=$(sed -n 's/^uptime-check: failed checks: //p' "$out" | tail -n 1)
  [ "$rc" -eq 0 ] || [ -n "$codes" ] || codes=$rc
  codes=",$codes,"
  has() { case "$codes" in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
  local detail
  detail=$(fails "$out")
  if has 1; then log "uptime-check saw /healthz fail just after it answered here: not judged this run"; return 0; fi

  if has 2; then group checkpoint-fetch checkpoint_unreachable "$detail"
  else
    group checkpoint-fetch ""
    if has 3; then group checkpoint checkpoint_stale "$detail"
    elif has 4; then
      mark checkpoint_age_unknown
      if marked checkpoint_age_seen; then group checkpoint checkpoint_age_lost "$detail"
      else group checkpoint ""; fi
    else group checkpoint ""; mark checkpoint_age_seen; rm -f "$STATE/markers/checkpoint_age_unknown"
    fi
  fi
  if has 10; then group limits-fetch limits_unreachable "$detail"
  else
    group limits-fetch ""
    if has 8; then group notices notice_register "$detail"; else group notices ""; fi
    if has 9; then group exhaustion resource_exhaustion "$detail"; else group exhaustion ""; fi
  fi
  local other
  other=$(printf '%s' "$codes" | tr ',' '\n' | grep -vxE '(0|1|2|3|4|8|9|10)?' | tr '\n' ' ')
  if [ -n "$other" ]; then group uptime-other uptime_error "uptime-check exit code(s) $other: $detail"
  else group uptime-other ""; fi
}

# --- mirror and the witness's view -------------------------------------------
tlog() {
  if command -v aics-tlog >/dev/null 2>&1; then aics-tlog "$@"
  else uv run --quiet --project "$OPS_DIR/../packages/aics-tlog" aics-tlog "$@"; fi
}

run_mirror() {
  local base="$STATE/mirror-evidence" out="$WORK/mirror.out" rc ev detail
  mkdir -p "$base"
  AICS_API_BASE_URL="$API" AICS_TILES_BASE="$TILES" AICS_MIRROR_EVIDENCE_DIR="$base" \
    bash "$OPS_DIR/mirror-check.sh" "$VKEY_FILE" >"$out" 2>&1; rc=$?
  ev=$(sed -n 's/^evidence: //p' "$out" | head -n 1)
  detail="$(fails "$out")${ev:+
evidence kept on the vantage host: $ev}"
  local api_down=0
  [ "$(group_state health)" = api_down ] && api_down=1
  case "$rc" in
    0) group mirror-fetch ""; group mirror ""
       # keep only the newest successful run; failed runs are evidence and stay
       if [ -n "$ev" ] && [ -d "$ev" ]; then
         local last; last=$(cat "$base/.last-good" 2>/dev/null)
         case "$last" in "$base"/check-*) [ "$last" != "$ev" ] && rm -rf -- "$last" ;; esac
         printf '%s\n' "$ev" > "$base/.last-good"
       fi ;;
    3) if [ "$api_down" = 1 ]; then log "API down (uptime group): mirror fetch failure not judged"
       else group mirror-fetch mirror_fetch "$detail"; fi ;;
    4) group mirror-fetch ""; group mirror mirror_bad_signature "$detail" ;;
    5) group mirror-fetch ""; group mirror mirror_split "api and tiles serve checkpoints of different origins, or the same size with different roots. $detail" ;;
    6) group mirror-fetch ""; group mirror mirror_unproven "$detail" ;;
    *) group mirror-fetch mirror_setup "mirror-check exit $rc: $detail" ;;
  esac
  find "$base" -maxdepth 1 -name 'check-*' -type d -mtime +90 -exec rm -rf {} + 2>/dev/null
  [ -n "$WITNESS_URL" ] && witness_view
  return 0
}

keep_split() { # the two signed notes are the evidence; named by content, so a persisting split keeps one copy
  local side h; KEPT=""
  for side in witness api; do
    h=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()[:16])' "$WORK/$side.note")
    [ -f "$STATE/split-$side-$h.note" ] || cp "$WORK/$side.note" "$STATE/split-$side-$h.note"
    KEPT="$KEPT $STATE/split-$side-$h.note"
  done
}

api_note() { # fetch the api's checkpoint and verify it under the pinned key: $WORK/api.note, $WORK/api.json
  curl -fsS --max-time 30 -o "$WORK/api.note" "$API/tiles/checkpoint" 2>/dev/null \
    && tlog verify-checkpoint --note "$WORK/api.note" --vkey-file "$VKEY_FILE" \
         ${AICS_LOG_ORIGIN:+--origin "$AICS_LOG_ORIGIN"} >"$WORK/api.json" 2>"$WORK/api.err"
}

witness_view() {
  local info="$STATE/witness.info" code rc
  # The origin names the witness's URL: from the api's checkpoint, verified under the pinned key.
  if ! api_note; then
    log "api checkpoint not fetched or not verified: witness view not judged this run"
    return 0
  fi
  local origin
  origin=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["origin"])' "$WORK/api.json") || return 0
  local hash
  hash=$(printf '%s' "$origin" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')
  local url="$WITNESS_URL/$hash/checkpoint"
  code=$(curl -sS --max-time 15 -o "$WORK/witness.note" -w '%{http_code}' "$url" 2>"$WORK/witness.err"); rc=$?
  if [ "$rc" -ne 0 ] || { [ "$code" != 200 ] && [ "$code" != 404 ]; }; then
    group witness-fetch witness_down "GET $url: ${code:-no answer} $(head -c 200 "$WORK/witness.err")"
    return 0
  fi
  group witness-fetch ""
  # The checkpoint compared with the witness's is fetched after it: the server feeds a checkpoint to the witness
  # only once it serves it, so an honest witness is never ahead of this one. Compared with the note fetched
  # first, a leaf published and fed in between would look like a rollback.
  if [ "$code" = 200 ] && ! api_note; then
    log "api checkpoint not fetched or not verified the second time: witness view not judged this run"
    return 0
  fi
  if [ "$code" = 404 ]; then
    if marked witness_seen; then
      group witness witness_lost_state "the local witness answers 404 for $origin although it cosigned it before (first seen $(cat "$STATE/markers/witness_seen")): its database is lost or replaced; a witness that lost its database must be retired, not restarted (packages/aics-witness README, Operations)"
    else
      group witness ""
      printf 'witness: nothing cosigned yet for %s (the feeder is not wired)\n' "$origin" > "$info"
    fi
    return 0
  fi
  local wargs=()
  if [ -r "$WITNESS_VKEY_FILE" ]; then wargs=(--witness-key "$(head -n 1 "$WITNESS_VKEY_FILE")" --quorum 1); fi
  if ! tlog verify-checkpoint --note "$WORK/witness.note" --vkey-file "$VKEY_FILE" \
       ${AICS_LOG_ORIGIN:+--origin "$AICS_LOG_ORIGIN"} ${wargs[@]+"${wargs[@]}"} >"$WORK/witness.json" 2>"$WORK/witness.verr"; then
    group witness witness_bad_note "the witness serves a checkpoint for $origin that fails verification under the pinned log key${wargs[0]+ or its own witness key}: $(cat "$WORK/witness.verr" "$WORK/witness.json" 2>/dev/null | head -c 400)"
    return 0
  fi
  [ -f "$STATE/markers/witness_seen" ] || mark witness_seen
  local cmp
  cmp=$(python3 - "$WORK/api.json" "$WORK/witness.json" "$WORK/witness.note" "${wargs[1]:-}" <<'PY'
import base64, json, sys, time
a, w = (json.load(open(p)) for p in sys.argv[1:3])
name = sys.argv[4].split("+")[0] if sys.argv[4] else None
ts = 0
text = open(sys.argv[3], encoding="utf-8").read()
for line in text.split("\n\n", 1)[-1].splitlines():
    parts = line.split()
    if len(parts) != 3 or parts[0] != "\N{EM DASH}" or (name and parts[1] != name):
        continue
    try:
        blob = base64.b64decode(parts[2], validate=True)
    except ValueError:
        continue
    if len(blob) == 76:
        ts = max(ts, int.from_bytes(blob[4:12], "big"))
if a["origin"] != w["origin"]:
    rel = "split"
elif w["size"] == a["size"]:
    rel = "same" if w["root"] == a["root"] else "split"
else:
    rel = "behind" if w["size"] < a["size"] else "ahead"
print(rel, a["size"], w["size"], ts, w["root"], a["root"])
PY
) || return 0
  set -- $cmp
  local rel=$1 asize=$2 wsize=$3 wts=$4 wroot=$5 aroot=$6 t
  t=$(now)
  printf 'witness: cosigned size %s (api %s), last cosignature %s\n' "$wsize" "$asize" \
    "$( [ "$wts" -gt 0 ] && iso "$wts" || echo unknown)" > "$info"
  case "$rel" in
    same) group witness "" ;;
    split) keep_split
           group witness witness_split "same size $asize, different roots: witness $wroot, api $aroot. Both notes kept: $KEPT" ;;
    ahead) keep_split
           group witness witness_ahead "the api serves size $asize but the witness already cosigned size $wsize (the api's note was fetched after the witness's): the api rolled back or forked. Both notes kept: $KEPT" ;;
    behind)
      if ! tlog verify-consistency --tiles "$API/tiles/" --vkey-file "$VKEY_FILE" \
           --old-checkpoint "$WORK/witness.note" --checkpoint "$WORK/api.note" >"$WORK/wcons.json" 2>"$WORK/wcons.err"; then
        group witness witness_unproven "no consistency proof from the witness's size $wsize to the api's $asize from $API/tiles: $(cat "$WORK/wcons.err" "$WORK/wcons.json" 2>/dev/null | head -c 400)"
      elif [ "$wts" -gt 0 ] && [ $((t - wts)) -gt "$WITNESS_MAX_LAG" ]; then
        group witness witness_stalled "the log is at $asize, the witness cosigned $wsize last at $(iso "$wts") ($(dur $((t - wts))) ago): is the feeder running?"
      else group witness ""; fi ;;
  esac
}

# --- daily summary -----------------------------------------------------------
run_status() {
  local out="$WORK/status.out" rc open="" f t n=0
  AICS_API_BASE_URL="$API" AICS_TILES_BASE="$TILES" bash "$OPS_DIR/status.sh" >"$out" 2>&1; rc=$?
  t=$(now)
  for f in "$STATE"/groups/*; do
    [ -f "$f" ] || continue
    case "$f" in *.tmp) continue ;; esac
    [ "$(field alerted "$f")" = 1 ] || [ "$(field owed "$f")" = 1 ] || continue
    n=$((n + 1))
    open="$open
- $(field title "$f") (since $(iso "$(field since "$f")"), runs: $(field count "$f"))"
  done
  local age_line="checkpoint age: measured from a cosignature"
  if marked checkpoint_age_unknown; then
    if marked checkpoint_age_seen; then age_line="checkpoint age: unknown again (cosignature gone)"
    else age_line="checkpoint age: unknown, no cosignature yet (alerted only once one has been seen)"; fi
  elif ! marked checkpoint_age_seen; then age_line="checkpoint age: not measured yet"; fi
  local body title prio=2 tags=bar_chart
  body="$(head -c 2500 "$out")
$age_line
$(cat "$STATE/witness.info" 2>/dev/null || echo 'witness: not checked yet')
open alerts: $n$open"
  if [ "$rc" -ne 0 ]; then title="wesupport-ai daily: status.sh FAILED (exit $rc)"; prio=4; tags=warning
  elif [ "$n" -gt 0 ]; then title="wesupport-ai daily: $n open alert(s)"; prio=3
  else title="wesupport-ai daily: all clear"; fi
  notify "$title" "$body" "$prio" "$tags" || true
}

case "$MODE" in
  uptime) run_uptime ;;
  mirror) run_mirror ;;
  status) run_status ;;
esac
exit 0
