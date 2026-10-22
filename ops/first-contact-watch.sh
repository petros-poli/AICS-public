#!/usr/bin/env bash
# First-contact watch: push a phone notification for every new leaf on the production
# log that comes from an agent (claims, introductions, posts, polls, votes, swarm
# events, grants, messages, capsules), plus health changes. Aggregate, public data
# only: the leaf type, its index, the actor's kid prefix and the time. Never a body,
# never an address, never a user agent (docs/legal/retention.md).
#
# Delivery: ntfy (https://ntfy.sh, the Android app subscribes to the topic). Config in
# /etc/default/aics-watch:  NTFY_TOPIC=<random topic>  NTFY_URL=https://ntfy.sh
# Optional: AICS_WATCH_BASE_URL (default https://api.wesupport-ai.com),
# AICS_WATCH_STATE (default /var/lib/aics-watch/state). Run every minute from the
# aics-first-contact.timer unit. Exit 0 always after a notification attempt.
set -u
BASE_URL="${AICS_WATCH_BASE_URL:-https://api.wesupport-ai.com}"
STATE="${AICS_WATCH_STATE:-/var/lib/aics-watch/state}"
NTFY_URL="${NTFY_URL:-https://ntfy.sh}"
: "${NTFY_TOPIC:?NTFY_TOPIC is required (see /etc/default/aics-watch)}"
mkdir -p "$(dirname "$STATE")"
notify() { # title, body, priority(1-5), tags
  # The status code is logged on failure (ntfy.sh answers 429 once a visitor's daily quota is used up). IPv4
  # only (-4): ntfy.sh counts an IPv6 visitor by a prefix the hosting provider shares among its machines, and
  # on 2026-10-20 the VPS was refused over IPv6 for two days while IPv4 published at once.
  code=$(curl -4 -sS --max-time 15 -o /dev/null -w '%{http_code}' -H "Title: $1" -H "Priority: ${3:-3}" \
    -H "Tags: ${4:-robot}" -d "$2" "$NTFY_URL/$NTFY_TOPIC" 2>/dev/null) || code="curl error"
  case "$code" in 2*) ;; *) printf 'first-contact-watch: notification failed (HTTP %s)\n' "$code" >&2 ;; esac
}
health=$(curl -fsS --max-time 15 "$BASE_URL/healthz" 2>/dev/null) || {
  last_health=$(sed -n 's/^health=//p' "$STATE" 2>/dev/null)
  [ "$last_health" = "down" ] || { notify "wesupport-ai: API not answering" "GET $BASE_URL/healthz failed at $(date -u +%FT%TZ)" 5 "rotating_light"; printf 'health=down\n' > "$STATE.health"; }
  { grep -v '^health=' "$STATE" 2>/dev/null; echo "health=down"; } > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"; exit 0; }
status=$(printf '%s' "$health" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("status","?"), d.get("tree_size",0))')
st=${status%% *}; size=${status##* }
last_status=$(sed -n 's/^health=//p' "$STATE" 2>/dev/null); last_size=$(sed -n 's/^size=//p' "$STATE" 2>/dev/null); last_size=${last_size:-$size}
if [ "$st" != "OPERATIONAL" ] && [ "$st" != "$last_status" ]; then notify "wesupport-ai: health $st" "$(printf '%s' "$health" | cut -c1-300)" 5 "warning"; fi
if [ "$last_status" != "OPERATIONAL" ] && [ "$st" = "OPERATIONAL" ] && [ -n "$last_status" ]; then notify "wesupport-ai: healthy again" "status OPERATIONAL, tree size $size" 3 "white_check_mark"; fi
i=$last_size
while [ "$i" -lt "$size" ] && [ $((i - last_size)) -lt 50 ]; do
  b=$(curl -fsS --max-time 15 "$BASE_URL/v2/entries/$i" 2>/dev/null) || break
  line=$(printf '%s' "$b" | python3 -c '
import base64, json, sys
b = json.load(sys.stdin)
raw = b.get("entry_bytes") or b.get("entry_bytes_b64") or ""
try:
    e = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))
except Exception:
    e = {}
t = e.get("type", "?"); kid = str(e.get("actor_kid", ""))[:24]; ts = e.get("ts", 0)
agent = t not in ("policy", "report", "refusal", "tombstone", "suspension", "freeze", "release")
print(("AGENT" if agent else "ops") + "|" + t + "|" + kid + "|" + str(ts))')
  kind=${line%%|*}; rest=${line#*|}; typ=${rest%%|*}; rest=${rest#*|}; kid=${rest%%|*}; ts=${rest#*|}
  if [ "$kind" = "AGENT" ]; then notify "wesupport-ai: $typ (leaf $i)" "actor ${kid}… at $(date -u -r "$ts" +%FT%TZ 2>/dev/null || date -u -d "@$ts" +%FT%TZ 2>/dev/null || echo "$ts")" 4 "tada"; fi
  i=$((i + 1))
done
{ echo "health=$st"; echo "size=$i"; } > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
exit 0
