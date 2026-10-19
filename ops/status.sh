#!/usr/bin/env bash
# Read-only status report from the public endpoints of one deployment.
#
# Prints, from the public endpoints of the given base URL:
#   - the transparency-log checkpoint: tree size, root hash and age;
#   - the number of agents seen in the last hour, if an endpoint exposes it
#     (none does today; DESIGN §9 plans a live "agents online now" endpoint.
#     The probe looks for plausible fields in /stats?format=json and
#     /agents-online?format=json and says n/a when nothing exposes it);
#   - the mirror consistency between the api.* checkpoint and the tiles.*
#     checkpoint copy (decision 17: /checkpoint served on api.wesupport-ai.com,
#     a copy on tiles.*): the same tree size must mean the same root —
#     a shared size with different roots is a fork and fails the probe.
#
# Usage: ops/status.sh [BASE_URL]
#   BASE_URL          API origin, default https://api.wesupport-ai.com
#                     (AICS_API_BASE_URL overrides; an argument wins).
#   AICS_TILES_BASE   tile mirror origin, default https://tiles.wesupport-ai.com
#   AICS_PAGES_BASE   pages origin for the agents-count probe,
#                     default https://wesupport-ai.com
#
# Read-only: GET requests only, nothing stored anywhere. api.* is DNS-only
# (decision 10); tiles.* and the pages origin are Cloudflare-proxied, which is
# fine for a status read.
#
# Exit codes: 0 ok (a mirror size lag is reported but is not itself an error);
# 1 a required endpoint failed or the checkpoint could not be parsed;
# 2 mirror divergence — api and tiles agree on size but not on root.
set -euo pipefail

BASE_URL="${1:-${AICS_API_BASE_URL:-https://api.wesupport-ai.com}}"
TILES_BASE="${AICS_TILES_BASE:-https://tiles.wesupport-ai.com}"
PAGES_BASE="${AICS_PAGES_BASE:-https://wesupport-ai.com}"

fetch() { curl -fsS --max-time 15 "$1" 2>/dev/null || true; }

api_json="$(fetch "$BASE_URL/v2/tlog/checkpoint")"   # JSON envelope (served today)
api_note="$(fetch "$BASE_URL/checkpoint")"           # note text (spec AICS-1 canonical)
tiles_note="$(fetch "$TILES_BASE/checkpoint")"       # mirror copy of the note

if [ -z "$api_json$api_note" ]; then
  printf 'FAIL: no checkpoint at %s (tried /v2/tlog/checkpoint and /checkpoint)\n' "$BASE_URL" >&2
  exit 1
fi
if [ -z "$tiles_note" ]; then
  printf 'FAIL: no checkpoint at %s/checkpoint — mirror consistency cannot be checked\n' "$TILES_BASE" >&2
  exit 1
fi

api_json="$api_json" api_note="$api_note" tiles_note="$tiles_note" python3 - <<'PY'
import base64, json, os, sys, time


def parse_note(text):
    """(origin, size, root_hex) from C2SP tlog-checkpoint note text, or None.

    Note text is exactly `origin LF decimal_size LF B64(root) LF` (AICS-1 §,
    checkpoint format), so line 2 is the size and line 3 the B64 root.
    """
    lines = text.splitlines()
    if len(lines) < 3:
        return None
    try:
        size = int(lines[1])
        root_hex = base64.b64decode(lines[2], validate=True).hex()
    except ValueError:
        return None
    return lines[0], size, root_hex


def note_age(text):
    """Seconds since the newest cosignature timestamp in the note, or None.

    A cosignature/v1 line is `EM-DASH SP name SP B64(key_id(4) + POSIX
    seconds(8) + signature(64))`, so a 76-byte blob carries a timestamp; the
    plain log signature is 68 bytes and carries none.
    """
    ts = None
    for line in text.splitlines():
        if not line.startswith("\N{EM DASH} "):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            blob = base64.b64decode(parts[-1])
        except ValueError:
            continue
        if len(blob) == 76:
            ts = max(ts or 0, int.from_bytes(blob[4:12], "big"))
    return None if ts is None else int(time.time() - ts)


# --- api side: prefer the JSON envelope, fall back to the note itself -------
doc = None
try:
    maybe = json.loads(os.environ["api_json"])
    if isinstance(maybe.get("tree_size"), int):
        doc = maybe
except ValueError:
    doc = None

note = os.environ["api_note"]
if doc is not None:
    note = doc.get("signed_checkpoint") or note
    origin = doc.get("origin", "?")
    size = doc["tree_size"]
    root = doc.get("root_hash_hex") or "?"
else:
    parsed = parse_note(os.environ["api_note"])
    if parsed is None:
        print("FAIL: checkpoint at the API base is neither the JSON envelope "
              "nor a parseable checkpoint note", file=sys.stderr)
        sys.exit(1)
    origin, size, root = parsed

age = note_age(note) if note else None
age_s = f"{age}s" if age is not None else "unknown (no timestamp field, no cosignature in the note yet)"
print(f"checkpoint (api):   origin={origin} size={size} age={age_s}")
print(f"  root: {root}")

# --- tiles mirror: same size must mean the same root ------------------------
t = parse_note(os.environ["tiles_note"])
if t is None:
    print("FAIL: tiles checkpoint does not parse as a tlog-checkpoint note",
          file=sys.stderr)
    sys.exit(1)
t_origin, t_size, t_root = t
print(f"checkpoint (tiles):  origin={t_origin} size={t_size}")
print(f"  root: {t_root}")

if t_size == size:
    if t_root != root:
        print(f"FAIL: mirror divergence — size {size} on both sides but roots differ:\n"
              f"  api:   {root}\n"
              f"  tiles: {t_root}", file=sys.stderr)
        sys.exit(2)
    print("mirror consistency: ok — same size, same root")
elif t_size < size:
    print(f"mirror consistency: tiles mirror is behind (tiles size {t_size} < api size {size}); "
          "not comparable — roots must match again once it catches up")
else:
    print(f"mirror consistency: tiles mirror is AHEAD of api (tiles size {t_size} > api size {size}); "
          "agents with saved checkpoints would flag this as a rollback — investigate")
PY

# --- agents seen in the last hour, if an endpoint exposes it -----------------
stats_json="$(fetch "$BASE_URL/stats?format=json")"
[ -n "$stats_json" ] || stats_json="$(fetch "$PAGES_BASE/stats?format=json")"
online_json="$(fetch "$PAGES_BASE/agents-online?format=json")"

if [ -n "$stats_json$online_json" ]; then
  STATS="$stats_json" ONLINE="$online_json" python3 - <<'PY'
import json, os

docs = []
for env in ("ONLINE", "STATS"):
    try:
        d = json.loads(os.environ[env])
    except ValueError:
        continue
    if isinstance(d, dict):
        docs.append(d)

candidates = (  # (field names, honest label) in priority order
    (("agents_last_hour", "agents_seen_last_hour", "active_agents_last_hour"),
     "agents seen in the last hour"),
    (("agents_online", "agents_online_now", "agents_active", "agents_seen_now"),
     "agents online now (nearest available figure)"),
)
for names, label in candidates:
    for d in docs:
        for n in names:
            v = d.get(n)
            if isinstance(v, int) and v >= 0:
                print(f"agents seen in the last hour: {v} ('{n}' from the stats endpoint, {label})")
                raise SystemExit(0)
for d in docs:
    if isinstance(d.get("registered_agents"), int):
        print(f"agents seen in the last hour: n/a (stats endpoint gives only "
              f"registered_agents={d['registered_agents']}, a lifetime total)")
        raise SystemExit(0)
print("agents seen in the last hour: n/a (stats endpoint exposes no agent-count field)")
PY
else
  printf 'agents seen in the last hour: n/a (no endpoint exposes it yet; a live count is planned, DESIGN §9)\n'
fi
