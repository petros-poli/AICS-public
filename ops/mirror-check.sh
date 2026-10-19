#!/usr/bin/env bash
# Usage: ops/mirror-check.sh /absolute/path/to/local-log.vkey
# Or set AICS_LOG_VKEY_FILE. Pin the key out of band, outside served tiles.
# AICS_LOG_ORIGIN optionally pins the origin from the local trust bundle.
# AICS_API_BASE_URL overrides the origin; AICS_TILES_BASE is the complete
# C2SP prefix, including /tiles.
# AICS_MIRROR_EVIDENCE_DIR defaults to ./mirror-evidence; each run retains
# exact fetched notes and verification JSON, including on failure.
# Exit 0: consistency proved from mirror data; lag is tolerated only when
# the mirror has all tiles needed for both saved heads. Ordinary propagation
# lag with missing newer tiles exits 6 (incomplete), not divergence.
# Other exits: 1 local/unexpected error, 2 usage/setup,
# 3 fetch failure, 4 invalid signature/note, 5 origin/root divergence,
# 6 consistency unproven (missing/bad tiles or proof; not itself fork proof).
# This checks log signatures and historical consistency, not witness quorum
# or independently authenticated freshness. Negative lag means mirror ahead.
set -euo pipefail
umask 077
fail() { printf 'mirror-check: %s\n' "$2" >&2; exit "$1"; }
[[ $# -le 1 ]] || fail 2 'expected one local vkey filename'
KEY=${1:-${AICS_LOG_VKEY_FILE:-}}
[[ -n "$KEY" && "$KEY" != *://* && -f "$KEY" && -r "$KEY" ]] || fail 2 'a readable local vkey file is required'
for tool in curl python3; do
    command -v "$tool" >/dev/null || fail 2 "missing dependency: $tool"
done
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if command -v aics-tlog >/dev/null; then
    CLI=(aics-tlog)
else
    command -v uv >/dev/null || fail 2 'install aics-tlog or uv'
    CLI=(uv run --project "$ROOT/packages/aics-tlog" aics-tlog)
fi
API=${AICS_API_BASE_URL:-https://api.wesupport-ai.com}
MIRROR=${AICS_TILES_BASE:-https://tiles.wesupport-ai.com/tiles}
[[ "$API" == https://* && "$MIRROR" == https://* ]] || fail 2 'HTTPS endpoints required'
BASE=${AICS_MIRROR_EVIDENCE_DIR:-./mirror-evidence}
mkdir -p -- "$BASE"
EVIDENCE=$(mktemp -d "$BASE/check-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
printf 'evidence: %s\n' "$EVIDENCE"
fetch() {
    local code
    code=$(curl --silent --show-error --proto '=https' --max-time 30 \
        --max-filesize 33554432 --output "$2" --write-out '%{http_code}' "$1") || return 1
    [[ "$code" == 200 ]]  # no redirects, including redirects to another host
}
origin_ok=0
fetch "${API%/}/tiles/checkpoint" "$EVIDENCE/origin.note" && origin_ok=1
if [[ $origin_ok == 0 ]]; then
    mv "$EVIDENCE/origin.note" "$EVIDENCE/origin-primary.response" 2>/dev/null || true
    fetch "${API%/}/checkpoint" "$EVIDENCE/origin.note" && origin_ok=1
fi
mirror_ok=0
fetch "${MIRROR%/}/checkpoint" "$EVIDENCE/mirror.note" && mirror_ok=1
[[ $origin_ok == 1 && $mirror_ok == 1 ]] || fail 3 "fetch failed; available responses in $EVIDENCE"
ARGS=(--vkey-file "$KEY")
[[ -z "${AICS_LOG_ORIGIN:-}" ]] || ARGS+=(--origin "$AICS_LOG_ORIGIN")
valid=1
for side in origin mirror; do
    "${CLI[@]}" verify-checkpoint --note "$EVIDENCE/$side.note" "${ARGS[@]}" \
        >"$EVIDENCE/$side.json" || valid=0
done
[[ $valid == 1 ]] || fail 4 "signature/note verification failed; see $EVIDENCE"
# Read only authenticated CLI reports, never a server-supplied key.
python3 - "$EVIDENCE" <<'PYTHON' || fail 5 "origin/root mismatch; both notes retained in $EVIDENCE"
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
a, b = [json.loads((p / (s + '.json')).read_text()) for s in ('origin', 'mirror')]
print(f"lag={a['size'] - b['size']} leaves (origin={a['size']}, mirror={b['size']})")
if a['origin'] != b['origin'] or (a['size'] == b['size'] and a['root'] != b['root']):
    sys.exit(1)
old, new = ('mirror', 'origin') if a['size'] >= b['size'] else ('origin', 'mirror')
(p / 'order').write_text(old + '\n' + new + '\n')
PYTHON
{ read -r OLD; read -r NEW; } <"$EVIDENCE/order"
# Explicit saved heads prevent a concurrent fetch from silently changing the
# comparison. Only mirror tiles may supply the proof, even when it lags.
"${CLI[@]}" verify-consistency --tiles "${MIRROR%/}/" "${ARGS[@]}" \
    --old-checkpoint "$EVIDENCE/$OLD.note" --checkpoint "$EVIDENCE/$NEW.note" \
    >"$EVIDENCE/consistency.json" \
    || fail 6 "consistency-unproven; inspect $EVIDENCE/consistency.json (missing data is not proof of a fork)"
printf 'mirror-check: consistent; remote freshness unproven (log signatures only)\n'
