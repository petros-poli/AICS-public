#!/usr/bin/env bash
set -euo pipefail

# Build a deterministic staging directory for the Zenodo deposit of the
# AICS-1 specification and its companion documents, or verify that all
# prerequisites are met (--check mode, the default).

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGING="$REPO_ROOT/ops/discovery/.zenodo-staging"
MODE="check"

if [[ "${1:-}" == "--build" ]]; then
  MODE="build"
elif [[ "${1:-}" != "--check" && -n "${1:-}" ]]; then
  echo "Usage: $0 [--check | --build]" >&2
  echo "  --check   Validate prerequisites without creating files (default)" >&2
  echo "  --build   Create the staging directory with files and digests" >&2
  exit 1
fi

ERRORS=0
err() { echo "FAIL: $1" >&2; ERRORS=$((ERRORS + 1)); }
ok()  { echo "  ok: $1"; }

echo "=== Zenodo bundle ${MODE} ==="
echo

# --- Validate source files exist ---
SPEC="$REPO_ROOT/docs/spec/AICS-1.md"
SWARMS="$REPO_ROOT/docs/spec/SWARMS.md"
PROTO="$REPO_ROOT/docs/PROTOCOL-TEXT.md"
ZENODO_JSON="$REPO_ROOT/ops/discovery/zenodo.json"

for f in "$SPEC" "$SWARMS" "$PROTO" "$ZENODO_JSON"; do
  if [[ -f "$f" ]]; then
    ok "exists: ${f#"$REPO_ROOT"/}"
  else
    err "missing: ${f#"$REPO_ROOT"/}"
  fi
done

# --- Validate zenodo.json is well-formed JSON ---
if [[ -f "$ZENODO_JSON" ]]; then
  if python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$ZENODO_JSON" 2>/dev/null; then
    ok "zenodo.json is valid JSON"
  else
    err "zenodo.json is not valid JSON"
  fi

  # Check required metadata fields
  if python3 -c "
import json, sys
m = json.load(open(sys.argv[1]))['metadata']
assert m.get('title'), 'title missing'
assert m.get('upload_type'), 'upload_type missing'
assert m.get('creators'), 'creators missing'
assert m.get('version'), 'version missing'
" "$ZENODO_JSON" 2>/dev/null; then
    ok "zenodo.json has required metadata fields"
  else
    err "zenodo.json is missing required metadata fields (title, upload_type, creators, version)"
  fi
fi

# --- Validate spec version string ---
if [[ -f "$SPEC" ]]; then
  if grep -q '0\.2-draft' "$SPEC"; then
    ok "AICS-1.md contains version 0.2-draft"
  else
    err "AICS-1.md does not contain version 0.2-draft"
  fi
fi

# --- Validate licence is set in the spec ---
if [[ -f "$SPEC" ]]; then
  if grep -q 'CC-BY-4.0' "$SPEC"; then
    ok "AICS-1.md licence is CC-BY-4.0"
  else
    err "AICS-1.md licence is not set to CC-BY-4.0"
  fi
fi

# --- Compute and display SHA-256 digests ---
echo
echo "--- SHA-256 digests ---"
for f in "$SPEC" "$SWARMS" "$PROTO"; do
  if [[ -f "$f" ]]; then
    digest=$(shasum -a 256 "$f" | cut -d' ' -f1)
    echo "  ${digest}  ${f#"$REPO_ROOT"/}"
  fi
done

# Do not replace a previously valid bundle when validation has failed.
if [[ "$ERRORS" -gt 0 ]]; then
  echo "RESULT: $ERRORS error(s) found; staging directory left unchanged." >&2
  exit 1
fi

# --- Build mode: create staging directory ---
if [[ "$MODE" == "build" ]]; then
  echo
  echo "--- Building staging directory ---"

  rm -rf "$STAGING"
  mkdir -p "$STAGING"

  cp "$SPEC"   "$STAGING/AICS-1-v0.2-draft.md"
  cp "$SWARMS"  "$STAGING/SWARMS-v0.2-draft.md"
  cp "$PROTO"   "$STAGING/PROTOCOL-TEXT.md"
  cp "$ZENODO_JSON" "$STAGING/zenodo.json"

  # Write deterministic manifest with digests
  (
    cd "$STAGING"
    for f in AICS-1-v0.2-draft.md SWARMS-v0.2-draft.md PROTOCOL-TEXT.md zenodo.json; do
      shasum -a 256 "$f"
    done
  ) > "$STAGING/SHA256SUMS"

  ok "staging directory: $STAGING"
  echo
  cat "$STAGING/SHA256SUMS"
  echo

  echo "--- Zenodo deposit commands ---"
  echo "  (requires ZENODO_TOKEN in environment; see ops/discovery/zenodo-upload.md)"
  echo
  cat <<'CMDS'
  # 1. Create draft deposit
  curl --fail-with-body -sS -X POST \
    -H "Authorization: Bearer $ZENODO_TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary @ops/discovery/.zenodo-staging/zenodo.json \
    https://zenodo.org/api/deposit/depositions

  # 2. Upload files (set BUCKET from step 1 response: jq -r '.links.bucket')
  for f in AICS-1-v0.2-draft.md SWARMS-v0.2-draft.md PROTOCOL-TEXT.md zenodo.json SHA256SUMS; do
    curl --fail-with-body -sS -X PUT \
      -H "Authorization: Bearer $ZENODO_TOKEN" \
      --data-binary @ops/discovery/.zenodo-staging/$f \
      "$BUCKET/$f"
  done

  # 3. Review at https://zenodo.org/deposits/<id>, then publish
  curl --fail-with-body -sS -X POST \
    -H "Authorization: Bearer $ZENODO_TOKEN" \
    https://zenodo.org/api/deposit/depositions/<id>/actions/publish
CMDS
fi

# --- Summary ---
echo
if [[ "$ERRORS" -gt 0 ]]; then
  echo "RESULT: $ERRORS error(s) found." >&2
  exit 1
else
  echo "RESULT: all checks passed."
  exit 0
fi
