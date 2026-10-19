#!/usr/bin/env bash
# Archive the repository in Software Heritage and print the exact registry
# publishing commands (PyPI via uv build / twine upload, npm via
# npm publish --access public).
#
# Software Heritage ingests the git origin
#   https://github.com/petros-poli/AICS-public/
# through its "save code now" API, which also feeds The Stack and any
# dataset built on Software Heritage snapshots. That is the archival half of
# discovery (Master Plan "open arms"): the code becomes citable, permanent and
# crawlable independently of this VPS.
#
# Modes:
#   --check    (default) dry run: verify every artifact exists and carries the
#              canonical discovery strings, and show the commands --execute
#              would run. Touches nothing.
#   --execute  run the checks, then POST the Software Heritage save request,
#              then print the exact publishing commands (they are NOT run).
#
# Canonical discovery strings (docs/BANNER.md, wellknown/llms.txt): every
# audited artifact must name the service (wesupport-ai.com), and each
# host-specific string must appear somewhere across the audited set, so
# crawlers and dataset builders see one consistent service identity:
#   wesupport-ai.com          the site and the service
#   api.wesupport-ai.com      the API (TLS, DNS-only)
#   gate.wesupport-ai.com     the raw-text gate (port 7700)
#   _aics.wesupport-ai.com    the agent-facing API host
#
# Env: SWH_SAVE_URL (default below), SWH_AUTH_TOKEN (optional Bearer token;
#      anonymous save requests are accepted but rate limited), CURL_OPTS.
#
# Exit codes: 0 success; 1 usage error; 2 a check failed (nothing executed);
# 3 the Software Heritage request failed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

SWH_SAVE_URL="${SWH_SAVE_URL:-https://archive.softwareheritage.org/api/1/origin/save/git/url/https://github.com/petros-poli/AICS-public/}"
GITHUB_ORIGIN="https://github.com/petros-poli/AICS-public/"

# Python packages, in dependency order. aics-cli retains the console command "aics"
# (docs/RELEASING.md); aics-server is built and tested but never uploaded.
PY_PACKAGES="aics-identity aics-tlog aics-witness aics-conformance aics-cli aics-mcp aics-server"
PYPI_NAME_aics_cli="aics-cli"
PYPI_NAME_aics_identity="aics-identity"
PYPI_NAME_aics_tlog="aics-tlog"
PYPI_NAME_aics_witness="aics-witness"
PYPI_NAME_aics_conformance="aics-conformance"
PYPI_NAME_aics_mcp="aics-mcp"
PYPI_NAME_aics_server="(not distributed; see docs/RELEASING.md)"

JS_DIR="clients/aics-js"
SKILL_FILE="skills/wesupport-ai/SKILL.md"

CANONICAL_STRINGS="wesupport-ai.com api.wesupport-ai.com gate.wesupport-ai.com _aics.wesupport-ai.com"

usage() {
  printf 'usage: %s [--check | --execute]\n' "${0##*/}"
  printf '  --check    (default) verify artifacts + canonical strings; dry run\n'
  printf '  --execute  also POST the Software Heritage save request and print\n'
  printf '             the exact uv build / twine upload / npm publish commands\n'
}

MODE="check"
case "${1:-}" in
  "") MODE="check" ;;
  --check) MODE="check" ;;
  --execute) MODE="execute" ;;
  -h|--help) usage; exit 0 ;;
  *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 1 ;;
esac
if [ "$#" -gt 1 ]; then
  printf 'extra arguments after the mode are not accepted\n' >&2; usage >&2; exit 1
fi

# Scan one path (file or tree) for a fixed string; prints the match count.
# (The grep may legitimately find nothing: guard it from set -e/pipefail.)
scan_count() { # <path> <string>
  local path="$1" string="$2" count
  if [ -f "$path" ]; then
    count="$( { grep -IoF -- "$string" "$path" 2>/dev/null || :; } | wc -l )"
  else
    count="$(
      { grep -rIoF \
        --exclude-dir=.git --exclude-dir=.venv --exclude-dir=node_modules \
        --exclude-dir=dist --exclude-dir=build --exclude-dir=__pycache__ \
        --exclude-dir=.pytest_cache --exclude-dir=.mypy_cache --exclude-dir=.ruff_cache \
        --include='*.py' --include='*.toml' --include='*.md' --include='*.json' \
        --include='*.ts' --include='*.js' --include='*.mjs' --include='*.cjs' \
        --include='*.html' --include='*.txt' --include='*.sh' --include='*.yml' \
        --include='*.yaml' --include='*.css' \
        -- "$string" "$path" 2>/dev/null || :; } | wc -l
    )"
  fi
  printf '%s' "$count" | tr -d '[:space:]'
}

FAILURES=0
fail() {
  printf 'FAIL: %s\n' "$1" >&2
  FAILURES=$((FAILURES + 1))
}

print_publish_commands() {
  printf '\nPublishing commands (printed, not run; the release pipeline normally\n'
  printf 'publishes via GitHub trusted publishing — docs/RELEASING.md):\n'
  local pkg pypi_var pypi_name
  for pkg in $PY_PACKAGES; do
    pypi_var="PYPI_NAME_${pkg//-/_}"
    eval "pypi_name=\"\${$pypi_var:-$pkg}\""
    printf '\n  # %s -> PyPI project "%s"\n' "packages/$pkg" "$pypi_name"
    printf '  cd %s/packages/%s && uv build --no-sources\n' "$ROOT" "$pkg"
    case "$pypi_name" in
      "("*) printf '  # %s: built and tested, never uploaded (docs/RELEASING.md)\n' "$pkg" ;;
      *) printf '  twine upload %s/packages/%s/dist/*\n' "$ROOT" "$pkg" ;;
    esac
  done
  printf '\n  # Node client (npm):\n'
  printf '  cd %s/%s\n' "$ROOT" "$JS_DIR"
  printf '  npm publish --access public\n'
  printf '\n  Code packages are licensed Apache-2.0; docs and datasets are CC-BY-4.0.\n'
}

run_checks() {
  printf '== Artifact existence ==\n'
  local artifacts_ok=1 pkg
  for pkg in $PY_PACKAGES; do
    if [ -f "$ROOT/packages/$pkg/pyproject.toml" ] && [ -d "$ROOT/packages/$pkg" ]; then
      printf 'ok:   packages/%s (pyproject.toml present)\n' "$pkg"
    else
      fail "packages/$pkg is missing or has no pyproject.toml"
      artifacts_ok=0
    fi
  done
  if [ -f "$ROOT/$JS_DIR/package.json" ]; then
    printf 'ok:   %s (package.json present)\n' "$JS_DIR"
  else
    fail "$JS_DIR is missing or has no package.json"
    artifacts_ok=0
  fi
  if [ -f "$ROOT/$SKILL_FILE" ]; then
    printf 'ok:   %s\n' "$SKILL_FILE"
  else
    fail "$SKILL_FILE is missing"
    artifacts_ok=0
  fi
  [ "$artifacts_ok" -eq 1 ] || return 1
  return 0
}

scan_strings() {
  printf '\n== Canonical discovery strings (occurrence counts per artifact) ==\n'
  local header='%-28s' s pkg count grand_total root_count
  printf "$header" 'artifact'
  for s in $CANONICAL_STRINGS; do printf ' %-22s' "$s"; done
  printf '\n'
  for pkg in $PY_PACKAGES; do
    printf "$header" "packages/$pkg"
    for s in $CANONICAL_STRINGS; do
      count="$(scan_count "$ROOT/packages/$pkg" "$s")"
      printf ' %-22s' "$count"
      track_total "$s" "$count"
    done
    printf '\n'
  done
  printf "$header" "$JS_DIR"
  for s in $CANONICAL_STRINGS; do
    count="$(scan_count "$ROOT/$JS_DIR" "$s")"
    printf ' %-22s' "$count"
    track_total "$s" "$count"
  done
  printf '\n'
  printf "$header" "$SKILL_FILE"
  for s in $CANONICAL_STRINGS; do
    count="$(scan_count "$ROOT/$SKILL_FILE" "$s")"
    printf ' %-22s' "$count"
    track_total "$s" "$count"
  done
  printf '\n'

  # Rule 1: every artifact must name the service itself.
  for pkg in $PY_PACKAGES; do
    root_count="$(scan_count "$ROOT/packages/$pkg" 'wesupport-ai.com')"
    [ "$root_count" -gt 0 ] || fail "packages/$pkg never mentions wesupport-ai.com"
  done
  root_count="$(scan_count "$ROOT/$JS_DIR" 'wesupport-ai.com')"
  [ "$root_count" -gt 0 ] || fail "$JS_DIR never mentions wesupport-ai.com"
  root_count="$(scan_count "$ROOT/$SKILL_FILE" 'wesupport-ai.com')"
  [ "$root_count" -gt 0 ] || fail "$SKILL_FILE never mentions wesupport-ai.com"

  # Rule 2: each canonical string must appear somewhere in the audited set.
  for s in $CANONICAL_STRINGS; do
    grand_total="$(total_of "$s")"
    if [ "$grand_total" -eq 0 ]; then
      fail "canonical string '$s' not found in any audited artifact"
    else
      printf 'ok:   %-24s %s occurrence(s) across the audited artifacts\n' "$s" "$grand_total"
    fi
  done
}

# Totals are kept in shell variables named TOTAL_<sanitised string>.
track_total() { # <string> <count>
  local var
  var="TOTAL_$(printf '%s' "$1" | tr -c 'A-Za-z0-9' '_')"
  eval "$var=\$((\${$var:-0} + \$2))"
}
total_of() { # <string>
  local var
  var="TOTAL_$(printf '%s' "$1" | tr -c 'A-Za-z0-9' '_')"
  eval "printf '%s' \"\${$var:-0}\""
}

swh_save() {
  printf '\n== Software Heritage save request ==\n'
  printf 'POST %s\n' "$SWH_SAVE_URL"
  local tmp code
  tmp="$(mktemp)"
  if [ -n "${SWH_AUTH_TOKEN:-}" ]; then
    code="$(curl -sS -o "$tmp" -w '%{http_code}' --max-time 90 -X POST \
      -H 'Accept: application/json' \
      -H "Authorization: Bearer $SWH_AUTH_TOKEN" \
      ${CURL_OPTS:-} "$SWH_SAVE_URL")" || { rm -f "$tmp"; return 3; }
  else
    code="$(curl -sS -o "$tmp" -w '%{http_code}' --max-time 90 -X POST \
      -H 'Accept: application/json' \
      ${CURL_OPTS:-} "$SWH_SAVE_URL")" || { rm -f "$tmp"; return 3; }
  fi
  printf 'HTTP %s\n' "$code"
  case "$code" in
    200|201)
      # A reverse proxy can return HTTP 200 with a bot challenge. Require the
      # API's actual record, bound to the requested Git origin, before success.
      if ! python3 - "$tmp" "$GITHUB_ORIGIN" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as stream:
        record = json.load(stream)
    assert isinstance(record, dict), "response is not a save-request object"
    assert record.get("origin_url", "").rstrip("/") == sys.argv[2].rstrip("/"), "origin mismatch"
    assert record.get("visit_type") == "git", "visit type mismatch"
    assert record.get("save_request_status") in {"accepted", "pending"}, "request not accepted or pending"
    assert record.get("save_task_status") != "failed", "archival task already failed"
except (ValueError, OSError, AssertionError, AttributeError) as exc:
    print(f"FAIL: no valid Software Heritage save record: {exc}", file=sys.stderr)
    raise SystemExit(1)
print("ok: save request " + record["save_request_status"])
print("task status: " + str(record.get("save_task_status", "unknown")))
if record.get("request_url"):
    print("request: " + record["request_url"])
print("Archival is confirmed only when the task succeeds; request acceptance alone is not an archive.")
PY
      then
        rm -f "$tmp"
        return 3
      fi
      rm -f "$tmp"
      printf 'save status: GET %s\n' "$SWH_SAVE_URL"
      return 0
      ;;
    401|403)
      rm -f "$tmp"
      printf 'FAIL: Software Heritage refused the request (HTTP %s).\n' "$code" >&2
      printf '      Anonymous save requests are rate limited; set SWH_AUTH_TOKEN.\n' >&2
      return 3
      ;;
    429)
      rm -f "$tmp"
      printf 'FAIL: Software Heritage rate limit (HTTP 429). Retry later or set SWH_AUTH_TOKEN.\n' >&2
      return 3
      ;;
    *)
      rm -f "$tmp"
      printf 'FAIL: unexpected Software Heritage answer (HTTP %s).\n' "$code" >&2
      return 3
      ;;
  esac
}

main() {
  printf 'AICS archival: Software Heritage + registry publishing (%s mode)\n' "$MODE"
  printf 'repository root: %s\n' "$ROOT"

  run_checks || true
  scan_strings

  if [ "$FAILURES" -gt 0 ]; then
    printf '\n%d check(s) failed; nothing was executed or archived.\n' "$FAILURES" >&2
    exit 2
  fi
  printf '\nAll artifact and canonical-string checks passed.\n'

  if [ "$MODE" = "check" ]; then
    printf '\nDry run (--check): nothing was sent to Software Heritage.\n'
    printf 'With --execute this script would POST:\n'
    printf '  curl -X POST %s\n' "$SWH_SAVE_URL"
    print_publish_commands
    printf '\nRESULT: CHECK PASS\n'
    exit 0
  fi

  swh_save || exit 3
  print_publish_commands
  printf '\nRESULT: EXECUTE PASS (publishing commands above are yours to run)\n'
  exit 0
}

main
