#!/usr/bin/env bash
# Local verification of the whole repository: the checks GitHub Actions used to
# run on every push, run here instead. The release workflow calls this script
# too, so the two cannot drift.
#
#   scripts/verify.sh [--full]              every check (the default)
#   scripts/verify.sh --affected [<ref>]    only what changed since <ref>
#                                           (default origin/main, else HEAD~1)
#   scripts/verify.sh --list [...]          print the checks, run nothing
#
# Options: --only <glob[,glob...]> keep only matching check names;
#          --strict  a SKIPPED check fails the run (the release's Verify and
#                    Interop jobs use it);
#          --verbose stream each check's output instead of logging it.
#
# Exit status: 0 every executed check passed (and, with --strict, none was
# skipped); 1 a check failed (or was skipped under --strict); 2 bad usage or a
# repository state the script cannot plan from.
#
# It never publishes, never contacts the production hosts, needs no
# credentials and writes only to ignored caches (.venv, node_modules, dist,
# .test-tmp) and to a log directory under $TMPDIR. Runs on bash 3.2 (macOS).

set -o pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd -P) || exit 2
CONFIG="$ROOT/scripts/verify/inputs.txt"
NL='
'

usage() {
  sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
}

MODE=full
REF=""
LIST=0
STRICT=0
VERBOSE=0
ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --full) MODE=full ;;
    --affected)
      MODE=affected
      if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then REF=$2; shift; fi ;;
    --list) LIST=1 ;;
    --strict) STRICT=1 ;;
    --verbose|-v) VERBOSE=1 ;;
    --only)
      [ $# -gt 1 ] || { echo "verify.sh: --only needs a pattern" >&2; exit 2; }
      ONLY=$2; shift ;;
    --only=*) ONLY=${1#--only=} ;;
    -h|--help) usage; exit 0 ;;
    *) echo "verify.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

have() { command -v "$1" >/dev/null 2>&1; }

# Membership in a space-separated set.
in_set() { case " $2 " in *" $1 "*) return 0 ;; esac; return 1; }

# ---------------------------------------------------------------------------
# Discovery: nodes, their path inputs and their dependencies
# ---------------------------------------------------------------------------
NODES=""        # space-separated node ids
INPUTS=""       # lines "node prefix"
EDGES=""        # lines "node dependency"
EVERYTHING=""   # space-separated prefixes
RELEASE_LIBS="" # space-separated directory names under packages/

add_node() { in_set "$1" "$NODES" || NODES="${NODES:+$NODES }$1"; }
add_input() { INPUTS="$INPUTS$1 $2$NL"; }
add_edge() { EDGES="$EDGES$1 $2$NL"; }

# Path dependencies of one pyproject.toml, as repository-relative directories.
uv_path_sources() {
  local dir=$1 rel target
  awk '
    /^[[:space:]]*\[/ { insec = ($0 ~ /^[[:space:]]*\[tool\.uv\.sources\][[:space:]]*$/); next }
    insec && /path[[:space:]]*=[[:space:]]*"/ {
      s = $0; sub(/.*path[[:space:]]*=[[:space:]]*"/, "", s); sub(/".*/, "", s); print s
    }' "$ROOT/$dir/pyproject.toml" | while IFS= read -r rel; do
    target=$(cd "$ROOT/$dir/$rel" 2>/dev/null && pwd -P) || continue
    case "$target" in "$ROOT"/*) echo "${target#"$ROOT"/}" ;; esac
  done
}

discover() {
  local f dir dep node kind value
  for f in "$ROOT"/packages/*/pyproject.toml "$ROOT"/tools/*/pyproject.toml "$ROOT"/card/pyproject.toml; do
    [ -f "$f" ] || continue
    dir=${f%/pyproject.toml}; dir=${dir#"$ROOT"/}
    add_node "$dir"; add_input "$dir" "$dir/"
  done
  for dir in $NODES; do
    for dep in $(uv_path_sources "$dir"); do add_edge "$dir" "$dep"; done
  done
  if [ -f "$ROOT/clients/aics-js/package.json" ]; then
    add_node clients/aics-js; add_input clients/aics-js clients/aics-js/
  fi
  [ -n "$(release_isolation_files)" ] && add_node release-isolation
  [ -n "$(host_ops_files)" ] && add_node host-ops
  [ -d "$ROOT/ops/vantage/tests" ] && add_node vantage
  [ -f "$ROOT/tools/test_verify_script.py" ] && add_node verify-script
  [ -f "$CONFIG" ] || return 0
  while read -r node kind value _; do
    case "$node" in ''|'#'*) continue ;; esac
    case "$node:$kind" in
      everything:path) EVERYTHING="$EVERYTHING $value" ;;
      release:lib) [ -f "$ROOT/packages/$value/pyproject.toml" ] && RELEASE_LIBS="${RELEASE_LIBS:+$RELEASE_LIBS }$value" ;;
      *:path) in_set "$node" "$NODES" && add_input "$node" "$value" ;;
      *:dep) in_set "$node" "$NODES" && in_set "$value" "$NODES" && add_edge "$node" "$value" ;;
      *) echo "verify.sh: ignoring malformed line in scripts/verify/inputs.txt: $node $kind $value" >&2 ;;
    esac
  done < "$CONFIG"
}

has_launch_mark() {
  grep -Eq '^[[:space:]]*markers[[:space:]]*=.*"launch:' "$ROOT/$1/pyproject.toml" 2>/dev/null
}

# The checks a node contributes, in run order.
node_checks() {
  case "$1" in
    packages/aics-interop) echo interop ;;
    clients/aics-js) echo js ;;
    release-isolation|verify-script|host-ops|vantage) echo "$1" ;;
    *)
      echo "python:${1##*/}"
      has_launch_mark "$1" && echo "python:${1##*/}:launch" ;;
  esac
  return 0
}

check_node() {
  case "$1" in
    interop) echo packages/aics-interop ;;
    js) echo clients/aics-js ;;
    release-isolation|verify-script|host-ops|vantage) echo "$1" ;;
    reproducible:*) echo "packages/${1#reproducible:}" ;;
    python:card|python:card:launch) echo card ;;
    python:*)
      local name=${1#python:}; name=${name%:launch}
      local n; for n in $NODES; do [ "${n##*/}" = "$name" ] && { echo "$n"; return; }; done ;;
  esac
}

describe() {
  local node; node=$(check_node "$1")
  case "$1" in
    interop) echo "packages/aics-interop: AICS_INTEROP_REQUIRE_TOOLS=1 uv run --locked --all-extras pytest -q -rsx; uv run --locked aics-interop-fixtures --check" ;;
    js) echo "clients/aics-js: npm ci; npm run build; npm test (live tests use packages/aics-identity and packages/aics-server, synced with uv sync --locked)" ;;
    release-isolation) echo "uv run --locked --project packages/aics-server pytest -q $(release_isolation_files)" ;;
    verify-script) echo "uv run --locked --project packages/aics-server pytest -q tools/test_verify_script.py" ;;
    host-ops) echo "uv run --locked --project packages/aics-server --with pyyaml pytest -q $(host_ops_files)" ;;
    vantage) echo "uv run --no-project --with pytest pytest -q ops/vantage/tests" ;;
    reproducible:*) echo "$node: two uv build --no-sources from two copies of the tree, wheel and sdist SHA-256 must match" ;;
    python:*:launch) echo "$node: uv run --locked --all-extras pytest -q -m launch" ;;
    python:*) echo "$node: uv run --locked --all-extras pytest -q" ;;
  esac
}

# The offline tests of the second host and the DNS plan (ops/witness, the witness compose and
# Caddyfile, ops/cloudflare-dns.sh), of the tiles mirror snapshot (ops/mirror-sync.sh) and of the
# relaunch procedure (ops/relaunch-genesis.sh).
host_ops_files() {
  local f out=""
  for f in tools/test_witness_host.py tools/test_cloudflare_dns.py tools/test_mirror_sync.py tools/test_relaunch_genesis.py; do
    [ -f "$ROOT/$f" ] && out="${out:+$out }$f"
  done
  echo "$out"
}

release_isolation_files() {
  local f out=""
  for f in tools/test_pypi_release.py tools/test_workflows.py tools/test_deploy_vps.py; do
    [ -f "$ROOT/$f" ] && out="${out:+$out }$f"
  done
  echo "$out"
}

# Tools a check needs, in the order the PREREQ lines name them.
check_tools() {
  case "$1" in
    interop) echo "uv openssl ssh-keygen git" ;;
    js) echo "node npm" ;;
    reproducible:*) echo "uv git" ;;
    *) echo "uv" ;;
  esac
}

all_checks() {
  local node lib
  for node in $NODES; do node_checks "$node"; done
  for lib in $RELEASE_LIBS; do echo "reproducible:$lib"; done
}

# Order the run: Python projects first (their venvs serve the js live tests),
# then interop, js, the release checks and the script's own tests.
order_checks() {
  local rank seq=0
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    seq=$((seq + 1))
    case "$c" in
      python:*) rank=1 ;; interop) rank=2 ;; js) rank=3 ;; release-isolation|host-ops|vantage) rank=4 ;;
      reproducible:*) rank=5 ;; verify-script) rank=6 ;; *) rank=9 ;;
    esac
    echo "$rank $seq $c"
  done | sort -k1,1n -k2,2n | awk '!seen[$3]++ { print $3 }'
}

matches_only() {
  [ -n "$ONLY" ] || return 0
  local IFS=, pat
  for pat in $ONLY; do
    # shellcheck disable=SC2254
    case "$1" in $pat) return 0 ;; esac
  done
  return 1
}

# ---------------------------------------------------------------------------
# --affected: changed paths -> nodes -> checks
# ---------------------------------------------------------------------------
is_documentation() {
  case "$1" in
    docs/*|*.md|LICENSE*|research/*) return 0 ;;
  esac
  return 1
}

prefix_matches() { case "$1" in "$2"*) return 0 ;; esac; return 1; }

affected_checks() {
  local base_ref=$REF base changed path node prefix hit selected="" repro="" everything=0 grew dep lib
  if ! have git; then
    echo "PREREQ git: not found on PATH; --affected cannot compute changed paths" >&2
    exit 2
  fi
  if ! git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    echo "verify.sh: $ROOT is not a git repository; --affected needs one" >&2; exit 2
  fi
  if [ -z "$base_ref" ]; then
    if git -C "$ROOT" rev-parse --verify --quiet 'origin/main^{commit}' >/dev/null; then
      base_ref=origin/main
    elif git -C "$ROOT" rev-parse --verify --quiet 'HEAD~1^{commit}' >/dev/null; then
      base_ref=HEAD~1
    else
      echo "verify.sh: neither origin/main nor HEAD~1 exists; pass a ref to --affected" >&2; exit 2
    fi
  elif ! git -C "$ROOT" rev-parse --verify --quiet "$base_ref^{commit}" >/dev/null; then
    echo "verify.sh: --affected: unknown git ref: $base_ref" >&2; exit 2
  fi
  base=$(git -C "$ROOT" merge-base "$base_ref" HEAD 2>/dev/null) || base=$(git -C "$ROOT" rev-parse "$base_ref^{commit}")
  # Committed, staged and unstaged changes since the merge base, plus new files.
  changed=$( { git -C "$ROOT" diff --name-only --no-renames "$base" -- && \
               git -C "$ROOT" ls-files --others --exclude-standard; } | sort -u) || {
    echo "verify.sh: git diff against $base_ref failed" >&2; exit 2; }
  echo "AFFECTED since $base_ref (merge base $(git -C "$ROOT" rev-parse --short "$base")): $(printf '%s' "$changed" | grep -c . | tr -d ' ') changed path(s)"
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    hit=""
    for prefix in $EVERYTHING; do
      if prefix_matches "$path" "$prefix"; then everything=1; hit="everything"; fi
    done
    while read -r node prefix; do
      [ -n "$node" ] || continue
      if prefix_matches "$path" "$prefix"; then
        in_set "$node" "$selected" || selected="$selected $node"
        in_set "$node" "$hit" || hit="${hit:+$hit }$node"
      fi
    done <<EOF
$INPUTS
EOF
    for lib in $RELEASE_LIBS; do
      prefix_matches "$path" "packages/$lib/" && repro="$repro $lib"
    done
    if [ -n "$hit" ]; then
      echo "CHANGED $path -> $hit"
    elif is_documentation "$path"; then
      echo "CHANGED $path -> documentation, no check reads it"
    else
      echo "CHANGED $path -> NOTE no check reads this path"
    fi
  done <<EOF
$changed
EOF
  if [ "$everything" = 1 ]; then
    AFFECTED_LIST=$(all_checks)
    return 0
  fi
  # Dependents: a node is selected when anything it depends on is selected.
  grew=1
  while [ "$grew" = 1 ]; do
    grew=0
    while read -r node dep; do
      [ -n "$node" ] || continue
      if in_set "$dep" "$selected" && ! in_set "$node" "$selected"; then
        selected="$selected $node"; grew=1
      fi
    done <<EOF
$EDGES
EOF
  done
  AFFECTED_LIST=$(
    for node in $selected; do node_checks "$node"; done
    for lib in $RELEASE_LIBS; do in_set "$lib" "$repro" && echo "reproducible:$lib"; done
    true
  )
  return 0
}

# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------
sha256_line() {
  # "digest  name" for one file, with whichever tool this host has.
  local d
  if have sha256sum; then d=$(sha256sum -- "$1" | cut -d' ' -f1)
  elif have shasum; then d=$(shasum -a 256 -- "$1" | cut -d' ' -f1)
  elif have openssl; then d=$(openssl dgst -sha256 -r "$1" | cut -d' ' -f1)
  else echo "no SHA-256 tool (sha256sum, shasum or openssl)" >&2; return 1
  fi
  printf '%s  %s\n' "$d" "${1##*/}"
}

utf8_locale() {
  if locale -a 2>/dev/null | grep -qix 'c.utf-\{0,1\}8'; then echo C.UTF-8
  elif locale -a 2>/dev/null | grep -qix 'en_US.utf-\{0,1\}8'; then echo en_US.UTF-8
  else echo C
  fi
}

run_reproducible() {
  local lib=$1 work epoch copy dest f files
  work=$(mktemp -d "${TMPDIR:-/tmp}/aics-verify-repro.XXXXXXXX") || return 1
  # The release builds from the tag's commit time, never the run time.
  epoch=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct HEAD)} || { rm -rf -- "$work"; return 1; }
  echo "SOURCE_DATE_EPOCH=$epoch TZ=UTC; copies under $work"
  files=$(cd "$ROOT" && git ls-files -co --exclude-standard -- "packages/$lib") || { rm -rf -- "$work"; return 1; }
  for copy in 1 2; do
    # Different absolute paths expose embedded build-directory names.
    dest="$work/source-$copy"
    while IFS= read -r f; do
      [ -f "$ROOT/$f" ] || continue
      mkdir -p "$dest/$(dirname "$f")" && cp -p "$ROOT/$f" "$dest/$f" || { rm -rf -- "$work"; return 1; }
    done <<EOF
$files
EOF
    ( cd "$dest/packages/$lib" && \
      SOURCE_DATE_EPOCH=$epoch PYTHONHASHSEED=$copy TZ=UTC LC_ALL=$(utf8_locale) \
      uv build --no-sources --out-dir "$work/dist-$copy" ) || { rm -rf -- "$work"; return 1; }
    ( cd "$work/dist-$copy" && ls ./*.whl >/dev/null 2>&1 && ls ./*.tar.gz >/dev/null 2>&1 ) || {
      echo "build $copy produced no wheel or no sdist"; rm -rf -- "$work"; return 1; }
    for f in "$work/dist-$copy"/*.whl "$work/dist-$copy"/*.tar.gz; do
      sha256_line "$f" || { rm -rf -- "$work"; return 1; }
    done | sort -k2 > "$work/SHA256SUMS-$copy"
  done
  if cmp -s "$work/SHA256SUMS-1" "$work/SHA256SUMS-2"; then
    sed 's/^/REPRODUCIBLE /' "$work/SHA256SUMS-1"
    rm -rf -- "$work"
    return 0
  fi
  echo "build 1 and build 2 differ:"
  diff "$work/SHA256SUMS-1" "$work/SHA256SUMS-2"
  rm -rf -- "$work"
  return 1
}

run_check() {
  local c=$1 node; node=$(check_node "$c")
  case "$c" in
    interop)
      ( cd "$ROOT/$node" || exit 1
        openssl version; git --version; command -v ssh-keygen
        AICS_INTEROP_REQUIRE_TOOLS=1 uv run --locked --all-extras pytest -q -rsx || exit 1
        uv run --locked aics-interop-fixtures --check ) ;;
    js)
      ( local d
        if have uv; then
          for d in packages/aics-identity packages/aics-server; do
            [ -f "$ROOT/$d/pyproject.toml" ] || continue
            echo "uv sync --locked in $d (for the live tests)"
            ( cd "$ROOT/$d" && uv sync --locked ) || exit 1
          done
        else
          echo "NOTE uv is missing: the js live tests against aics-identity and aics-server will skip"
        fi
        cd "$ROOT/$node" || exit 1
        npm ci || exit 1
        if node -e 'process.exit(((require("./package.json").scripts)||{}).build ? 0 : 1)'; then
          npm run build || exit 1
        fi
        npm test ) ;;
    release-isolation)
      # shellcheck disable=SC2046
      ( cd "$ROOT" && uv run --locked --project packages/aics-server pytest -q -p no:cacheprovider $(release_isolation_files) ) ;;
    verify-script)
      ( cd "$ROOT" && uv run --locked --project packages/aics-server pytest -q -p no:cacheprovider tools/test_verify_script.py ) ;;
    host-ops)
      # shellcheck disable=SC2046
      ( cd "$ROOT" && uv run --locked --project packages/aics-server --with pyyaml pytest -q -p no:cacheprovider $(host_ops_files) ) ;;
    vantage)
      ( cd "$ROOT" && uv run --no-project --with pytest pytest -q -p no:cacheprovider ops/vantage/tests ) ;;
    reproducible:*)
      run_reproducible "${c#reproducible:}" ;;
    python:*:launch)
      ( cd "$ROOT/$node" && uv run --locked --all-extras pytest -q -m launch ) ;;
    python:*)
      ( cd "$ROOT/$node" && uv run --locked --all-extras pytest -q ) ;;
    *) echo "unknown check $c"; return 1 ;;
  esac
}

python_version_of() {
  # The interpreter the check's own `uv run` used: the same command, so uv
  # resolves the same environment (UV_PYTHON, .python-version or
  # requires-python) and the sync is a no-op after the check.
  (cd "$ROOT/$1" 2>/dev/null && \
    uv run --locked --all-extras python -c 'import platform; print(platform.python_version())' 2>/dev/null) |
    tail -n 1
  return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
discover

if [ "$MODE" = affected ]; then
  affected_checks || exit 2
  CHECKS=$(printf '%s\n' "$AFFECTED_LIST" | order_checks)
else
  CHECKS=$(all_checks | order_checks)
fi
FILTERED=""
for c in $CHECKS; do matches_only "$c" && FILTERED="$FILTERED$c$NL"; done
CHECKS=$FILTERED

if [ -z "$CHECKS" ]; then
  if [ -n "$ONLY" ]; then echo "NOTHING-TO-RUN: no check matches --only $ONLY"
  else echo "NOTHING-TO-RUN: no check covers the changed paths (documentation only or unread paths)"
  fi
  exit 0
fi

# PREREQ: one line per missing tool, naming the checks it costs.
MISSING=""
for tool in uv node npm openssl ssh-keygen git; do
  have "$tool" && continue
  needed=""
  for c in $CHECKS; do in_set "$tool" "$(check_tools "$c")" && needed="${needed:+$needed, }$c"; done
  MISSING="$MISSING $tool"
  echo "PREREQ $tool: not found on PATH; needed by: ${needed:-no check in this run}"
done

skip_reason() {
  local t r=""
  for t in $(check_tools "$1"); do in_set "$t" "$MISSING" && r="${r:+$r, }$t"; done
  [ -n "$r" ] && echo "PREREQ $r missing"
}

if [ "$LIST" = 1 ]; then
  echo "PLAN mode=$MODE${ONLY:+ only=$ONLY}$( [ "$STRICT" = 1 ] && echo ' strict')"
  for c in $CHECKS; do
    r=$(skip_reason "$c")
    if [ -n "$r" ]; then printf 'CHECK %-34s would be SKIPPED (%s)\n' "$c" "$r"
    else printf 'CHECK %-34s %s\n' "$c" "$(describe "$c")"
    fi
  done
  exit 0
fi

LOGDIR=${VERIFY_LOG_DIR:-}
if [ -z "$LOGDIR" ]; then
  LOGDIR=$(mktemp -d "${TMPDIR:-/tmp}/aics-verify.XXXXXXXX") || exit 2
else
  mkdir -p "$LOGDIR" || exit 2
fi
echo "LOGS $LOGDIR"

TABLE=""
NPASS=0; NFAIL=0; NSKIP=0
for c in $CHECKS; do
  r=$(skip_reason "$c")
  if [ -n "$r" ]; then
    echo "SKIPPED $c: $r"
    TABLE="$TABLE$c SKIPPED - $r$NL"; NSKIP=$((NSKIP + 1))
    continue
  fi
  log="$LOGDIR/$(printf '%s' "$c" | tr ':/' '__').log"
  echo "RUN  $c: $(describe "$c")"
  start=$(date +%s)
  if [ "$VERBOSE" = 1 ]; then
    run_check "$c" 2>&1 | tee "$log"; status=$?
  else
    run_check "$c" > "$log" 2>&1; status=$?
  fi
  secs=$(( $(date +%s) - start ))
  note=""
  case "$c" in
    python:*|interop)
      v=$(python_version_of "$(check_node "$c")"); [ -n "$v" ] && note="Python $v" ;;
    reproducible:*)
      [ "$status" = 0 ] && note="$(grep -c '^REPRODUCIBLE ' "$log" | tr -d ' ') files byte-identical" ;;
  esac
  if [ "$status" = 0 ]; then
    echo "PASS $c (${secs}s)"
    TABLE="$TABLE$c PASS ${secs}s ${note}$NL"; NPASS=$((NPASS + 1))
  else
    echo "FAIL $c (${secs}s, exit $status), log $log; last lines:"
    tail -n 25 "$log" | sed 's/^/    /'
    TABLE="$TABLE$c FAIL ${secs}s ${note:+$note, }log $log$NL"; NFAIL=$((NFAIL + 1))
  fi
done

echo
echo "SUMMARY ($MODE)"
printf '%-34s %-8s %6s  %s\n' CHECK RESULT TIME NOTE
printf '%s' "$TABLE" | while read -r c res t note; do
  [ -n "$c" ] && printf '%-34s %-8s %6s  %s\n' "$c" "$res" "$t" "$note"
done
echo
echo "MIRRORED ci.yml test job (uv sync --all-extras --dev; uv run pytest -q per packages/*) -> python:<package>, now --locked"
echo "MIRRORED ci.yml discover step (unittest tools/test_pypi_release.py) -> release-isolation, with tools/test_workflows.py and tools/test_deploy_vps.py"
echo "MIRRORED interop.yml (required openssl/ssh-keygen/git, AICS_INTEROP_REQUIRE_TOOLS=1, pytest -q -rsx, aics-interop-fixtures --check) -> interop"
echo "MIRRORED reproducible.yml (two uv build --no-sources at two paths, PYTHONHASHSEED 1/2, SOURCE_DATE_EPOCH = commit time, hashes compared) -> reproducible:<library>"
echo "NOTE Python: each project ran on the interpreter its uv run used (UV_PYTHON if set, else its .python-version or requires-python), shown above;"
echo "NOTE a Verified: line names each distinct version shown (or set UV_PYTHON for a uniform run)."
echo "NOTE the Linux VM runs the 3.12/3.13/3.14 matrix. No other Python version is claimed by this run."
if [ "$NFAIL" -gt 0 ]; then
  echo "RESULT FAIL: $NPASS passed, $NFAIL failed, $NSKIP skipped"
  exit 1
fi
if [ "$NSKIP" -gt 0 ] && [ "$STRICT" = 1 ]; then
  echo "RESULT FAIL (--strict): $NPASS passed, $NSKIP skipped"
  exit 1
fi
if [ "$NSKIP" -gt 0 ]; then
  echo "RESULT PASS with skips: $NPASS passed, $NSKIP skipped (not verified here; --strict fails on skips)"
else
  echo "RESULT PASS: $NPASS passed"
fi
exit 0
