#!/usr/bin/env bash
# shellcheck disable=SC2029
# (SC2029: the ssh command strings are built on this side on purpose; every value in them is public
# and quoted with printf %q.)
#
# ops/relaunch-genesis.sh: the second genesis of wesupport-ai.com, the relaunch of 2026-10-20
# (docs/DECISIONS.md, row "Relaunch: a second genesis"; ops/RUNBOOK-first-deploy.md step 11).
#
# The log started on 2026-10-19 (log key api.wesupport-ai.com/tiles+0e2f3a1e+...) is discarded
# before any agent has used it, and a new log starts on the same origin name: a new server seed
# (so new log and policy keys), the same owner key, a new identity of the founder-run witness
# (witness.wesupport-ai.com/w2: w1 cosigned the discarded log and is retired with it), a first card
# that names that witness at quorum 1, and the new trust bundle wherever the old one was published.
# Staging (test.wesupport-ai.com) is not touched.
#
#   ops/relaunch-genesis.sh [options] STAGE...     run these stages, in the order given
#   ops/relaunch-genesis.sh --dry-run all          print the whole procedure; change nothing
#   ops/relaunch-genesis.sh plan                   list the stages and the steps after them
#   ops/relaunch-genesis.sh --show-remote NAME     print a script that runs on a host
#
# Stages, in order. Run them one at a time and read each output before the next one.
#   archive   launch dir: the files of the log to discard, and of the witness identity to retire,
#             move into v1-2026-10-19/
#   prep      a clean worktree of origin/main (--worktree) without merge-conflict markers, the public
#             docs exported, the inputs checked, a census of the live log about to be discarded
#   freeze    VPS: the watch timers stopped, a backup, aics-server stopped (no more writes, no
#             more checkpoints fed to the witness), AICS_WITNESSES and AICS_CARD_FILE dropped
#             from deploy/.env; witness host: the probe timers stopped, the witness state backed
#             up, the witness stopped. Then the census of the frozen volume: its size, the keys
#             that wrote to it and every refused attempt, each of which must be ours
#   wipe      VPS: the discarded log's containers and volumes removed (aics_data and aics_tiles
#             only: never a staging volume, never caddy's); needs --discard-size, the census's size
#   seed      a new server seed, written to --custody-dir and the VPS's deploy/.env, nowhere else
#   genesis   the new log's first start (leaf 0, the charter); pubkeys.txt into the launch dir
#   witness   witness host: the retired identity's config, key and database set aside, the new
#             identity created and pinned to the new log at its verified size; its vkey (public)
#             into the launch dir. The feeder is still off: the card stage turns it on
#   card      the card filled with the new keys and the new witness, AICS_CARD_FILE and
#             AICS_WITNESSES set, deployed; the witness must cosign at quorum 1 before the preview
#   card-log  the owner logs the previewed card (the bootstrap card, normally leaf 1) while the
#             witness cosigns; needs --owner-key
#   bundle    the trust bundle and the launch-dir files (bundle.txt, readme-block.txt, ...)
#   dns       DNS TXT _aics (the new bundle) and _aics-witness.witness (the new witness vkey),
#             through ops/cloudflare-dns.sh on the VPS
#   vantage   witness host: the probes pinned to the new log and witness keys, their state set
#             aside, their timers back; VPS: the first-contact watch reset and its timer back
#   docs      README, DECISIONS, ops/witness/README.md, aics-cli published_keys.py and CHANGELOG
#             rewritten from the new facts in --docs-repo; prints the diff and the commands, commits
#             nothing
#   verify    a fresh CLI home pinned from DNS and the README block; card, checkpoint,
#             consistency, uptime and whole-chain checks; the witness's page and TXT record; the
#             served client; staging unchanged
#
# Options:
#   --dry-run             print every command and remote script; run nothing, contact no host,
#                         write nothing
#   --print-only          for the witness host (freeze, witness, vantage): print the commands to
#                         run there instead of running them over ssh
#   --launch-dir DIR      the public launch artifacts (default ~/aics-launch)
#   --worktree DIR        the clean worktree of origin/main the deploys run from (default
#                         ${TMPDIR:-/tmp}/aics-relaunch-w; prep creates it)
#   --repo DIR            the main checkout (default: the one this script is in); it receives a
#                         copy of deploy/card/card-unsigned.json
#   --docs-repo DIR       the checkout the docs stage rewrites (default: --worktree)
#   --custody-dir DIR     seed, genesis: the owner's custody directory (outside git, mode 0700);
#                         the new seed goes to DIR/<seed name> and to the VPS, nowhere else
#   --seed-name NAME      the new seed's file in the custody directory (default server-seed-v2.hex)
#   --discard-size N      wipe: the size of the log being discarded, as its frozen census names it
#   --owner-key FILE      card-log: the owner key; only aics_client.py opens it
#   --custodian-name TEXT, --custodian-holds TEXT
#                         card: the values of the custodian placeholders
#   --card-set NAME=VALUE card: the value of another placeholder (repeatable)
#   --witness-name NAME   the new witness identity (default witness.wesupport-ai.com/w2; never a
#                         retired one)
#   --witness-vkey VKEY   its vkey as a --print-only witness stage printed it (else the witness
#                         stage records it in the launch dir)
#   --hf-revision REV     docs: the Hugging Face revision of the new log's export, once pushed
#   --witness-sync        witness: rsync aics-tlog, aics-witness and ops/witness there first
#   --skip-cli-tests      docs: do not run the aics-cli published_keys tests afterwards
#   --discard-log-vkey VKEY, --retire-witness-vkey VKEY
#                         only to redo a relaunch whose new log came out wrong: the log to discard
#                         (default the 2026-10-19 log) and the witness identity to retire (default
#                         w1). A redo also needs a new --seed-name and a new --witness-name
#                         (docs/internal/relaunch-2026-10-20.md, "Redo")
#   --vps HOST (wesupport-vps)   --vps-ip IPV4 (148.113.238.39)
#   --witness-host HOST (aics-trials)   --remote-dir DIR (/opt/wesupport-ai)
#
# Every stage that changes something checks first whether it already happened; then it does
# nothing, or stops and says why, so that no stage acts twice. Nothing here prints a seed, a
# token or a private key: the new seed travels only on ssh stdin, the Cloudflare token never
# leaves the VPS, the witness keys never leave their volume, and the owner key is a path handed
# to aics_client.py.
set -euo pipefail
umask 077

# -- public facts ---------------------------------------------------------------------------------
ORIGIN=api.wesupport-ai.com/tiles
API=https://api.wesupport-ai.com
SITE=https://wesupport-ai.com
DOMAIN=wesupport-ai.com
STAGING_CHECKPOINT=https://test.wesupport-ai.com/tiles/checkpoint
OWNER_KID=did:key:z6MkiN89VfP5ZqFRC9epYQNjDyXQvYxrGn11r4Wrf6dvVb6K
WITNESS_DOMAIN=witness.wesupport-ai.com
WITNESS_URL=https://witness.wesupport-ai.com
WITNESS_NAME_DEFAULT=witness.wesupport-ai.com/w2
# The discarded log (genesis 2026-10-19 16:06 UTC); the guards compare against these.
V1_LOG_VKEY='api.wesupport-ai.com/tiles+0e2f3a1e+ASx//oWlf4UBmbnXHfpMCsF2NrQOZuN32Q25NiTBC7fV'
V1_POLICY_KID=did:key:z6MkhhjWtmdwmSmAZGq1kkc8EiC1u3GmQ4eS8EEvTKfbKcze
V1_BUNDLE_SHA256=bc234cc34b1b0941d0e833c41112109fe7fe020cebbba9f58f98f3a59448da0c
# Its witness. A cosignature (cosignature/v1) signs the origin, size and root, not the log key, and
# checkpoints of the discarded log with this key's cosignature are public (docs/evidence keeps one of
# size 3). The same key cosigning the new log at those sizes would prove that it signed two histories
# of one origin. So it is retired with that log (its files set aside on the witness host, never used
# again) and the new log gets a new identity (ops/witness/README.md, Retiring).
V1_WITNESS_VKEY='witness.wesupport-ai.com/w1+45a4adcd+BHew2Ur+QH2S82rpq+DkFdR0fevS0fs+/SKQexugKGNN'
V1_LABEL=discarded-2026-10-19   # the name of everything set aside from the discarded log
V1_DIR=v1-2026-10-19            # its files in the launch directory
CARD_FILE_IN_CONTAINER=/etc/aics/card/card-unsigned.json
SEED_NAME_DEFAULT=server-seed-v2.hex
VKEY_RE='^[^+[:space:]]+\+[0-9a-f]{8}\+[A-Za-z0-9+/]+=*$'
STAGES="archive prep freeze wipe seed genesis witness card card-log bundle dns vantage docs verify"
REMOTE_NAMES="vps_state vps_pubkeys vps_freeze vps_census vps_wipe vps_card_env vps_dns vps_resume witness_freeze witness_repin witness_vantage"

# -- messages and running -------------------------------------------------------------------------
say() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
die() { printf 'relaunch-genesis: STOP: %s\n' "$*" >&2; exit 1; }
usage_error() { printf 'relaunch-genesis: %s (see --help)\n' "$*" >&2; exit 2; }
usage() {
  awk '/^# ops\/relaunch-genesis\.sh:/ {on = 1} /^set -euo pipefail/ {exit} on {sub(/^# ?/, ""); print}' "$0"
}
is_vkey() { printf '%s' "$1" | grep -Eq "$VKEY_RE"; }
# q ARG...: shell-quoted, for display and for the ssh command line; in a dry run an argument
# holding a <PLACEHOLDER> stays readable (it is a template there, not a command to paste as is)
q() {
  local a out=""
  for a in "$@"; do
    if [ "$DRY" = 1 ]; then
      case $a in
        *'<'*'>'*' '*|*' '*'<'*'>'*) out="$out '$a'"; continue ;;
        *'<'*'>'*) out="$out $a"; continue ;;
      esac
    fi
    out="$out $(printf '%q' "$a")"
  done
  printf '%s' "${out# }"
}
dry() { [ "$DRY" = 1 ]; }
# run CMD...: show the command, then run it (a dry run only shows it)
run() { printf '   $ %s\n' "$(q "$@")"; dry || "$@"; }
# run_in DIR CMD...: the same, in DIR
run_in() {
  local dir=$1
  shift
  printf '   $ (cd %s && %s)\n' "$(q "$dir")" "$(q "$@")"
  dry || (cd "$dir" && "$@")
}
# run_in_to DIR FILE CMD...: the same, in DIR, with stdout into FILE
run_in_to() {
  local dir=$1 file=$2
  shift 2
  printf '   $ (cd %s && %s) > %s\n' "$(q "$dir")" "$(q "$@")" "$(q "$file")"
  dry || (cd "$dir" && "$@") > "$file"
}
need_cmd() {
  dry && return 0
  local c
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "$c is required on this machine"; done
}
witness_printed() { [ "$DRY" = 1 ] || [ "$PRINT_ONLY" = 1 ]; }
# run_witness CMD...: a command from here that contacts the witness host (shown, not run, with
# --print-only)
run_witness() {
  printf '   $ %s\n' "$(q "$@")"
  witness_printed || "$@"
}
fetch() { curl -fsS --max-time 30 --proto '=https' "$@"; }
py() { python3 -I - "$@"; }

# remote HOST NAME ARG...: run the script NAME (below) on HOST with bash -s and these public
# arguments. A dry run prints it; --print-only prints the witness host's scripts, ready to paste.
remote() {
  local host=$1 name=$2 arg
  shift 2
  for arg in "$@"; do
    case $arg in *"'"*|*$'\n'*) die "a remote argument holds a quote or a newline: $arg" ;; esac
  done
  if dry || { [ "$PRINT_ONLY" = 1 ] && [ "$host" = "$WITNESS_HOST" ]; }; then
    printf "\n--- %s: run on %s ---\nssh %s 'bash -s -- %s' <<'RELAUNCH_REMOTE'\n" "$name" "$host" "$host" "$(q "$@")"
    if dry && [ "$PREAMBLE_SHOWN" = 1 ]; then
      printf '# ... the preamble printed with the first script above (all of it: --show-remote %s)\n' "$name"
      "remote_$name"
    else
      remote_script "$name"
      if dry; then PREAMBLE_SHOWN=1; fi
    fi
    printf 'RELAUNCH_REMOTE\n--- end of %s ---\n' "$name"
    return 0
  fi
  printf '   [%s] %s %s\n' "$host" "$name" "$(q "$@")" >&2
  remote_script "$name" | ssh -o BatchMode=yes "$host" "bash -s -- $(q "$@")" \
    || die "$name on $host stopped (its output is above)"
}
remote_script() {
  case " $REMOTE_NAMES " in *" $1 "*) ;; *) usage_error "no remote script '$1' (one of: $REMOTE_NAMES)" ;; esac
  printf '%s\n' '# shellcheck disable=SC2034,SC2329 # R and the helpers below are shared; not every script uses each'
  remote_preamble
  "remote_$1"
}

# -- the remote scripts ---------------------------------------------------------------------------
# envedit FILE KEY --unset|--stdin|--value VALUE: set or drop one KEY=VALUE line of a .env file,
# atomically, mode 0600. It never prints a value. --stdin is how the seed travels.
ENV_EDIT_PY=$(cat <<'PY'
import os, re, sys, tempfile
args = sys.argv[1:]
if len(args) < 3 or args[2] not in ("--unset", "--stdin", "--value") or (args[2] == "--value") != (len(args) == 4):
    sys.exit("envedit: usage: FILE KEY --unset | --stdin | --value VALUE")
path, key, how = args[0], args[1], args[2]
if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
    sys.exit("envedit: bad variable name")
value = sys.stdin.read().strip() if how == "--stdin" else args[3] if how == "--value" else None
if value is not None:
    if not value or any(c in value for c in "\r\n\0"):
        sys.exit(f"envedit: refusing an empty or multi-line value for {key}")
    if key == "AICS_SERVER_SEED_HEX" and not re.fullmatch(r"[0-9a-f]{64}", value):
        sys.exit("envedit: AICS_SERVER_SEED_HEX must be 64 lowercase hex characters")
with open(path, encoding="utf-8") as f:
    lines = f.read().splitlines(keepends=True)
match = re.compile(r"[ \t]*(export[ \t]+)?" + re.escape(key) + r"[ \t]*=").match
hits = [line for line in lines if match(line)]
want = None if value is None else f"{key}={value}\n"
if (want is None and not hits) or (want is not None and len(hits) == 1 and hits[0].rstrip("\r\n") == want[:-1]):
    print(f"{key}: unchanged")
    sys.exit(0)
kept = [line for line in lines if not match(line)]
if kept and not kept[-1].endswith("\n"):
    kept[-1] += "\n"
if want is not None:
    kept.append(want)
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".env.relaunch.")
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.writelines(kept)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
except BaseException:
    os.unlink(tmp)
    raise
print(f"{key}: " + ("removed" if want is None else "replaced" if hits else "added"))
PY
)
ENV_EDIT_B64=$(printf '%s\n' "$ENV_EDIT_PY" | base64 | tr -d '\n')

remote_preamble() {
  printf "ENV_EDIT_PY=\$(cat <<'ENVEDIT'\n%s\nENVEDIT\n)\n" "$ENV_EDIT_PY"
  cat <<'PREAMBLE'
set -euo pipefail
# AICS_RELAUNCH_ROOT is a test hook: a prefix for the absolute host paths below. Unset on a host.
R=${AICS_RELAUNCH_ROOT:-}
envedit() { python3 -c "$ENV_EDIT_PY" "$@"; }
need_sudo() { sudo -n true 2>/dev/null || { echo "passwordless sudo is needed on $(hostname) for systemctl" >&2; exit 1; }; }
# prod_volumes (VPS, in deploy/): "DATA TILES", the names of the production log's two volumes
prod_volumes() {
  docker compose config --format json </dev/null 2>/dev/null | python3 -c '
import json, sys
try:
    vols = json.load(sys.stdin).get("volumes") or {}
except ValueError:
    sys.exit("docker compose config failed; run docker compose config --quiet on the VPS")
names = [(vols.get(k) or {}).get("name") for k in ("aics_data", "aics_tiles")]
if not all(names):
    sys.exit("no aics_data/aics_tiles volume in the compose configuration")
print(*names)
'
}
# read_volume ARG... (VPS, in deploy/): sed in a one-off container on the stopped log's volumes. Only
# when the data volume exists: docker compose run would create a missing one.
read_volume() {
  docker compose run --rm --no-deps -T --name "aics-relaunch-read-$$" --entrypoint sed aics-server "$@" </dev/null
}
PREAMBLE
}

# vps_state DIR: the public facts the guards read on the VPS, one "key value" per line.
remote_vps_state() { cat <<'REMOTE'
cd "$1/deploy"
names=$(prod_volumes)
read -r data tiles <<<"$names"
echo "data-volume $data"
echo "tiles-volume $tiles"
if docker volume inspect "$data" >/dev/null 2>&1; then echo "data-volume-exists 1"; else echo "data-volume-exists 0"; fi
if [ -n "$(docker compose ps -q --status running aics-server </dev/null 2>/dev/null || true)" ]; then
  echo "server-running 1"
else
  echo "server-running 0"
fi
echo "seed-lines $(grep -cE '^AICS_SERVER_SEED_HEX=[0-9a-f]{64}$' .env || true)"
# A domain-separated digest of the seed, to compare with the custody copy; never the seed.
echo "seed-check $(sed -n 's/^AICS_SERVER_SEED_HEX=//p' .env | tail -n 1 | tr -d '\r\n' | python3 -c 'import hashlib,sys; print(hashlib.sha256(b"aics-relaunch-seed-check:" + sys.stdin.buffer.read()).hexdigest())')"
for k in AICS_OWNER_PUBKEY AICS_CARD_FILE AICS_WITNESSES; do
  echo "env-$k $(grep -cE "^$k=.+" .env || true)"
done
REMOTE
}

# vps_pubkeys DIR: the running log's public keys (/data/pubkeys.txt).
remote_vps_pubkeys() { cat <<'REMOTE'
cd "$1/deploy"
docker compose exec -T aics-server cat /data/pubkeys.txt </dev/null
REMOTE
}

# vps_freeze DIR LOG LABEL: stop the log to discard (no writes, no witness feed), print its final
# size, and drop the settings the genesis start must not have.
remote_vps_freeze() { cat <<'REMOTE'
cd "$1/deploy"
want_log=$2 label=$3
need_sudo
names=$(prod_volumes)
read -r data tiles <<<"$names"
running=$(docker compose ps -q --status running aics-server </dev/null 2>/dev/null || true)
if [ -n "$running" ]; then
  log=$(docker compose exec -T aics-server sed -n 's/^log //p' /data/pubkeys.txt </dev/null)
elif docker volume inspect "$data" >/dev/null 2>&1; then
  log=$(read_volume -n 's/^log //p' /data/pubkeys.txt)
else
  log=""
fi
if [ -n "$log" ] && [ "$log" != "$want_log" ]; then
  echo "freeze: the production log is '$log', not the log to discard; refusing" >&2
  exit 1
fi
for t in aics-first-contact.timer aics-mirror-sync.timer aics-dsa-submitter.timer aics-backup.timer; do
  if systemctl is-active --quiet "$t"; then sudo -n systemctl stop "$t"; echo "stopped $t"; fi
done
if [ -n "$running" ]; then
  if systemctl cat aics-backup.service >/dev/null 2>&1; then
    # An evidence copy of the discarded log, kept as long as the backups are (30 days).
    if sudo -n systemctl start aics-backup.service; then
      echo "backup of the discarded log: $(systemctl show -p Result --value aics-backup.service)"
    else
      echo "WARNING: the backup run failed (journalctl -u aics-backup.service); the nightly copy remains" >&2
    fi
  fi
  docker compose stop aics-server </dev/null
  echo "stopped aics-server: no more writes, no more checkpoints fed to the witness"
else
  echo "aics-server is not running: already frozen"
fi
if [ -n "$log" ]; then
  # Read after the stop, from the volume: no later write can change it.
  echo "discarded-log-size $(read_volume -n 2p /data/tiles/checkpoint)"
else
  echo "discarded-log-size none: $data does not exist (wiped already)"
fi
if [ ! -e ".env.$label.bak" ]; then
  (umask 077; grep -v '^AICS_SERVER_SEED_HEX=' .env > ".env.$label.bak" || true)
  echo "kept deploy/.env.$label.bak (mode 0600, without the seed line)"
fi
# The first start of a log takes neither a card body nor witnesses (runbook step 4).
envedit .env AICS_WITNESSES --unset
envedit .env AICS_CARD_FILE --unset
REMOTE
}

# vps_census DIR LOG: the frozen log's checkpoint and every entry bundle, from its volume, as JSON
# lines {name, b64} (public data: what the tiles served).
remote_vps_census() { cat <<'REMOTE'
cd "$1/deploy"
want_log=$2
names=$(prod_volumes)
read -r data tiles <<<"$names"
if [ -n "$(docker compose ps -q --status running aics-server </dev/null 2>/dev/null || true)" ]; then
  echo "census: aics-server is running; the census reads the frozen volume (run the freeze stage first)" >&2
  exit 1
fi
docker volume inspect "$data" >/dev/null 2>&1 || { echo "census: $data does not exist (wiped already)" >&2; exit 1; }
docker compose run --rm --no-deps -T --name "aics-relaunch-census-$$" --entrypoint python3 aics-server - "$want_log" <<'PY'
import base64, json, os, re, sys
from pathlib import Path
want = sys.argv[1]
keys = Path(os.environ.get("AICS_PUBKEYS_OUT", "/data/pubkeys.txt")).read_text(encoding="utf-8")
m = re.search(r"^log (\S+)$", keys, re.M)
if not m or m.group(1) != want:
    sys.exit(f"census: the volume holds the log {m.group(1) if m else None!r}, not {want}")
tiles = Path(os.environ.get("AICS_TILES_DIR", "/data/tiles"))
note = (tiles / "checkpoint").read_bytes()
size = int(note.split(b"\n")[1])
if size > 5000:
    sys.exit(f"census: {size} leaves; the census reads every entry and stops at 5000")
def emit(name, data):
    print(json.dumps({"name": name, "b64": base64.b64encode(data).decode("ascii")}), flush=True)
emit("checkpoint", note)
for k in range((size + 255) // 256):
    width = min(256, size - 256 * k)
    emit(f"entries-{k:03d}", (tiles / (f"tile/entries/{k:03d}" + ("" if width == 256 else f".p/{width}"))).read_bytes())
PY
REMOTE
}

# vps_wipe DIR LOG SIZE: remove the discarded log's two volumes, and nothing else.
remote_vps_wipe() { cat <<'REMOTE'
cd "$1/deploy"
want_log=$2 want_size=$3
if [ -n "$(docker compose ps -q --status running aics-server </dev/null 2>/dev/null || true)" ]; then
  echo "wipe: aics-server is running; run the freeze stage first" >&2
  exit 1
fi
names=$(prod_volumes)
read -r data tiles <<<"$names"
case " $data $tiles " in
  *staging*|*caddy*|*witness*|*gate*) echo "wipe: refusing the volume names '$data $tiles'" >&2; exit 1 ;;
esac
if ! docker volume inspect "$data" >/dev/null 2>&1; then
  echo "wipe: $data does not exist: the discarded log is already wiped; nothing to do"
  exit 0
fi
log=$(read_volume -n 's/^log //p' /data/pubkeys.txt)
if [ "$log" != "$want_log" ]; then
  echo "wipe: $data holds the log '$log', not the log to discard; refusing" >&2
  exit 1
fi
size=$(read_volume -n 2p /data/tiles/checkpoint)
if [ "$size" != "$want_size" ]; then
  echo "wipe: the discarded log has ${size:-no} leaves, not the $want_size given with --discard-size; refusing" >&2
  exit 1
fi
staging_before=$(docker volume ls -q --filter label=wesupport-ai.disposable=true | sort | tr '\n' ' ')
staging_running=$(docker compose ps -q --status running aics-staging </dev/null 2>/dev/null || true)
docker compose rm -s -f aics-server caddy </dev/null
docker volume rm "$data" "$tiles"
echo "removed $data and $tiles: the discarded log's database ($size leaves) and tiles"
staging_after=$(docker volume ls -q --filter label=wesupport-ai.disposable=true | sort | tr '\n' ' ')
if [ "$staging_before" != "$staging_after" ]; then
  echo "wipe: the staging volumes changed ('$staging_before' -> '$staging_after')" >&2
  exit 1
fi
if [ -n "$staging_running" ] && [ -z "$(docker compose ps -q --status running aics-staging </dev/null 2>/dev/null || true)" ]; then
  echo "WARNING: aics-staging is not running any more" >&2
fi
echo "kept: every staging volume (${staging_after:-none}), caddy's certificate volumes and the gate certificate copy"
echo "until the genesis stage deploys, caddy is down: wesupport-ai.com and test.wesupport-ai.com do not answer over HTTPS"
REMOTE
}

# vps_card_env DIR CARD_FILE WITNESSES: the card body and the witness, for the card's start.
remote_vps_card_env() { cat <<'REMOTE'
cd "$1/deploy"
envedit .env AICS_CARD_FILE --value "$2"
envedit .env AICS_WITNESSES --value "$3"
docker compose config --quiet </dev/null
echo "compose configuration ok"
REMOTE
}

# vps_dns DIR VPS_IP TXT WITNESS_VKEY: publish the TXT values (public) through ops/cloudflare-dns.sh
# with the token deploy/.env holds. The token is read from that one line; deploy/.env is never
# sourced, and cloudflare-dns.sh gets PATH, HOME and the token in its environment, nothing else.
remote_vps_dns() { cat <<'REMOTE'
cd "$1/deploy"
ip=$2 txt=$3 wvkey=$4
tmp=$(mktemp -d "$PWD/.relaunch-dns.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
printf '%s\n' "$txt" > "$tmp/bundle.txt"
printf '%s\n' "$wvkey" > "$tmp/witness.vkey"
token=$(python3 - <<'PY'
import re
value = ""
with open(".env", encoding="utf-8") as f:
    for line in f:
        m = re.fullmatch(r"[ \t]*(?:export[ \t]+)?CLOUDFLARE_API_TOKEN[ \t]*=[ \t]*(.*?)[ \t]*", line.rstrip("\r\n"))
        if m:
            value = m.group(1)
if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
    value = value[1:-1]
print(value, end="")
PY
)
[ -n "$token" ] || { echo "dns: CLOUDFLARE_API_TOKEN is not set in deploy/.env" >&2; exit 1; }
(
  # shellcheck disable=SC2046
  export -n $(compgen -e)
  export PATH=/usr/local/bin:/usr/bin:/bin HOME CLOUDFLARE_API_TOKEN="$token"
  exec bash "$1/ops/cloudflare-dns.sh" --apply --bundle "$tmp/bundle.txt" --witness-txt "$tmp/witness.vkey" "$ip" </dev/null
)
REMOTE
}

# vps_resume LABEL: the watches follow the new log; their state of the discarded one is kept aside.
remote_vps_resume() { cat <<'REMOTE'
label=$1
need_sudo
sudo -n env R="$R" LABEL="$label" sh -s <<'SH'
set -eu
for s in "$R/var/lib/aics-watch/state" "$R/var/lib/aics-dsa/state.json"; do
  if [ -f "$s" ] && [ ! -e "$s.$LABEL" ]; then mv "$s" "$s.$LABEL"; echo "set aside $s.$LABEL"; fi
done
SH
for t in aics-first-contact.timer aics-dsa-submitter.timer aics-backup.timer; do
  if systemctl is-enabled --quiet "$t" 2>/dev/null; then sudo -n systemctl start "$t"; echo "started $t"; fi
done
if systemctl is-enabled --quiet aics-mirror-sync.timer 2>/dev/null; then
  echo "NOT started: aics-mirror-sync.timer. The R2 and B2 tile buckets hold the discarded log's tiles, and"
  echo "mirror-sync never overwrites a tile (rclone --immutable). Empty both buckets' tile/ prefix and their"
  echo "checkpoint first (docs/internal/relaunch-2026-10-20.md), then: sudo systemctl start aics-mirror-sync.timer"
fi
REMOTE
}

# witness_freeze LABEL: the probes stop, the witness state is backed up, the witness stops.
remote_witness_freeze() { cat <<'REMOTE'
label=$1
need_sudo
for t in aics-vantage-uptime.timer aics-vantage-mirror.timer aics-vantage-status.timer aics-first-contact.timer; do
  if systemctl is-active --quiet "$t"; then sudo -n systemctl stop "$t"; echo "stopped $t"; fi
done
here="$HOME/aics/ops/witness"
[ -f "$here/compose.yml" ] || { echo "witness: no $here/compose.yml on this host" >&2; exit 1; }
cd "$here"
if docker info >/dev/null 2>&1; then D=(docker); else D=(sudo -n docker); fi
if [ -n "$("${D[@]}" compose ps -q --status running aics-witness </dev/null 2>/dev/null || true)" ]; then
  # Evidence of what this witness cosigned for the discarded log (never a restore path).
  if ! sudo -n bash "$here/backup-witness.sh" </dev/null; then
    echo "WARNING: backup-witness.sh failed; the witness's files are set aside in the volume anyway (witness stage)" >&2
  fi
  "${D[@]}" compose stop aics-witness </dev/null
  echo "stopped aics-witness ($label): it cosigns nothing until the witness stage pins the new log"
else
  echo "aics-witness is not running: already frozen"
fi
REMOTE
}

# witness_repin ORIGIN NEW_LOG SIZE ROOT WITNESS_NAME RETIRE_VKEY: retire the identity that cosigned
# the discarded log (its config, key and database move to /data/retired-<name>/ in the volume: never
# deleted, never used again), create the identity WITNESS_NAME (a new key and database), and pin the
# new log at a checkpoint of SIZE leaves with ROOT, verified from the laptop under the new log key.
# Its last line is "witness-vkey <vkey>" (public).
remote_witness_repin() { cat <<'REMOTE'
origin=$1 new_log=$2 size=$3 root=$4 wname=$5 old_vkey=$6
old_name=${old_vkey%%+*}
retired="retired-${old_name##*/}"
here="$HOME/aics/ops/witness"
[ -f "$here/compose.yml" ] && [ -f "$here/bootstrap-witness-host.sh" ] \
  || { echo "witness: $here lacks compose.yml or bootstrap-witness-host.sh (rsync ops/witness first)" >&2; exit 1; }
cd "$here"
if docker info >/dev/null 2>&1; then D=(docker); else D=(sudo -n docker); fi
compose() { "${D[@]}" compose "$@"; }
in_volume() { compose run --rm --no-deps -T --entrypoint python3 aics-witness - "$@"; }
# Which of the witness's files are in the volume, and which are in the retired directory already.
look=$(in_volume "$retired" <<'PY'
import json, os, sys
from pathlib import Path
data = Path(os.environ.get("AICS_WITNESS_CONFIG", "/data/witness.json")).parent
names = ("witness.json", "witness.key", "witness.db", "witness.db-wal", "witness.db-shm")
print(json.dumps({"data": [n for n in names if os.path.lexists(data / n)],
                  "retired": [n for n in names if os.path.lexists(data / sys.argv[1] / n)]}))
PY
)
status=null
if LOOK="$look" python3 -c 'import json, os, sys; sys.exit(0 if "witness.json" in json.loads(os.environ["LOOK"])["data"] else 1)'; then
  status=$(compose run --rm --no-deps -T aics-witness status --json </dev/null)
fi
step=$(LOOK="$look" STATUS_JSON="$status" python3 -I - "$origin" "$new_log" "$wname" "$old_vkey" <<'PY'
import json, os, sys
origin, new, wname, old_vkey = sys.argv[1:]
old_name = old_vkey.split("+", 1)[0]
look, doc = json.loads(os.environ["LOOK"]), json.loads(os.environ["STATUS_JSON"])
if doc is None:
    # No config: only right after the identity to retire was moved aside.
    if "witness.json" in look["retired"] and not look["data"]:
        print("init")
        sys.exit(0)
    sys.exit(f"witness: the volume has no witness config (files {look['data']}, retired {look['retired']}); stop and look")
w = doc["witness"]
if w["name"] == old_name:
    if w.get("vkey") != old_vkey:
        sys.exit(f"witness: this host's {old_name} has the key {w.get('vkey')}, not {old_vkey}; stop and look")
    both = sorted(set(look["data"]) & set(look["retired"]))
    if both:
        sys.exit(f"witness: {', '.join(both)} exist both in the volume and in its retired directory; stop and look")
    print("retire")
    sys.exit(0)
if w["name"] != wname:
    sys.exit(f"witness: this host's witness is {w['name']}: neither the identity to retire ({old_name}) nor {wname}")
if not w.get("vkey") or w.get("db_status") != "initialised" or w.get("db_witness_vkey") != w["vkey"]:
    sys.exit(f"witness: {wname} has no usable key and database (vkey {w.get('vkey')}, database {w.get('db_status')}); stop and look")
entry = next((e for e in doc["logs"] if e["origin"] == origin), None)
if entry is None or (not entry["configured"] and entry["size"] is None):
    print("bootstrap")
elif entry["configured"] and entry["vkeys"] == [new] and (entry["initial"] is not None or entry["size"] is not None):
    print("done")
elif entry["configured"] and entry["vkeys"] == [new] and entry["size"] is None:
    print("bootstrap")  # trusted but not pinned yet: the pin applies while nothing is cosigned
else:
    sys.exit(f"witness: {wname} holds {origin} with {entry['vkeys'] or 'state of an unconfigured log'}, "
             "not the new log alone; stop and look")
PY
)
if [ "$step" = "retire" ]; then
  compose stop aics-witness </dev/null
  in_volume "$retired" <<'PY'
import os, sys
from pathlib import Path
from aics_witness.config import load_config
cfg_path = Path(os.environ.get("AICS_WITNESS_CONFIG", "/data/witness.json"))
cfg = load_config(cfg_path)
dest = cfg_path.parent / sys.argv[1]
dest.mkdir(mode=0o700, exist_ok=True)
moved = []
# The database and the key first, the config last.
for p in (cfg.db_path, Path(f"{cfg.db_path}-wal"), Path(f"{cfg.db_path}-shm"), cfg.key_path, cfg_path):
    if os.path.lexists(p):
        target = dest / p.name
        if os.path.lexists(target):
            sys.exit(f"witness: {p} and {target} both exist; stop and look")
        os.replace(p, target)
        moved.append(p.name)
print(f"witness: retired {cfg.name}: {', '.join(moved)} moved into {dest} (kept, never used again)")
PY
  step=init
fi
if [ "$step" = "init" ]; then
  compose stop aics-witness </dev/null
  out=$(compose run --rm --no-deps -T aics-witness init --name "$wname" </dev/null) \
    || { echo "witness: init --name $wname refused (its message is above)" >&2; exit 1; }
  vkey=$(printf '%s\n' "$out" | tail -n 1)
  case $vkey in "$wname+"*) ;; *) echo "witness: init printed '$vkey', not a vkey of $wname" >&2; exit 1 ;; esac
  echo "witness: created the identity $wname: a new key and database in the volume"
  step=bootstrap
fi
if [ "$step" = "bootstrap" ]; then
  bash "$here/bootstrap-witness-host.sh" --name "$wname" --origin "$origin" --log-vkey "$new_log" \
    --initial-size "$size" --initial-root "$root" </dev/null
else
  echo "witness: $wname already trusts the new log alone; making sure it runs"
  compose up -d </dev/null
fi
vkey=$(compose run --rm --no-deps -T aics-witness status --json </dev/null | python3 -c 'import json, sys; print(json.load(sys.stdin)["witness"]["vkey"])')
case $vkey in "$wname+"*) ;; *) echo "witness: status shows '$vkey', not a vkey of $wname" >&2; exit 1 ;; esac
echo "witness-vkey $vkey"
REMOTE
}

# witness_vantage NEW_LOG WITNESS_VKEY LABEL: the probes on the witness host check the new log and
# its witness.
remote_witness_vantage() { cat <<'REMOTE'
new_log=$1 wvkey=$2 label=$3
need_sudo
for v in "$new_log" "$wvkey"; do
  printf '%s' "$v" | grep -Eq '^[^+[:space:]]+\+[0-9a-f]{8}\+[A-Za-z0-9+/]+=*$' \
    || { echo "vantage: '$v' is not a vkey" >&2; exit 2; }
done
conf="$R/etc/aics-vantage"
pin() {  # FILE VKEY WHAT
  local cur
  cur=$(head -n 1 "$1" 2>/dev/null || true)
  if [ "$cur" = "$2" ]; then echo "vantage: the $3 is already pinned"; return 0; fi
  printf '%s\n' "$2" | sudo -n tee "$1.relaunch" >/dev/null
  sudo -n chmod 0644 "$1.relaunch"
  sudo -n mv "$1.relaunch" "$1"
  echo "vantage: pinned the $3 (it was: ${cur:-none})"
}
if [ -d "$conf" ]; then
  pin "$conf/log.vkey" "$new_log" "new log vkey"
  pin "$conf/witness.vkey" "$wvkey" "new witness vkey"
else
  echo "vantage: no $conf on this host (the probes are not installed); nothing to pin"
fi
sudo -n env R="$R" LABEL="$label" sh -s <<'SH'
set -eu
s="$R/var/lib/aics-vantage" a="$R/var/lib/aics-vantage-$LABEL"
if [ -e "$a/.done" ]; then
  echo "vantage: the probes' state of the discarded log is already in $a"
elif [ -d "$s" ]; then
  mkdir -p "$a"
  for x in "$s/markers" "$s/groups" "$s/witness.info" "$s"/split-*.note; do
    if [ -e "$x" ]; then mv "$x" "$a/"; fi
  done
  touch "$a/.done"
  echo "vantage: set the probes' state of the discarded log aside in $a"
fi
w="$R/var/lib/aics-watch/state"
if [ -f "$w" ] && [ ! -e "$w.$LABEL" ]; then mv "$w" "$w.$LABEL"; echo "first-contact watch: set aside $w.$LABEL"; fi
SH
for t in aics-vantage-uptime.timer aics-vantage-mirror.timer aics-vantage-status.timer aics-first-contact.timer; do
  if systemctl is-enabled --quiet "$t" 2>/dev/null; then sudo -n systemctl start "$t"; echo "started $t"; fi
done
REMOTE
}

# -- local helpers --------------------------------------------------------------------------------
VPS_STATE=""
load_vps_state() {
  if dry; then
    remote "$VPS" vps_state "$REMOTE_DIR"
    return 0
  fi
  VPS_STATE=$(remote "$VPS" vps_state "$REMOTE_DIR") || die "could not read the VPS state"
}
state() { printf '%s\n' "$VPS_STATE" | awk -v k="$1" '$1 == k { print $2; exit }'; }

# names_discarded FILE: the pubkeys FILE names the log to discard (or the 2026-10-19 one)
names_discarded() { grep -qxF "log $DISCARD_LOG_VKEY" "$1" || grep -qxF "log $V1_LOG_VKEY" "$1"; }
# pub_value LABEL PLACEHOLDER: LABEL's value in the new log's pubkeys.txt (the placeholder in a
# dry run before genesis).
pub_value() {
  local v=""
  if [ -f "$LAUNCH/pubkeys.txt" ] && ! names_discarded "$LAUNCH/pubkeys.txt"; then
    v=$(sed -n "s/^$1 //p" "$LAUNCH/pubkeys.txt" | head -n 1)
  fi
  if [ -z "$v" ]; then
    if dry; then printf '%s' "$2"; return 0; fi
    die "no '$1' line of the new log in $LAUNCH/pubkeys.txt (run the genesis stage)"
  fi
  printf '%s' "$v"
}
# witness_vkey: the new witness identity's vkey: --witness-vkey, else what the witness stage recorded
# (a dry run before that shows the placeholder)
witness_vkey() {
  local v="" f="$LAUNCH/witness-vkey.txt"
  if [ -s "$f" ]; then
    v=$(head -n 1 "$f")
    case $v in
      "$WITNESS_NAME+"*) ;;
      *) if dry; then v=""; else
           die "$f holds $v, not a vkey of $WITNESS_NAME: run archive (it holds the retired witness's file), then witness"
         fi ;;
    esac
  fi
  if [ -n "$WITNESS_VKEY_ARG" ]; then
    if [ -n "$v" ] && [ "$v" != "$WITNESS_VKEY_ARG" ]; then die "--witness-vkey is not the vkey $f records ($v)"; fi
    v=$WITNESS_VKEY_ARG
  fi
  if [ -z "$v" ]; then
    if dry; then printf '%s' '<NEW_WITNESS_VKEY>'; return 0; fi
    die "no vkey of $WITNESS_NAME yet: run the witness stage (it records it in $f), or give --witness-vkey"
  fi
  printf '%s' "$v"
}
# need_worktree: the worktree prep made (the verifiers and the deploy run from it)
need_worktree() {
  dry || [ -d "$WORKTREE/packages/aics-tlog" ] || die "no worktree at $WORKTREE (packages/aics-tlog): run prep first"
}
need_file() {
  [ -s "$1" ] && return 0
  if dry; then note "(not there yet: $1)"; return 0; fi
  die "$1 is missing (${2:-run the earlier stages})"
}
seed_check() {
  tr -d '\r\n' < "$1" | python3 -I -c 'import hashlib,sys; print(hashlib.sha256(b"aics-relaunch-seed-check:" + sys.stdin.buffer.read()).hexdigest())'
}
card_source() {
  fetch -o /dev/null -D - "$API/.well-known/aics-card.json" | tr -d '\r' \
    | awk -F': ' 'tolower($1) == "x-aics-card-source" { print $2 }'
}
# deploy_run LOG: deploy/deploy-vps.sh from the worktree, its output into LOG; returns its status
deploy_run() {
  printf '   $ (cd %s && bash deploy/deploy-vps.sh %s) > %s 2>&1\n' "$(q "$WORKTREE")" "$(q "$VPS")" "$(q "$1")"
  dry && return 0
  (cd "$WORKTREE" && bash deploy/deploy-vps.sh "$VPS") > "$1" 2>&1
}
# deploy_result STATUS LOG: 0 and 2 go on (2: healthy inside, a public check from here failed), others stop
deploy_result() {
  case $1 in
    0) note "deployed (log: $2)" ;;
    2) note "deployed and healthy inside; a public check from here failed (DNS, ports or a certificate may lag): $2" ;;
    *) tail -n 30 "$2" >&2; die "deploy/deploy-vps.sh exited $1 (log: $2)" ;;
  esac
}
deploy() {
  local rc=0
  deploy_run "$1" || rc=$?
  dry && return 0
  deploy_result "$rc" "$1"
}
# seed_started SEEDFILE WHAT: SEEDFILE.started says that a deploy used this seed (WHAT: pending, started,
# or the log vkey it started); seed and genesis never give it to another log
seed_started() {
  printf 'log %s\nat %s\n' "$2" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$1.started.tmp"
  mv -f "$1.started.tmp" "$1.started"
}
# seed_unused SEEDFILE: stop unless no log was ever started with this seed. "pending" (a deploy ran but
# no data volume came of it, so no leaf was written with the seed) allows a retry, except in a redo.
seed_unused() {
  local m=$1.started what
  [ -e "$m" ] || return 0
  what=$(sed -n 's/^log //p' "$m" | head -n 1)
  if [ "$what" = pending ] && [ "$DISCARD_LOG_VKEY" = "$V1_LOG_VKEY" ]; then
    note "$m: a deploy used this seed but made no data volume; trying again with it"
    return 0
  fi
  die "$1 has started a log before ($what, $(sed -n 's/^at //p' "$m")): a seed never starts a second log, its key would sign two histories; give a new --seed-name (server-seed-v3.hex) to seed and genesis"
}
# inside PATH DIR: PATH is DIR or below it, both resolved
inside() {
  python3 -I -c '
import os, sys
a, b = (os.path.realpath(os.path.expanduser(p)) for p in sys.argv[1:3])
sys.exit(0 if a == b or a.startswith(b.rstrip(os.sep) + os.sep) else 1)
' "$1" "$2"
}
sha256_of() { python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"; }
# txt_of NAME: the TXT value 1.1.1.1 answers for NAME, its strings joined
txt_of() { dig +short TXT "$1" @1.1.1.1 | head -n 1 | sed -e 's/" "//g' -e 's/^"//' -e 's/"$//'; }

# witness_gate LOG_VKEY WITNESS_VKEY NAME: the feeder runs and the witness cosigns. /healthz must show
# the witness ok with cosigned_current, and the served checkpoint (into $LAUNCH/NAME.txt, its report
# NAME.json) must verify under the new log key with the witness's cosignature at quorum 1, at most
# 300 s old: what a client holding the card checks. Both are tried together, every 5 s for 3 minutes:
# right after a write the served head carries the log signature alone until the witness answers.
witness_gate() {
  local log=$1 wvkey=$2 cp="$LAUNCH/$3.txt" report="$LAUNCH/$3.json" i why=""
  local verify=(uv run --quiet aics-tlog verify-checkpoint --note "$cp" --origin "$ORIGIN" --log-key "$log"
                --witness-key "$wvkey" --quorum 1 --max-age 300)
  need_worktree
  printf '   $ every 5 s, 3 minutes at most, until both hold: GET %s/healthz lists the witness %s ok with cosigned_current true,\n' \
    "$API" "$(q "$wvkey")"
  printf '   $ and %s; (cd %s && %s) > %s answers "ok": true\n' "$(q fetch -o "$cp" "$API/checkpoint")" \
    "$(q "$WORKTREE/packages/aics-tlog")" "$(q "${verify[@]}")" "$(q "$report")"
  dry && return 0
  for i in $(seq 1 36); do
    if ! fetch "$API/healthz" 2>/dev/null | python3 -I -c '
import json, sys
doc = json.load(sys.stdin)
sys.exit(0 if any(w.get("vkey") == sys.argv[1] and w.get("state") == "ok" and w.get("cosigned_current") is True
                  for w in doc.get("witnesses") or []) else 1)' "$wvkey" 2>/dev/null; then
      why="$API/healthz does not show $WITNESS_NAME ok with cosigned_current true (its witnesses entry says why)"
    elif ! fetch -o "$cp" "$API/checkpoint"; then
      why="$API/checkpoint does not answer"
    elif ! (cd "$WORKTREE/packages/aics-tlog" && "${verify[@]}") > "$report" 2> "$report.err" \
         || ! python3 -I -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("ok") is True else 1)' "$report"; then
      why="the served checkpoint does not verify at quorum 1 with $WITNESS_NAME's cosignature, at most 300 s old (see $report)"
    else
      rm -f "$report.err"
      note "the witness cosigns: checkpoint size $(sed -n 2p "$cp") verifies at quorum 1, at most 300 s old"
      return 0
    fi
    [ "$i" = 36 ] || sleep 5
  done
  die "after 3 minutes: $why"
}

# -- the census of the log to discard --------------------------------------------------------------
# census_py DIR ORIGIN LOG_VKEY OUT SOURCE HOW: read a checkpoint and its entry bundles (DIR/checkpoint,
# DIR/entries-NNN), check that the entries hash to the checkpoint's root, and count who wrote to the
# log: agent-type leaves by key, refusals by the key that attempted (attempt_kid; none when the
# signature did not verify), claimed names. Writes OUT (JSON) and prints the summary.
census_py() { cat <<'PY'
import base64, collections, datetime, hashlib, json, re, sys
from pathlib import Path

src, origin, log_vkey, out, source, how = sys.argv[1:7]
d = Path(src)
OPS = {"policy", "report", "refusal", "tombstone", "suspension", "freeze", "release"}
HARNESS_NAME = re.compile(r"ct-[0-9a-f]{16}")  # the names aics-conformance claims

def stop(msg):
    sys.exit(f"relaunch-genesis: STOP: census: {msg}")

def iso(ts):
    if not isinstance(ts, int):
        return "?"
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def span(rows):
    ts = [r["ts"] for r in rows if isinstance(r.get("ts"), int)]
    return (min(ts), max(ts)) if ts else (None, None)

note = (d / "checkpoint").read_text(encoding="utf-8")
head = note.split("\n")
if len(head) < 4 or head[0] != origin:
    stop(f"the checkpoint names {head[0]!r}, not {origin}")
size, root = int(head[1]), base64.b64decode(head[2], validate=True)
if size > 5000:
    stop(f"{size} leaves; the census reads every entry and stops at 5000")
entries = []
for k in range((size + 255) // 256):
    data, i, chunk = (d / f"entries-{k:03d}").read_bytes(), 0, []
    while i < len(data):
        n = int.from_bytes(data[i:i + 2], "big")
        if i + 2 + n > len(data):
            stop(f"entry bundle {k} is truncated")
        chunk.append(data[i + 2:i + 2 + n])
        i += 2 + n
    if len(chunk) != min(256, size - 256 * k):
        stop(f"entry bundle {k} holds {len(chunk)} entries, not {min(256, size - 256 * k)}")
    entries += chunk

def mth(hashes):
    """RFC 6962: the Merkle tree hash over these leaf hashes."""
    if len(hashes) == 1:
        return hashes[0]
    split = 1
    while split * 2 < len(hashes):
        split *= 2
    return hashlib.sha256(b"\x01" + mth(hashes[:split]) + mth(hashes[split:])).digest()

if (mth([hashlib.sha256(b"\x00" + e).digest() for e in entries]) if entries else hashlib.sha256(b"").digest()) != root:
    stop("the entries do not hash to the checkpoint's root")

rows = []
for i, raw in enumerate(entries):
    try:
        e = json.loads(raw)
    except ValueError:
        stop(f"entry {i} is not JSON")
    p = e.get("payload") if isinstance(e.get("payload"), dict) else {}
    row = {"index": i, "type": e.get("type", "?"), "ts": e.get("ts"), "actor": e.get("actor_kid")}
    if row["type"] == "refusal":
        row["attempt_kid"], row["reason_code"] = p.get("attempt_kid"), p.get("reason_code")
    elif row["type"] == "name.claim":
        row["name"] = p.get("name_norm")
    rows.append(row)

types = collections.Counter(r["type"] for r in rows)
agent = [r for r in rows if r["type"] not in OPS]
agent_keys = sorted({r["actor"] for r in agent if r["actor"]})
refusals = [r for r in rows if r["type"] == "refusal"]
keyless = [r for r in refusals if not r.get("attempt_kid")]
refused = {}
for r in refusals:
    if r.get("attempt_kid"):
        k = refused.setdefault(r["attempt_kid"], {"refusals": 0, "reasons": [], "indices": []})
        k["refusals"] += 1
        k["indices"].append(r["index"])
        if r.get("reason_code") not in k["reasons"]:
            k["reasons"].append(r.get("reason_code"))
for kid, k in refused.items():
    k["first_ts"], k["last_ts"] = span([r for r in refusals if r.get("attempt_kid") == kid])
outside = sorted((kid for kid in refused if kid not in set(agent_keys)), key=lambda kid: refused[kid]["first_ts"] or 0)
names = [r for r in rows if r["type"] == "name.claim"]
odd_names = sorted({str(r.get("name")) for r in names if not (isinstance(r.get("name"), str) and HARNESS_NAME.fullmatch(r["name"]))})
a_first, a_last = span(agent)
k_first, k_last = span(keyless)

key_id = log_vkey.split("+")[1] if log_vkey.count("+") >= 2 else "?"
print(f"   census of the {how} log ({source}): {origin}+{key_id}+… at size {size}; the entries hash to its root {head[2]}")
print("   leaf types: " + (", ".join(f"{t} {n}" for t, n in sorted(types.items())) or "none"))
if agent:
    print(f"   {len(agent)} agent-type leaves from {len(agent_keys)} keys, {iso(a_first)} to {iso(a_last)}")
else:
    print("   no agent-type leaf")
if names:
    print(f"   {len(names)} names claimed; " + ("all of them the conformance harness's (ct- and 16 hex digits)" if not odd_names
                                               else "NOT the conformance harness's: " + ", ".join(odd_names)))
if refusals:
    print(f"   {len(refusals)} refusals: {len(refused)} keys that attempted, and {len(keyless)} unauthenticated attempts"
          + (f" (no verified signature, so no key: {iso(k_first)} to {iso(k_last)}; "
             + ", ".join(f"{c} {n}" for c, n in sorted(collections.Counter(r.get('reason_code') for r in keyless).items()))
             + ")" if keyless else ""))
    for kid in outside:
        k = refused[kid]
        print(f"     refused, with no accepted leaf: {kid} ({k['refusals']}x {', '.join(map(str, k['reasons']))}, "
              f"{iso(k['first_ts'])} to {iso(k['last_ts'])})")
else:
    print("   no refusal leaf")
print(f"   Every one of these must be ours (a conformance run, a test): the {len(agent_keys)} keys with accepted leaves,"
      f" the {len(outside)} refused keys without one and the {len(keyless)} unauthenticated attempts.")
print("   The relaunch rests on nobody having used this log; if one of them is not ours, stop here.")
doc = {
    "census_of": how, "source": source, "origin": origin, "log_vkey": log_vkey, "tree_size": size, "root": head[2],
    "checkpoint": note, "types": dict(sorted(types.items())),
    "agent_leaves": len(agent), "agent_keys": agent_keys, "agent_first_ts": a_first, "agent_last_ts": a_last,
    "names_claimed": len(names), "names_not_harness": odd_names,
    "refusals": len(refusals), "refused_keys": refused, "refused_keys_without_accepted_leaf": outside,
    "unauthenticated": {"count": len(keyless), "first_ts": k_first, "last_ts": k_last, "indices": [r["index"] for r in keyless],
                        "reasons": dict(collections.Counter(str(r.get("reason_code")) for r in keyless))},
    "rows": rows,
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=1)
    f.write("\n")
PY
}
# census_of DIR HOW SOURCE: verify DIR/checkpoint under the key of the log to discard, then count it
# into $LAUNCH/discard-census.json
census_of() {
  local dir=$1 how=$2 source=$3
  need_worktree
  run_in_to "$WORKTREE/packages/aics-tlog" "$dir.json" uv run --quiet aics-tlog verify-checkpoint \
    --note "$dir/checkpoint" --origin "$ORIGIN" --log-key "$DISCARD_LOG_VKEY" \
    || die "census: the checkpoint does not verify under the key of the log to discard (see $dir.json)"
  printf '   $ census: the entries checked against that checkpoint and counted > %s\n' "$(q "$LAUNCH/discard-census.json")"
  dry && return 0
  python3 -I -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("ok") is True else 1)' "$dir.json" \
    || die "census: the checkpoint does not verify under the key of the log to discard (see $dir.json)"
  census_py | py "$dir" "$ORIGIN" "$DISCARD_LOG_VKEY" "$LAUNCH/discard-census.json.new" "$source" "$how" \
    || die "the census stopped (see above)"
  mv -f "$LAUNCH/discard-census.json.new" "$LAUNCH/discard-census.json"
}
# census_live: the census of the log while it still runs, from its tiles over HTTPS (an early look)
census_live() {
  local dir="$LAUNCH/census-live" size k w path try ok
  printf '   $ GET %s/tiles/checkpoint and every entry bundle it covers > %s/\n' "$API" "$(q "$dir")"
  if dry; then census_of "$dir" live "$API/tiles"; return 0; fi
  if [ -s "$LAUNCH/pubkeys.txt" ] && ! names_discarded "$LAUNCH/pubkeys.txt"; then
    note "no census: the launch directory holds the new log's keys already"
    return 0
  fi
  for try in 1 2; do
    rm -rf "$dir.new"
    mkdir -p "$dir.new"
    if ! fetch -o "$dir.new/checkpoint" "$API/tiles/checkpoint"; then
      rm -rf "$dir.new"
      note "no census of the live log: $API does not answer (frozen already?); freeze takes the census of the frozen volume"
      return 0
    fi
    size=$(sed -n 2p "$dir.new/checkpoint")
    case $size in ''|*[!0-9]*) die "census: the checkpoint's size is '$size'" ;; esac
    [ "$size" -le 5000 ] || die "census: $size leaves; the census reads every entry and stops at 5000"
    k=0 ok=1
    while [ $((k * 256)) -lt "$size" ]; do
      w=$((size - k * 256))
      path=$(printf 'tile/entries/%03d' "$k")
      [ "$w" -ge 256 ] || path="$path.p/$w"
      fetch -o "$(printf '%s/entries-%03d' "$dir.new" "$k")" "$API/tiles/$path" || { ok=0; break; }
      k=$((k + 1))
    done
    [ "$ok" = 0 ] || break
    # The log grew between the two fetches and the partial bundle moved on: once more, from a new checkpoint.
    [ "$try" = 1 ] || die "census: an entry bundle of the checkpoint does not answer, twice; stop and look"
  done
  rm -rf "$dir"
  mv "$dir.new" "$dir"
  census_of "$dir" live "$API/tiles"
}
# census_frozen: the census of the frozen log, from its volume on the VPS (the one wipe relies on)
census_frozen() {
  local dir="$LAUNCH/census-frozen"
  if dry; then
    remote "$VPS" vps_census "$REMOTE_DIR" "$DISCARD_LOG_VKEY"
    note "> $dir/ (the frozen volume's checkpoint and entry bundles)"
    census_of "$dir" frozen "$VPS volume"
    return 0
  fi
  rm -rf "$dir.new"
  mkdir -p "$dir.new"
  remote "$VPS" vps_census "$REMOTE_DIR" "$DISCARD_LOG_VKEY" > "$dir.new/files.jsonl"
  py "$dir.new/files.jsonl" "$dir.new" <<'PY' || die "census: the frozen volume's files are not what was asked for (see above)"
import base64, json, re, sys
from pathlib import Path
src, out = Path(sys.argv[1]), Path(sys.argv[2])
seen = 0
for line in src.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    doc = json.loads(line)
    if not re.fullmatch(r"checkpoint|entries-[0-9]{3}", doc["name"]):
        sys.exit(f"census: unexpected file {doc['name']!r}")
    (out / doc["name"]).write_bytes(base64.b64decode(doc["b64"], validate=True))
    seen += 1
if not (out / "checkpoint").is_file():
    sys.exit("census: no checkpoint from the frozen volume")
PY
  rm -f "$dir.new/files.jsonl"
  rm -rf "$dir"
  mv "$dir.new" "$dir"
  census_of "$dir" frozen "$VPS volume"
}
# census_frozen_ok SIZE: the census in the launch dir is the frozen volume's, of the log to discard, at SIZE
census_frozen_ok() {
  py "$LAUNCH/discard-census.json" "$DISCARD_LOG_VKEY" "$1" <<'PY'
import json, sys
path, log, size = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    with open(path, encoding="utf-8") as f:
        c = json.load(f)
except (OSError, ValueError) as exc:
    sys.exit(f"relaunch-genesis: STOP: wipe: no census of the frozen log ({exc}): run the freeze stage (it reads the frozen volume)")
problems = []
if c.get("census_of") != "frozen":
    problems.append("it is the census of the live log, not of the frozen volume: run the freeze stage")
if c.get("log_vkey") != log:
    problems.append(f"it counts the log {c.get('log_vkey')}, not {log}")
if c.get("tree_size") != size:
    problems.append(f"it counts {c.get('tree_size')} leaves, not the {size} given with --discard-size")
if problems:
    sys.exit("relaunch-genesis: STOP: wipe: the census " + path + ": " + "; ".join(problems))
print(f"   the census of the frozen log: {size} leaves; {len(c.get('agent_keys') or [])} keys with accepted leaves, "
      f"{len(c.get('refused_keys_without_accepted_leaf') or [])} refused keys without one, "
      f"{(c.get('unauthenticated') or {}).get('count', 0)} unauthenticated attempts: wiping means every one is ours")
PY
}

# -- stages ---------------------------------------------------------------------------------------
stage_archive() {
  say "archive: the files of the log to discard in $LAUNCH move into $DISCARD_DIR/"
  if [ ! -d "$LAUNCH" ]; then
    if dry; then note "(no $LAUNCH yet)"; return 0; fi
    die "no launch directory $LAUNCH"
  fi
  local dest=$LAUNCH/$DISCARD_DIR f moved=0 wfiles=""
  for f in witness-vkey.txt witness-feeder.env; do
    if [ -e "$LAUNCH/$f" ] && grep -qF "$RETIRE_WITNESS_NAME+" "$LAUNCH/$f"; then wfiles="$wfiles $f"; fi
  done
  if [ -f "$LAUNCH/pubkeys.txt" ] && ! grep -qxF "log $DISCARD_LOG_VKEY" "$LAUNCH/pubkeys.txt"; then
    note "$LAUNCH/pubkeys.txt is not the discarded log's: the new log's files are here already"
  elif [ -f "$LAUNCH/pubkeys.txt" ]; then
    # Only while pubkeys.txt names the log to discard, and it moves last: a rerun after prep never takes
    # prep's own files (the new charter's hash, the census), and a rerun after a crash finishes the move.
    [ -d "$dest" ] || run mkdir -m 0700 "$dest"
    for f in log.vkey bundle.txt bundle.json bundle.jcs genesis.json readme-block.txt txt-value.txt txt-live.txt \
             witness-txt-live.txt card.json card.headers card-fill.json card-preview.json card-template.json \
             card-checkpoint.txt card-checkpoint.json card-log-checkpoint.txt card-log-checkpoint.json logged.json \
             logged.headers logged-leaf.json card-unsigned.json card-successor.json successor-logged.json witness-pin.txt \
             witness-pin.json checkpoint-cosigned.txt checkpoint-verify.txt deploy-genesis.log deploy-card.log leaf0.json \
             charter.sha256 discard-census.json census-live census-live.json census-frozen census-frozen.json home \
             pubkeys.txt; do
      [ -e "$LAUNCH/$f" ] || continue
      [ ! -e "$dest/$f" ] || die "both $LAUNCH/$f and $dest/$f exist; sort them out by hand"
      run mv "$LAUNCH/$f" "$dest/$f"
      moved=$((moved + 1))
    done
  else
    note "no pubkeys.txt here: the discarded log's files were moved already"
  fi
  # The retired witness identity's files (the new identity's, once the witness stage ran, stay).
  for f in $wfiles; do
    [ -d "$dest" ] || run mkdir -m 0700 "$dest"
    [ ! -e "$dest/$f" ] || die "both $LAUNCH/$f and $dest/$f exist; sort them out by hand"
    run mv "$LAUNCH/$f" "$dest/$f"
    moved=$((moved + 1))
  done
  if ! dry && [ -d "$dest" ] && [ ! -e "$dest/README.txt" ]; then
    if [ "$DISCARD_LOG_VKEY" = "$V1_LOG_VKEY" ]; then
      printf '%s\n' "The launch files of the log started on 2026-10-19 (log key $V1_LOG_VKEY," \
        "trust bundle sha256 $V1_BUNDLE_SHA256) and of its witness $RETIRE_WITNESS_NAME. That log was discarded" \
        "at the relaunch of 2026-10-20 before any outside agent had used it, and the witness identity retired with it" \
        "(ops/relaunch-genesis.sh). Public values only; kept as a record." > "$dest/README.txt"
    else
      printf '%s\n' "The launch files of the log $DISCARD_LOG_VKEY and of the witness $RETIRE_WITNESS_NAME," \
        "discarded and retired by a redo of the relaunch (ops/relaunch-genesis.sh). Public values only; kept as a record." \
        > "$dest/README.txt"
    fi
  fi
  note "moved $moved item(s)"
}

stage_prep() {
  say "prep: a clean worktree of origin/main, the public docs, the inputs, a census of the log to discard"
  # The worktree is deployed with rsync -a, which keeps modes: under this script's umask 077 its directories
  # would reach the VPS as 0700, which the app's user cannot traverse (2026-10-22). Public files, public modes.
  umask 022
  need_cmd git uv python3 curl ssh rsync dig
  run git -C "$REPO" fetch -q origin || die "git fetch failed in $REPO"
  if [ -e "$WORKTREE/.git" ]; then
    if ! dry && [ -n "$(git -C "$WORKTREE" status --porcelain --untracked-files=no)" ]; then
      die "$WORKTREE has uncommitted changes (the docs stage writes there): commit and push them, or remove the worktree"
    fi
    run git -C "$WORKTREE" checkout -q --detach origin/main || die "could not move $WORKTREE to origin/main"
  else
    run git -C "$REPO" worktree add -q --detach "$WORKTREE" origin/main || die "could not create the worktree $WORKTREE"
  fi
  run git -C "$WORKTREE" log --oneline -1
  # Leaf 0 pins the charter and the card hashes the legal texts: no unresolved merge may reach them.
  printf '   $ git -C %s grep the merge-conflict markers (<<<<<<<, =======, >>>>>>> alone at a line start)\n' "$(q "$WORKTREE")"
  if ! dry; then
    local markers rc=0
    markers=$(git -C "$WORKTREE" grep -nE '^(<<<<<<<|>>>>>>>)( |$)|^=======$') || rc=$?
    [ "$rc" -le 1 ] || die "git grep failed in $WORKTREE"
    if [ -n "$markers" ]; then
      die "origin/main holds merge-conflict markers; resolve them on main first: $(printf '%s\n' "$markers" | head -n 5 | tr '\n' ' ')"
    fi
  fi
  run_in "$WORKTREE" bash ops/sync-docs.sh deploy/docs-public || die "ops/sync-docs.sh refused (see above)"
  if ! dry; then
    local f
    for f in deploy/docs-public/legal/charter.md deploy/docs-public/legal/secret-patterns.json card/card-content.json; do
      [ -s "$WORKTREE/$f" ] || die "$WORKTREE/$f is missing"
    done
    if grep -q 'FILL' "$WORKTREE/docs/legal/charter.md"; then die "docs/legal/charter.md still holds placeholders"; fi
    for f in '<FILL:WITNESS_NAME>' '<FILL:WITNESS_VKEY>'; do
      grep -qF "$f" "$WORKTREE/card/card-content.json" \
        || die "card/card-content.json has no $f: the first card names the new witness, whose vkey exists only after the witness stage"
    done
    mkdir -p "$LAUNCH"
  fi
  run_in_to "$WORKTREE/card" "$LAUNCH/card-template.json" uv run --quiet python validate_card.py card-content.json \
    || die "card/card-content.json does not validate as a template (see $LAUNCH/card-template.json)"
  if ! dry; then
    printf '%s  deploy/docs-public/legal/charter.md\n' "$(sha256_of "$WORKTREE/deploy/docs-public/legal/charter.md")" > "$LAUNCH/charter.sha256"
    note "charter: $(cat "$LAUNCH/charter.sha256")"
  fi
  census_live
}

stage_freeze() {
  say "freeze: no more writes on the log to discard, no more checkpoints to the witness; then its census"
  remote "$VPS" vps_freeze "$REMOTE_DIR" "$DISCARD_LOG_VKEY" "$DISCARD_LABEL"
  remote "$WITNESS_HOST" witness_freeze "$DISCARD_LABEL"
  census_frozen
  note "next: wipe --discard-size <the size the census of the frozen log names>, once every key above is ours"
}

stage_wipe() {
  say "wipe: the discarded log's containers and volumes on the VPS (production only; staging stays)"
  if [ -z "$DISCARD_SIZE" ] && ! dry; then
    usage_error "wipe needs --discard-size N: the size of the census of the frozen log (freeze)"
  fi
  if dry; then
    note "refuses unless $LAUNCH/discard-census.json is the census of the frozen volume of the log to discard, at that size"
  else
    census_frozen_ok "$DISCARD_SIZE" || exit 1
  fi
  remote "$VPS" vps_wipe "$REMOTE_DIR" "$DISCARD_LOG_VKEY" "${DISCARD_SIZE:-<DISCARDED_LOG_SIZE>}"
}

stage_seed() {
  say "seed: a new server seed for the new log (new log and policy keys); the custody copy and the VPS only"
  [ -n "$CUSTODY" ] || usage_error "seed needs --custody-dir DIR: the owner's custody directory, outside git"
  local seedfile=$CUSTODY/$SEED_NAME d
  if ! dry || [ -d "$CUSTODY" ]; then
    [ -d "$CUSTODY" ] || die "no custody directory $CUSTODY"
    for d in "$REPO" "$WORKTREE" "$LAUNCH"; do
      if inside "$CUSTODY" "$d"; then
        die "the custody directory $CUSTODY is inside $d: a seed never goes into a checkout or the public launch directory"
      fi
    done
    python3 -I -c 'import os,stat,sys; sys.exit(0 if stat.S_IMODE(os.stat(sys.argv[1]).st_mode) & 0o077 == 0 else 1)' "$CUSTODY" \
      || die "the custody directory $CUSTODY is open to other users: chmod 700 it first"
  fi
  load_vps_state
  if dry; then
    note "refuses if the production data volume exists (the seed of a started log never changes), and a seed that"
    note "started a log before ($seedfile.started): a seed is never used for a second log"
    note "\$ create $seedfile (mode 0600, exclusively) holding 32 random bytes as hex (python3 secrets.token_hex)"
    printf "   \$ tr -d '\\\\r\\\\n' < %s | ssh -o BatchMode=yes %s 'cd %s/deploy && python3 -c <envedit> .env AICS_SERVER_SEED_HEX --stdin'\n" \
      "$(q "$seedfile")" "$(q "$VPS")" "$REMOTE_DIR"
    note "(the seed travels on stdin only; the VPS answers 'AICS_SERVER_SEED_HEX: replaced', never the value)"
    return 0
  fi
  [ "$(state data-volume-exists)" = 0 ] \
    || die "the production data volume $(state data-volume) exists: the seed of a started log never changes (wipe first; or genesis already ran)"
  seed_unused "$seedfile"
  if [ -e "$seedfile" ]; then
    if [ "$(state seed-lines)" = 1 ] && [ "$(state seed-check)" = "$(seed_check "$seedfile")" ]; then
      note "already rotated: the VPS holds the seed of $seedfile"
      return 0
    fi
    note "$seedfile exists but the VPS does not hold it: sending the custody copy"
  else
    python3 -I -c '
import os, secrets, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(secrets.token_hex(32) + "\n")
' "$seedfile"
    note "wrote $seedfile (mode 0600); copy it to the offline media beside the owner key (runbook step 0)"
  fi
  printf '   [%s] envedit .env AICS_SERVER_SEED_HEX --stdin\n' "$VPS" >&2
  tr -d '\r\n' < "$seedfile" | ssh -o BatchMode=yes "$VPS" \
    "cd $(q "$REMOTE_DIR/deploy") && python3 -c 'import base64,sys; exec(base64.b64decode(sys.argv.pop(1)))' $ENV_EDIT_B64 .env AICS_SERVER_SEED_HEX --stdin" \
    || die "the seed write on $VPS failed (its message is above; the seed itself is never printed)"
  load_vps_state
  if [ "$(state seed-lines)" != 1 ] || [ "$(state seed-check)" != "$(seed_check "$seedfile")" ]; then
    die "the VPS does not hold the new seed after the write; look at deploy/.env there (never print it)"
  fi
  note "the VPS holds the new seed; the old one is gone from deploy/.env (the freeze backup has no seed line)"
}

stage_genesis() {
  say "genesis: the new log's first start; leaf 0 is the charter"
  [ -n "$CUSTODY" ] || usage_error "genesis needs --custody-dir DIR, to check that the VPS holds the custody seed"
  local seedfile=$CUSTODY/$SEED_NAME new="$LAUNCH/pubkeys.txt.new" rc=0
  load_vps_state
  if ! dry; then
    if [ "$(state data-volume-exists)" = 1 ]; then
      remote "$VPS" vps_pubkeys "$REMOTE_DIR" > "$new" || die "the data volume exists but no aics-server answers; stop and look"
      # A log volume and the VPS holds this seed: this seed started that log; the marker says so.
      if [ -s "$seedfile" ] && [ "$(state seed-lines)" = 1 ] && [ "$(state seed-check)" = "$(seed_check "$seedfile")" ] \
         && ! grep -q '^log api\.' "$seedfile.started" 2>/dev/null; then
        seed_started "$seedfile" "$(sed -n 's/^log //p' "$new" | head -n 1)"
      fi
      if [ -f "$LAUNCH/pubkeys.txt" ] && cmp -s "$new" "$LAUNCH/pubkeys.txt"; then
        rm -f "$new"
        note "genesis already ran: the VPS serves the log of $LAUNCH/pubkeys.txt"
        return 0
      fi
      die "the production data volume exists and holds a log that is not the launch directory's ($new); stop and look"
    fi
    [ -s "$seedfile" ] || die "no $seedfile: run the seed stage first"
    if [ "$(state seed-lines)" != 1 ] || [ "$(state seed-check)" != "$(seed_check "$seedfile")" ]; then
      die "the VPS's deploy/.env does not hold the seed of $seedfile: run the seed stage"
    fi
    seed_unused "$seedfile"
    if [ "$(state env-AICS_CARD_FILE)" != 0 ] || [ "$(state env-AICS_WITNESSES)" != 0 ]; then
      die "deploy/.env still sets AICS_CARD_FILE or AICS_WITNESSES: run the freeze stage"
    fi
    [ "$(state env-AICS_OWNER_PUBKEY)" = 1 ] || die "deploy/.env does not set AICS_OWNER_PUBKEY"
    [ -s "$LAUNCH/charter.sha256" ] || die "no $LAUNCH/charter.sha256: run prep"
  fi
  if dry; then
    note "> $seedfile.started before the deploy: a seed a deploy has used never starts another log"
    deploy "$LAUNCH/deploy-genesis.log"
    remote "$VPS" vps_pubkeys "$REMOTE_DIR"
    note "> $LAUNCH/pubkeys.txt, checked: origin $ORIGIN, owner $OWNER_KID, the exported charter's hash,"
    note "  and a log and a policy key that are not the discarded log's; > $LAUNCH/log.vkey"
    return 0
  fi
  # A deploy with this seed is about to run: from here the seed is spent, unless no log volume appears.
  seed_started "$seedfile" pending
  deploy_run "$LAUNCH/deploy-genesis.log" || rc=$?
  load_vps_state
  if [ "$(state data-volume-exists)" = 1 ]; then seed_started "$seedfile" started; fi
  deploy_result "$rc" "$LAUNCH/deploy-genesis.log"
  remote "$VPS" vps_pubkeys "$REMOTE_DIR" > "$new"
  seed_started "$seedfile" "$(sed -n 's/^log //p' "$new" | head -n 1)"
  py "$new" "$ORIGIN" "$OWNER_KID" "$V1_LOG_VKEY" "$V1_POLICY_KID" "$(cut -d' ' -f1 "$LAUNCH/charter.sha256")" "$DISCARD_LOG_VKEY" <<'PY' \
    || die "the new log's keys are not what the relaunch expects (see above); $LAUNCH/pubkeys.txt was not written"
import re, sys
path, origin, owner, v1_log, v1_policy, charter, discard_log = sys.argv[1:]
lines = dict(re.findall(r"^([a-z0-9-]+) (\S+)$", open(path, encoding="utf-8").read(), re.M))
problems = []
if lines.get("origin") != origin: problems.append(f"origin {lines.get('origin')} is not {origin}")
if lines.get("owner") != owner: problems.append(f"owner {lines.get('owner')} is not {owner}")
if lines.get("charter-sha256") != charter: problems.append(f"leaf 0 pins charter {lines.get('charter-sha256')}, the export is {charter}")
log = lines.get("log", "")
if not log.startswith(origin + "+"): problems.append(f"the log key {log!r} is not named {origin}")
if log in (v1_log, discard_log): problems.append("the log key is the discarded log's: the seed was not rotated")
if lines.get("policy") == v1_policy: problems.append("the policy key is the discarded log's: the seed was not rotated")
for p in problems: print("   problem: " + p)
for k in ("origin", "log", "policy", "owner", "charter-sha256"): print(f"   {k} {lines.get(k)}")
sys.exit(1 if problems else 0)
PY
  mv "$new" "$LAUNCH/pubkeys.txt"
  sed -n 's/^log //p' "$LAUNCH/pubkeys.txt" > "$LAUNCH/log.vkey"
  local a b
  a=$(fetch "$API/tiles/checkpoint") || die "$API/tiles/checkpoint does not answer (see $LAUNCH/deploy-genesis.log)"
  b=$(fetch "$API/checkpoint") || die "$API/checkpoint does not answer"
  [ "$a" = "$b" ] || die "/tiles/checkpoint and /checkpoint differ"
  [ "$(printf '%s\n' "$a" | head -n 1)" = "$ORIGIN" ] || die "the checkpoint's origin is not $ORIGIN"
  note "leaf 0 written; checkpoint size $(printf '%s\n' "$a" | sed -n 2p); the keys are in $LAUNCH/pubkeys.txt and log.vkey"
  note "$seedfile.started records that this seed started this log: seed and genesis refuse it for any other"
}

stage_witness() {
  say "witness: $RETIRE_WITNESS_NAME retired; $WITNESS_NAME, a new identity, pinned to the new log at its verified size"
  local log size root pin="$LAUNCH/witness-pin.txt" out vkey f="$LAUNCH/witness-vkey.txt"
  log=$(pub_value log '<NEW_LOG_VKEY>')
  if ! dry && [ -s "$f" ]; then
    case $(head -n 1 "$f") in
      "$WITNESS_NAME+"*) ;;
      *) die "$f holds $(head -n 1 "$f"), not a vkey of $WITNESS_NAME: run archive first (it is the retired witness's file)" ;;
    esac
  fi
  run fetch -o "$pin" "$API/tiles/checkpoint" || die "$API/tiles/checkpoint does not answer"
  need_worktree
  run_in_to "$WORKTREE/packages/aics-tlog" "$LAUNCH/witness-pin.json" uv run --quiet aics-tlog verify-checkpoint \
    --note "$pin" --origin "$ORIGIN" --log-key "$log" || die "the checkpoint to pin does not verify under the new log key"
  if dry; then
    size='<SIZE>'
    root='<ROOT>'
  else
    python3 -I -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("ok") is True else 1)' "$LAUNCH/witness-pin.json" \
      || die "the checkpoint to pin does not verify under the new log key"
    size=$(sed -n 2p "$pin")
    root=$(sed -n 3p "$pin")
    case $size in ''|*[!0-9]*|0) die "the checkpoint has '$size' leaves: run genesis first" ;; esac
    note "pinning at size $size, root $root (verified under the new log key)"
  fi
  if [ "$WITNESS_SYNC" = 1 ]; then
    run_witness ssh -o BatchMode=yes "$WITNESS_HOST" 'mkdir -p ~/aics/packages ~/aics/ops'
    run_witness rsync -a --delete --exclude .venv --exclude __pycache__ --exclude .pytest_cache --exclude .env \
      --exclude /aics-witness/data "$WORKTREE/packages/aics-tlog" "$WORKTREE/packages/aics-witness" "$WITNESS_HOST:aics/packages/"
    run_witness rsync -a --delete --exclude .env --exclude site/ "$WORKTREE/ops/witness" "$WITNESS_HOST:aics/ops/"
  fi
  if witness_printed; then
    remote "$WITNESS_HOST" witness_repin "$ORIGIN" "$log" "$size" "$root" "$WITNESS_NAME" "$RETIRE_WITNESS_VKEY"
    note "once the block above has run on $WITNESS_HOST, run this stage again without --print-only (it finds"
    note "$WITNESS_NAME pinned, leaves it so and records its vkey), or give --witness-vkey with the vkey it printed"
    note "to the later stages; the feeder stays off until the card stage"
    return 0
  fi
  out=$(remote "$WITNESS_HOST" witness_repin "$ORIGIN" "$log" "$size" "$root" "$WITNESS_NAME" "$RETIRE_WITNESS_VKEY") \
    || { printf '%s\n' "$out"; die "witness_repin on $WITNESS_HOST stopped (its output is above)"; }
  printf '%s\n' "$out"
  vkey=$(printf '%s\n' "$out" | sed -n 's/^witness-vkey //p' | tail -n 1)
  is_vkey "$vkey" || die "the witness host printed no vkey of $WITNESS_NAME (see above)"
  case $vkey in "$WITNESS_NAME+"*) ;; *) die "the witness host printed $vkey, not a vkey of $WITNESS_NAME" ;; esac
  if [ "$vkey" = "$RETIRE_WITNESS_VKEY" ] || [ "$vkey" = "$V1_WITNESS_VKEY" ]; then die "$vkey is a retired witness identity"; fi
  if [ -n "$WITNESS_VKEY_ARG" ] && [ "$WITNESS_VKEY_ARG" != "$vkey" ]; then
    die "--witness-vkey $WITNESS_VKEY_ARG is not the vkey the witness host reports ($vkey)"
  fi
  if [ -s "$f" ] && [ "$(head -n 1 "$f")" != "$vkey" ]; then
    die "$f holds $(head -n 1 "$f"), not $vkey: two keys of $WITNESS_NAME for one relaunch; stop and look"
  fi
  printf '%s\n' "$vkey" > "$f"
  printf 'AICS_WITNESSES=%s=%s=%s\n' "$WITNESS_LABEL" "$WITNESS_URL" "$vkey" > "$LAUNCH/witness-feeder.env"
  chmod 0644 "$f" "$LAUNCH/witness-feeder.env"
  note "recorded $WITNESS_NAME's vkey (public) in $f and witness-feeder.env; the card stage names it and turns the feeder on"
}

stage_card() {
  say "card: the first card of the new log (the new keys, $WITNESS_NAME at quorum 1), served from AICS_CARD_FILE, previewed"
  local log pol own wvkey budget now exp src served
  log=$(pub_value log '<NEW_LOG_VKEY>')
  pol=$(pub_value policy '<NEW_POLICY_KID>')
  own=$(pub_value owner "$OWNER_KID")
  [ "$own" = "$OWNER_KID" ] || die "pubkeys.txt names the owner $own, not $OWNER_KID"
  wvkey=$(witness_vkey)
  if dry; then
    budget='<limits.ciphertext_budget_bytes of GET /v2/limits>'
    note "checks that $WITNESS_URL/vkey.txt serves $wvkey"
  else
    src=$(card_source || true)
    if [ "$src" = logged ]; then note "the served card is logged already (card-log ran): nothing to fill"; return 0; fi
    budget=$(fetch "$API/v2/limits" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["limits"]["ciphertext_budget_bytes"])')
    served=$(fetch "$WITNESS_URL/vkey.txt") || die "$WITNESS_URL/vkey.txt does not answer"
    served=$(printf '%s\n' "$served" | head -n 1)
    [ "$served" = "$wvkey" ] || die "$WITNESS_URL/vkey.txt serves '$served', not the vkey the witness stage recorded ($wvkey)"
  fi
  now=$(date +%s)
  exp=$((now + 365 * 86400))
  local card="$WORKTREE/card/card-content.json" names="" name value opt=""
  local sets=()
  if [ -f "$card" ]; then
    names=$(python3 -I -c '
import re, sys
print(" ".join(sorted(set(re.findall(r"<FILL:([A-Z_]+)(?=[:>])", open(sys.argv[1], encoding="utf-8").read())))))
' "$card")
  fi
  for name in ISSUED_AT EXPIRES LOG_VKEY POLICY_KID OWNER_KID CIPHERTEXT_BUDGET_BYTES WITNESS_NAME WITNESS_VKEY CUSTODIAN_NAME CUSTODIAN_HOLDS; do
    case " $names " in *" $name "*) ;; *) [ -z "$names" ] || continue ;; esac
    case $name in
      ISSUED_AT) value=$now ;;
      EXPIRES) value=$exp ;;
      LOG_VKEY) value=$log ;;
      POLICY_KID) value=$pol ;;
      OWNER_KID) value=$own ;;
      CIPHERTEXT_BUDGET_BYTES) value=$budget ;;
      WITNESS_NAME) value=$WITNESS_NAME ;;
      WITNESS_VKEY) value=$wvkey ;;
      CUSTODIAN_NAME) value=$CUSTODIAN_NAME; opt=--custodian-name ;;
      CUSTODIAN_HOLDS) value=$CUSTODIAN_HOLDS; opt=--custodian-holds ;;
    esac
    if [ -z "$value" ]; then
      if dry; then value="<$name>"; else usage_error "the card holds <FILL:$name>: give $opt"; fi
    fi
    sets+=(--set "$name=$value")
  done
  for value in ${CARD_SETS[@]+"${CARD_SETS[@]}"}; do sets+=(--set "$value"); done
  run_in_to "$WORKTREE/card" "$LAUNCH/card-fill.json" uv run --quiet python validate_card.py card-content.json --fill-hashes .. \
    --patterns ../docs/legal/secret-patterns.json ${sets[@]+"${sets[@]}"} --final --write ../deploy/card/card-unsigned.json \
    || die "the filled card does not validate (its report: $LAUNCH/card-fill.json)"
  local body="$WORKTREE/deploy/card/card-unsigned.json"
  if ! dry; then
    py "$body" "$log" "$pol" "$own" "$WITNESS_NAME" "$wvkey" "$RETIRE_WITNESS_VKEY" "$V1_WITNESS_VKEY" <<'PY' || die "the filled card is not the first card the relaunch needs (see above)"
import json, sys
body, log, pol, own, wname, wvkey, *retired = sys.argv[1:]
c = json.load(open(body, encoding="utf-8"))
problems = []
for k, v in (("log_vkey", log), ("policy_kid", pol), ("owner_kid", own)):
    if c.get(k) != v: problems.append(f"{k} is {c.get(k)}, not {v}")
wp = c.get("witness_policy") or {}
if not (isinstance(wp.get("quorum"), int) and wp["quorum"] >= 1): problems.append(f"witness quorum {wp.get('quorum')}, not at least 1")
listed = wp.get("witnesses") or []
if not any(w.get("vkey") == wvkey and w.get("name") == wname for w in listed):
    problems.append(f"the witness {wname} is not listed with its vkey")
for w in listed:
    if w.get("vkey") in retired or any(w.get("name") == r.split("+")[0] for r in retired):
        problems.append(f"it lists the retired witness {w.get('name')}")
for p in problems: print("   problem: " + p)
sys.exit(1 if problems else 0)
PY
  fi
  if [ "$(cd "$REPO" 2>/dev/null && pwd -P)" != "$(cd "$WORKTREE" 2>/dev/null && pwd -P)" ]; then
    if ! dry && [ -f "$REPO/deploy/card/card-unsigned.json" ] && [ -d "$LAUNCH/$DISCARD_DIR" ] && [ ! -e "$LAUNCH/$DISCARD_DIR/card-unsigned.repo.json" ]; then
      cp -p "$REPO/deploy/card/card-unsigned.json" "$LAUNCH/$DISCARD_DIR/card-unsigned.repo.json"
    fi
    run cp "$body" "$REPO/deploy/card/card-unsigned.json"
  fi
  run cp "$body" "$LAUNCH/card-unsigned.json"
  remote "$VPS" vps_card_env "$REMOTE_DIR" "$CARD_FILE_IN_CONTAINER" "$WITNESS_LABEL=$WITNESS_URL=$wvkey"
  deploy "$LAUNCH/deploy-card.log"
  # The card names the witness and is in force the moment it is logged: the witness cosigns first.
  witness_gate "$log" "$wvkey" card-checkpoint
  run fetch -D "$LAUNCH/card.headers" -o "$LAUNCH/card.json" "$API/.well-known/aics-card.json" \
    || die "the card does not answer (see $LAUNCH/deploy-card.log)"
  if ! dry; then
    tr -d '\r' < "$LAUNCH/card.headers" | grep -qi '^x-aics-card-source: file$' \
      || die "the served card is not the reviewed file: $(grep -i '^x-aics-card' "$LAUNCH/card.headers" | tr '\r\n' '  ')"
    tr -d '\r' < "$LAUNCH/card.headers" | grep -qi '^x-aics-card-leaf: none$' \
      || die "the served card says it is logged already: $(grep -i '^x-aics-card' "$LAUNCH/card.headers" | tr '\r\n' '  ')"
  fi
  run_in_to "$WORKTREE/card" "$LAUNCH/card-preview.json" uv run --quiet python validate_card.py --signed --final \
    --patterns ../docs/legal/secret-patterns.json "$LAUNCH/card.json" \
    || die "the served card does not validate (its report: $LAUNCH/card-preview.json)"
  dry && return 0
  py "$LAUNCH/card.json" "$LAUNCH/card-preview.json" <<'PY' || die "the served card does not validate (see $LAUNCH/card-preview.json)"
import hashlib, json, sys
raw = open(sys.argv[1], "rb").read()
card, report = json.loads(raw), json.load(open(sys.argv[2]))
print(f"   preview: J(card) {len(raw)} bytes, sha256 {hashlib.sha256(raw).hexdigest()} (the bundle will pin it)")
print(f"   origin {card['origin']}; log {card['log_vkey']}; policy {card['policy_kid']}; owner {card['owner_kid']}")
wp = card["witness_policy"]
print(f"   witness quorum {wp['quorum']}: " + ", ".join(f"{w['name']} ({w['trust_domain']}, independent {w['independent']})" for w in wp["witnesses"]))
by = {}
for a in card.get("assurances", []):
    by.setdefault(a["status"], []).append(a["id"])
print("   " + "; ".join(f"{k}: {' '.join(v)}" for k, v in sorted(by.items())))
print(f"   issued {card['issued_at']}, expires {card['expires']}; validator ok: {report.get('ok')}")
sys.exit(0 if report.get("ok") else 1)
PY
  note "read the preview; then card-log logs exactly $LAUNCH/card.json"
}

stage_card_log() {
  say "card-log: the owner logs the previewed card (the bootstrap card, zero notice) while the witness cosigns"
  [ -n "$OWNER_KEY" ] || usage_error "card-log needs --owner-key FILE"
  dry || [ -f "$OWNER_KEY" ] || die "no owner key at $OWNER_KEY"
  local log src wvkey leaf served_leaf
  log=$(pub_value log '<NEW_LOG_VKEY>')
  need_file "$LAUNCH/card.json" "run the card stage"
  if ! dry; then
    src=$(card_source || true)
    if [ "$src" = logged ]; then
      fetch -o "$LAUNCH/logged.check" "$API/.well-known/aics-card.json"
      cmp -s "$LAUNCH/logged.check" "$LAUNCH/card.json" || die "a card is logged, but not the previewed $LAUNCH/card.json; stop and look"
      rm -f "$LAUNCH/logged.check"
      note "the previewed card is logged already"
      [ -s "$LAUNCH/logged.json" ] || fetch -D "$LAUNCH/logged.headers" -o "$LAUNCH/logged.json" "$API/.well-known/aics-card.json"
      return 0
    fi
    [ "$src" = file ] || die "the served card's source is '$src', not the reviewed file"
    fetch -o "$LAUNCH/card.check" "$API/.well-known/aics-card.json"
    cmp -s "$LAUNCH/card.check" "$LAUNCH/card.json" || die "the served card changed since the preview: run the card stage again"
    rm -f "$LAUNCH/card.check"
  fi
  wvkey=$(witness_vkey)
  # Logged, the card is in force at once: a client holding it refuses any checkpoint without the cosignature.
  witness_gate "$log" "$wvkey" card-log-checkpoint
  run_in_to "$WORKTREE/packages/aics-server" "$LAUNCH/logged-leaf.json" uv run --quiet python src/aics_server/static/aics_client.py \
    owner --key "${OWNER_KEY:-<OWNER_KEY>}" --log-vkey "$log" log-card --document-file "$LAUNCH/card.json" \
    || die "the owner tool did not log the card (its message is above; its output: $LAUNCH/logged-leaf.json)"
  run fetch -D "$LAUNCH/logged.headers" -o "$LAUNCH/logged.json" "$API/.well-known/aics-card.json" || die "the card does not answer"
  dry && return 0
  cmp -s "$LAUNCH/card.json" "$LAUNCH/logged.json" || die "the card bytes changed after logging"
  tr -d '\r' < "$LAUNCH/logged.headers" | grep -qi '^x-aics-card-source: logged$' || die "the card is not served as logged"
  served_leaf=$(tr -d '\r' < "$LAUNCH/logged.headers" | awk -F': ' 'tolower($1) == "x-aics-card-leaf" { print $2 }')
  leaf=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["policy"]["leaf_index"])' "$LAUNCH/logged-leaf.json" 2>/dev/null || true)
  if [ -n "$leaf" ] && [ "$leaf" != "$served_leaf" ]; then
    die "the owner tool logged the card at leaf $leaf, but the server serves it as leaf '$served_leaf'; stop and look"
  fi
  note "the card is leaf ${served_leaf:-?} (normally 1: a daily report or a refusal may come first; the bundle takes the index it reports)"
  note "checkpoint size now $(fetch "$API/checkpoint" | sed -n 2p)"
}

stage_bundle() {
  say "bundle: the trust bundle of the new log, and the launch-dir files that carry it"
  need_file "$LAUNCH/pubkeys.txt" "run genesis"
  need_file "$LAUNCH/logged.json" "run card-log"
  local wvkey
  wvkey=$(witness_vkey)
  local build=(uv run --quiet aics trust build --pubkeys "$LAUNCH/pubkeys.txt" --card "$LAUNCH/logged.json" --policies-url "$API/v2/policies")
  run_in_to "$WORKTREE/packages/aics-cli" "$LAUNCH/bundle.txt" "${build[@]}" || die "aics trust build refused (see $LAUNCH/bundle.txt)"
  run_in_to "$WORKTREE/packages/aics-cli" "$LAUNCH/bundle.json.new" "${build[@]}" --json || die "aics trust build --json refused"
  run fetch -o "$LAUNCH/leaf0.json" "$API/v2/entries/0" || die "$API/v2/entries/0 does not answer (the genesis time is leaf 0's)"
  printf '   $ bundle.json, bundle.jcs, txt-value.txt, readme-block.txt, genesis.json > %s/\n' "$LAUNCH"
  dry && return 0
  py "$LAUNCH" "$V1_BUNDLE_SHA256" "$V1_LOG_VKEY" "$OWNER_KID" "$wvkey" "$RETIRE_WITNESS_VKEY" <<'PY' || die "the bundle is not the one the relaunch needs (see above)"
import base64, datetime, hashlib, json, os, sys
from pathlib import Path
L = Path(sys.argv[1])
v1_sha, v1_log, owner, wvkey, retired = sys.argv[2:]
new = json.loads((L / "bundle.json.new").read_text(encoding="utf-8"))
jcs = new["bundle_jcs"].encode("utf-8")
b = json.loads(jcs)
problems = []
if not new.get("ok"): problems.append("aics trust build did not succeed")
if hashlib.sha256(jcs).hexdigest() != new["sha256"]: problems.append("sha256 is not the digest of the bundle bytes")
if new["sha256"] == v1_sha or b["log_vkey"] == v1_log: problems.append("this is the discarded log's bundle")
if b["owner_kid"] != owner: problems.append(f"owner {b['owner_kid']} is not {owner}")
card = (L / "logged.json").read_bytes()
if hashlib.sha256(card).hexdigest() != b["bootstrap_card_hash"]: problems.append("the bundle does not pin logged.json")
listed = [w.get("vkey") for w in (json.loads(card).get("witness_policy") or {}).get("witnesses") or []]
if wvkey not in listed: problems.append(f"the card the bundle pins does not list the witness {wvkey}")
old = L / "bundle.json"
if old.exists() and json.loads(old.read_text(encoding="utf-8"))["sha256"] != new["sha256"]:
    problems.append(f"{old} holds another bundle: two bundles for one relaunch; stop and look")
if problems:
    for p in problems: print("   problem: " + p)
    sys.exit(1)
raw = json.loads((L / "leaf0.json").read_text(encoding="utf-8"))["entry_bytes"]
leaf0 = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
if leaf0.get("type") != "policy" or leaf0.get("origin") != b["origin"]:
    print("   problem: entry 0 is not the charter's policy leaf of this origin")
    sys.exit(1)
pub = dict(line.split(" ", 1) for line in (L / "pubkeys.txt").read_text(encoding="utf-8").splitlines() if line and not line.startswith("#"))
facts = {
    "origin": b["origin"], "log_vkey": b["log_vkey"], "policy_kid": b["policy_kid"], "owner_kid": b["owner_kid"],
    "bundle_sha256": new["sha256"], "card_hash": b["bootstrap_card_hash"], "card_size": len(card),
    "card_leaf_index": new.get("card_leaf_index"), "charter_sha256": pub.get("charter-sha256"),
    "genesis_ts": leaf0["ts"], "genesis_utc": datetime.datetime.fromtimestamp(leaf0["ts"], datetime.timezone.utc).isoformat(),
    "witness_name": wvkey.split("+")[0], "witness_vkey": wvkey, "retired_witness_vkey": retired,
    "discarded_bundle_sha256": v1_sha, "discarded_log_vkey": v1_log,
}
def put(name, data):
    tmp = L / (name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, L / name)
put("bundle.jcs", jcs)
put("txt-value.txt", (new["txt"] + "\n").encode())
put("readme-block.txt", f"{new['txt']}\nsha256: {new['sha256']}\n".encode())
put("genesis.json", (json.dumps(facts, indent=1) + "\n").encode())
os.replace(L / "bundle.json.new", L / "bundle.json")
print(f"   bundle sha256 {new['sha256']}; card leaf {facts['card_leaf_index']}; genesis {facts['genesis_utc']}")
print(f"   TXT value: {new['txt']}")
PY
}

stage_dns() {
  say "dns: TXT _aics.$DOMAIN carries the new bundle, TXT _aics-witness.$WITNESS_DOMAIN the new witness vkey (the token stays on the VPS)"
  need_file "$LAUNCH/txt-value.txt" "run the bundle stage"
  local wvkey txt="<NEW_TXT_VALUE>" i live wlive
  wvkey=$(witness_vkey)
  if ! dry; then
    if grep -qF "$V1_BUNDLE_SHA256" "$LAUNCH/readme-block.txt"; then die "readme-block.txt is the discarded log's bundle"; fi
    txt=$(cat "$LAUNCH/txt-value.txt")
    [ "$txt" = "$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["txt"])' "$LAUNCH/bundle.json")" ] \
      || die "txt-value.txt is not bundle.json's TXT value"
  fi
  run bash "$WORKTREE/ops/cloudflare-dns.sh" --bundle "$LAUNCH/txt-value.txt" --witness-txt "$LAUNCH/witness-vkey.txt" "$VPS_IP" \
    || die "the DNS plan was refused"
  remote "$VPS" vps_dns "$REMOTE_DIR" "$VPS_IP" "$txt" "$wvkey"
  if dry; then
    note "then: dig +short TXT _aics.$DOMAIN and _aics-witness.$WITNESS_DOMAIN @1.1.1.1 until both answer the new"
    note "values (6.5 minutes at most: the records' TTL is auto, 300 s) > $LAUNCH/txt-live.txt, witness-txt-live.txt"
    return 0
  fi
  for i in $(seq 1 78); do
    live=$(dig +short TXT "_aics.$DOMAIN" @1.1.1.1 | tr -d '" \n')
    wlive=$(txt_of "_aics-witness.$WITNESS_DOMAIN")
    if [ "$live" = "$txt" ] && [ "$wlive" = "aics-witness-vkey $wvkey" ]; then break; fi
    [ "$i" != 78 ] || die "after 6.5 minutes 1.1.1.1 answers '$live' and '$wlive' (a cached old value outlives the 300 s TTL rarely; run dns again)"
    sleep 5
  done
  printf '%s\n' "$live" > "$LAUNCH/txt-live.txt"
  printf '%s\n' "$wlive" > "$LAUNCH/witness-txt-live.txt"
  chmod 0644 "$LAUNCH/txt-live.txt" "$LAUNCH/witness-txt-live.txt"
  note "1.1.1.1 answers the new bundle and the new witness vkey (txt-live.txt, witness-txt-live.txt)"
}

stage_vantage() {
  say "vantage: the probes and the watches follow the new log and its witness"
  local log wvkey
  log=$(pub_value log '<NEW_LOG_VKEY>')
  wvkey=$(witness_vkey)
  remote "$WITNESS_HOST" witness_vantage "$log" "$wvkey" "$DISCARD_LABEL"
  remote "$VPS" vps_resume "$DISCARD_LABEL"
}

stage_docs() {
  local repo=${DOCS_REPO:-$WORKTREE}
  say "docs: README, DECISIONS, the witness README, aics-cli published_keys.py and CHANGELOG from the new facts, in $repo"
  if dry && { [ ! -s "$LAUNCH/bundle.json" ] || [ ! -s "$LAUNCH/genesis.json" ] || [ ! -f "$repo/README.md" ]; }; then
    note "rewrites in $repo, from $LAUNCH/bundle.json, genesis.json and logged.json:"
    note "  README.md: the genesis statement, the trust-bundle block, aics-cli 0.1.1, the client digest, the Status"
    note "  docs/DECISIONS.md: rows 20 and 30 marked; the relaunch row with the new facts"
    note "  ops/witness/README.md: the witness identity in use, and that w1 is retired"
    note "  packages/aics-cli/src/aics_cli/published_keys.py: AICS_TRUST_BUNDLE and AICS_TRUST_BUNDLE_SHA256"
    note "  packages/aics-cli/CHANGELOG.md: the 0.1.1 date and digest; docs/astra_*.md: a superseded banner"
    return 0
  fi
  need_file "$LAUNCH/bundle.json" "run the bundle stage"
  docs_py | py "$repo" "$LAUNCH" "$HF_REVISION" "$DRY" "$V1_BUNDLE_SHA256" "$V1_LOG_VKEY" "$V1_WITNESS_VKEY" \
    || die "the docs rewrite stopped (see above)"
  dry && return 0
  if [ "$SKIP_CLI_TESTS" = 1 ]; then
    note "skipped: the aics-cli published_keys tests (--skip-cli-tests)"
  else
    run_in "$repo/packages/aics-cli" uv run --quiet pytest -q tests/test_published_keys.py
  fi
  note "review the diff above; then the main session commits it, puts it on the newest main and pushes it:"
  note "  git -C $(q "$repo") add README.md docs/DECISIONS.md docs/astra_remaining_pushes.md docs/astra_finish_the_job.md \\"
  note "      ops/witness/README.md packages/aics-cli/src/aics_cli/published_keys.py packages/aics-cli/CHANGELOG.md"
  note "  git -C $(q "$repo") commit -m 'relaunch: the trust bundle of the second genesis in the README, DECISIONS and aics-cli 0.1.1'"
  note "  git -C $(q "$repo") fetch origin && git -C $(q "$repo") rebase origin/main && git -C $(q "$repo") push origin HEAD:main"
  note "then, in this order: tag v0.3.1 (aics-cli 0.1.1 on PyPI, docs/RELEASING.md), yank aics-cli 0.1.0, and only then"
  note "deploy the site from that main (bash ops/sync-docs.sh deploy/docs-public && bash deploy/deploy-vps.sh $VPS): the"
  note "served DECISIONS says 0.1.1 is on PyPI and 0.1.0 is yanked. Deploy only if git diff <the prep commit> HEAD --"
  note "packages/aics-identity packages/aics-tlog packages/aics-witness packages/aics-server deploy/Dockerfile"
  note "deploy/requirements.txt deploy/build-requirements.txt is empty: the image stays the one the card's reports ran on"
}

stage_verify() {
  say "verify: a fresh CLI home from DNS + the README block; card, checkpoint, consistency; uptime; whole chain; the witness"
  need_file "$LAUNCH/readme-block.txt" "run the bundle stage"
  # The CLI of the checkout the docs stage rewrote: aics holds every policy against its own constant.
  local cliroot="${DOCS_REPO:-$WORKTREE}/packages/aics-cli"
  local home="$LAUNCH/home" keys="$cliroot/src/aics_cli/published_keys.py" sha log wvkey
  log=$(pub_value log '<NEW_LOG_VKEY>')
  wvkey=$(witness_vkey)
  if ! dry; then
    sha=$(sed -n 's/^sha256: //p' "$LAUNCH/readme-block.txt")
    grep -qF "'$sha'" "$keys" || die "$keys does not carry the new bundle: run the docs stage first (aics holds every policy against the package's constant)"
    if [ -f "$home/policy.toml" ] && ! grep -qF "$sha" "$home/policy.toml"; then
      mv "$home" "$home.$DISCARD_LABEL.$(date -u +%Y%m%dT%H%M%SZ)"
      note "a CLI home of another bundle was moved aside"
    fi
  fi
  local cli=(uv run --quiet aics --home "$home")
  if dry || [ ! -f "$home/policy.toml" ]; then
    run_in "$cliroot" "${cli[@]}" policy init --from-dns "$DOMAIN" --bundle "$LAUNCH/readme-block.txt" \
      || die "aics policy init refused (its evidence is above)"
  fi
  run_in "$cliroot" "${cli[@]}" verify card || die "aics verify card failed"
  run_in "$cliroot" "${cli[@]}" verify checkpoint || die "aics verify checkpoint failed (is the witness cosigning?)"
  run_in "$cliroot" "${cli[@]}" verify consistency || die "aics verify consistency failed"
  run env AICS_API_BASE_URL="$API" AICS_DISK_CHECK=0 AICS_WITNESS_VKEY_FILE="$LAUNCH/witness-vkey.txt" \
    AICS_LOG_VKEY_FILE="$LAUNCH/log.vkey" bash "$WORKTREE/ops/uptime-check.sh" \
    || die "ops/uptime-check.sh exited $? (its codes: ops/uptime-check.sh header)"
  run fetch -o "$LAUNCH/checkpoint-verify.txt" "$API/checkpoint" || die "$API/checkpoint does not answer"
  run_in "$WORKTREE/packages/aics-tlog" uv run --quiet aics-tlog verify-checkpoint --note "$LAUNCH/checkpoint-verify.txt" \
    --origin "$ORIGIN" --log-key "$log" --witness-key "$wvkey" --quorum 1 --max-age 300 \
    || die "the checkpoint does not verify at quorum 1 with the witness's cosignature"
  printf '   $ the served one-file client against the worktree copy and the README digest\n'
  printf '   $ the witness page %s/vkey.txt and TXT _aics-witness.%s against %s\n' "$WITNESS_URL" "$WITNESS_DOMAIN" "$(q "$wvkey")"
  printf '   $ the staging checkpoint still names test.wesupport-ai.com/tiles\n'
  dry && return 0
  local served here
  served=$(fetch "$SITE/static/aics_client.py" | python3 -I -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')
  here=$(sha256_of "$WORKTREE/packages/aics-server/src/aics_server/static/aics_client.py")
  [ "$served" = "$here" ] || die "the served client ($served) is not the worktree's ($here)"
  grep -qF "$served" "${DOCS_REPO:-$WORKTREE}/README.md" || die "the README does not name the served client's digest $served"
  [ "$(fetch "$WITNESS_URL/vkey.txt" | head -n 1)" = "$wvkey" ] || die "$WITNESS_URL/vkey.txt does not serve $wvkey"
  [ "$(txt_of "_aics-witness.$WITNESS_DOMAIN")" = "aics-witness-vkey $wvkey" ] || die "TXT _aics-witness.$WITNESS_DOMAIN does not name $wvkey (run dns)"
  [ "$(fetch "$STAGING_CHECKPOINT" | head -n 1)" = test.wesupport-ai.com/tiles ] || die "the staging checkpoint does not name test.wesupport-ai.com/tiles"
  note "verified: card, checkpoint, consistency, uptime, the whole chain at quorum 1, the witness's page and TXT, the served client; staging untouched"
}

stage_plan() {
  usage | awk '/^Stages, in order/ {on = 1} /^Options:/ {exit} on'
  cat <<'PLAN'
After the stages (the main session; docs/internal/relaunch-2026-10-20.md has the exact commands):
  1. commit what the docs stage wrote, rebase it onto the newest main, push it
  2. aics-cli 0.1.1 on PyPI: PUBLISH_PYPI=true and PYPI_ONLY_PROJECT=aics-cli, tag v0.3.1, then
     PUBLISH_PYPI=false and the selector cleared (docs/RELEASING.md, "The relaunch of 2026-10-20")
  3. yank aics-cli 0.1.0 on pypi.org (reason: the trust bundle of the discarded 2026-10-19 log)
  4. only then deploy the site from that main (sync-docs, deploy-vps.sh): its DECISIONS says 0.1.1
     is on PyPI and 0.1.0 is yanked
  5. AICS-public refreshed from main (README, SHA256SUMS, the client digest) right after 3, without
     waiting for 6; a Software Heritage visit
  6. a Hugging Face revision of wesupport-ai/aics-public-log for the new log, then docs
     --hf-revision, a commit, and AICS-public once more
PLAN
}

# The docs rewrite (stage docs), from the launch-dir facts only; running it twice changes nothing.
docs_py() { cat <<'PY'
import base64, datetime, difflib, hashlib, json, os, re, sys, tempfile, textwrap
from pathlib import Path
from zoneinfo import ZoneInfo

repo, launch, hf_rev, dry, v1_sha, v1_log, v1_wvkey = sys.argv[1:8]
repo, launch, dry = Path(repo), Path(launch), dry == "1"

def stop(msg):
    sys.exit(f"relaunch-genesis: STOP: docs: {msg}")

def need(path):
    if not path.is_file():
        stop(f"{path} is missing")
    return path

bundle = json.loads(need(launch / "bundle.json").read_text(encoding="utf-8"))
facts = json.loads(need(launch / "genesis.json").read_text(encoding="utf-8"))
card_bytes = need(launch / "logged.json").read_bytes()
card = json.loads(card_bytes)
jcs = bundle["bundle_jcs"].encode("utf-8")
sha = bundle["sha256"]
if hashlib.sha256(jcs).hexdigest() != sha:
    stop("bundle.json: sha256 is not the digest of bundle_jcs")
if sha == v1_sha:
    stop(f"the bundle is the discarded log's ({v1_sha}): nothing to publish")
b = json.loads(jcs)
if b.get("log_vkey") == v1_log:
    stop("the bundle names the discarded log key")
txt = "aics1=" + base64.urlsafe_b64encode(jcs).decode().rstrip("=")
if bundle.get("txt") != txt:
    stop("bundle.json: the TXT value is not these bundle bytes")
if hashlib.sha256(card_bytes).hexdigest() != b["bootstrap_card_hash"]:
    stop("logged.json is not the card the bundle pins")

utc = datetime.datetime.fromtimestamp(int(facts["genesis_ts"]), datetime.timezone.utc)
ath = utc.astimezone(ZoneInfo("Europe/Athens"))
day_long, day_iso = f"{utc.day} {utc:%B %Y}", utc.date().isoformat()
hm_utc, hm_ath = utc.strftime("%H:%M"), ath.strftime("%H:%M")
by_status = {}
for a in card.get("assurances") or []:
    by_status.setdefault(a.get("status"), []).append(a.get("id"))
wp = card.get("witness_policy") or {}
quorum = wp.get("quorum", 0)
witnesses = wp.get("witnesses") or []
v1_wname = v1_wvkey.split("+")[0]
if quorum < 1 or not witnesses:
    stop("the card names no witness at a positive quorum: not the first card of the relaunch")
wname, wvkey = witnesses[0].get("name"), witnesses[0].get("vkey")
if any(w.get("name") == v1_wname or w.get("vkey") == v1_wvkey for w in witnesses):
    stop(f"the card lists the retired witness {v1_wname}")
v1_name, v1_keyid = v1_log.split("+")[0], v1_log.split("+")[1]
card_leaf = facts.get("card_leaf_index")
WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine"}
card_leaf_text = WORDS.get(card_leaf, str(card_leaf))

def series(ids):
    ids = list(ids or [])
    if not ids:
        return "none"
    return ids[0] if len(ids) == 1 else ", ".join(ids[:-1]) + " and " + ids[-1]

def para(text):
    return textwrap.fill(" ".join(text.split()), width=86, break_long_words=False, break_on_hyphens=False)

def one(text, pattern, new, what, flags=re.M | re.S):
    found = list(re.finditer(pattern, text, flags))
    if len(found) != 1:
        stop(f"{what}: its anchor matched {len(found)} times, not once (did the text change? update ops/relaunch-genesis.sh)")
    m = found[0]
    return text[:m.start()] + new + text[m.end():]

changed = []
def write(rel, new):
    path = repo / rel
    old = path.read_text(encoding="utf-8")
    if old == new:
        print(f"   {rel}: unchanged")
        return
    sys.stdout.writelines(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{rel}", f"b/{rel}"))
    changed.append(rel)
    if dry:
        return
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(new)
    os.chmod(tmp, path.stat().st_mode & 0o777)
    os.replace(tmp, path)

# -- docs/DECISIONS.md: rows 20 and 30 marked; the relaunch row (the next free number)
rel = "docs/DECISIONS.md"
dec = need(repo / rel).read_text(encoding="utf-8")
TITLE = "**Relaunch: a second genesis before any outside agent used the log**"
mine = re.search(r"^\| (\d+) \| " + re.escape(TITLE), dec, re.M)
row = int(mine.group(1)) if mine else max(int(n) for n in re.findall(r"^\| (\d+) \| ", dec, re.M)) + 1

def mark(text, number, title, marker, sentence):
    m = re.search(r"^\| " + str(number) + r" \| " + re.escape(title) + r".*$", text, re.M)
    if not m:
        stop(f"{rel}: row {number} ({title}) not found")
    line = m.group(0)
    if marker in line:
        return text
    cut = line.rstrip().rfind("|")
    return text[:m.start()] + line[:cut].rstrip() + " " + sentence + " |" + text[m.end():]

dec = mark(dec, 20, "**Production genesis: when and with what**", "**Discarded on",
           f"**Discarded on {day_iso} (row {row}):** this log was discarded before any outside agent had used it; a second "
           "genesis on the same origin name replaced it, and the facts above are void.")
dec = mark(dec, 30, "**External witnesses**", f"**Relaunch (row {row}):**",
           f"**Relaunch (row {row}):** the first card of the second log lists a new identity of the founder-run witness, "
           f"`{wname}`, at quorum {quorum} from the start. `{v1_wname}`, which cosigned the discarded log, is retired with it "
           "(a cosignature names the origin, not the log key, so one key must never witness both logs), and the successor "
           "card of the discarded log (leaf 2 above) is void.")
quote = ("We have yet to actually and really launch the service. 0 visits = noone has seen us yet. Use this fact to "
         "expedite a build that has everything that we have build so far without long waits. You can touch public, "
         "update everything, start over if you want.")
row_line = (
    f"| {row} | {TITLE} | No outside agent had used the log started on 2026-10-19: the owner's statistics showed no "
    "agent-signed request before the decision, and its agent-type leaves and refused attempts were our own test and "
    "conformance runs. Its bootstrap card had quorum 0, the successor that names the witness (row 30) could "
    "take effect only on 2026-11-18, and the logged card hashed a privacy text the site no longer served. The 30-day "
    "notice protects agents who rely on a log; this one had none. | A★ Discard that log and run genesis again on the "
    "same origin name: a new server seed (new log and policy keys), the same owner key, a new identity of the "
    "founder-run witness (the one that cosigned the discarded log is retired with it), a first card that names it at "
    "quorum 1, the current legal texts and every row a conformance report proves; publish the new trust bundle wherever "
    "the old one was, and say what happened. B Keep the log and wait for 2026-11-18. "
    f"| **A (owner, 2026-10-20):** \"{quote}\" **Done {day_iso} {hm_utc} UTC:** leaf 0 pins charter sha256 "
    f"{facts['charter_sha256']}, owner kid {b['owner_kid']} (unchanged), policy kid {b['policy_kid']}, log vkey "
    f"{b['log_vkey']}; the card is leaf {card_leaf} (hash {b['bootstrap_card_hash']}, witness {wvkey} at quorum "
    f"{quorum}, proven: {series(by_status.get('proven'))}); trust bundle sha256 {sha} in TXT `_aics`, the README and "
    f"aics-cli 0.1.1. Void since then: the 2026-10-19 bundle {v1_sha}, the log key {v1_log}, the witness {v1_wvkey} "
    "(retired), aics-cli 0.1.0 (yanked) and Hugging Face revision 6a209839. |")
if mine:
    dec = one(dec, r"^\| " + str(row) + r" \| " + re.escape(TITLE) + r".*$", row_line, f"{rel}: row {row}", re.M)
else:
    last = list(re.finditer(r"^\| \d+ \| .*$", dec, re.M))[-1]
    dec = dec[:last.end()] + "\n" + row_line + dec[last.end():]
write(rel, dec)

# -- README.md
rel = "README.md"
text = need(repo / rel).read_text(encoding="utf-8")
client = need(repo / "packages/aics-server/src/aics_server/static/aics_client.py")
client_version = re.search(r'^__version__ = "([^"]+)"', client.read_text(encoding="utf-8"), re.M).group(1)
client_sha = hashlib.sha256(client.read_bytes()).hexdigest()
text = one(text, r"^AICS is the protocol\. wesupport-ai\.com is the instance that runs it\.\n.*?(?=\n\n## Published resources)",
           "AICS is the protocol. wesupport-ai.com is the instance that runs it.\n" + para(f"""
Production genesis happened on {day_long} at {hm_ath} Athens time ({hm_utc} UTC), with origin
`api.wesupport-ai.com/tiles`. The trust bundle is published below, in DNS and in `aics-cli 0.1.1`
on PyPI. An earlier log on the same origin, started on 19 October 2026, was discarded on
{day_long} before any outside agent had used it; see Status below. Six Python packages, the Node client
and the MCP registry entry are public."""), "README: the introduction")
text = re.sub(r"\[aics-cli 0\.1\.\d+\]\(https://pypi\.org/project/aics-cli/0\.1\.\d+/\)",
              "[aics-cli 0.1.1](https://pypi.org/project/aics-cli/0.1.1/)", text)
text = one(text, r"^- \[CLI installation and verification guide\]\(packages/aics-cli/README\.md\)\n  — [^\n]*\n",
           "- [CLI installation and verification guide](packages/aics-cli/README.md)\n"
           "  — `aics-cli 0.1.1` carries the trust bundle of this log.\n", "README: the CLI guide item")
if hf_rev:
    hf = (f"- [Production public-log snapshot](https://huggingface.co/datasets/wesupport-ai/aics-public-log/tree/{hf_rev})\n"
          "  — a verified export of this log with its signed checkpoint, trust bundle and log\n"
          "  proofs; its dataset card states the checkpoint and the number of rows. Earlier\n"
          f"  revisions describe the disposable PILOT log and the log discarded on {day_long};\n"
          "  none of these snapshots is a training corpus.\n")
else:
    hf = ("- [Public-log dataset](https://huggingface.co/datasets/wesupport-ai/aics-public-log)\n"
          "  — its revisions so far describe the disposable PILOT log and the log discarded on\n"
          f"  {day_long}; an export of this log follows. None of them is a training corpus.\n")
text = one(text, r"^- \[(?:Production public-log snapshot|Public-log dataset)\]\(https://huggingface\.co/datasets/wesupport-ai/aics-public-log[^)]*\)\n(?:  [^\n]*\n)+", hf, "README: the public-log item")
text = one(text, r"^- \[Software Heritage source archive\]\([^)]*\)\n(?:  [^\n]*\n)+",
           "- [Software Heritage source archive](https://archive.softwareheritage.org/browse/origin/directory/?origin_url=https://github.com/petros-poli/AICS-public)\n"
           "  — archives of the public source repository; snapshots taken before\n"
           f"  {day_long} carry the discarded log's trust bundle.\n", "README: the Software Heritage item")
text = one(text, r'python -m pip install "aics-cli==0\.1\.\d+"', 'python -m pip install "aics-cli==0.1.1"', "README: the install line")
text = one(text, r"^2\. A constant in \[`aics-cli 0\.1\.\d+` on PyPI\]\(https://pypi\.org/project/aics-cli/0\.1\.\d+/\)",
           "2. A constant in [`aics-cli 0.1.1` on PyPI](https://pypi.org/project/aics-cli/0.1.1/)", "README: source 2")
text = one(text, r"^    AICS trust bundle \(AICS-1 §6\.4\)[^\n]*\n    aics1=[A-Za-z0-9_-]+\n    sha256: [0-9a-f]{64}\n",
           f"    AICS trust bundle (AICS-1 §6.4) — published {day_iso}, the same bytes as the DNS record _aics.wesupport-ai.com:\n"
           f"    {txt}\n    sha256: {sha}\n", "README: the trust-bundle block")
text = one(text, r"^The \[CLI implementation and guide\]\(packages/aics-cli/README\.md\)\s+describe\s+the\s.*?does\s+not\s+establish\s+production\s+trust\.\n",
           para("""The [CLI implementation and guide](packages/aics-cli/README.md) describe the
`aics-cli` distribution and its `aics` command. Version 0.1.1 carries this trust bundle. Version
0.1.0 carried the discarded log's bundle; it is yanked from PyPI, and with it installed `aics
policy init` stops with exit 2, because DNS disagrees with the package. Verification still
requires independently authenticated key material; a key supplied by the server itself does not
establish production trust.""") + "\n", "README: the CLI paragraph")
text = one(text, r"^The served \[one-file client\]\(https://wesupport-ai\.com/static/aics_client\.py\),\nversion [^,\n]+, has SHA-256\n`[0-9a-f]{64}`\.",
           f"The served [one-file client](https://wesupport-ai.com/static/aics_client.py),\nversion {client_version}, has SHA-256\n`{client_sha}`.",
           "README: the client digest")
status = "\n\n".join([f"## Status: production online — relaunched {day_long}", para(f"""
The website, HTTPS API and text gate are deployed with valid TLS. The log identifies itself as
`api.wesupport-ai.com/tiles`: genesis was written on {day_long} at {hm_ath} Athens time ({hm_utc}
UTC), with the charter at leaf zero and no seeded content (decision 6), and the assurance card at
leaf {card_leaf_text}. The card lists the founder-run witness `{wname}` at quorum {quorum}: it runs on
another provider than the log but belongs to the same operator: a client accepts a checkpoint as
current only with its fresh cosignature, which proves freshness, not independence. Its vkey is in the card and in the DNS TXT record
`_aics-witness.{wname.split('/')[0]}`. Proven on the card:
{series(by_status.get('proven'))}; promised: {series(by_status.get('promised'))}. The trust bundle
above is published in DNS, this repository and `aics-cli 0.1.1` on PyPI. Pin keys from
authenticated out-of-band sources, never from the server alone."""), para(f"""
An earlier log under the same origin name ran from 19 October 2026, 16:06 UTC, until {day_long}.
No outside agent had used it: its agent-type leaves and refused attempts were our own test and
conformance runs. It was discarded so that the first card could carry everything built so far
instead of waiting out a 30-day notice period ([docs/DECISIONS.md](docs/DECISIONS.md), row {row}).
The server seed was replaced, so the log and policy keys are new; the owner key stayed the same.
Nothing from the earlier log is valid for this one: not its trust bundle (sha256
`{v1_sha[:8]}…`), not the `aics-cli 0.1.0` constant that carried it, not its public-log
snapshot, and not any checkpoint signed by its log key (`{v1_name}+{v1_keyid}+…`). Its witness,
`{v1_wname}`, cosigned checkpoints of that log and was retired with it: a cosignature names the
origin, not the log key, so this log's witness is a new identity with its own key, and no witness
key vouches for both histories."""),
para("""
Six Python packages and the Node client are published, and the MCP Registry entry is active. The
reviewed public source is available at [petros-poli/AICS-public](https://github.com/petros-poli/AICS-public).
Public packages and source do not prove live deployment conformance, witness independence, or the
absence of split views. What is not yet proven remains stated on the card.""")]) + "\n\n"
text = one(text, r"^## Status:.*?(?=^## Repository map)", status, "README: the Status section")
if re.search(r"aics-cli/0\.1\.0/|aics-cli==0\.1\.0|`aics-cli 0\.1\.0` carries", text):
    stop("README: a link to or a recommendation of aics-cli 0.1.0 is left")
write(rel, text)

# -- ops/witness/README.md: the identity the host runs
rel = "ops/witness/README.md"
page = need(repo / rel).read_text(encoding="utf-8")
page = one(page, r"^\| Name \(permanent, part of the vkey\) \| .*$",
           f"| Name (permanent, part of the vkey) | `{wname}`, since {day_iso}. `{v1_wname}` cosigned the log discarded that "
           f"day and is retired: its config, key and database are in the volume's `retired-{v1_wname.rsplit('/', 1)[-1]}/`, "
           "never used again |", f"{rel}: the host table's name row", re.M)
write(rel, page)

# -- the aics-cli constant
rel = "packages/aics-cli/src/aics_cli/published_keys.py"
keys = need(repo / rel).read_text(encoding="utf-8")
if not re.search(r"^PLACEHOLDER = False$", keys, re.M):
    stop(f"{rel}: PLACEHOLDER = False is missing")
keys = one(keys, r"^AICS_TRUST_BUNDLE: bytes \| None = .*$", f"AICS_TRUST_BUNDLE: bytes | None = {jcs!r}", f"{rel}: the bundle", re.M)
keys = one(keys, r"^AICS_TRUST_BUNDLE_SHA256: str \| None = .*$", f"AICS_TRUST_BUNDLE_SHA256: str | None = '{sha}'", f"{rel}: the digest", re.M)
keys = one(keys, r'^PLACEHOLDER was True until.*?(?=^""")', f"""PLACEHOLDER was True until the first production genesis of 2026-10-19; while it
is True the constant is ``None`` and ``aics policy init`` and ``aics policy diff``
report it as "placeholder" - not published, never counted as agreement.
aics-cli 0.1.0 carried the bundle of that log (sha256 {v1_sha[:8]}...).  The log was
discarded on {day_iso} before any outside agent had used it, and a second genesis on the same
origin started a log with new log and policy keys (docs/DECISIONS.md row {row}); 0.1.0
is yanked, and with it installed ``aics policy init`` refuses the new DNS record
(exit 2).  Since 0.1.1 both constants carry the bundle of the second log (bytes
exactly as in DNS and the README) and ``PLACEHOLDER`` is False.  Every command holds
the pinned policy against it (by domain, or by log origin when the policy has no
domain) and refuses a policy it contradicts; and ``policy init --from-dns`` alone
meets the default of two independent key sources.
""", f"{rel}: the docstring")
write(rel, keys)

# -- the aics-cli changelog
rel = "packages/aics-cli/CHANGELOG.md"
log = need(repo / rel).read_text(encoding="utf-8")
log = one(log, r"^## 0\.1\.1 — [^\n]*$", f"## 0.1.1 — {day_iso}", f"{rel}: the 0.1.1 heading", re.M)
log = one(log, r"The new bundle's SHA-256 is [^\n]*$", f"The new bundle's SHA-256 is `{sha}`.", f"{rel}: the digest", re.M)
write(rel, log)

# -- the historical publication records
banner = (f"> **Superseded on {day_iso}.** The log described here (log key `{v1_log}`, trust bundle sha256 "
          f"`{v1_sha}`) was discarded at the relaunch before any outside agent had used it; its bundle, `aics-cli 0.1.0` and "
          f"Hugging Face revision 6a209839 are void (docs/DECISIONS.md row {row}). Kept as the historical record.\n")
for rel in ("docs/astra_remaining_pushes.md", "docs/astra_finish_the_job.md"):
    path = repo / rel
    if not path.is_file():
        print(f"   {rel}: not in this checkout")
        continue
    page = path.read_text(encoding="utf-8")
    if "> **Superseded on " not in page:
        head, _, rest = page.partition("\n")
        page = head + "\n\n" + banner + rest
    write(rel, page)

print(f"   docs: {len(changed)} file(s) {'would change' if dry else 'changed'}: {', '.join(changed) or 'none'}; "
      f"DECISIONS row {row}; bundle sha256 {sha}")
PY
}

# -- arguments ------------------------------------------------------------------------------------
DRY=0 PRINT_ONLY=0 WITNESS_SYNC=0 SKIP_CLI_TESTS=0 PREAMBLE_SHOWN=0
LAUNCH=$HOME/aics-launch
TMPBASE=${TMPDIR:-/tmp}
WORKTREE=${TMPBASE%/}/aics-relaunch-w
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
DOCS_REPO="" CUSTODY="" OWNER_KEY="" CUSTODIAN_NAME="" CUSTODIAN_HOLDS="" HF_REVISION="" SHOW_REMOTE="" DISCARD_SIZE=""
VPS=wesupport-vps VPS_IP=148.113.238.39 WITNESS_HOST=aics-trials REMOTE_DIR=/opt/wesupport-ai
WITNESS_NAME=$WITNESS_NAME_DEFAULT WITNESS_VKEY_ARG="" RETIRE_WITNESS_VKEY=$V1_WITNESS_VKEY
DISCARD_LOG_VKEY=$V1_LOG_VKEY SEED_NAME=$SEED_NAME_DEFAULT
CARD_SETS=()
stages=()
value_of() { [ "$#" -ge 2 ] && [ -n "$2" ] || usage_error "$1 needs a value"; }
while [ "$#" -gt 0 ]; do
  case $1 in
    --dry-run) DRY=1; shift ;;
    --print-only) PRINT_ONLY=1; shift ;;
    --witness-sync) WITNESS_SYNC=1; shift ;;
    --skip-cli-tests) SKIP_CLI_TESTS=1; shift ;;
    --launch-dir) value_of "$@"; LAUNCH=$2; shift 2 ;;
    --worktree) value_of "$@"; WORKTREE=$2; shift 2 ;;
    --repo) value_of "$@"; REPO=$2; shift 2 ;;
    --docs-repo) value_of "$@"; DOCS_REPO=$2; shift 2 ;;
    --custody-dir) value_of "$@"; CUSTODY=$2; shift 2 ;;
    --seed-name) value_of "$@"; SEED_NAME=$2; shift 2 ;;
    --discard-size) value_of "$@"; DISCARD_SIZE=$2; shift 2 ;;
    --owner-key) value_of "$@"; OWNER_KEY=$2; shift 2 ;;
    --custodian-name) value_of "$@"; CUSTODIAN_NAME=$2; shift 2 ;;
    --custodian-holds) value_of "$@"; CUSTODIAN_HOLDS=$2; shift 2 ;;
    --card-set)
      value_of "$@"
      case $2 in [A-Z]*=*) CARD_SETS+=("$2") ;; *) usage_error "--card-set takes NAME=VALUE" ;; esac
      shift 2 ;;
    --witness-name) value_of "$@"; WITNESS_NAME=$2; shift 2 ;;
    --witness-vkey) value_of "$@"; WITNESS_VKEY_ARG=$2; shift 2 ;;
    --retire-witness-vkey) value_of "$@"; RETIRE_WITNESS_VKEY=$2; shift 2 ;;
    --discard-log-vkey) value_of "$@"; DISCARD_LOG_VKEY=$2; shift 2 ;;
    --hf-revision) value_of "$@"; HF_REVISION=$2; shift 2 ;;
    --vps) value_of "$@"; VPS=$2; shift 2 ;;
    --vps-ip) value_of "$@"; VPS_IP=$2; shift 2 ;;
    --witness-host) value_of "$@"; WITNESS_HOST=$2; shift 2 ;;
    --remote-dir) value_of "$@"; REMOTE_DIR=$2; shift 2 ;;
    --show-remote) value_of "$@"; SHOW_REMOTE=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; stages+=("$@"); break ;;
    -*) usage_error "unknown option $1" ;;
    *) stages+=("$1"); shift ;;
  esac
done
if [ -n "$SHOW_REMOTE" ]; then
  remote_script "$SHOW_REMOTE"
  exit 0
fi
[ "${#stages[@]}" -gt 0 ] || usage_error "no stage given"
for s in "${stages[@]}"; do
  case " $STAGES all plan " in *" $s "*) ;; *) usage_error "unknown stage '$s' (one of: $STAGES, all, plan)" ;; esac
  if [ "$s" = all ] && [ "$DRY" != 1 ]; then usage_error "all runs only with --dry-run: run the real stages one at a time"; fi
done
case $VPS_IP in *[!0-9.]*|'') usage_error "--vps-ip takes an IPv4 address" ;; esac
case $HF_REVISION in *[!0-9a-f]*) usage_error "--hf-revision takes a hex commit id" ;; esac
case $DISCARD_SIZE in *[!0-9]*) usage_error "--discard-size takes a number" ;; esac
case $REMOTE_DIR in /*) ;; *) usage_error "--remote-dir takes an absolute path" ;; esac
for v in "$VPS" "$WITNESS_HOST"; do
  case $v in *[!A-Za-z0-9@._-]*|'') usage_error "a host alias holds letters, digits and @ . _ - only: $v" ;; esac
done
printf '%s' "$SEED_NAME" | grep -Eq '^server-seed-v[0-9]+\.hex$' || usage_error "--seed-name: server-seed-vN.hex, not $SEED_NAME"
printf '%s' "$WITNESS_NAME" | grep -Eq '^witness\.wesupport-ai\.com/w[0-9]+$' \
  || usage_error "--witness-name: witness.wesupport-ai.com/wN, not $WITNESS_NAME"
is_vkey "$RETIRE_WITNESS_VKEY" || usage_error "--retire-witness-vkey: not a vkey"
RETIRE_WITNESS_NAME=${RETIRE_WITNESS_VKEY%%+*}
for n in "${V1_WITNESS_VKEY%%+*}" "$RETIRE_WITNESS_NAME"; do
  if [ "$WITNESS_NAME" = "$n" ]; then
    usage_error "--witness-name $WITNESS_NAME is a retired identity: it cosigned a discarded log, and its old and new cosignatures would prove two histories of $ORIGIN"
  fi
done
if [ -n "$WITNESS_VKEY_ARG" ] && { ! is_vkey "$WITNESS_VKEY_ARG" || [ "${WITNESS_VKEY_ARG%%+*}" != "$WITNESS_NAME" ]; }; then
  usage_error "--witness-vkey: not a vkey of $WITNESS_NAME"
fi
if ! is_vkey "$DISCARD_LOG_VKEY" || [ "${DISCARD_LOG_VKEY%%+*}" != "$ORIGIN" ]; then
  usage_error "--discard-log-vkey: not a log vkey of $ORIGIN"
fi
if [ "$DISCARD_LOG_VKEY" = "$V1_LOG_VKEY" ]; then
  DISCARD_LABEL=$V1_LABEL DISCARD_DIR=$V1_DIR
else
  DISCARD_LABEL="discarded-$(printf '%s' "$DISCARD_LOG_VKEY" | cut -d+ -f2)"
  DISCARD_DIR=$DISCARD_LABEL
fi
WITNESS_LABEL="founder-${WITNESS_NAME##*/}"

if [ "$DRY" = 1 ]; then say "DRY RUN: every command and remote script below is printed; nothing is run"; fi
for s in "${stages[@]}"; do
  if [ "$s" = all ]; then
    for t in $STAGES; do "stage_${t//-/_}"; done
  else
    "stage_${s//-/_}"
  fi
done
