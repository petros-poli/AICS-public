#!/usr/bin/env bash
# Install the second-vantage probes on the witness host (Ubuntu 24.04, systemd).
# Run as root from a checkout of the repository on that host:
#
#   sudo ops/vantage/install.sh [--log-vkey-file FILE] [--witness-vkey-file FILE]
#                               [--generate-topic] [--prefix /opt/wesupport-ai]
#                               [--no-enable]
#
# Idempotent: rerun it after a git pull or after filling in what it asks for.
# What it does, each step skipped when already in place:
#   1. copies ops/uptime-check.sh, ops/mirror-check.sh, ops/status.sh and
#      ops/vantage/vantage-probe.sh to PREFIX/ops/ (nothing else of the repo);
#   2. builds PREFIX/vantage-venv with packages/aics-tlog (mirror-check.sh and
#      the witness's view verify signatures with it), reinstalled only when the
#      checkout's version differs;
#   3. creates /etc/default/aics-vantage (root, mode 0600) from a template
#      without a topic, and forces mode 0600 on an existing one; with
#      --generate-topic and no topic set yet, writes a random topic and prints
#      it once so the phone can subscribe;
#   4. pins the public log vkey at /etc/aics-vantage/log.vkey from
#      --log-vkey-file (a copy you obtained out of band: the _aics DNS TXT
#      record, the README, the aics-cli PyPI package; never fetched here), and
#      optionally the witness vkey at /etc/aics-vantage/witness.vkey;
#   5. installs the aics-vantage-{uptime,mirror,status} units and enables the
#      timers whose inputs exist (uptime and status: a topic; mirror: a topic and
#      the log vkey), printing what is still missing.
# It never writes a secret anywhere but the env file, never prints an existing
# topic, never touches the witness, its compose project or its key.
# Testing aids: --destdir DIR (install under DIR, no root needed),
# --no-systemctl, --skip-venv.
set -euo pipefail

PREFIX=/opt/wesupport-ai
DESTDIR=""
LOG_VKEY_SRC=""
WITNESS_VKEY_SRC=""
GENERATE_TOPIC=0
ENABLE=1
SYSTEMCTL=1
VENV=1
usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX=${2:?}; shift 2 ;;
    --destdir) DESTDIR=${2:?}; shift 2 ;;
    --log-vkey-file) LOG_VKEY_SRC=${2:?}; shift 2 ;;
    --witness-vkey-file) WITNESS_VKEY_SRC=${2:?}; shift 2 ;;
    --generate-topic) GENERATE_TOPIC=1; shift ;;
    --no-enable) ENABLE=0; shift ;;
    --no-systemctl) SYSTEMCTL=0; shift ;;
    --skip-venv) VENV=0; shift ;;
    -h|--help) usage 0 ;;
    *) printf 'install.sh: unknown argument %s\n' "$1" >&2; usage 2 ;;
  esac
done
case "$PREFIX" in /*) ;; *) printf 'install.sh: --prefix must be absolute\n' >&2; exit 2 ;; esac
if [ -z "$DESTDIR" ] && [ "$(id -u)" != 0 ]; then
  printf 'install.sh: run as root (or use --destdir for a test install)\n' >&2; exit 2
fi
SRC=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
D="$DESTDIR"
ENV_FILE="$D/etc/default/aics-vantage"
CONF_DIR="$D/etc/aics-vantage"
UNIT_DIR="$D/etc/systemd/system"
OPS="$D$PREFIX/ops"
NEED=()
changed_units=0
say() { printf 'install.sh: %s\n' "$*"; }

# 1. scripts ------------------------------------------------------------------
install -d -m 0755 "$OPS" "$OPS/vantage"
for f in uptime-check.sh mirror-check.sh status.sh vantage/vantage-probe.sh; do
  if [ "$SRC/ops/$f" -ef "$OPS/$f" ]; then continue; fi
  if cmp -s "$SRC/ops/$f" "$OPS/$f" 2>/dev/null; then continue; fi
  install -m 0755 "$SRC/ops/$f" "$OPS/$f"; say "installed $PREFIX/ops/$f"
done

# 2. aics-tlog venv -------------------------------------------------------------
if [ "$VENV" = 1 ]; then
  venv="$D$PREFIX/vantage-venv"
  want=$(sed -n 's/^version = "\(.*\)"/\1/p' "$SRC/packages/aics-tlog/pyproject.toml" | head -n 1)
  have=$("$venv/bin/python" -c 'import importlib.metadata as m; print(m.version("aics-tlog"))' 2>/dev/null || true)
  if [ "$have" != "$want" ]; then
    if command -v uv >/dev/null 2>&1; then
      [ -x "$venv/bin/python" ] || uv venv --quiet --python python3 "$venv"
      uv pip install --quiet --python "$venv/bin/python" "$SRC/packages/aics-tlog"
    else
      if [ ! -x "$venv/bin/python" ] && ! python3 -m venv "$venv"; then
        printf 'install.sh: python3 -m venv failed: apt-get install python3-venv (or install uv), then rerun\n' >&2; exit 1
      fi
      "$venv/bin/python" -m pip install --quiet --upgrade "$SRC/packages/aics-tlog"
    fi
    say "aics-tlog $want installed in $PREFIX/vantage-venv"
  fi
  "$venv/bin/aics-tlog" --help >/dev/null || { printf 'install.sh: %s/bin/aics-tlog does not run\n' "$venv" >&2; exit 1; }
fi

# 3. env file (the only place the topic lives) ---------------------------------
install -d -m 0755 "$D/etc/default"
if [ ! -f "$ENV_FILE" ]; then
  (umask 077; cat > "$ENV_FILE" <<'EOF'
# /etc/default/aics-vantage: EnvironmentFile of the aics-vantage-* units.
# Root-only (mode 0600): NTFY_TOPIC is the secret that lets anyone post to the
# owner's phone. Never commit this file or copy it into the repository.
NTFY_TOPIC=
NTFY_URL=https://ntfy.sh
# Optional overrides (defaults in ops/vantage/vantage-probe.sh):
# AICS_API_BASE_URL=https://api.wesupport-ai.com
# AICS_TILES_BASE=https://tiles.wesupport-ai.com/tiles
# AICS_LOG_ORIGIN=api.wesupport-ai.com/tiles
# AICS_VANTAGE_WITNESS_URL=http://127.0.0.1:7380
# AICS_VANTAGE_WITNESS_MAX_LAG=1800
# AICS_CHECKPOINT_MAX_AGE=240
EOF
  )
  say "created $ENV_FILE (mode 0600)"
fi
chmod 0600 "$ENV_FILE"
[ -n "$DESTDIR" ] || chown root:root "$ENV_FILE"
topic=$(sed -n 's/^NTFY_TOPIC=//p' "$ENV_FILE" | tail -n 1 | tr -d '"'"'"' ')
if [ -z "$topic" ] && [ "$GENERATE_TOPIC" = 1 ]; then
  topic="aics-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  tmp="$ENV_FILE.tmp"
  (umask 077; sed "s|^NTFY_TOPIC=.*|NTFY_TOPIC=$topic|" "$ENV_FILE" > "$tmp")
  grep -q "^NTFY_TOPIC=$topic\$" "$tmp" || printf 'NTFY_TOPIC=%s\n' "$topic" >> "$tmp"
  chmod 0600 "$tmp"; mv "$tmp" "$ENV_FILE"
  say "generated an ntfy topic; subscribe the phone's ntfy app to it now (shown once, kept only in $ENV_FILE):"
  printf '\n    %s\n\n' "$topic"
fi
[ -n "$topic" ] || NEED+=("an ntfy topic: put NTFY_TOPIC=<topic> in /etc/default/aics-vantage (the topic the phone already subscribes to for the first-contact watch, or rerun with --generate-topic for a new one), then rerun")

# 4. pinned vkeys (public) -------------------------------------------------------
install -d -m 0755 "$CONF_DIR"
pin() { # source, target, what
  local line
  line=$(head -n 1 "$1" | tr -d '\r')
  printf '%s' "$line" | grep -Eq '^[^+[:space:]]+\+[0-9a-f]{8}\+[A-Za-z0-9+/]+=*$' \
    || { printf 'install.sh: %s does not hold a vkey (<name>+<8 hex>+<base64>)\n' "$1" >&2; exit 2; }
  if [ "$(cat "$2" 2>/dev/null)" != "$line" ]; then
    [ ! -f "$2" ] || say "replacing the pinned $3 in $2 (was: $(cat "$2"))"
    printf '%s\n' "$line" > "$2.tmp"; chmod 0644 "$2.tmp"; mv "$2.tmp" "$2"
    say "pinned $3: $line"
  fi
}
[ -z "$LOG_VKEY_SRC" ] || pin "$LOG_VKEY_SRC" "$CONF_DIR/log.vkey" "log vkey"
[ -z "$WITNESS_VKEY_SRC" ] || pin "$WITNESS_VKEY_SRC" "$CONF_DIR/witness.vkey" "witness vkey"
have_vkey=0
[ -s "$CONF_DIR/log.vkey" ] && have_vkey=1
[ "$have_vkey" = 1 ] || NEED+=("the log vkey for the mirror check: copy it out of band (the log_vkey in the _aics TXT record's trust bundle, the README, the aics-cli package) into a file and rerun with --log-vkey-file FILE")
[ -s "$CONF_DIR/witness.vkey" ] || say "optional: --witness-vkey-file FILE (the vkey 'aics-witness status' prints) makes the witness's view verify its cosignature too"

# 5. units ------------------------------------------------------------------------
install -d -m 0755 "$UNIT_DIR"
for u in "$SRC"/ops/vantage/systemd/aics-vantage-*; do
  tgt="$UNIT_DIR/$(basename "$u")"
  sed "s|/opt/wesupport-ai|$PREFIX|g" "$u" > "$tgt.tmp"
  if cmp -s "$tgt.tmp" "$tgt" 2>/dev/null; then rm -f "$tgt.tmp"
  else chmod 0644 "$tgt.tmp"; mv "$tgt.tmp" "$tgt"; changed_units=1; say "installed $(basename "$u")"; fi
done
if [ "$SYSTEMCTL" = 1 ]; then
  [ "$changed_units" = 0 ] || systemctl daemon-reload
  if [ "$ENABLE" = 1 ]; then
    timers=()
    [ -z "$topic" ] || timers+=(aics-vantage-uptime.timer aics-vantage-status.timer)
    [ -z "$topic" ] || [ "$have_vkey" = 0 ] || timers+=(aics-vantage-mirror.timer)
    for t in ${timers[@]+"${timers[@]}"}; do
      systemctl is-enabled --quiet "$t" 2>/dev/null && systemctl is-active --quiet "$t" && continue
      systemctl enable --now "$t"; say "enabled $t"
    done
  fi
fi

if [ ${#NEED[@]} -gt 0 ]; then
  say "still needed:"
  for n in "${NEED[@]}"; do printf '  - %s\n' "$n"; done
else
  say "done. First runs: systemctl start aics-vantage-uptime.service aics-vantage-mirror.service; journalctl -u 'aics-vantage-*' -n 50"
  say "a test notification: systemctl start aics-vantage-status.service (the daily summary, sent now)"
fi
