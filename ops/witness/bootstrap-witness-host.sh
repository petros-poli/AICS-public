#!/usr/bin/env bash
# Set up (or re-check) the founder-run witness of wesupport-ai.com on the second
# host: ops/witness/README.md, runbook step 6. Run it ON the witness host, from
# the copy of the repository subset the README's rsync puts in ~/aics:
#
#   bash ~/aics/ops/witness/bootstrap-witness-host.sh \
#       --origin '<origin from the pinned trust bundle>' \
#       --log-vkey '<log_vkey from the pinned trust bundle>' \
#       [--initial-size N --initial-root '<base64 root>'] \
#       [--name witness.wesupport-ai.com/wN] [--domain witness.wesupport-ai.com] [--no-start]
#
# --name is needed once, for a new volume: a name never used before (a retired name, such as
# witness.wesupport-ai.com/w1, is never used again). Later runs take the name from the config in the volume.
#
# Idempotent: run it again at any time (after an rsync of new code, to re-print
# the published lines, to add a log). What it does, in order:
#   1. installs Docker only if it is absent (from Docker's apt repository, as the
#      agent-trials bootstrap does), and the compose plugin if only that is missing;
#   2. writes ops/witness/.env (WITNESS_DOMAIN, public) once; refuses a different domain later;
#   3. builds the witness image from packages/aics-tlog + packages/aics-witness;
#   4. `aics-witness init`: creates the witness key once, inside the witness_data
#      volume (mode 0600, never printed, never in git), and its database; later
#      runs only re-read it, and refuse if the key or the database went missing;
#   5. `add-log` with the origin and log vkey you pass (from the out-of-band trust
#      bundle: _aics TXT, README block, the aics-cli package; never from the API), and
#      optionally an `initial` pin for the already running log;
#   6. writes the public page (./site: index.html, vkey.txt, witness.json);
#   7. starts the witness and Caddy (Let's Encrypt HTTP-01 for the domain), or
#      reloads the log list of a running witness;
#   8. prints the lines to publish: the witness vkey, the AICS_WITNESSES value for
#      the log server's feeder, the card's witness_policy entry, the DNS TXT
#      record, and the one-time offline key backup command.
#
# It never prints, copies or uploads the witness key, never touches the trials
# containers, and never opens a firewall port (the README says which to open).
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DOMAIN_DEFAULT=witness.wesupport-ai.com

die() { printf 'bootstrap-witness-host.sh: %s\n' "$*" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
usage() { sed -n '2,35p' "$0" | sed 's/^# \{0,1\}//'; }

origin='' log_vkey='' name='' domain='' initial_size='' initial_root='' start=1
while [ $# -gt 0 ]; do
    case $1 in
        --origin) [ $# -ge 2 ] || die "--origin needs a value"; origin=$2; shift 2 ;;
        --log-vkey) [ $# -ge 2 ] || die "--log-vkey needs a value"; log_vkey=$2; shift 2 ;;
        --name) [ $# -ge 2 ] || die "--name needs a value"; name=$2; shift 2 ;;
        --domain) [ $# -ge 2 ] || die "--domain needs a value"; domain=$2; shift 2 ;;
        --initial-size) [ $# -ge 2 ] || die "--initial-size needs a value"; initial_size=$2; shift 2 ;;
        --initial-root) [ $# -ge 2 ] || die "--initial-root needs a value"; initial_root=$2; shift 2 ;;
        --no-start) start=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done
if [ -n "$origin" ] || [ -n "$log_vkey" ]; then
    [ -n "$origin" ] && [ -n "$log_vkey" ] || die "--origin and --log-vkey go together"
fi
if [ -n "$initial_size" ] || [ -n "$initial_root" ]; then
    [ -n "$initial_size" ] && [ -n "$initial_root" ] || die "--initial-size and --initial-root go together"
    [ -n "$origin" ] || die "--initial-size/--initial-root pin the log given with --origin"
    case $initial_size in ''|*[!0-9]*|0) die "--initial-size must be a whole number of at least 1" ;; esac
fi
case $origin in
    test.*|pilot.*) die "refusing $origin: a staging or pilot origin never goes into a witness (runbook step 4)" ;;
esac

# -- 0. the host and the checkout ---------------------------------------------
[ "$(uname -s)" = Linux ] || die "run this on the witness host (Linux), not on the laptop"
# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}" in
    debian) CODENAME="${VERSION_CODENAME:?}" ;;
    ubuntu) CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:?}}" ;;
    *) die "Debian or Ubuntu only (this is ${PRETTY_NAME:-unknown})" ;;
esac
for f in "$HERE/compose.yml" "$HERE/Caddyfile" "$ROOT/packages/aics-witness/Dockerfile" \
         "$ROOT/packages/aics-witness/uv.lock" "$ROOT/packages/aics-tlog/pyproject.toml"; do
    [ -f "$f" ] || die "missing $f: rsync packages/aics-tlog, packages/aics-witness and ops/witness first (README)"
done
command -v python3 >/dev/null 2>&1 || die "python3 is required (apt-get install -y python3)"

if [ "$(id -u)" -eq 0 ]; then SUDO=(); else SUDO=(sudo); fi
as_root() { "${SUDO[@]}" "$@"; }

# -- 1. Docker, only if absent ------------------------------------------------
installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }
if ! command -v docker >/dev/null 2>&1; then
    say "Docker is absent: installing docker-ce from download.docker.com"
    as_root apt-get update -qq
    as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl >/dev/null
    as_root install -m 0755 -d /etc/apt/keyrings
    as_root curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
    as_root chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${CODENAME} stable" \
        | as_root tee /etc/apt/sources.list.d/docker.list >/dev/null
    as_root apt-get update -qq
    as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
    as_root systemctl enable --now docker >/dev/null
else
    say "Docker is present: $(docker --version 2>/dev/null || echo unknown version)"
fi
if docker info >/dev/null 2>&1; then DOCKER=(docker); else DOCKER=("${SUDO[@]}" docker); fi
if ! "${DOCKER[@]}" compose version >/dev/null 2>&1; then
    # The agent-trials bootstrap installs docker-ce without the compose plugin.
    say "installing the Docker compose plugin"
    if installed docker-ce; then pkg=docker-compose-plugin; else pkg=docker-compose-v2; fi
    as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" >/dev/null
    "${DOCKER[@]}" compose version >/dev/null 2>&1 || die "docker compose still unavailable after installing $pkg"
fi
compose() { "${DOCKER[@]}" compose --project-directory "$HERE" -f "$HERE/compose.yml" "$@"; }

if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)" != yes ]; then
    warn "the system clock is not NTP-synchronised (timedatectl): the witness never dates a cosignature before its previous one, so fix time sync (sudo timedatectl set-ntp true) before it starts cosigning"
fi

# -- 2. .env (public values only) ---------------------------------------------
ENV_FILE="$HERE/.env"
if [ -f "$ENV_FILE" ]; then
    current="$(sed -n 's/^WITNESS_DOMAIN=//p' "$ENV_FILE" | tail -n 1)"
    [ -n "$current" ] || die "$ENV_FILE has no WITNESS_DOMAIN= line; add it"
    if [ -n "$domain" ] && [ "$domain" != "$current" ]; then
        die "$ENV_FILE names $current, not $domain; the domain is part of the published witness URL, change it by hand only on purpose"
    fi
    domain=$current
else
    domain=${domain:-$DOMAIN_DEFAULT}
    printf '# ops/witness/.env, written by bootstrap-witness-host.sh. Public values only; never a key.\nWITNESS_DOMAIN=%s\n' "$domain" > "$ENV_FILE"
    say "wrote $ENV_FILE (WITNESS_DOMAIN=$domain)"
fi
python3 -c 'import re, sys; sys.exit(0 if re.fullmatch(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", sys.argv[1]) else 1)' "$domain" \
    || die "WITNESS_DOMAIN '$domain' is not a lower-case DNS name"
mkdir -p "$HERE/site"

# -- 3. the image -------------------------------------------------------------
say "building the witness image (uv.lock pins every dependency)"
compose build aics-witness

# -- 4. the witness identity --------------------------------------------------
# An identity is permanent: a rerun keeps the name the volume's config holds, and only a new volume
# takes --name (a name never used before: README, host table and Retiring).
current="$(compose run --rm --no-deps -T aics-witness status --json 2>/dev/null \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["witness"]["name"])' 2>/dev/null || true)"
if [ -z "$name" ]; then
    [ -n "$current" ] || die "no witness config in the volume yet: give --name, a name never used before (the README's host table names the identity in use; a retired name is never reused)"
    name=$current
fi
say "witness identity $name (init: creates the key once, then only re-reads it)"
vkey="$(compose run --rm --no-deps -T aics-witness init --name "$name")" \
    || die "init refused (read its message above; a lost key or database means retiring the identity, README 'Operations')"
vkey="$(printf '%s\n' "$vkey" | tail -n 1)"
case $vkey in "$name+"*) ;; *) die "init printed no vkey for $name (got: $vkey)" ;; esac

# -- 5. the log ---------------------------------------------------------------
changed=0
if [ -n "$origin" ]; then
    say "trusting the log $origin (values from the out-of-band trust bundle)"
    out="$(compose run --rm --no-deps -T aics-witness add-log --origin "$origin" --vkey "$log_vkey")"
    printf '%s\n' "$out"
    case $out in unchanged:*) ;; *) changed=1 ;; esac
fi
if [ -n "$initial_size" ]; then
    say "pinning $origin at size $initial_size (used only while this witness holds no state for it)"
    out="$(compose run --rm --no-deps -T --entrypoint python3 aics-witness - "$origin" "$initial_size" "$initial_root" <<'PY'
import json, os, sys
from pathlib import Path
from aics_witness.config import load_config, parse_initial, write_config
from aics_witness.store import WitnessStore, database_status

origin, size, root = sys.argv[1], int(sys.argv[2]), sys.argv[3]
path = os.environ.get("AICS_WITNESS_CONFIG", "/data/witness.json")
cfg = load_config(path)
pin = {"size": size, "root": root}
parse_initial(pin, origin)
if database_status(cfg.db_path) == "initialised":
    with WitnessStore(cfg.db_path) as store:
        if any(s.origin == origin for s in store.all_logs()):
            print(f"ignored: this witness already holds state for {origin}; the pin no longer applies")
            sys.exit(0)
doc = json.loads(Path(path).read_text(encoding="utf-8"))
for entry in doc.get("logs", []):
    if entry.get("origin") == origin:
        if entry.get("initial") == pin:
            print("unchanged: pin")
            sys.exit(0)
        entry["initial"] = pin
        break
else:
    sys.exit(f"{origin} is not configured")
write_config(path, doc)
load_config(path)
print("pinned")
PY
)" || die "the pin was refused"
    printf '%s\n' "$out"
    case $out in pinned) changed=1 ;; esac
fi

status_json="$(compose run --rm --no-deps -T aics-witness status --json)"

# -- 6. the public page -------------------------------------------------------
say "writing the public page into $HERE/site"
STATUS_JSON="$status_json" python3 -I - "$HERE/site" "$domain" <<'PY'
import html, json, os, sys, tempfile
from pathlib import Path

site, domain = Path(sys.argv[1]), sys.argv[2]
status = json.loads(os.environ["STATUS_JSON"])
w = status["witness"]
url = "https://" + domain
logs = [{"origin": e["origin"], "vkeys": e["vkeys"],
         "monitor": f"{url}/{e['origin_hash']}/checkpoint"} for e in status["logs"] if e["configured"]]
info = {
    "name": w["name"],
    "vkey": w["vkey"],
    "url": url,
    "add_checkpoint": url + "/add-checkpoint",
    "protocol": "C2SP tlog-witness v1.1.0 (Ed25519 cosignature/v1 only: no ML-DSA-44, no sign-subtree)",
    "operator": "the operator of wesupport-ai.com (founder-run)",
    "trust_domain": "founder",
    "independent": False,
    "dns_txt": {"name": f"_aics-witness.{domain}", "value": f"aics-witness-vkey {w['vkey']}"},
    "logs": logs,
    "authority": "The assurance card's witness_policy of each log is authoritative; this page is a convenience copy.",
}
rows = "".join(f"<li><code>{html.escape(l['origin'])}</code>: <a href=\"{html.escape(l['monitor'])}\">latest cosigned checkpoint</a></li>"
               for l in logs) or "<li>none yet</li>"
page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Witness {html.escape(w['name'])}</title>
<style>body{{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem}}code{{word-break:break-all}}</style>
</head><body>
<h1>Witness <code>{html.escape(w['name'])}</code></h1>
<p>A <a href="https://c2sp.org/tlog-witness">C2SP tlog-witness</a> (v1.1.0) for the AICS transparency log of wesupport-ai.com.
It cosigns a checkpoint only after checking the log signature and a consistency proof from the last checkpoint it cosigned.</p>
<p><strong>Founder-run</strong>: operated by the operator of the log on another provider, so it is in the log's trust domain
(<code>trust_domain: founder</code>, <code>independent: false</code>). It makes a split view detectable, not prevented; the log's
G5 single-view assurance stays <em>promised</em>.</p>
<h2>Verifier key</h2>
<p><code>{html.escape(w['vkey'])}</code> (<a href="/vkey.txt">vkey.txt</a>, <a href="/witness.json">witness.json</a>)</p>
<p>Also published as DNS TXT <code>_aics-witness.{html.escape(domain)}</code> and, authoritatively, in the log's assurance card
(<code>witness_policy</code>). Take it from there, not from this page alone.</p>
<h2>Logs witnessed</h2>
<ul>{rows}</ul>
<h2>Endpoints</h2>
<ul><li><code>POST {html.escape(url)}/add-checkpoint</code> (the log's feeder)</li>
<li><code>GET {html.escape(url)}/&lt;sha256(origin) hex&gt;/checkpoint</code></li>
<li><code>GET {html.escape(url)}/healthz</code></li></ul>
<p>No access log is kept; no client address or user agent is recorded.</p>
</body></html>
"""
for fname, data in (("index.html", page), ("vkey.txt", w["vkey"] + "\n"),
                    ("witness.json", json.dumps(info, indent=2, ensure_ascii=False) + "\n")):
    fd, tmp = tempfile.mkstemp(dir=site, prefix="." + fname)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)
    os.chmod(tmp, 0o644)
    os.replace(tmp, site / fname)
PY

# -- 7. start, or reload ------------------------------------------------------
if [ "$start" = 1 ]; then
    running="$(compose ps --status running -q aics-witness 2>/dev/null || true)"
    say "starting the witness and Caddy (Let's Encrypt HTTP-01 for $domain needs DNS and ports 80/443 open)"
    compose up -d
    if [ -n "$running" ] && [ "$changed" = 1 ]; then
        compose kill -s HUP aics-witness >/dev/null
        echo "sent SIGHUP: the running witness reloads its log list"
    fi
else
    say "--no-start: nothing started"
fi

# -- 8. what to publish -------------------------------------------------------
STATUS_JSON="$status_json" python3 -I - "$domain" "$vkey" <<'PY'
import json, os, sys
domain, vkey = sys.argv[1], sys.argv[2]
status = json.loads(os.environ["STATUS_JSON"])
w = status["witness"]
if w.get("vkey") != vkey or (w.get("db_witness_vkey") not in (None, vkey)):
    sys.exit("bootstrap-witness-host.sh: status shows another vkey than init; stop and investigate (README 'Operations')")
logs = [e for e in status["logs"] if e["configured"]]
entry = {"name": w["name"], "vkey": vkey, "trust_domain": "founder", "independent": False}
label = "founder-" + w["name"].rsplit("/", 1)[-1]  # the feeder's local name for this witness
print(f"""
== done. Publish these (public values; the key itself stays in the witness_data volume)

witness vkey:
  {vkey}

log server feeder (deploy/.env on the VPS; comma-separated name=url=vkey entries, aics_server/witness_feed.py):
  AICS_WITNESSES={label}=https://{domain}={vkey}

assurance card, witness_policy.witnesses entry (successor card, advance-noticed; G5 stays promised):
  {json.dumps(entry, separators=(", ", ": "))}

DNS TXT (Cloudflare, DNS only):
  _aics-witness.{domain}  "aics-witness-vkey {vkey}"

public page:      https://{domain}/   (vkey.txt, witness.json)
uptime, one line: curl -fsS --max-time 10 https://{domain}/healthz | grep -qx ok || echo "witness {domain} DOWN"
logs trusted:     {", ".join(e["origin"] for e in logs) or "NONE: rerun with --origin and --log-vkey from the trust bundle"}
""")
for e in logs:
    state = "nothing cosigned yet" if e["size"] is None else f"size {e['size']}"
    pin = f", pinned at size {e['initial']['size']}" if e.get("initial") else ""
    print(f"  {e['origin']}: {state}{pin}")
print("""
Once, by hand, back the witness key up OFFLINE (it never changes; never into the daily backup):
  umask 077; docker compose run --rm --no-deps -T --entrypoint cat aics-witness /data/witness.key > witness.key.offline
  # move witness.key.offline to offline media (the custodian's sealed copy too), then: shred -u witness.key.offline""")
PY
