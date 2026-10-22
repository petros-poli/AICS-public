"""ops/relaunch-genesis.sh: argument parsing, the dry run, and every stage and host script that can run offline.

No host is contacted. The fake ``ssh`` runs the command it is given locally with bash, in a pretend host: its
``docker``, ``sudo`` and ``systemctl`` are fakes that record every call. On the witness host the fake docker runs the
real aics-witness (packages/aics-witness) on a temporary volume directory; on the VPS it runs ``sed`` and the
census's Python on a temporary log volume when a test gives one. ``--remote-dir`` points the VPS's
/opt/wesupport-ai at a temporary directory, the witness host's home is a temporary directory, and
AICS_RELAUNCH_ROOT (the remote scripts' test hook) prefixes the absolute host paths under /etc and /var/lib. The
fake ``curl`` serves https URLs from a map, the fake ``dig`` TXT records from another, and the fake ``uv`` runs
aics-tlog and card/validate_card.py for real when a test asks for it (FAKE_UV_REAL=1); the checkpoints,
cosignatures and card signatures those tests verify are made here with throwaway keys.

    uv run --project packages/aics-server --with pyyaml pytest -q tools/test_relaunch_genesis.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/aics-witness/src"))

from aics_identity.keys import did_key_from_bytes  # noqa: E402
from aics_tlog import (  # noqa: E402
    Checkpoint,
    Note,
    cosignature_vkey,
    format_vkey,
    sign_checkpoint,
    sign_cosignature,
    vkey_from_ed25519,
)
from aics_witness.config import load_config  # noqa: E402
from aics_witness.store import WitnessStore  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

SCRIPT = ROOT / "ops/relaunch-genesis.sh"
INVENTORY = ROOT / "docs/internal/relaunch-2026-10-20.md"
#: The public repository omits docs/internal: the tests that read the inventory skip there.
needs_inventory = pytest.mark.skipif(not INVENTORY.exists(), reason="docs/internal/relaunch-2026-10-20.md is not in this checkout")
BOOTSTRAP = ROOT / "ops/witness/bootstrap-witness-host.sh"
WITNESS_SRC = ROOT / "packages/aics-witness/src"

ORIGIN = "api.wesupport-ai.com/tiles"
V1_LOG = "api.wesupport-ai.com/tiles+0e2f3a1e+ASx//oWlf4UBmbnXHfpMCsF2NrQOZuN32Q25NiTBC7fV"
V1_SHA = "bc234cc34b1b0941d0e833c41112109fe7fe020cebbba9f58f98f3a59448da0c"
OWNER = "did:key:z6MkiN89VfP5ZqFRC9epYQNjDyXQvYxrGn11r4Wrf6dvVb6K"
W1 = "witness.wesupport-ai.com/w1"
W1_VKEY = "witness.wesupport-ai.com/w1+45a4adcd+BHew2Ur+QH2S82rpq+DkFdR0fevS0fs+/SKQexugKGNN"
W2 = "witness.wesupport-ai.com/w2"
LABEL = "discarded-2026-10-19"
OLD_SEED = "ab" * 32
TOKEN = "cf-token-never-print"
ROOT_AT_2 = "4QzEfNS1dngXuqikf2l9GQ1g8Hf0DwQsZMWq1tWCmdo="


class Key:
    """A throwaway Ed25519 key."""

    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes_raw()


LOG = Key()  # the new log
NEW_LOG = format_vkey(vkey_from_ed25519(ORIGIN, LOG.public))
POLICY = Key()
NEW_POLICY = did_key_from_bytes(POLICY.public)
OLD = Key()  # stands in for a log to discard whose signature a test must verify (--discard-log-vkey)
OLD_LOG = format_vkey(vkey_from_ed25519(ORIGIN, OLD.public))
W2_KEY = Key()
W2_VKEY = format_vkey(cosignature_vkey(W2, W2_KEY.public))


def mth(hashes: list[bytes]) -> bytes:
    if len(hashes) == 1:
        return hashes[0]
    split = 1
    while split * 2 < len(hashes):
        split *= 2
    return hashlib.sha256(b"\x01" + mth(hashes[:split]) + mth(hashes[split:])).digest()


def tlog(entries: list[bytes], key: Key, cosigners: tuple = ()) -> tuple[str, dict[str, bytes], bytes]:
    """The signed checkpoint note of these entries (cosigned now by each (name, Key)), their entry bundles by
    tile path, and the root."""
    root = mth([hashlib.sha256(b"\x00" + e).digest() for e in entries]) if entries else hashlib.sha256(b"").digest()
    note = sign_checkpoint(Checkpoint(origin=ORIGIN, size=len(entries), root=root), key.private, ORIGIN)
    sigs = list(note.signatures)
    for name, w in cosigners:
        sigs.append(sign_cosignature(w.private, name, int(time.time()), ORIGIN, len(entries), root)[1])
    bundles = {}
    for k in range(0, len(entries), 256):
        chunk = entries[k:k + 256]
        path = f"tile/entries/{k // 256:03d}" + ("" if len(chunk) == 256 else f".p/{len(chunk)}")
        bundles[path] = b"".join(len(e).to_bytes(2, "big") + e for e in chunk)
    return Note(text=note.text, signatures=tuple(sigs)).serialise(), bundles, root


def leaf(type_: str, actor: str | None, ts: int, payload: dict | None = None) -> bytes:
    return json.dumps({"actor_kid": actor, "origin": ORIGIN, "payload": payload or {}, "ts": ts, "type": type_, "v": 2},
                      separators=(",", ":"), sort_keys=True).encode()


FAKE_SSH = f"""#!{sys.executable}
import json, os, subprocess, sys
args = sys.argv[1:]
while args and args[0].startswith("-"):
    args = args[2:] if args[0] in ("-o", "-p", "-i", "-F", "-l") else args[1:]
host, command = args[0], " ".join(args[1:])
data = sys.stdin.buffer.read()
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({{"tool": "ssh", "host": host, "command": command}}) + "\\n")
with open(os.environ["FAKE_SSH_STDIN"], "ab") as f:
    f.write(data + b"\\n--- end of stdin ---\\n")
env = dict(os.environ, HOME=os.environ["FAKE_HOST_HOME"])
sys.exit(subprocess.run(["bash", "-c", command], input=data, env=env).returncode)
"""

# docker: a small state file of containers and volumes. "volume_dir" (a directory standing for /data of the VPS's
# aics-server, with pubkeys.txt and tiles/) makes sed and python3 runs real there; "witness_data" (standing for
# /data of the witness) makes every aics-witness run the real package there.
FAKE_DOCKER = f"""#!{sys.executable}
import json, os, subprocess, sys
args = sys.argv[1:]
path = os.environ["FAKE_DOCKER_STATE"]
st = json.load(open(path))
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({{"tool": "docker", "args": args}}) + "\\n")
def save():
    json.dump(st, open(path, "w"))
def data(arg):
    vol = st.get("volume_dir")
    return vol + arg[len("/data"):] if vol and arg.startswith("/data/") else arg
def server(argv, stdin=None):
    env = dict(os.environ)
    if st.get("volume_dir"):
        env.update(AICS_TILES_DIR=st["volume_dir"] + "/tiles", AICS_PUBKEYS_OUT=st["volume_dir"] + "/pubkeys.txt")
    sys.exit(subprocess.run(argv, input=stdin, env=env).returncode)
def witness(argv):
    env = dict(os.environ, AICS_WITNESS_CONFIG=st["witness_data"] + "/witness.json",
               PYTHONPATH={str(WITNESS_SRC)!r} + os.pathsep + os.environ.get("PYTHONPATH", ""))
    sys.exit(subprocess.run(argv, stdin=sys.stdin, env=env).returncode)
if args == ["info"]:
    sys.exit(0)
if args[:1] == ["volume"]:
    if args[1] == "inspect":
        sys.exit(0 if args[2] in st["volumes"] else 1)
    if args[1] == "ls":
        print("\\n".join(v for v in st["volumes"] if "staging" in v))
        sys.exit(0)
    if args[1] == "rm":
        for v in args[2:]:
            if v not in st["volumes"]:
                sys.exit(f"no volume {{v}}")
            st["volumes"].remove(v)
            print(v)
        save()
        sys.exit(0)
if args[:1] != ["compose"]:
    sys.exit(f"fake docker: unexpected {{args}}")
c = args[1:]
if c[:3] == ["config", "--format", "json"]:
    print(json.dumps({{"volumes": {{"aics_data": {{"name": "deploy_aics_data"}}, "aics_tiles": {{"name": "deploy_aics_tiles"}},
                                 "caddy_data": {{"name": "deploy_caddy_data"}}}}}}))
elif c[:2] == ["config", "--quiet"]:
    pass
elif c[:1] == ["ps"]:
    if c[-1] in st["running"]:
        print("cid-" + c[-1])
elif c[:1] == ["exec"]:
    if "aics-server" not in st["running"]:
        sys.exit("service aics-server is not running")
    if st.get("volume_dir") and c[c.index("aics-server") + 1] in ("sed", "cat"):
        rest = c[c.index("aics-server") + 1:]
        server([rest[0], *map(data, rest[1:])])
    if c[-1] == "/data/pubkeys.txt" and c[-3:-1] == ["-n", "s/^log //p"]:
        print(st["log"])
    elif c[-1] == "/data/pubkeys.txt":
        print(st["pubkeys"], end="")
    elif c[-1] == "/data/tiles/checkpoint":
        print(st["size"])
elif c[:1] == ["stop"]:
    st["running"] = [s for s in st["running"] if s not in c[1:]]
    save()
elif c[:1] == ["rm"]:
    st["running"] = [s for s in st["running"] if s not in c]
    st.setdefault("removed", []).extend(s for s in c if not s.startswith("-") and s != "rm")
    save()
elif c[:1] == ["up"]:
    st["running"] = sorted(set(st["running"]) | {{"aics-witness", "caddy"}})
    save()
elif c[:1] == ["kill"]:
    pass
elif c[:1] == ["run"]:
    i, entrypoint = 1, None
    while c[i].startswith("-"):
        if c[i] in ("--name", "--entrypoint", "--user", "-e"):
            entrypoint = c[i + 1] if c[i] == "--entrypoint" else entrypoint
            i += 2
        else:
            i += 1
    service, rest = c[i], c[i + 1:]
    if service == "aics-witness":
        if "witness_data" not in st:
            sys.exit("fake docker: no witness_data for aics-witness")
        witness([sys.executable, *rest] if entrypoint == "python3" else [sys.executable, "-m", "aics_witness", *rest])
    if entrypoint == "python3" and st.get("volume_dir"):
        server([sys.executable, *rest], stdin=sys.stdin.buffer.read())
    if entrypoint == "sed":
        if st.get("volume_dir"):
            server(["sed", *map(data, rest)])
        print(st["volume_log"] if rest[-1] == "/data/pubkeys.txt" else st["volume_size"])
    else:
        sys.exit(f"fake docker: unexpected compose run {{c}}")
else:
    sys.exit(f"fake docker: unexpected compose {{c}}")
"""

FAKE_SYSTEMCTL = f"""#!{sys.executable}
import json, os, sys
args = [a for a in sys.argv[1:] if a != "--quiet"]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({{"tool": "systemctl", "args": args}}) + "\\n")
active, enabled = os.environ.get("FAKE_ACTIVE", "").split(), os.environ.get("FAKE_ENABLED", "").split()
if args[0] == "is-active":
    sys.exit(0 if args[1] in active else 3)
if args[0] == "is-enabled":
    sys.exit(0 if args[1] in enabled else 1)
if args[0] == "cat":
    sys.exit(0 if args[1] in os.environ.get("FAKE_UNITS", "").split() else 1)
if args[0] == "show":
    print("success")
"""

FAKE_SUDO = '#!/bin/sh\n[ "$1" = -n ] && shift\nexec "$@"\n'

RECORDER = f"""#!{sys.executable}
import json, os, sys
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({{"tool": os.path.basename(sys.argv[0]), "args": sys.argv[1:]}}) + "\\n")
"""

# git: records; "grep" searches the -C directory for real (the merge-conflict check).
FAKE_GIT = f"""#!{sys.executable}
import json, os, subprocess, sys
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({{"tool": "git", "args": args}}) + "\\n")
where = args[args.index("-C") + 1] if "-C" in args else "."
if "grep" in args:
    pattern = args[-1]
    sys.exit(subprocess.run(["grep", "-rnE", "--exclude-dir=.git", pattern, where]).returncode)
"""

# curl that answers from FAKE_CURL_MAP (url -> {"body" or "body_b64", "headers"}, or {"sequence": [answers]}: one
# after the other, the last one again and again); -o FILE / -D FILE|- like curl.
FAKE_CURL = f"""#!{sys.executable}
import base64, hashlib, json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({{"tool": "curl", "args": args}}) + "\\n")
url = [a for a in args if a.startswith("https://")][-1]
answer = json.load(open(os.environ["FAKE_CURL_MAP"])).get(url)
if answer is None:
    print(f"curl: (22) The requested URL returned error: 404 ({{url}})", file=sys.stderr)
    sys.exit(22)
if "sequence" in answer:
    counter = os.environ["FAKE_CURL_MAP"] + ".n." + hashlib.sha256(url.encode()).hexdigest()[:12]
    n = int(open(counter).read()) if os.path.exists(counter) else 0
    open(counter, "w").write(str(n + 1))
    answer = answer["sequence"][min(n, len(answer["sequence"]) - 1)]
def target(flag):
    return args[args.index(flag) + 1] if flag in args else None
headers = answer.get("headers", "HTTP/2 200\\r\\n\\r\\n")
body = base64.b64decode(answer["body_b64"]) if "body_b64" in answer else answer["body"].encode()
out, dump = target("-o"), target("-D")
if dump == "-":
    sys.stdout.write(headers)
elif dump:
    open(dump, "w").write(headers)
sys.stdout.flush()
if out and out != "/dev/null":
    open(out, "wb").write(body)
elif not out:
    sys.stdout.buffer.write(body)
"""

# dig +short TXT NAME @1.1.1.1, from FAKE_DIG_MAP (name -> value; a long value comes back in 255-byte strings)
FAKE_DIG = f"""#!{sys.executable}
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({{"tool": "dig", "args": args}}) + "\\n")
name = [a for a in args if not a.startswith(("+", "@")) and a != "TXT"][0]
value = json.load(open(os.environ["FAKE_DIG_MAP"])).get(name)
if value is not None:
    print(" ".join('"' + value[i:i + 255] + '"' for i in range(0, len(value), 255)))
"""

# uv: records every call. aics-tlog and validate_card.py answer {{"ok": true}}, or run for real with FAKE_UV_REAL=1
# (or FAKE_UV_REAL=aics-tlog, =validate_card for one of them);
# the owner tool and everything else only record (FAKE_OWNER_OUTPUT is what the owner tool prints).
FAKE_UV = f"""#!{sys.executable}
import json, os, subprocess, sys
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({{"tool": "uv", "args": args, "cwd": os.getcwd()}}) + "\\n")
rest = [a for a in args[1:] if a not in ("--quiet", "--locked")] if args[:1] == ["run"] else []
real = os.environ.get("FAKE_UV_REAL", "").split(",")
if rest[:1] == ["aics-tlog"]:
    if "1" in real or "aics-tlog" in real:
        sys.exit(subprocess.run([sys.executable, "-m", "aics_tlog", *rest[1:]]).returncode)
    print(json.dumps({{"ok": True}}))
elif rest[:2] == ["python", "validate_card.py"]:
    if "1" in real or "validate_card" in real:
        sys.exit(subprocess.run([sys.executable, *rest[1:]]).returncode)
    print(json.dumps({{"ok": True}}))
elif any(a.endswith("aics_client.py") for a in rest):
    print(os.environ.get("FAKE_OWNER_OUTPUT", "{{}}"))
elif rest[:3] == ["aics", "trust", "build"] and os.environ.get("FAKE_TRUST_BUILD"):
    doc = json.load(open(os.environ["FAKE_TRUST_BUILD"]))
    print(json.dumps(doc) if "--json" in rest else doc["txt"] + "\\nsha256: " + doc["sha256"])
"""

FAKE_SLEEP = "#!/bin/sh\nexit 0\n"


class Host:
    """A pretend VPS and witness host, and the fakes that stand in for their tools."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.log = tmp / "calls.jsonl"
        self.log.touch()
        self.stdin = tmp / "ssh-stdin.bin"
        self.stdin.touch()
        self.state = tmp / "docker.json"
        self.remote = tmp / "vps/opt/wesupport-ai"
        (self.remote / "deploy").mkdir(parents=True)
        self.home = tmp / "witness-home"
        (self.home / "aics/ops/witness").mkdir(parents=True)
        self.root = tmp / "hostroot"
        self.root.mkdir()
        self.launch = tmp / "launch"
        self.launch.mkdir()
        self.worktree = tmp / "worktree"
        for pkg in ("aics-tlog", "aics-server", "aics-cli"):
            (self.worktree / "packages" / pkg).mkdir(parents=True)
        self.repo = tmp / "mainrepo"
        (self.repo / "deploy/card").mkdir(parents=True)
        for name, text in (("ssh", FAKE_SSH), ("docker", FAKE_DOCKER), ("systemctl", FAKE_SYSTEMCTL), ("sudo", FAKE_SUDO),
                           ("git", FAKE_GIT), ("curl", FAKE_CURL), ("dig", FAKE_DIG), ("uv", FAKE_UV), ("sleep", FAKE_SLEEP)):
            self.tool(name, text)
        for name in ("scp", "rsync"):
            self.tool(name, RECORDER)
        self.curl_map = tmp / "curl.json"
        self.curl_map.write_text("{}")
        self.dig_map = tmp / "dig.json"
        self.dig_map.write_text("{}")
        self.docker(running=["aics-server", "caddy"], volumes=["deploy_aics_data", "deploy_aics_tiles", "deploy_caddy_data",
                                                                "aics_staging_data", "aics_staging_tiles"],
                    log=V1_LOG, size="35", volume_log=V1_LOG, volume_size="35", pubkeys="")
        self.env_file({"COMPOSE_FILE": "docker-compose.yml:gate-tls.yml:docker-compose.staging.yml",
                       "AICS_OWNER_PUBKEY": OWNER, "AICS_SERVER_SEED_HEX": OLD_SEED, "CLOUDFLARE_API_TOKEN": TOKEN,
                       "AICS_CARD_FILE": "/etc/aics/card/card-unsigned.json",
                       "AICS_WITNESSES": f"founder-w1=https://witness.wesupport-ai.com={W1_VKEY}"})

    def tool(self, name: str, text: str) -> None:
        path = self.bin / name
        path.write_text(text)
        path.chmod(0o755)

    def docker(self, **state) -> None:
        current = json.loads(self.state.read_text()) if self.state.exists() else {}
        current.update(state)
        self.state.write_text(json.dumps(current))

    def docker_state(self) -> dict:
        return json.loads(self.state.read_text())

    def env_file(self, values: dict[str, str]) -> None:
        path = self.remote / "deploy/.env"
        path.write_text("".join(f"{k}={v}\n" for k, v in values.items()))
        path.chmod(0o600)

    def env_lines(self) -> list[str]:
        return (self.remote / "deploy/.env").read_text().splitlines()

    def calls(self, tool: str | None = None) -> list[dict]:
        rows = [json.loads(line) for line in self.log.read_text().splitlines()]
        return [r for r in rows if tool is None or r["tool"] == tool]

    def serve(self, routes: dict[str, dict], *, merge: bool = False) -> None:
        """Answer these https URLs from the fake curl (every other URL is a 404)."""
        current = json.loads(self.curl_map.read_text()) if merge else {}
        current.update(routes)
        self.curl_map.write_text(json.dumps(current))

    def dns(self, records: dict[str, str]) -> None:
        self.dig_map.write_text(json.dumps(records))

    def environ(self, **extra) -> dict[str, str]:
        env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}", FAKE_LOG=str(self.log),
                   FAKE_SSH_STDIN=str(self.stdin), FAKE_DOCKER_STATE=str(self.state), FAKE_HOST_HOME=str(self.home),
                   AICS_RELAUNCH_ROOT=str(self.root), HOME=str(self.tmp / "laptop-home"), FAKE_CURL_MAP=str(self.curl_map),
                   FAKE_DIG_MAP=str(self.dig_map))
        env.update(extra)
        return env

    def run(self, *args: str, **extra) -> subprocess.CompletedProcess:
        base = ["bash", str(SCRIPT), "--launch-dir", str(self.launch), "--remote-dir", str(self.remote),
                "--worktree", str(self.worktree), "--repo", str(self.repo)]
        return subprocess.run(base + list(args), capture_output=True, text=True, env=self.environ(**extra))

    def remote_script(self, name: str) -> str:
        r = subprocess.run(["bash", str(SCRIPT), "--show-remote", name], capture_output=True, text=True, check=True)
        return r.stdout

    def run_remote(self, name: str, *args: str, **extra) -> subprocess.CompletedProcess:
        env = self.environ(**extra)
        env["HOME"] = str(self.home)
        return subprocess.run(["bash", "-s", "--", *args], input=self.remote_script(name), capture_output=True,
                              text=True, env=env, cwd=self.tmp)


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


# -- the script itself -------------------------------------------------------------------------------------------

def test_the_script_parses_and_passes_shellcheck():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
    if shutil.which("shellcheck"):
        subprocess.run(["shellcheck", "-x", str(SCRIPT)], check=True)


REMOTES = ["vps_state", "vps_pubkeys", "vps_freeze", "vps_census", "vps_wipe", "vps_card_env", "vps_dns", "vps_resume",
           "witness_freeze", "witness_repin", "witness_vantage"]


@pytest.mark.parametrize("name", REMOTES)
def test_every_host_script_is_valid_bash_passes_shellcheck_and_reads_no_secret_file(host, name):
    text = host.remote_script(name)
    subprocess.run(["bash", "-n"], input=text, text=True, check=True)
    if shutil.which("shellcheck"):
        r = subprocess.run(["shellcheck", "-s", "bash", "-"], input=text, capture_output=True, text=True)
        assert r.returncode == 0, r.stdout
    assert text.startswith("# shellcheck disable=") and "ENV_EDIT_PY=$(cat <<'ENVEDIT'\n" in text
    assert "set -euo pipefail" in text
    # No script prints or sources the files that hold secrets: deploy/.env is read line by line where needed.
    assert not re.search(r"\bcat\b[^|\n]*\.env\b", text)
    assert not re.search(r"(^|[;&|]\s*|\s)(\.|source)\s+\S*\.env\b", text, re.M)
    assert "docker compose config\n" not in text and "down -v" not in text


def test_help_names_every_stage_and_bad_arguments_stop_with_2(host):
    r = host.run("--help")
    assert r.returncode == 0
    for stage in ("archive", "prep", "freeze", "wipe", "seed", "genesis", "witness", "card", "card-log", "bundle", "dns",
                  "vantage", "docs", "verify"):
        assert re.search(rf"^  {re.escape(stage)} ", r.stdout, re.M), stage
    for args, message in ((["nonsense"], "unknown stage"), (["all"], "all runs only with --dry-run"),
                          (["--nope", "plan"], "unknown option"), (["--card-set", "lower=1", "plan"], "NAME=VALUE"),
                          (["--discard-size", "12a", "plan"], "takes a number"), (["--vps", "a b", "plan"], "host alias"),
                          (["--hf-revision", "main", "plan"], "hex commit"), ([], "no stage given"),
                          (["--witness-name", W1, "plan"], "is a retired identity"),
                          (["--witness-name", "witness.example.org/w2", "plan"], "witness.wesupport-ai.com/wN"),
                          (["--witness-vkey", W1_VKEY, "plan"], "not a vkey of witness.wesupport-ai.com/w2"),
                          (["--witness-vkey", "someone/else+00000000+AA==", "plan"], "not a vkey of"),
                          (["--retire-witness-vkey", W2_VKEY, "--witness-name", W2, "plan"], "is a retired identity"),
                          (["--discard-log-vkey", W2_VKEY, "plan"], "not a log vkey of"),
                          (["--seed-name", "seed.hex", "plan"], "server-seed-vN.hex")):
        r = host.run(*args)
        assert r.returncode == 2, (args, r.stdout, r.stderr)
        assert message in r.stderr, (args, r.stderr)
    assert host.calls() == []


def test_the_dry_run_prints_the_whole_procedure_and_touches_nothing(host):
    custody = host.tmp / "custody"
    custody.mkdir(mode=0o700)
    (host.launch / "pubkeys.txt").write_text(f"origin {ORIGIN}\nlog {V1_LOG}\n")
    (host.launch / "witness-vkey.txt").write_text(W1_VKEY + "\n")  # the retired witness's: archive moves it
    before = sorted(p.relative_to(host.tmp).as_posix() for p in host.tmp.rglob("*"))
    env_before = (host.remote / "deploy/.env").read_text()
    r = host.run("--dry-run", "--custody-dir", str(custody), "--owner-key", str(custody / "owner.key"),
                 "--custodian-name", "C. Custodian", "--custodian-holds", "sealed copies", "all")
    assert r.returncode == 0, r.stderr
    assert host.calls() == []  # no ssh, scp, curl, dig, uv, git, rsync or docker call at all
    assert sorted(p.relative_to(host.tmp).as_posix() for p in host.tmp.rglob("*")) == before
    assert (host.remote / "deploy/.env").read_text() == env_before
    headers = re.findall(r"^== ([a-z-]+):", r.stdout, re.M)
    # The witness is pinned before the card names it, and the card is logged only once the witness cosigns.
    assert headers == ["archive", "prep", "freeze", "wipe", "seed", "genesis", "witness", "card", "card-log", "bundle",
                       "dns", "vantage", "docs", "verify"]
    for needle in ("<NEW_LOG_VKEY>", "<DISCARDED_LOG_SIZE>", "<SIZE> <ROOT>", "docker volume rm", 'init --name "$wname"',
                   "--initial-size", "retired-", "AICS_SERVER_SEED_HEX --stdin", 'cloudflare-dns.sh" --apply --bundle',
                   "--witness-txt", "log-card --document-file", "--quorum 1 --max-age 300", f"mv {host.launch}/pubkeys.txt",
                   "<NEW_WITNESS_VKEY>", "--- vps_census: run on wesupport-vps ---", "cosigned_current",
                   f"founder-w2=https://witness.wesupport-ai.com=<NEW_WITNESS_VKEY>", "git -C"):
        assert needle in r.stdout, needle
    assert r.stdout.index("== witness:") < r.stdout.index("== card:") < r.stdout.index("== card-log:")
    assert "down -v" not in r.stdout
    assert OLD_SEED not in r.stdout + r.stderr and TOKEN not in r.stdout + r.stderr
    # every host script appears once in full; later ones point back at the preamble
    assert r.stdout.count("ENV_EDIT_PY=$(cat <<'ENVEDIT'") == 1


def test_plan_lists_the_stages_and_the_publication_steps(host):
    r = host.run("plan")
    assert r.returncode == 0, r.stderr
    assert "card-log" in r.stdout and "PYPI_ONLY_PROJECT=aics-cli" in r.stdout and "yank aics-cli 0.1.0" in r.stdout
    assert r.stdout.index("yank aics-cli 0.1.0") < r.stdout.index("only then deploy the site")
    assert "without\n     waiting for 6" in r.stdout
    assert host.calls() == []


# -- archive ------------------------------------------------------------------------------------------------------

def test_archive_moves_the_discarded_logs_and_the_retired_witnesss_files_once(host):
    L = host.launch
    (L / "pubkeys.txt").write_text(f"origin {ORIGIN}\nlog {V1_LOG}\n")
    for name in ("bundle.txt", "readme-block.txt", "txt-value.txt", "logged.json", "card-successor.json", "witness-pin.txt"):
        (L / name).write_text(name)
    (L / "home/cards").mkdir(parents=True)
    (L / "witness-vkey.txt").write_text(W1_VKEY + "\n")
    (L / "witness-feeder.env").write_text(f"AICS_WITNESSES=founder-w1=https://witness.wesupport-ai.com={W1_VKEY}\n")
    r = host.run("archive")
    assert r.returncode == 0, r.stderr
    v1 = L / "v1-2026-10-19"
    for name in ("pubkeys.txt", "bundle.txt", "readme-block.txt", "txt-value.txt", "logged.json", "card-successor.json",
                 "witness-pin.txt", "home", "witness-vkey.txt", "witness-feeder.env"):
        assert (v1 / name).exists() and not (L / name).exists(), name
    assert stat.S_IMODE(v1.stat().st_mode) == 0o700
    assert "discarded" in (v1 / "README.txt").read_text() and W1 in (v1 / "README.txt").read_text()
    r = host.run("archive")
    assert r.returncode == 0 and "moved 0 item(s)" in r.stdout
    (L / "pubkeys.txt").write_text(f"origin {ORIGIN}\nlog {NEW_LOG}\n")  # the new log's files: never archived
    (L / "witness-vkey.txt").write_text(W2_VKEY + "\n")
    r = host.run("archive")
    assert r.returncode == 0 and "the new log's files are here already" in r.stdout and "moved 0 item(s)" in r.stdout
    assert (L / "pubkeys.txt").exists() and (L / "witness-vkey.txt").read_text() == W2_VKEY + "\n"


def test_archive_keeps_the_new_witness_identitys_file(host):
    (host.launch / "witness-vkey.txt").write_text(W2_VKEY + "\n")  # the witness stage ran before archive
    r = host.run("archive")
    assert r.returncode == 0, r.stderr
    assert (host.launch / "witness-vkey.txt").read_text() == W2_VKEY + "\n"


def test_archive_run_again_after_prep_leaves_preps_files_alone(host):
    L = host.launch
    (L / "pubkeys.txt").write_text(f"origin {ORIGIN}\nlog {V1_LOG}\n")
    (L / "charter.sha256").write_text("c7e15c26  deploy/docs-public/legal/charter.md\n")  # genesis v1's
    assert host.run("archive").returncode == 0
    assert (L / "v1-2026-10-19/charter.sha256").exists()
    (L / "charter.sha256").write_text("e358ee83  deploy/docs-public/legal/charter.md\n")  # prep's, for genesis v2
    (L / "discard-census.json").write_text("{}")
    (L / "witness-vkey.txt").write_text(W1_VKEY + "\n")  # left behind: still w1's
    r = host.run("archive")
    assert r.returncode == 0 and "moved already" in r.stdout and "moved 1 item(s)" in r.stdout, r.stdout
    assert (L / "charter.sha256").read_text().startswith("e358ee83") and (L / "discard-census.json").exists()
    assert (L / "v1-2026-10-19/witness-vkey.txt").read_text() == W1_VKEY + "\n"
    assert (L / "v1-2026-10-19/charter.sha256").read_text().startswith("c7e15c26")


# -- the census of the log to discard ----------------------------------------------------------------------------

AGENT = "did:key:z6MkAgentOfTheConformanceRunxxxxxxxxxxxxxxxxxxxxxx"
STRANGER = "did:key:z6MkSomeoneWhoIsNotUsxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
T0 = 1792452470


def census_log() -> list[bytes]:
    """A small discarded log: the charter, a harness agent's claim and post, three refusals (of the agent, of a key
    with no accepted leaf, and of an attempt whose signature did not verify), a claim by a name that is not the
    harness's, and the daily report."""
    pol = "did:key:z6MkPolicyKeyOfTheDiscardedLogxxxxxxxxxxxxxxxxxxx"
    return [leaf("policy", pol, T0 - 100, {"kind": "charter"}),
            leaf("name.claim", AGENT, T0, {"name_norm": "ct-0123456789abcdef"}),
            leaf("post", AGENT, T0 + 2, {"body_hash": "00" * 32}),
            leaf("refusal", pol, T0 + 3, {"attempt_kid": AGENT, "reason_code": "replay"}),
            leaf("refusal", pol, T0 + 4, {"attempt_kid": STRANGER, "reason_code": "unknown_key"}),
            leaf("refusal", pol, T0 + 5, {"attempt_kid": None, "reason_code": "bad_signature"}),
            leaf("name.claim", "did:key:z6MkVisitorxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", T0 + 6, {"name_norm": "visitor"}),
            leaf("report", pol, T0 + 7, {"counts": []})]


def volume(host: Host, entries: list[bytes], key: Key, log_vkey: str) -> int:
    """The VPS's aics_data/aics_tiles volumes, as files the fake docker serves as /data."""
    vol = host.tmp / "volume"
    (vol / "tiles").mkdir(parents=True, exist_ok=True)
    note, bundles, _ = tlog(entries, key)
    (vol / "pubkeys.txt").write_text(f"origin {ORIGIN}\nlog {log_vkey}\n")
    (vol / "tiles/checkpoint").write_text(note)
    for path, data in bundles.items():
        (vol / "tiles" / path).parent.mkdir(parents=True, exist_ok=True)
        (vol / "tiles" / path).write_bytes(data)
    host.docker(volume_dir=str(vol), log=log_vkey, volume_log=log_vkey, volume_size=str(len(entries)))
    return len(entries)


def test_freeze_takes_the_census_of_the_frozen_volume_refusals_included(host):
    size = volume(host, census_log(), OLD, OLD_LOG)
    r = host.run("--print-only", "--discard-log-vkey", OLD_LOG, "freeze", FAKE_UV_REAL="1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"discarded-log-size {size}" in r.stdout
    assert ["compose", "stop", "aics-server"] in [c["args"] for c in host.calls("docker")]
    out = r.stdout
    assert f"census of the frozen log (wesupport-vps volume): {ORIGIN}+{OLD_LOG.split('+')[1]}+… at size {size}" in out
    assert "3 agent-type leaves from 2 keys" in out and "2 names claimed; NOT the conformance harness's: visitor" in out
    assert "3 refusals: 2 keys that attempted, and 1 unauthenticated attempts" in out
    assert f"refused, with no accepted leaf: {STRANGER} (1x unknown_key" in out
    assert "the 2 keys with accepted leaves, the 1 refused keys without one and the 1 unauthenticated attempts" in out
    census = json.loads((host.launch / "discard-census.json").read_text())
    assert census["census_of"] == "frozen" and census["log_vkey"] == OLD_LOG and census["tree_size"] == size
    assert census["refused_keys_without_accepted_leaf"] == [STRANGER] and census["unauthenticated"]["count"] == 1
    assert census["refused_keys"][AGENT]["reasons"] == ["replay"] and census["names_not_harness"] == ["visitor"]
    assert [row["attempt_kid"] for row in census["rows"] if row["type"] == "refusal"] == [AGENT, STRANGER, None]
    assert json.loads((host.launch / "census-frozen.json").read_text())["ok"] is True  # the real log signature check
    # The frozen census is what wipe relies on: another size is refused before anything is removed.
    host.docker(running=["caddy", "aics-staging"])
    r = host.run("--discard-log-vkey", OLD_LOG, "wipe", "--discard-size", str(size + 1))
    assert r.returncode == 1 and f"not the {size + 1} given with --discard-size" in r.stderr
    assert "deploy_aics_data" in host.docker_state()["volumes"]


def test_the_census_refuses_entries_that_do_not_hash_to_the_checkpoint(host):
    volume(host, census_log(), OLD, OLD_LOG)
    bundle = host.tmp / "volume/tiles/tile/entries/000.p/8"
    bundle.write_bytes(bundle.read_bytes().replace(b"visitor", b"vis1tor"))
    r = host.run("--print-only", "--discard-log-vkey", OLD_LOG, "freeze", FAKE_UV_REAL="1")
    assert r.returncode == 1 and "do not hash to the checkpoint's root" in r.stderr
    assert not (host.launch / "discard-census.json").exists()


def test_the_census_refuses_a_checkpoint_the_log_key_did_not_sign(host):
    volume(host, census_log(), LOG, OLD_LOG)  # signed by another key than the one to discard
    r = host.run("--print-only", "--discard-log-vkey", OLD_LOG, "freeze", FAKE_UV_REAL="1")
    assert r.returncode == 1 and "does not verify under the key of the log to discard" in r.stderr
    assert not (host.launch / "discard-census.json").exists()


def prep_worktree(host: Host) -> None:
    wt = host.worktree
    (wt / ".git").write_text("gitdir: elsewhere\n")
    (wt / "docs/legal").mkdir(parents=True)
    (wt / "docs/legal/charter.md").write_text("# Charter\n\nNo placeholder here.\n")
    (wt / "card").mkdir()
    (wt / "card/card-content.json").write_text('{"name": "<FILL:WITNESS_NAME>", "vkey": "<FILL:WITNESS_VKEY>"}\n')
    (wt / "ops").mkdir()
    (wt / "ops/sync-docs.sh").write_text("mkdir -p deploy/docs-public/legal\ncp docs/legal/charter.md deploy/docs-public/legal/\n"
                                         "echo '{}' > deploy/docs-public/legal/secret-patterns.json\n")


def test_prep_takes_a_census_of_the_live_log_from_its_tiles(host):
    prep_worktree(host)
    note, bundles, _ = tlog(census_log(), OLD)
    routes = {"https://api.wesupport-ai.com/tiles/checkpoint": {"body": note}}
    routes.update({f"https://api.wesupport-ai.com/tiles/{p}": {"body_b64": base64.b64encode(d).decode()}
                   for p, d in bundles.items()})
    host.serve(routes)
    r = host.run("--discard-log-vkey", OLD_LOG, "prep", FAKE_UV_REAL="aics-tlog")
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"census of the live log (https://api.wesupport-ai.com/tiles): {ORIGIN}+" in r.stdout
    assert f"refused, with no accepted leaf: {STRANGER}" in r.stdout
    census = json.loads((host.launch / "discard-census.json").read_text())
    assert census["census_of"] == "live" and census["tree_size"] == 8
    assert (host.launch / "charter.sha256").read_text().endswith("  deploy/docs-public/legal/charter.md\n")
    # The live census is an early look only: wipe needs the frozen volume's.
    r = host.run("--discard-log-vkey", OLD_LOG, "wipe", "--discard-size", "8")
    assert r.returncode == 1 and "census of the live log, not of the frozen volume" in r.stderr


def test_prep_refuses_merge_conflict_markers_in_origin_main(host):
    prep_worktree(host)
    charter = host.worktree / "docs/legal/charter.md"
    charter.write_text(charter.read_text() + "<" * 7 + " HEAD\none text\n" + "=" * 7 + "\nanother\n" + ">" * 7 + " lane\n")
    r = host.run("prep")
    assert r.returncode == 1 and "merge-conflict markers" in r.stderr and "charter.md" in r.stderr
    assert not (host.worktree / "deploy/docs-public").exists()  # stopped before the export


# -- freeze -------------------------------------------------------------------------------------------------------

def test_freeze_stops_the_discarded_log_and_drops_the_witness_and_card_settings(host):
    volume(host, census_log(), OLD, OLD_LOG)
    r = host.run("--print-only", "--discard-log-vkey", OLD_LOG, "freeze", FAKE_ACTIVE="aics-first-contact.timer",
                 FAKE_UNITS="aics-backup.service")
    assert r.returncode == 0, r.stderr
    assert ["compose", "stop", "aics-server"] in [c["args"] for c in host.calls("docker")]
    systemctl = [c["args"] for c in host.calls("systemctl")]
    assert ["stop", "aics-first-contact.timer"] in systemctl and ["start", "aics-backup.service"] in systemctl
    lines = host.env_lines()
    assert not any(l.startswith(("AICS_WITNESSES=", "AICS_CARD_FILE=")) for l in lines)
    assert f"AICS_SERVER_SEED_HEX={OLD_SEED}" in lines and f"CLOUDFLARE_API_TOKEN={TOKEN}" in lines
    label = "discarded-" + OLD_LOG.split("+")[1]  # a redo's label; the 2026-10-19 log's is discarded-2026-10-19
    backup = host.remote / f"deploy/.env.{label}.bak"
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600 and OLD_SEED not in backup.read_text()
    assert "AICS_WITNESSES=" in backup.read_text()
    assert stat.S_IMODE((host.remote / "deploy/.env").stat().st_mode) == 0o600
    # the witness host's part is printed for the operator, not run
    assert "--- witness_freeze: run on aics-trials ---" in r.stdout and "compose stop aics-witness" in r.stdout
    assert {c["host"] for c in host.calls("ssh")} == {"wesupport-vps"}
    assert OLD_SEED not in r.stdout + r.stderr and TOKEN not in r.stdout + r.stderr
    # a second run finds it frozen, changes nothing and takes the same census again
    env_after = (host.remote / "deploy/.env").read_text()
    r = host.run("--print-only", "--discard-log-vkey", OLD_LOG, "freeze")
    assert r.returncode == 0 and "already frozen" in r.stdout and "AICS_WITNESSES: unchanged" in r.stdout
    assert "discarded-log-size 8" in r.stdout and "census of the frozen log" in r.stdout
    assert (host.remote / "deploy/.env").read_text() == env_after


def test_freeze_refuses_a_running_log_that_is_not_the_discarded_one(host):
    host.docker(log=NEW_LOG)
    r = host.run("--print-only", "freeze")
    assert r.returncode == 1 and "not the log to discard" in r.stderr
    assert ["compose", "stop", "aics-server"] not in [c["args"] for c in host.calls("docker")]
    assert any(l.startswith("AICS_WITNESSES=") for l in host.env_lines())


def test_witness_freeze_backs_the_state_up_then_stops_the_witness(host):
    (host.home / "aics/ops/witness/compose.yml").write_text("name: aics-witness\n")
    backup = host.home / "aics/ops/witness/backup-witness.sh"
    backup.write_text(f'#!/bin/sh\necho backup >> "{host.tmp}/backup.ran"\n')
    host.docker(running=["aics-witness", "caddy"])
    r = host.run_remote("witness_freeze", LABEL, FAKE_ACTIVE="aics-vantage-uptime.timer aics-first-contact.timer")
    assert r.returncode == 0, r.stderr
    assert (host.tmp / "backup.ran").exists()
    assert ["compose", "stop", "aics-witness"] in [c["args"] for c in host.calls("docker")]
    stopped = [c["args"][1] for c in host.calls("systemctl") if c["args"][0] == "stop"]
    assert stopped == ["aics-vantage-uptime.timer", "aics-first-contact.timer"]
    r = host.run_remote("witness_freeze", LABEL)
    assert r.returncode == 0 and "already frozen" in r.stdout


# -- wipe ---------------------------------------------------------------------------------------------------------

def frozen_census(host: Host, size: int = 35, log: str = V1_LOG) -> None:
    (host.launch / "discard-census.json").write_text(json.dumps({
        "census_of": "frozen", "log_vkey": log, "tree_size": size, "agent_keys": [AGENT],
        "refused_keys_without_accepted_leaf": [], "unauthenticated": {"count": 0}}))


def wipe_ready(host: Host) -> None:
    host.docker(running=["caddy", "aics-staging"])
    frozen_census(host)


def test_wipe_removes_the_discarded_logs_two_volumes_and_nothing_else(host):
    wipe_ready(host)
    r = host.run("wipe", "--discard-size", "35")
    assert r.returncode == 0, r.stderr
    assert "the census of the frozen log: 35 leaves" in r.stdout
    docker = [c["args"] for c in host.calls("docker")]
    assert ["compose", "rm", "-s", "-f", "aics-server", "caddy"] in docker
    assert ["volume", "rm", "deploy_aics_data", "deploy_aics_tiles"] in docker
    assert host.docker_state()["volumes"] == ["deploy_caddy_data", "aics_staging_data", "aics_staging_tiles"]
    assert not any("down" in call for call in docker)
    assert "aics-staging" in host.docker_state()["running"]
    r = host.run("wipe", "--discard-size", "35")  # a second run: nothing left to remove
    assert r.returncode == 0 and "already wiped" in r.stdout
    assert sum(c[:2] == ["volume", "rm"] for c in (c["args"] for c in host.calls("docker"))) == 1


@pytest.mark.parametrize(("state", "census", "args", "message"), [
    ({"volume_log": NEW_LOG}, {}, ("--discard-size", "35"), "not the log to discard"),
    ({}, {"size": 36}, ("--discard-size", "36"), "has 35 leaves, not the 36 given"),
    ({}, {}, ("--discard-size", "34"), "not the 34 given with --discard-size"),
    ({}, {"log": NEW_LOG}, ("--discard-size", "35"), f"it counts the log {NEW_LOG}"),
    ({"running": ["aics-server"]}, {}, ("--discard-size", "35"), "run the freeze stage first"),
])
def test_wipe_refuses_another_log_another_size_a_running_server_or_another_census(host, state, census, args, message):
    wipe_ready(host)
    host.docker(**state)
    frozen_census(host, **census)
    r = host.run("wipe", *args)
    assert r.returncode == 1 and message in r.stderr, r.stderr
    assert not any(c["args"][:2] in (["volume", "rm"], ["compose", "rm"]) for c in host.calls("docker"))
    assert "deploy_aics_data" in host.docker_state()["volumes"]


def test_wipe_needs_the_size_and_the_census_of_the_frozen_log(host):
    r = host.run("wipe")
    assert r.returncode == 2 and "--discard-size" in r.stderr and host.calls() == []
    host.docker(running=["caddy"])
    r = host.run("wipe", "--discard-size", "35")
    assert r.returncode == 1 and "no census of the frozen log" in r.stderr and host.calls("docker") == []


def test_a_redo_discards_the_log_it_names_and_only_that_one(host):
    wipe_ready(host)
    host.docker(volume_log=OLD_LOG)
    frozen_census(host, log=OLD_LOG)
    r = host.run("wipe", "--discard-size", "35")  # the default is the 2026-10-19 log, not this one
    assert r.returncode == 1 and "it counts the log" in r.stderr
    r = host.run("--discard-log-vkey", OLD_LOG, "wipe", "--discard-size", "35")
    assert r.returncode == 0, r.stderr
    assert "deploy_aics_data" not in host.docker_state()["volumes"]


# -- seed ---------------------------------------------------------------------------------------------------------

def custody_dir(host: Host) -> Path:
    path = host.tmp / "custody"
    path.mkdir(mode=0o700, exist_ok=True)
    return path


def wiped(host: Host) -> None:
    host.docker(running=[], volumes=["deploy_caddy_data", "aics_staging_data", "aics_staging_tiles"])


def test_the_seed_goes_to_custody_and_the_vps_only_and_is_never_printed(host):
    wiped(host)
    custody = custody_dir(host)
    r = host.run("seed", "--custody-dir", str(custody))
    assert r.returncode == 0, r.stderr
    seed_file = custody / "server-seed-v2.hex"
    seed = seed_file.read_text().strip()
    assert re.fullmatch(r"[0-9a-f]{64}", seed) and seed != OLD_SEED
    assert stat.S_IMODE(seed_file.stat().st_mode) == 0o600
    lines = host.env_lines()
    assert lines.count(f"AICS_SERVER_SEED_HEX={seed}") == 1 and not any(OLD_SEED in l for l in lines)
    assert f"CLOUDFLARE_API_TOKEN={TOKEN}" in lines and f"AICS_OWNER_PUBKEY={OWNER}" in lines
    assert stat.S_IMODE((host.remote / "deploy/.env").stat().st_mode) == 0o600
    out = r.stdout + r.stderr
    assert seed not in out and OLD_SEED not in out and TOKEN not in out
    assert all(seed not in c["command"] for c in host.calls("ssh"))  # never on a command line
    assert seed in host.stdin.read_text()  # only on ssh stdin
    env_after = (host.remote / "deploy/.env").read_text()
    r = host.run("seed", "--custody-dir", str(custody))
    assert r.returncode == 0 and "already rotated" in r.stdout
    assert (host.remote / "deploy/.env").read_text() == env_after and seed_file.read_text().strip() == seed
    assert seed not in r.stdout + r.stderr


def test_the_seed_of_a_started_log_is_never_changed(host):
    custody = custody_dir(host)
    r = host.run("seed", "--custody-dir", str(custody))  # the data volume exists
    assert r.returncode == 1 and "never changes" in r.stderr
    assert not (custody / "server-seed-v2.hex").exists()
    assert f"AICS_SERVER_SEED_HEX={OLD_SEED}" in host.env_lines()


def test_a_seed_that_started_a_log_never_starts_another(host):
    wiped(host)
    custody = custody_dir(host)
    (custody / "server-seed-v2.hex").write_text("cd" * 32 + "\n")
    (custody / "server-seed-v2.hex.started").write_text(f"log {NEW_LOG}\nat 2026-10-20T04:00:00Z\n")
    r = host.run("seed", "--custody-dir", str(custody))
    assert r.returncode == 1 and "has started a log before" in r.stderr and "--seed-name" in r.stderr
    assert f"AICS_SERVER_SEED_HEX={OLD_SEED}" in host.env_lines()
    # a deploy that made no data volume started nothing: the same seed may be tried again, except in a redo
    (custody / "server-seed-v2.hex.started").write_text("log pending\nat 2026-10-20T04:00:00Z\n")
    r = host.run("seed", "--custody-dir", str(custody))
    assert r.returncode == 0 and "made no data volume" in r.stdout, r.stdout + r.stderr
    r = host.run("--discard-log-vkey", OLD_LOG, "seed", "--custody-dir", str(custody))
    assert r.returncode == 1 and "has started a log before (pending" in r.stderr
    r = host.run("--discard-log-vkey", OLD_LOG, "--seed-name", "server-seed-v3.hex", "seed", "--custody-dir", str(custody))
    assert r.returncode == 0 and (custody / "server-seed-v3.hex").exists()
    assert "cd" * 32 not in (host.remote / "deploy/.env").read_text()


def test_the_seed_refuses_a_custody_dir_in_a_checkout_or_open_to_others(host):
    inside = host.launch / "custody"
    inside.mkdir(mode=0o700)
    r = host.run("seed", "--custody-dir", str(inside))
    assert r.returncode == 1 and "never goes into a checkout or the public launch directory" in r.stderr
    open_dir = host.tmp / "open"
    open_dir.mkdir()
    open_dir.chmod(0o755)
    r = host.run("seed", "--custody-dir", str(open_dir))
    assert r.returncode == 1 and "open to other users" in r.stderr
    r = host.run("seed")
    assert r.returncode == 2 and "--custody-dir" in r.stderr
    assert host.calls() == []


# -- genesis --------------------------------------------------------------------------------------------------------

NEW_SEED = "cd" * 32
CHARTER = "ef" * 32


def pubkeys_text(log: str = NEW_LOG, policy: str = NEW_POLICY) -> str:
    return (f"# Keys of the AICS log {ORIGIN}\norigin {ORIGIN}\nlog {log}\npolicy {policy}\npolicy-kid {policy}\n"
            f"owner {OWNER}\nowner-kid {OWNER}\ncharter-index 0\ncharter-sha256 {CHARTER}\n")


def genesis_ready(host: Host, *, pubkeys: str | None = None, **env) -> Path:
    """The state after freeze, wipe and seed, and a fake deploy that starts a log with these keys."""
    custody = custody_dir(host)
    (custody / "server-seed-v2.hex").write_text(NEW_SEED + "\n")
    values = {"COMPOSE_FILE": "docker-compose.yml:gate-tls.yml", "AICS_OWNER_PUBKEY": OWNER,
              "AICS_SERVER_SEED_HEX": NEW_SEED, "CLOUDFLARE_API_TOKEN": TOKEN}
    values.update(env)
    host.env_file(values)
    host.docker(running=["aics-staging"], volumes=["deploy_caddy_data", "aics_staging_data", "aics_staging_tiles"])
    (host.launch / "charter.sha256").write_text(f"{CHARTER}  deploy/docs-public/legal/charter.md\n")
    deploy = host.worktree / "deploy/deploy-vps.sh"
    deploy.parent.mkdir(parents=True, exist_ok=True)
    deploy.write_text(f"""#!/bin/sh
echo "deploy-vps.sh $*" >> "{host.tmp}/deploy.ran"
exec "{sys.executable}" - <<'PY'
import json, os
path = os.environ["FAKE_DOCKER_STATE"]
st = json.load(open(path))
st["volumes"] += ["deploy_aics_data", "deploy_aics_tiles"]
st["running"] += ["aics-server", "caddy"]
st["pubkeys"] = {json.dumps(pubkeys or pubkeys_text())}
json.dump(st, open(path, "w"))
PY
""")
    note, _, _ = tlog([leaf("policy", NEW_POLICY, T0)], LOG)
    host.serve({"https://api.wesupport-ai.com/tiles/checkpoint": {"body": note},
                "https://api.wesupport-ai.com/checkpoint": {"body": note}})
    return custody


def test_genesis_starts_the_new_log_keeps_its_keys_and_spends_the_seed(host):
    custody = genesis_ready(host)
    r = host.run("genesis", "--custody-dir", str(custody))
    assert r.returncode == 0, r.stdout + r.stderr
    assert (host.tmp / "deploy.ran").read_text() == "deploy-vps.sh wesupport-vps\n"
    assert (host.launch / "pubkeys.txt").read_text() == pubkeys_text()
    assert (host.launch / "log.vkey").read_text() == NEW_LOG + "\n"
    assert "leaf 0 written; checkpoint size 1" in r.stdout
    assert (custody / "server-seed-v2.hex.started").read_text().startswith(f"log {NEW_LOG}\nat ")
    assert NEW_SEED not in r.stdout + r.stderr and TOKEN not in r.stdout + r.stderr
    r = host.run("genesis", "--custody-dir", str(custody))  # a second run: the log is there already
    assert r.returncode == 0 and "genesis already ran" in r.stdout
    assert (host.tmp / "deploy.ran").read_text().count("\n") == 1


def test_a_failed_genesis_deploy_spends_the_seed_once_it_made_a_volume(host):
    custody = genesis_ready(host)
    deploy = host.worktree / "deploy/deploy-vps.sh"
    deploy.write_text(deploy.read_text().replace('exec "', 'trap "exit 1" EXIT; "', 1))  # it starts the log, then fails
    r = host.run("genesis", "--custody-dir", str(custody))
    assert r.returncode == 1 and "deploy/deploy-vps.sh exited 1" in r.stderr
    assert (custody / "server-seed-v2.hex.started").read_text().startswith("log started\n")
    assert not (host.launch / "pubkeys.txt").exists()


@pytest.mark.parametrize(("env", "message"), [
    ({"AICS_WITNESSES": f"founder-w1=https://witness.wesupport-ai.com={W1_VKEY}"}, "run the freeze stage"),
    ({"AICS_CARD_FILE": "/etc/aics/card/card-unsigned.json"}, "run the freeze stage"),
    ({"AICS_SERVER_SEED_HEX": OLD_SEED}, "does not hold the seed of"),
    ({"AICS_OWNER_PUBKEY": ""}, "does not set AICS_OWNER_PUBKEY"),
])
def test_genesis_refuses_to_start_unless_the_vps_was_frozen_wiped_and_reseeded(host, env, message):
    custody = genesis_ready(host, **env)
    r = host.run("genesis", "--custody-dir", str(custody))
    assert r.returncode == 1 and message in r.stderr, r.stderr
    assert not (host.tmp / "deploy.ran").exists() and not (host.launch / "pubkeys.txt").exists()
    assert not (custody / "server-seed-v2.hex.started").exists()


def test_genesis_refuses_a_seed_that_started_a_log_before(host):
    custody = genesis_ready(host)
    (custody / "server-seed-v2.hex.started").write_text(f"log {OLD_LOG}\nat 2026-10-20T04:00:00Z\n")
    r = host.run("genesis", "--custody-dir", str(custody))
    assert r.returncode == 1 and "has started a log before" in r.stderr
    assert not (host.tmp / "deploy.ran").exists()


@pytest.mark.parametrize(("pubkeys", "problem"), [
    (pubkeys_text(log=V1_LOG), "the seed was not rotated"),
    (pubkeys_text().replace(OWNER, "did:key:z6MkSomebodyElse"), "is not did:key:z6MkiN89"),
    (pubkeys_text().replace(CHARTER, "00" * 32), "the export is"),
])
def test_genesis_keeps_no_pubkeys_of_a_log_the_relaunch_did_not_mean(host, pubkeys, problem):
    custody = genesis_ready(host, pubkeys=pubkeys)
    r = host.run("genesis", "--custody-dir", str(custody))
    assert r.returncode == 1 and problem in r.stdout + r.stderr, r.stdout + r.stderr
    assert not (host.launch / "pubkeys.txt").exists()
    assert (custody / "server-seed-v2.hex.started").exists()  # that seed is spent all the same


# -- the witness: a new identity, pinned before the card names it ---------------------------------------------------

def witness_cli(data: Path, *args: str) -> str:
    env = dict(os.environ, AICS_WITNESS_CONFIG=str(data / "witness.json"),
               PYTHONPATH=str(WITNESS_SRC) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    r = subprocess.run([sys.executable, "-m", "aics_witness", *args], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def pin_step() -> str:
    """The pin step of ops/witness/bootstrap-witness-host.sh, exactly as it runs in the witness container."""
    m = re.search(r'--entrypoint python3 aics-witness - "\$origin" "\$initial_size" "\$initial_root" <<\'PY\'\n(.*?\n)PY\n',
                  BOOTSTRAP.read_text(), re.S)
    assert m, "the pin step of bootstrap-witness-host.sh moved"
    return m.group(1)


def witness_volume(host: Host, name: str = W1, origin_log: str = V1_LOG, size: int = 35) -> tuple[Path, str]:
    """The witness host as it stands at the relaunch: a real aics-witness of NAME in a volume directory, trusting
    the log to discard and holding its state at SIZE; and a bootstrap-witness-host.sh that does what the real one
    does to the volume (init, add-log, the pin step) and records its arguments."""
    data = host.tmp / "witness-data"
    data.mkdir()
    vkey = witness_cli(data, "init", "--name", name).splitlines()[-1]
    witness_cli(data, "add-log", "--origin", ORIGIN, "--vkey", origin_log)
    with WitnessStore(load_config(data / "witness.json").db_path) as store:
        with store.transaction() as tx:
            tx.put(origin=ORIGIN, size=size, root=b"\x11" * 32, note="a cosigned note of the discarded log\n",
                   timestamp=T0, updated_at=T0)
    here = host.home / "aics/ops/witness"
    (here / "compose.yml").write_text("name: aics-witness\n")
    (host.tmp / "pin_step.py").write_text(pin_step())
    (host.tmp / "fake_bootstrap.py").write_text(f"""import os, subprocess, sys
args = sys.argv[1:]
open({str(host.tmp / "bootstrap.args")!r}, "w").write("\\n".join(args) + "\\n")
opts = dict(zip(args[::2], args[1::2]))
env = dict(os.environ, AICS_WITNESS_CONFIG={str(data / "witness.json")!r},
           PYTHONPATH={str(WITNESS_SRC)!r} + os.pathsep + os.environ.get("PYTHONPATH", ""))
def run(*argv, **kw):
    subprocess.run([sys.executable, *argv], env=env, check=True, **kw)
run("-m", "aics_witness", "init", "--name", opts["--name"])
run("-m", "aics_witness", "add-log", "--origin", opts["--origin"], "--vkey", opts["--log-vkey"])
run({str(host.tmp / "pin_step.py")!r}, opts["--origin"], opts["--initial-size"], opts["--initial-root"])
""")
    (here / "bootstrap-witness-host.sh").write_text(f'#!/bin/sh\nexec "{sys.executable}" "{host.tmp / "fake_bootstrap.py"}" "$@"\n')
    host.docker(running=["caddy"], witness_data=str(data))
    return data, vkey


def status(data: Path) -> dict:
    return json.loads(witness_cli(data, "status", "--json"))


def test_the_witness_retires_w1_and_pins_a_new_identity_to_the_new_log(host):
    data, w1_vkey = witness_volume(host)
    w1_key = (data / "witness.key").read_bytes()
    r = host.run_remote("witness_repin", ORIGIN, NEW_LOG, "2", ROOT_AT_2, W2, w1_vkey)
    assert r.returncode == 0, r.stdout + r.stderr
    retired = data / "retired-w1"
    assert sorted(p.name for p in retired.iterdir() if not p.name.endswith(("-wal", "-shm"))) == \
        ["witness.db", "witness.json", "witness.key"]
    assert (retired / "witness.key").read_bytes() == w1_key  # moved, never rewritten or deleted
    with WitnessStore(retired / "witness.db") as old:
        assert [(s.origin, s.size) for s in old.all_logs()] == [(ORIGIN, 35)]  # the discarded log's record, intact
    doc = status(data)
    w = doc["witness"]
    assert w["name"] == W2 and w["vkey"].startswith(W2 + "+") and w["db_witness_vkey"] == w["vkey"]
    assert w["vkey"] != w1_vkey and (data / "witness.key").read_bytes() != w1_key
    assert [(e["origin"], e["vkeys"], e["initial"], e["size"]) for e in doc["logs"]] == \
        [(ORIGIN, [NEW_LOG], {"size": 2, "root": ROOT_AT_2}, None)]  # pinned, nothing cosigned yet
    assert r.stdout.splitlines()[-1] == f"witness-vkey {w['vkey']}"
    assert (host.tmp / "bootstrap.args").read_text().splitlines()[:2] == ["--name", W2]
    docker = [c["args"] for c in host.calls("docker")]
    assert docker.index(["compose", "stop", "aics-witness"]) < next(
        i for i, c in enumerate(docker) if c[-3:] == ["init", "--name", W2])
    # once more: pinned already, left alone, the same vkey
    (host.tmp / "bootstrap.args").unlink()
    r = host.run_remote("witness_repin", ORIGIN, NEW_LOG, "2", ROOT_AT_2, W2, w1_vkey)
    assert r.returncode == 0 and "already trusts the new log alone" in r.stdout, r.stdout + r.stderr
    assert r.stdout.splitlines()[-1] == f"witness-vkey {w['vkey']}" and not (host.tmp / "bootstrap.args").exists()
    assert status(data)["witness"]["vkey"] == w["vkey"]


def test_the_witness_refuses_before_stopping_when_its_key_is_not_the_one_to_retire(host):
    data, _ = witness_volume(host)
    r = host.run_remote("witness_repin", ORIGIN, NEW_LOG, "2", ROOT_AT_2, W2, W1_VKEY)  # the production w1's vkey
    assert r.returncode != 0 and f"has the key" in r.stderr and f"not {W1_VKEY}" in r.stderr, r.stderr
    assert ["compose", "stop", "aics-witness"] not in [c["args"] for c in host.calls("docker")]
    assert status(data)["witness"]["name"] == W1 and not (data / "retired-w1").exists()


def test_the_witness_refuses_an_identity_that_is_neither_the_old_nor_the_new_one(host):
    data, _ = witness_volume(host, name="witness.wesupport-ai.com/w7")
    r = host.run_remote("witness_repin", ORIGIN, NEW_LOG, "2", ROOT_AT_2, W2, W1_VKEY)
    assert r.returncode != 0 and "neither the identity to retire" in r.stderr
    assert not any(c["args"][:2] == ["compose", "stop"] for c in host.calls("docker"))


def test_the_new_identity_never_trusts_another_log(host):
    data, w1_vkey = witness_volume(host)
    assert host.run_remote("witness_repin", ORIGIN, NEW_LOG, "2", ROOT_AT_2, W2, w1_vkey).returncode == 0
    r = host.run_remote("witness_repin", ORIGIN, OLD_LOG, "2", ROOT_AT_2, W2, w1_vkey)  # a redo's log, same name
    assert r.returncode != 0 and "not the new log alone" in r.stderr


def test_the_witness_finishes_a_retirement_that_stopped_after_the_move(host):
    data, w1_vkey = witness_volume(host)
    retired = data / "retired-w1"
    retired.mkdir()
    for name in ("witness.db", "witness.db-wal", "witness.db-shm", "witness.key", "witness.json"):
        if (data / name).exists():
            os.replace(data / name, retired / name)
    r = host.run_remote("witness_repin", ORIGIN, NEW_LOG, "2", ROOT_AT_2, W2, w1_vkey)
    assert r.returncode == 0, r.stdout + r.stderr
    assert status(data)["witness"]["name"] == W2 and (retired / "witness.key").exists()


def stage_witness_ready(host: Host) -> tuple[Path, str]:
    (host.launch / "pubkeys.txt").write_text(pubkeys_text())
    note, _, _ = tlog([leaf("policy", NEW_POLICY, T0)], LOG)
    host.serve({"https://api.wesupport-ai.com/tiles/checkpoint": {"body": note}})
    return witness_volume(host)


def test_the_witness_stage_pins_the_verified_size_1_checkpoint_and_records_the_new_vkey(host):
    data, w1_vkey = stage_witness_ready(host)
    r = host.run("--retire-witness-vkey", w1_vkey, "witness", FAKE_UV_REAL="1")
    assert r.returncode == 0, r.stdout + r.stderr
    vkey = status(data)["witness"]["vkey"]
    assert (host.launch / "witness-vkey.txt").read_text() == vkey + "\n"
    assert (host.launch / "witness-feeder.env").read_text() == \
        f"AICS_WITNESSES=founder-w2=https://witness.wesupport-ai.com={vkey}\n"
    pin = status(data)["logs"][0]["initial"]
    assert pin["size"] == 1 and pin == {"size": 1, "root": (host.launch / "witness-pin.txt").read_text().splitlines()[2]}
    assert json.loads((host.launch / "witness-pin.json").read_text())["ok"] is True  # verified under the new log key
    assert not host.calls("curl")[1:]  # no cosignature wait: the feeder is off until the card stage
    r = host.run("--retire-witness-vkey", w1_vkey, "witness", FAKE_UV_REAL="1")
    assert r.returncode == 0 and "already trusts the new log alone" in r.stdout
    assert (host.launch / "witness-vkey.txt").read_text() == vkey + "\n"


def test_the_witness_stage_refuses_a_checkpoint_of_another_log(host):
    data, w1_vkey = stage_witness_ready(host)
    note, _, _ = tlog([leaf("policy", NEW_POLICY, T0)], OLD)
    host.serve({"https://api.wesupport-ai.com/tiles/checkpoint": {"body": note}})
    r = host.run("--retire-witness-vkey", w1_vkey, "witness", FAKE_UV_REAL="1")
    assert r.returncode == 1 and "does not verify under the new log key" in r.stderr
    assert status(data)["witness"]["name"] == W1 and host.calls("ssh") == []


def test_the_witness_stage_stops_before_the_host_while_the_retired_witnesss_file_is_left(host):
    data, w1_vkey = stage_witness_ready(host)
    (host.launch / "witness-vkey.txt").write_text(w1_vkey + "\n")  # archive did not run
    r = host.run("--retire-witness-vkey", w1_vkey, "witness", FAKE_UV_REAL="1")
    assert r.returncode == 1 and "run archive first" in r.stderr
    assert host.calls("ssh") == [] and status(data)["witness"]["name"] == W1


def test_the_witness_stage_with_print_only_prints_the_block_and_records_nothing(host):
    data, w1_vkey = stage_witness_ready(host)
    r = host.run("--print-only", "--retire-witness-vkey", w1_vkey, "witness", FAKE_UV_REAL="1")
    assert r.returncode == 0, r.stderr
    assert "--- witness_repin: run on aics-trials ---" in r.stdout and 'retired="retired-${old_name##*/}"' in r.stdout
    assert "--witness-vkey" in r.stdout and host.calls("ssh") == []
    assert not (host.launch / "witness-vkey.txt").exists() and status(data)["witness"]["name"] == W1


# -- the card: the new keys and the new witness, which must cosign before the card is previewed and logged -----------

CARD_URL = "https://api.wesupport-ai.com/.well-known/aics-card.json"


def healthz(ok: bool = True) -> dict:
    return {"body": json.dumps({"status": "OPERATIONAL", "witnesses": [
        {"name": "founder-w2", "vkey": W2_VKEY, "state": "ok" if ok else "failing", "cosigned_current": ok}]})}


def cosigned_note(size: int = 2) -> str:
    entries = [leaf("policy", NEW_POLICY, T0 + i) for i in range(size)]
    return tlog(entries, LOG, cosigners=((W2, W2_KEY),))[0]


def card_ready(host: Host) -> None:
    """After genesis and the witness stage: the new keys, the witness's vkey, and a VPS whose deploy serves the filled
    body signed by the policy key (as aics-server does with AICS_CARD_FILE) while the witness cosigns."""
    (host.launch / "pubkeys.txt").write_text(pubkeys_text())
    (host.launch / "witness-vkey.txt").write_text(W2_VKEY + "\n")
    wt = host.worktree
    for d in ("card", "docs"):
        shutil.copytree(ROOT / d, wt / d, ignore=shutil.ignore_patterns(".venv", "__pycache__", ".pytest_cache", ".test-tmp"))
    (wt / "deploy/card").mkdir(parents=True)
    (host.tmp / "policy.seed").write_bytes(POLICY.private.private_bytes_raw())
    (wt / "deploy/deploy-vps.sh").write_text(f"""#!/bin/sh
echo "deploy-vps.sh $*" >> "{host.tmp}/deploy.ran"
exec "{sys.executable}" - <<'PY'
import json, sys
sys.path.insert(0, {str(wt / "card")!r})
from validate_card import b64u, jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
body = json.load(open({str(wt / "deploy/card/card-unsigned.json")!r}))
key = Ed25519PrivateKey.from_private_bytes(open({str(host.tmp / "policy.seed")!r}, "rb").read())
protected = b64u(jcs({{"alg": "EdDSA", "kid": body["policy_kid"], "typ": "JOSE"}}))
sig = b64u(key.sign((protected + "." + b64u(jcs(body))).encode()))
card = jcs(dict(body, signatures=[{{"protected": protected, "signature": sig}}])).decode()
routes = json.load(open({str(host.curl_map)!r}))
routes[{CARD_URL!r}] = {{"body": card, "headers": "HTTP/2 200\\r\\nx-aics-card-source: file\\r\\nx-aics-card-leaf: none\\r\\n\\r\\n"}}
json.dump(routes, open({str(host.curl_map)!r}, "w"))
PY
""")
    host.env_file({"AICS_OWNER_PUBKEY": OWNER, "AICS_SERVER_SEED_HEX": NEW_SEED, "CLOUDFLARE_API_TOKEN": TOKEN})
    host.serve({"https://api.wesupport-ai.com/v2/limits": {"body": json.dumps({"limits": {"ciphertext_budget_bytes": 8589934592}})},
                "https://witness.wesupport-ai.com/vkey.txt": {"body": W2_VKEY + "\n"},
                "https://api.wesupport-ai.com/healthz": healthz(),
                "https://api.wesupport-ai.com/checkpoint": {"body": cosigned_note()}})


def missing_card_inputs() -> list[str]:
    text = (ROOT / "card/card-content.json").read_text()
    return [p for p in sorted(set(re.findall(r"<FILL:SHA256:([^>]+)>", text))) if not (ROOT / p).is_file()]


CARD_ARGS = ("--custodian-name", "C. Custodian", "--custodian-holds", "named successor; receives a sealed offline copy")


@pytest.mark.skipif(bool(missing_card_inputs()), reason=f"the card hashes files not committed yet: {missing_card_inputs()}")
def test_the_card_stage_fills_the_template_names_the_new_witness_and_waits_for_its_cosignature(host):
    card_ready(host)
    r = host.run("card", *CARD_ARGS, FAKE_UV_REAL="1")
    assert r.returncode == 0, r.stdout + r.stderr
    body = json.loads((host.worktree / "deploy/card/card-unsigned.json").read_text())
    assert (body["log_vkey"], body["policy_kid"], body["owner_kid"]) == (NEW_LOG, NEW_POLICY, OWNER)
    wp = body["witness_policy"]
    assert wp["quorum"] == 1 and [(w["name"], w["vkey"]) for w in wp["witnesses"]] == [(W2, W2_VKEY)]
    report = json.loads((host.launch / "card-fill.json").read_text())
    assert report["ok"] is True and report.get("ready_to_sign") is True
    assert (host.repo / "deploy/card/card-unsigned.json").read_bytes() == (host.launch / "card-unsigned.json").read_bytes()
    lines = host.env_lines()
    assert "AICS_CARD_FILE=/etc/aics/card/card-unsigned.json" in lines
    assert f"AICS_WITNESSES=founder-w2=https://witness.wesupport-ai.com={W2_VKEY}" in lines
    gate = json.loads((host.launch / "card-checkpoint.json").read_text())
    assert gate["ok"] is True and gate["cosignatures"] >= 1 and gate["quorum"] == 1  # the real whole-chain check
    assert "the witness cosigns: checkpoint size 2 verifies at quorum 1" in r.stdout
    assert f"witness quorum 1: {W2} (founder, independent False)" in r.stdout and "validator ok: True" in r.stdout
    assert json.loads((host.launch / "card-preview.json").read_text())["ok"] is True
    assert NEW_SEED not in r.stdout + r.stderr and TOKEN not in r.stdout + r.stderr


@pytest.mark.skipif(bool(missing_card_inputs()), reason=f"the card hashes files not committed yet: {missing_card_inputs()}")
def test_the_card_stage_stops_before_the_preview_while_the_witness_does_not_cosign(host):
    card_ready(host)
    host.serve({"https://api.wesupport-ai.com/healthz": healthz(ok=False)}, merge=True)
    r = host.run("card", *CARD_ARGS, FAKE_UV_REAL="validate_card")
    assert r.returncode == 1 and "does not show witness.wesupport-ai.com/w2 ok with cosigned_current" in r.stderr
    assert not (host.launch / "card.json").exists() and not (host.launch / "card-preview.json").exists()


def test_the_card_stage_refuses_a_witness_page_that_serves_another_vkey(host):
    card_ready(host)
    host.serve({"https://witness.wesupport-ai.com/vkey.txt": {"body": W1_VKEY + "\n"}}, merge=True)
    r = host.run("card", *CARD_ARGS)
    assert r.returncode == 1 and "vkey.txt serves" in r.stderr
    assert not (host.tmp / "deploy.ran").exists()


def test_the_card_stage_needs_the_witness_stage(host):
    card_ready(host)
    (host.launch / "witness-vkey.txt").unlink()
    r = host.run("card", *CARD_ARGS)
    assert r.returncode == 1 and "run the witness stage" in r.stderr
    (host.launch / "witness-vkey.txt").write_text(W1_VKEY + "\n")  # the retired witness's file, not archived
    r = host.run("card", *CARD_ARGS)
    assert r.returncode == 1 and "run archive" in r.stderr
    assert not (host.tmp / "deploy.ran").exists()


def card_log_ready(host: Host, *, source: str = "file", body: str = '{"previewed": true}') -> Path:
    (host.launch / "pubkeys.txt").write_text(pubkeys_text())
    (host.launch / "witness-vkey.txt").write_text(W2_VKEY + "\n")
    (host.launch / "card.json").write_text('{"previewed": true}')
    key = custody_dir(host) / "owner.key"
    key.write_text("not read by this script\n")
    key.chmod(0o600)
    host.serve({CARD_URL: {"body": body, "headers": f"HTTP/2 200\r\nx-aics-card-source: {source}\r\n\r\n"},
                "https://api.wesupport-ai.com/healthz": healthz(),
                "https://api.wesupport-ai.com/checkpoint": {"body": cosigned_note(1)}})
    return key


def owner_tool_calls(host: Host) -> list[dict]:
    return [c for c in host.calls("uv") if any(a.endswith("aics_client.py") for a in c["args"])]


def test_card_log_logs_only_the_previewed_card(host):
    key = card_log_ready(host, body='{"changed": true}')
    r = host.run("card-log", "--owner-key", str(key))
    assert r.returncode == 1 and "changed since the preview" in r.stderr
    assert owner_tool_calls(host) == []  # the owner tool never ran
    card_log_ready(host, source="logged")
    r = host.run("card-log", "--owner-key", str(key))
    assert r.returncode == 0 and "logged already" in r.stdout and owner_tool_calls(host) == []
    assert (host.launch / "logged.json").read_text() == '{"previewed": true}'


def test_card_log_refuses_while_the_witness_does_not_cosign(host):
    key = card_log_ready(host)
    host.serve({"https://api.wesupport-ai.com/healthz": healthz(ok=False)}, merge=True)
    r = host.run("card-log", "--owner-key", str(key))
    assert r.returncode == 1 and "cosigned_current" in r.stderr
    assert owner_tool_calls(host) == []


def owner_tool_logs_the_card(host: Host) -> str:
    """The fake owner tool logs the card: the server then serves it as logged, leaf 1. Returns what the tool prints."""
    hook = host.bin / "uv"
    hook.write_text(hook.read_text().replace(
        "    print(os.environ.get(\"FAKE_OWNER_OUTPUT\", \"{}\"))",
        "    routes = json.load(open(os.environ['FAKE_CURL_MAP']))\n"
        f"    routes[{CARD_URL!r}]['headers'] = 'HTTP/2 200\\r\\nx-aics-card-source: logged\\r\\nx-aics-card-leaf: 1\\r\\n\\r\\n'\n"
        "    json.dump(routes, open(os.environ['FAKE_CURL_MAP'], 'w'))\n"
        "    print(os.environ.get(\"FAKE_OWNER_OUTPUT\", \"{}\"))"))
    return json.dumps({"policy": {"leaf_index": 1, "prev_policy_index": 0}})


@pytest.mark.parametrize("cosigned", [True, False])
def test_card_log_needs_the_served_checkpoint_to_verify_at_quorum_1(host, cosigned):
    key = card_log_ready(host)
    if not cosigned:  # healthz says ok, but the note carries the log signature alone
        host.serve({"https://api.wesupport-ai.com/checkpoint": {"body": tlog([leaf("policy", NEW_POLICY, T0)], LOG)[0]}},
                   merge=True)
    owner = owner_tool_logs_the_card(host)  # it runs only after the gate
    r = host.run("card-log", "--owner-key", str(key), FAKE_UV_REAL="1", FAKE_OWNER_OUTPUT=owner)
    if cosigned:
        assert r.returncode == 0, r.stdout + r.stderr
        assert len(owner_tool_calls(host)) == 1 and "the card is leaf 1" in r.stdout
        assert json.loads((host.launch / "logged-leaf.json").read_text())["policy"]["leaf_index"] == 1
    else:
        assert r.returncode == 1 and "does not verify at quorum 1" in r.stderr
        assert owner_tool_calls(host) == []


def test_the_witness_gate_waits_out_a_head_the_witness_has_not_cosigned_yet(host):
    """Publish-then-cosign: right after a write the served head carries the log signature alone."""
    key = card_log_ready(host)
    log_only = tlog([leaf("policy", NEW_POLICY, T0)], LOG)[0]
    host.serve({"https://api.wesupport-ai.com/checkpoint": {"sequence": [{"body": log_only}, {"body": cosigned_note(1)}]}},
               merge=True)
    owner = owner_tool_logs_the_card(host)
    r = host.run("card-log", "--owner-key", str(key), FAKE_UV_REAL="aics-tlog", FAKE_OWNER_OUTPUT=owner)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "the witness cosigns: checkpoint size 1 verifies at quorum 1" in r.stdout
    assert len(owner_tool_calls(host)) == 1  # logged once the head carried the cosignature
    assert len([c for c in host.calls("curl") if c["args"][-1] == "https://api.wesupport-ai.com/checkpoint"]) >= 2


# -- card environment, the remote .env editor ------------------------------------------------------------------------

def test_the_card_settings_are_set_once(host):
    host.env_file({"AICS_OWNER_PUBKEY": OWNER, "AICS_SERVER_SEED_HEX": OLD_SEED})
    wit = f"founder-w2=https://witness.wesupport-ai.com={W2_VKEY}"
    r = host.run_remote("vps_card_env", str(host.remote), "/etc/aics/card/card-unsigned.json", wit)
    assert r.returncode == 0, r.stderr
    assert "AICS_CARD_FILE: added" in r.stdout and "AICS_WITNESSES: added" in r.stdout
    assert host.env_lines()[-2:] == ["AICS_CARD_FILE=/etc/aics/card/card-unsigned.json", f"AICS_WITNESSES={wit}"]
    r = host.run_remote("vps_card_env", str(host.remote), "/etc/aics/card/card-unsigned.json", wit)
    assert "AICS_CARD_FILE: unchanged" in r.stdout and "AICS_WITNESSES: unchanged" in r.stdout
    assert OLD_SEED not in r.stdout + r.stderr


# -- dns ------------------------------------------------------------------------------------------------------------

FAKE_CLOUDFLARE = """#!/bin/sh
{
  printf 'args:'; printf ' %s' "$@"; printf '\\n'
  env | sort | sed 's/=.*//' | tr '\\n' ' '; printf '\\n'
  printf 'token:%s\\n' "$CLOUDFLARE_API_TOKEN"
  while [ $# -gt 0 ]; do
    case $1 in --bundle|--witness-txt) printf '%s:%s\\n' "$1" "$(cat "$2")"; shift 2 ;; *) shift ;; esac
  done
} > "$CF_RECORD"
env > "$CF_RECORD.env"
"""


def dns_ready(host: Host, token_line: str = f"CLOUDFLARE_API_TOKEN={TOKEN}") -> str:
    txt = "aics1=" + "A" * 600
    for name, text in (("txt-value.txt", txt + "\n"), ("readme-block.txt", f"{txt}\nsha256: {'12' * 32}\n"),
                       ("bundle.json", json.dumps({"txt": txt})), ("witness-vkey.txt", W2_VKEY + "\n")):
        (host.launch / name).write_text(text)
    (host.worktree / "ops").mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "ops/cloudflare-dns.sh", host.worktree / "ops/cloudflare-dns.sh")
    (host.remote / "ops").mkdir(parents=True, exist_ok=True)
    (host.remote / "ops/cloudflare-dns.sh").write_text(FAKE_CLOUDFLARE.replace("$CF_RECORD", str(host.tmp / "cf.record")))
    (host.remote / "deploy/.env").write_text(f"AICS_SERVER_SEED_HEX={OLD_SEED}\n{token_line}\nAICS_OWNER_PUBKEY={OWNER}\n")
    host.dns({"_aics.wesupport-ai.com": txt, "_aics-witness.witness.wesupport-ai.com": f"aics-witness-vkey {W2_VKEY}"})
    return txt


@pytest.mark.parametrize("token_line", [f"CLOUDFLARE_API_TOKEN={TOKEN}", f'export CLOUDFLARE_API_TOKEN="{TOKEN}"'])
def test_dns_publishes_both_records_with_the_token_alone_and_waits_for_1111(host, token_line):
    txt = dns_ready(host, token_line)
    r = host.run("dns")
    assert r.returncode == 0, r.stdout + r.stderr
    record = (host.tmp / "cf.record").read_text().splitlines()
    assert record[0].startswith("args: --apply --bundle ") and " --witness-txt " in record[0] and record[0].endswith(" 148.113.238.39")
    names = set(record[1].split()) - {"PWD", "SHLVL", "_", "OLDPWD"}
    assert names == {"PATH", "HOME", "CLOUDFLARE_API_TOKEN"}, names  # nothing else of deploy/.env or the shell
    assert record[2] == f"token:{TOKEN}"
    assert record[3] == f"--bundle:{txt}" and record[4] == f"--witness-txt:{W2_VKEY}"
    assert OLD_SEED not in (host.tmp / "cf.record.env").read_text()
    assert not list((host.remote / "deploy").glob(".relaunch-dns.*"))  # the files it was given are gone
    assert (host.launch / "txt-live.txt").read_text() == txt + "\n"
    assert (host.launch / "witness-txt-live.txt").read_text() == f"aics-witness-vkey {W2_VKEY}\n"
    assert '"name":"_aics-witness.witness.wesupport-ai.com"' in r.stdout  # the local plan, printed first
    assert TOKEN not in r.stdout + r.stderr and OLD_SEED not in r.stdout + r.stderr
    assert all(TOKEN not in c["command"] for c in host.calls("ssh"))


def test_dns_waits_for_the_old_witness_record_to_go(host):
    dns_ready(host)
    host.dns({"_aics.wesupport-ai.com": "aics1=" + "A" * 600,
              "_aics-witness.witness.wesupport-ai.com": f"aics-witness-vkey {W1_VKEY}"})
    r = host.run("dns")
    assert r.returncode == 1 and "after 6.5 minutes" in r.stderr
    assert len(host.calls("dig")) == 2 * 78
    assert not (host.launch / "txt-live.txt").exists()


# -- bundle and verify ------------------------------------------------------------------------------------------------

def new_card(witness: tuple[str, str] = (W2, W2_VKEY)) -> bytes:
    return json.dumps({"origin": ORIGIN, "log_vkey": NEW_LOG, "policy_kid": NEW_POLICY, "owner_kid": OWNER,
                       "witness_policy": {"quorum": 1, "witnesses": [{"name": witness[0], "vkey": witness[1],
                                                                      "trust_domain": "founder", "independent": False}]}},
                      separators=(",", ":"), sort_keys=True).encode()


def trust_build(host: Host, card: bytes, log: str = NEW_LOG) -> dict:
    """What aics trust build answers for this card (the fake uv prints it)."""
    jcs = json.dumps({"bootstrap_card_hash": hashlib.sha256(card).hexdigest(), "log_vkey": log, "origin": ORIGIN,
                      "owner_kid": OWNER, "policy_kid": NEW_POLICY, "v": 1}, separators=(",", ":"), sort_keys=True)
    doc = {"ok": True, "bundle_jcs": jcs, "sha256": hashlib.sha256(jcs.encode()).hexdigest(),
           "txt": "aics1=" + base64.urlsafe_b64encode(jcs.encode()).decode().rstrip("="), "card_leaf_index": 1}
    (host.tmp / "trust-build.json").write_text(json.dumps(doc))
    return doc


def bundle_ready(host: Host, card: bytes | None = None, log: str = NEW_LOG) -> dict:
    card = card or new_card()
    (host.launch / "pubkeys.txt").write_text(pubkeys_text())
    (host.launch / "logged.json").write_bytes(card)
    (host.launch / "witness-vkey.txt").write_text(W2_VKEY + "\n")
    leaf0 = base64.urlsafe_b64encode(leaf("policy", NEW_POLICY, GENESIS_TS)).decode().rstrip("=")
    host.serve({"https://api.wesupport-ai.com/v2/entries/0": {"body": json.dumps({"entry_bytes": leaf0})}})
    return trust_build(host, card, log)


def test_bundle_writes_the_launch_files_of_the_new_bundle(host):
    doc = bundle_ready(host)
    r = host.run("bundle", FAKE_TRUST_BUILD=str(host.tmp / "trust-build.json"))
    assert r.returncode == 0, r.stdout + r.stderr
    L = host.launch
    assert (L / "bundle.jcs").read_text() == doc["bundle_jcs"] and (L / "txt-value.txt").read_text() == doc["txt"] + "\n"
    assert (L / "readme-block.txt").read_text() == f"{doc['txt']}\nsha256: {doc['sha256']}\n"
    facts = json.loads((L / "genesis.json").read_text())
    assert facts["genesis_ts"] == GENESIS_TS and facts["card_leaf_index"] == 1 and facts["charter_sha256"] == CHARTER
    assert facts["witness_name"] == W2 and facts["witness_vkey"] == W2_VKEY and facts["retired_witness_vkey"] == W1_VKEY
    assert json.loads((L / "bundle.json").read_text())["sha256"] == doc["sha256"]
    r = host.run("bundle", FAKE_TRUST_BUILD=str(host.tmp / "trust-build.json"))  # the same bundle again: fine
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize(("card", "log", "problem"), [
    (new_card((W2, "witness.wesupport-ai.com/w2+00000000+AAAA")), NEW_LOG, "does not list the witness"),
    (None, V1_LOG, "this is the discarded log's bundle"),
])
def test_bundle_refuses_a_card_without_the_new_witness_or_the_discarded_log(host, card, log, problem):
    bundle_ready(host, card, log)
    r = host.run("bundle", FAKE_TRUST_BUILD=str(host.tmp / "trust-build.json"))
    assert r.returncode == 1 and problem in r.stdout, r.stdout + r.stderr
    assert not (host.launch / "bundle.json").exists() and not (host.launch / "genesis.json").exists()


def verify_ready(host: Host) -> Path:
    doc = bundle_ready(host)
    L = host.launch
    (L / "readme-block.txt").write_text(f"{doc['txt']}\nsha256: {doc['sha256']}\n")
    (L / "log.vkey").write_text(NEW_LOG + "\n")
    client = b"# the one-file client\n__version__ = \"4.3.0\"\n"
    (host.worktree / "packages/aics-server/src/aics_server/static").mkdir(parents=True)
    (host.worktree / "packages/aics-server/src/aics_server/static/aics_client.py").write_bytes(client)
    (host.worktree / "ops").mkdir()
    (host.worktree / "ops/uptime-check.sh").write_text(f'echo "uptime $AICS_WITNESS_VKEY_FILE" >> "{host.tmp}/uptime.ran"\n')
    repo = host.tmp / "docsrepo"
    (repo / "packages/aics-cli/src/aics_cli").mkdir(parents=True)
    (repo / "packages/aics-cli/src/aics_cli/published_keys.py").write_text(f"AICS_TRUST_BUNDLE_SHA256 = '{doc['sha256']}'\n")
    (repo / "README.md").write_text(f"`{hashlib.sha256(client).hexdigest()}`.\n")
    host.serve({"https://api.wesupport-ai.com/checkpoint": {"body": cosigned_note(2)},
                "https://wesupport-ai.com/static/aics_client.py": {"body_b64": base64.b64encode(client).decode()},
                "https://witness.wesupport-ai.com/vkey.txt": {"body": W2_VKEY + "\n"},
                "https://test.wesupport-ai.com/tiles/checkpoint": {"body": "test.wesupport-ai.com/tiles\n3\nAAAA\n"}})
    host.dns({"_aics-witness.witness.wesupport-ai.com": f"aics-witness-vkey {W2_VKEY}"})
    return repo


def test_verify_checks_the_chain_the_witness_and_the_served_client(host):
    repo = verify_ready(host)
    r = host.run("verify", "--docs-repo", str(repo), FAKE_UV_REAL="aics-tlog")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "verified: card, checkpoint, consistency, uptime, the whole chain at quorum 1" in r.stdout
    aics = [c["args"] for c in host.calls("uv") if "aics" in c["args"]]
    assert [a[a.index("aics") + 3:a.index("aics") + 5] for a in aics] == \
        [["policy", "init"], ["verify", "card"], ["verify", "checkpoint"], ["verify", "consistency"]]
    assert (host.tmp / "uptime.ran").read_text() == f"uptime {host.launch}/witness-vkey.txt\n"


@pytest.mark.parametrize(("change", "message"), [
    ("dns", "does not name"),
    ("keys", "does not carry the new bundle"),
    ("page", "vkey.txt does not serve"),
])
def test_verify_stops_on_a_stale_record(host, change, message):
    repo = verify_ready(host)
    if change == "dns":
        host.dns({"_aics-witness.witness.wesupport-ai.com": f"aics-witness-vkey {W1_VKEY}"})
    elif change == "keys":
        (repo / "packages/aics-cli/src/aics_cli/published_keys.py").write_text(f"AICS_TRUST_BUNDLE_SHA256 = '{V1_SHA}'\n")
    else:
        host.serve({"https://witness.wesupport-ai.com/vkey.txt": {"body": W1_VKEY + "\n"}}, merge=True)
    r = host.run("verify", "--docs-repo", str(repo), FAKE_UV_REAL="aics-tlog")
    assert r.returncode == 1 and message in r.stderr, r.stdout + r.stderr


# -- the probes and watches ----------------------------------------------------------------------------------------

def test_the_vantage_pins_the_new_log_and_witness_keys_and_sets_the_old_state_aside_once(host):
    conf = host.root / "etc/aics-vantage"
    conf.mkdir(parents=True)
    (conf / "log.vkey").write_text(V1_LOG + "\n")
    (conf / "witness.vkey").write_text(W1_VKEY + "\n")
    state = host.root / "var/lib/aics-vantage"
    (state / "markers").mkdir(parents=True)
    (state / "markers/witness_seen").write_text("2026-10-20T00:00:00Z\n")
    (state / "groups").mkdir()
    (state / "witness.info").write_text("witness: size 35\n")
    (state / "mirror-evidence").mkdir()
    watch = host.root / "var/lib/aics-watch"
    watch.mkdir(parents=True)
    (watch / "state").write_text("health=OPERATIONAL\nsize=35\n")
    enabled = "aics-vantage-uptime.timer aics-vantage-mirror.timer aics-first-contact.timer"
    r = host.run_remote("witness_vantage", NEW_LOG, W2_VKEY, LABEL, FAKE_ENABLED=enabled)
    assert r.returncode == 0, r.stderr
    assert (conf / "log.vkey").read_text() == NEW_LOG + "\n" and (conf / "witness.vkey").read_text() == W2_VKEY + "\n"
    aside = host.root / f"var/lib/aics-vantage-{LABEL}"
    assert (aside / "markers/witness_seen").exists() and (aside / "witness.info").exists() and (aside / "groups").exists()
    assert not (state / "markers").exists() and (state / "mirror-evidence").exists()
    assert (watch / f"state.{LABEL}").exists() and not (watch / "state").exists()
    started = [c["args"][1] for c in host.calls("systemctl") if c["args"][0] == "start"]
    assert started == enabled.split()
    (state / "markers").mkdir()  # the probe's new state after the restart
    r = host.run_remote("witness_vantage", NEW_LOG, W2_VKEY, LABEL, FAKE_ENABLED=enabled)
    assert r.returncode == 0 and "new log vkey is already pinned" in r.stdout and "already in" in r.stdout
    assert "new witness vkey is already pinned" in r.stdout and (state / "markers").exists()
    r = host.run_remote("witness_vantage", NEW_LOG, "not a vkey", LABEL)
    assert r.returncode == 2 and "is not a vkey" in r.stderr


def test_the_vps_watches_restart_but_the_mirror_waits_for_empty_buckets(host):
    watch = host.root / "var/lib/aics-watch"
    watch.mkdir(parents=True)
    (watch / "state").write_text("health=OPERATIONAL\nsize=35\n")
    r = host.run_remote("vps_resume", LABEL, FAKE_ENABLED="aics-first-contact.timer aics-mirror-sync.timer")
    assert r.returncode == 0, r.stderr
    started = [c["args"][1] for c in host.calls("systemctl") if c["args"][0] == "start"]
    assert started == ["aics-first-contact.timer"]
    assert "NOT started: aics-mirror-sync.timer" in r.stdout
    assert (watch / f"state.{LABEL}").exists() and not (watch / "state").exists()


# -- the docs rewrite ------------------------------------------------------------------------------------------------

#: The last commit before the docs stage rewrote these files on 2026-10-22.
DOCS_BASE = "34e8a5b"
DOCS = ["README.md", "docs/DECISIONS.md", "packages/aics-cli/src/aics_cli/published_keys.py",
        "packages/aics-cli/CHANGELOG.md", "docs/astra_remaining_pushes.md", "docs/astra_finish_the_job.md",
        "packages/aics-server/src/aics_server/static/aics_client.py", "ops/witness/README.md"]
GENESIS_TS = 1792465200  # 2026-10-20 03:00 UTC, 06:00 in Athens


def docs_inputs(host: Host, bundle_sha: str | None = None, witness: tuple[str, str] = (W2, W2_VKEY)) -> tuple[Path, bytes, str]:
    repo = host.tmp / "repo"
    # The texts as they were before the docs stage ran for real on 2026-10-22 (the repository's own copies
    # carry its result since then): the stage is tested on its real inputs, read from git history.
    for rel in DOCS:
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        data = subprocess.run(["git", "-C", str(ROOT), "show", f"{DOCS_BASE}:{rel}"], capture_output=True,
                              check=True).stdout
        (repo / rel).write_bytes(data)
    card = json.dumps({"origin": ORIGIN, "witness_policy": {"quorum": 1, "witnesses": [
        {"name": witness[0], "vkey": witness[1], "trust_domain": "founder", "independent": False}]},
        "assurances": [{"id": g, "status": s} for g, s in (("G1", "proven"), ("G2", "proven"), ("G3", "proven"),
                                                           ("G4", "promised"), ("G5", "promised"), ("G10", "proven"),
                                                           ("N1", "not-offered"))]},
        separators=(",", ":"), sort_keys=True).encode()
    (host.launch / "logged.json").write_bytes(card)
    bundle = {"bootstrap_card_hash": hashlib.sha256(card).hexdigest(), "log_vkey": NEW_LOG, "origin": ORIGIN,
              "owner_kid": OWNER, "policy_kid": NEW_POLICY, "v": 1}
    jcs = json.dumps(bundle, separators=(",", ":"), sort_keys=True).encode()
    sha = bundle_sha or hashlib.sha256(jcs).hexdigest()
    txt = "aics1=" + base64.urlsafe_b64encode(jcs).decode().rstrip("=")
    (host.launch / "bundle.json").write_text(json.dumps({"ok": True, "bundle_jcs": jcs.decode(), "txt": txt,
                                                         "sha256": sha, "card_leaf_index": 1}))
    (host.launch / "genesis.json").write_text(json.dumps({"genesis_ts": GENESIS_TS, "card_leaf_index": 1,
                                                          "charter_sha256": "cd" * 32}))
    return repo, jcs, sha


def run_docs(host: Host, repo: Path, *extra: str) -> subprocess.CompletedProcess:
    return host.run("docs", "--docs-repo", str(repo), "--skip-cli-tests", *extra)


def test_docs_rewrites_every_surface_from_the_new_bundle_and_only_once(host):
    repo, jcs, sha = docs_inputs(host)
    r = run_docs(host, repo, "--hf-revision", "abc123")
    assert r.returncode == 0, r.stdout + r.stderr
    readme = (repo / "README.md").read_text()
    txt = "aics1=" + base64.urlsafe_b64encode(jcs).decode().rstrip("=")
    assert (f"    AICS trust bundle (AICS-1 §6.4) — published 2026-10-20, the same bytes as the DNS record "
            f"_aics.wesupport-ai.com:\n    {txt}\n    sha256: {sha}\n") in readme
    assert "eyJib290c3RyYXBfY2FyZF9oYXNoIjoiODBkY2Qy" not in readme  # the discarded bundle's TXT value
    flat = " ".join(readme.split())  # the rewritten paragraphs are wrapped to the README's width
    assert "Production genesis happened on 20 October 2026 at 06:00 Athens time (03:00 UTC)" in flat
    assert "## Status: production online — relaunched 20 October 2026" in readme
    assert 'python -m pip install "aics-cli==0.1.1"' in readme and "aics-cli/0.1.0/" not in readme
    assert "aics-public-log/tree/abc123" in readme and "6a2098394ec227bb967930beb9c146a4b49a8f0c" not in readme
    assert "Proven on the card: G1, G2, G3 and G10; promised: G4 and G5." in flat
    assert "row 33" in flat and f"`{V1_SHA[:8]}…`" in flat and "the assurance card at leaf one" in flat
    assert f"The card lists the founder-run witness `{W2}` at quorum 1" in flat
    assert f"Its witness, `{W1}`, cosigned checkpoints of that log and was retired with it" in flat
    assert "`_aics-witness.witness.wesupport-ai.com`" in flat
    assert max(len(line) for line in readme.split("## Status:")[1].split("## Repository map")[0].splitlines()) <= 120
    client = (repo / "packages/aics-server/src/aics_server/static/aics_client.py").read_bytes()
    assert f"`{hashlib.sha256(client).hexdigest()}`." in readme
    decisions = (repo / "docs/DECISIONS.md").read_text()
    row20 = next(l for l in decisions.splitlines() if l.startswith("| 20 |"))
    row30 = next(l for l in decisions.splitlines() if l.startswith("| 30 |"))
    row33 = next(l for l in decisions.splitlines() if l.startswith("| 33 |"))
    assert "**Discarded on 2026-10-20 (row 33):**" in row20 and row20.endswith(" |")
    assert "**Relaunch (row 33):**" in row30 and f"`{W2}`" in row30 and f"`{W1}`, which cosigned the discarded log, is retired" in row30
    assert "**Relaunch: a second genesis before any outside agent used the log**" in row33
    assert sha in row33 and NEW_LOG in row33 and V1_SHA in row33 and "0 visits = noone has seen us yet" in row33
    assert f"witness {W2_VKEY} at quorum 1" in row33 and f"the witness {W1_VKEY} (retired)" in row33
    assert row33.count(" | ") >= 4 and row33.endswith(" |")
    wreadme = (repo / "ops/witness/README.md").read_text()
    assert f"| Name (permanent, part of the vkey) | `{W2}`, since 2026-10-20. `{W1}` cosigned the log discarded that day" in wreadme
    assert "`retired-w1/`" in wreadme
    keys: dict = {}
    exec(compile((repo / DOCS[2]).read_text(), "published_keys.py", "exec"), keys)
    assert keys["PLACEHOLDER"] is False and keys["AICS_TRUST_BUNDLE"] == jcs
    assert keys["AICS_TRUST_BUNDLE_SHA256"] == sha == hashlib.sha256(keys["AICS_TRUST_BUNDLE"]).hexdigest()
    assert "Since 0.1.1 both constants carry the bundle of the second log" in keys["__doc__"]
    changelog = (repo / "packages/aics-cli/CHANGELOG.md").read_text()
    assert "## 0.1.1 — 2026-10-20" in changelog and f"The new bundle's SHA-256 is `{sha}`." in changelog
    for rel in DOCS[4:6]:
        assert (repo / rel).read_text().count("> **Superseded on 2026-10-20.**") == 1
    assert "only then" in r.stdout and "rebase origin/main" in r.stdout and "ops/witness/README.md" in r.stdout
    snapshot = {rel: (repo / rel).read_text() for rel in DOCS}
    r = run_docs(host, repo, "--hf-revision", "abc123")
    assert r.returncode == 0 and "0 file(s) changed" in r.stdout, r.stdout
    assert {rel: (repo / rel).read_text() for rel in DOCS} == snapshot


def test_docs_without_a_dataset_revision_says_one_follows(host):
    repo, _, _ = docs_inputs(host)
    r = run_docs(host, repo)
    assert r.returncode == 0, r.stdout + r.stderr
    readme = (repo / "README.md").read_text()
    assert "an export of this log follows" in readme and "aics-public-log/tree/" not in readme


@needs_inventory
def test_docs_dry_run_shows_the_diff_and_writes_nothing(host):
    repo, _, sha = docs_inputs(host)
    before = {rel: (repo / rel).read_bytes() for rel in DOCS}
    r = host.run("--dry-run", "docs", "--docs-repo", str(repo))
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"+    sha256: {sha}" in r.stdout and "would change" in r.stdout
    assert {rel: (repo / rel).read_bytes() for rel in DOCS} == before


@pytest.mark.parametrize("kwargs", [{"bundle_sha": V1_SHA}, {"witness": (W1, W1_VKEY)}])
@needs_inventory
def test_docs_refuse_the_discarded_bundle_or_the_retired_witness(host, kwargs):
    repo, _, _ = docs_inputs(host, **kwargs)
    before = {rel: (repo / rel).read_bytes() for rel in DOCS}
    r = run_docs(host, repo)
    assert r.returncode == 1 and "STOP" in r.stderr
    assert {rel: (repo / rel).read_bytes() for rel in DOCS} == before


# -- the inventory ---------------------------------------------------------------------------------------------------

V1_FACTS = [V1_SHA, "80dcd2abd1c8e51c54961336c0f5da4f416d7e97c7825aaf35003e8ff0dc6c44", "0e2f3a1e",
            "ASx//oWlf4UBmbnXHfpMCsF2NrQOZuN32Q25NiTBC7fV", "z6MkhhjWtmdwmSmAZGq1kkc8EiC1u3GmQ4eS8EEvTKfbKcze",
            "6a2098394ec227bb967930beb9c146a4b49a8f0c", "e10cc47cd4b5767817baa8a47f697d190d60f077f40f042c64c5aad6d58299da",
            "eyJib290c3RyYXBfY2FyZF9oYXNoIjoiODBkY2Qy",
            "45a4adcd+BHew2Ur"]  # the retired witness's vkey
SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", ".tmp", "dist", "build", "data"}
# Evidence of the discarded log, kept and named by hash (added, never edited): the inventory lists the directory once.
LISTED_DIRS = ("docs/evidence/",)


@needs_inventory
def test_the_inventory_names_every_file_that_embeds_a_fact_of_the_discarded_log():
    """docs/internal/relaunch-2026-10-20.md must list each file that still carries the discarded log's facts."""
    inventory = INVENTORY.read_text()
    for d in LISTED_DIRS:
        assert f"`{d}`" in inventory, d
    missing = []
    # Tracked files only: ignored run directories (tools/agent-trials/runs/, scratch output) are not published
    # and may hold copies of anything.
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True).stdout
    for rel in sorted(filter(None, tracked.decode("utf-8", "surrogateescape").split("\0"))):
        path = ROOT / rel
        if any(part in SKIP_DIRS for part in Path(rel).parts[:-1]) or path.is_symlink() or not path.is_file():
            continue
        if rel in ("docs/internal/relaunch-2026-10-20.md", "ops/relaunch-genesis.sh", "tools/test_relaunch_genesis.py"):
            continue
        if rel.startswith(("deploy/docs-public/", ".claude/", *LISTED_DIRS)) or path.suffix in (".lock", ".png", ".gz"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if any(fact in text for fact in V1_FACTS) and f"`{rel}`" not in inventory:
            missing.append(rel)
    assert not missing, f"add these files to {INVENTORY.relative_to(ROOT)} (they embed the discarded log's facts): {missing}"
