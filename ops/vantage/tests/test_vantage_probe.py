"""Shell-level tests of ops/vantage/vantage-probe.sh and ops/vantage/install.sh.

A fake ``curl`` on PATH serves canned responses (routes.json) and records every
ntfy post (ntfy.log); a fake ``aics-tlog`` parses notes without cryptography;
ops/mirror-check.sh and ops/status.sh are replaced by stubs whose exit codes the
test sets, while ops/uptime-check.sh is the real script. No network, no root.

Run: uv run --no-project --with pytest pytest -q ops/vantage/tests
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest

OPS = Path(__file__).resolve().parents[2]
PROBE = OPS / "vantage" / "vantage-probe.sh"
INSTALL = OPS / "vantage" / "install.sh"
API = "https://api.test"
ORIGIN = "api.test/tiles"
WITNESS = "http://witness.test:7380"
TOPIC = "topic-secret-123"
# A synthetic log vkey (type 0x01, key bytes 00..1f): the fake aics-tlog never checks it, and a
# fixture that copies a production key goes stale whenever that log is replaced.
LOG_VKEY = f"{ORIGIN}+00000000+AQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"

FAKE_CURL = r"""#!/usr/bin/env python3
import json, os, sys
fake = os.environ["FAKE_DIR"]
args = sys.argv[1:]
out = wfmt = data = url = None
headers, fail, i = [], False, 0
while i < len(args):
    a = args[i]
    if a in ("-o", "--output"): out = args[i + 1]; i += 2; continue
    if a in ("-w", "--write-out"): wfmt = args[i + 1]; i += 2; continue
    if a in ("-d", "--data", "--data-binary"): data = args[i + 1]; i += 2; continue
    if a in ("-H", "--header"): headers.append(args[i + 1]); i += 2; continue
    if a in ("--max-time", "--proto", "--max-filesize"): i += 2; continue
    if a.startswith("--"):
        fail = fail or a == "--fail"; i += 1; continue
    if a.startswith("-"):
        fail = fail or "f" in a; i += 1; continue
    url = a; i += 1
with open(os.path.join(fake, "requests.log"), "a") as f:
    f.write(url + "\n")
if url.startswith("https://ntfy.test/"):
    if os.path.exists(os.path.join(fake, "ntfy.fail")):
        sys.stderr.write("curl: (22) The requested URL returned error: 500\n"); sys.exit(22)
    h = dict(x.split(": ", 1) for x in headers)
    with open(os.path.join(fake, "ntfy.log"), "a") as f:
        f.write(json.dumps({"url": url, "title": h.get("Title"), "priority": h.get("Priority"),
                            "tags": h.get("Tags"), "body": data}) + "\n")
    sys.exit(0)
r = json.load(open(os.path.join(fake, "routes.json"))).get(url)
if r is None:
    sys.stderr.write("curl: (7) Failed to connect\n")
    if wfmt: sys.stdout.write("000")
    sys.exit(7)
code, body = r.get("code", 200), r.get("body", "")
if fail and code >= 400:
    sys.stderr.write(f"curl: (22) The requested URL returned error: {code}\n"); sys.exit(22)
if out: open(out, "w").write(body)
else: sys.stdout.write(body)
if wfmt: sys.stdout.write(wfmt.replace("%{http_code}", str(code)))
"""

FAKE_TLOG = r"""#!/usr/bin/env python3
import base64, json, os, sys
fake = os.environ["FAKE_DIR"]
cmd, args = sys.argv[1], sys.argv[2:]
with open(os.path.join(fake, "tlog.log"), "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\n")
def opt(name):
    return args[args.index(name) + 1] if name in args else None
if cmd == "verify-checkpoint":
    text = open(opt("--note")).read()
    if "\n— bad " in text:
        print("signature does not verify", file=sys.stderr); sys.exit(1)
    lines = text.split("\n")
    print(json.dumps({"origin": lines[0], "size": int(lines[1]), "root": lines[2], "ok": True}))
elif cmd == "verify-consistency":
    if os.path.exists(os.path.join(fake, "consistency.fail")):
        print("missing tile", file=sys.stderr); sys.exit(1)
    print(json.dumps({"ok": True}))
else:
    sys.exit(2)
"""

FAKE_MIRROR = r"""#!/usr/bin/env bash
rc=$(cat "$FAKE_DIR/mirror.rc" 2>/dev/null || echo 0)
ev=$(mktemp -d "$AICS_MIRROR_EVIDENCE_DIR/check-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
echo "evidence: $ev"
echo "lag=0 leaves"
[ "$rc" = 0 ] && echo "mirror-check: consistent" || echo "mirror-check: failure $rc" >&2
exit "$rc"
"""

FAKE_STATUS = r"""#!/usr/bin/env bash
echo "checkpoint (api): origin=api.test/tiles size=7"
exit "$(cat "$FAKE_DIR/status.rc" 2>/dev/null || echo 0)"
"""


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def note(size: int, root: bytes = b"\x01" * 32, cosig_ts: int | None = None, bad: bool = False,
         witness_name: str = "witness.test/w1", key_id: bytes = bytes(4)) -> str:
    text = f"{ORIGIN}\n{size}\n{b64(root)}\n\n— {ORIGIN} {b64(bytes(68))}\n"
    if cosig_ts is not None:
        text += f"— {witness_name} {b64(key_id + cosig_ts.to_bytes(8, 'big') + bytes(64))}\n"
    if bad:
        text += f"— bad {b64(bytes(68))}\n"
    return text


def health(status: str = "OPERATIONAL", **extra) -> str:
    d = {"status": status, "tree_size": 7, "published_size": 7, "tiles_error": None, "diverged": None,
         "frozen": False, "freeze_index": None, "agent_writes_held": False, "resource_exhaustion": None}
    d.update(extra)
    return json.dumps(d)


def limits(open_count: int = 0, exhaustion=None) -> str:
    return json.dumps({"notice_register": {"open": open_count, "bytes": 0, "max_open": 100, "max_bytes": 10**6},
                       "resource_exhaustion": exhaustion})


class Env:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.fake = tmp / "fake"
        self.bin = tmp / "bin"
        self.ops = tmp / "ops"
        self.state = tmp / "state"
        for d in (self.fake, self.bin, self.ops / "vantage", self.state):
            d.mkdir(parents=True, exist_ok=True)
        self._exe(self.bin / "curl", FAKE_CURL)
        self._exe(self.bin / "aics-tlog", FAKE_TLOG)
        self._exe(self.ops / "mirror-check.sh", FAKE_MIRROR)
        self._exe(self.ops / "status.sh", FAKE_STATUS)
        shutil.copy(OPS / "uptime-check.sh", self.ops / "uptime-check.sh")
        (tmp / "log.vkey").write_text(LOG_VKEY + "\n")
        self.routes: dict[str, dict] = {}
        self.ok()

    @staticmethod
    def _exe(path: Path, text: str) -> None:
        path.write_text(text)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def route(self, url: str, body: str = "", code: int = 200) -> None:
        self.routes[url] = {"code": code, "body": body}
        (self.fake / "routes.json").write_text(json.dumps(self.routes))

    def drop(self, url: str) -> None:
        self.routes.pop(url, None)
        (self.fake / "routes.json").write_text(json.dumps(self.routes))

    def ok(self, cosig_ts: int | None = None) -> None:
        self.route(f"{API}/healthz", health())
        self.route(f"{API}/checkpoint", note(7, cosig_ts=cosig_ts))
        self.route(f"{API}/tiles/checkpoint", note(7, cosig_ts=cosig_ts))
        self.route(f"{API}/v2/limits", limits())

    def witness(self, body: str | None, code: int = 200) -> None:
        url = f"{WITNESS}/{hashlib.sha256(ORIGIN.encode()).hexdigest()}/checkpoint"
        if body is None:
            self.drop(url)
        else:
            self.route(url, body, code)

    def run(self, mode: str, **env: str) -> subprocess.CompletedProcess:
        e = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "TMPDIR": str(self.tmp),
            "FAKE_DIR": str(self.fake),
            "NTFY_URL": "https://ntfy.test",
            "NTFY_TOPIC": TOPIC,
            "AICS_API_BASE_URL": API,
            "AICS_TILES_BASE": "https://tiles.test/tiles",
            "AICS_LOG_VKEY_FILE": str(self.tmp / "log.vkey"),
            "AICS_VANTAGE_STATE": str(self.state),
            "AICS_VANTAGE_OPS_DIR": str(self.ops),
            "AICS_VANTAGE_RETRY_DELAY": "0",
            "AICS_VANTAGE_WITNESS_URL": WITNESS,
            "AICS_VANTAGE_WITNESS_VKEY_FILE": str(self.tmp / "no-witness.vkey"),
        }
        e.update(env)
        p = subprocess.run(["bash", str(PROBE), mode], env=e, capture_output=True, text=True, timeout=120)
        assert p.returncode == 0, p.stdout + p.stderr
        return p

    def sent(self) -> list[dict]:
        f = self.fake / "ntfy.log"
        if not f.exists():
            return []
        return [json.loads(line) for line in f.read_text().splitlines()]

    def titles(self) -> list[str]:
        return [n["title"] for n in self.sent()]


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


# --- uptime ---------------------------------------------------------------------

def test_healthy_without_cosignature_is_quiet(env: Env) -> None:
    env.run("uptime")
    env.run("uptime")
    assert env.sent() == []
    assert (env.state / "markers" / "checkpoint_age_unknown").exists()
    assert not (env.state / "markers" / "checkpoint_age_seen").exists()


def test_api_down_alerts_once_and_recovers_once(env: Env) -> None:
    env.drop(f"{API}/healthz")
    for _ in range(3):
        env.run("uptime")
    sent = env.sent()
    assert [n["title"] for n in sent] == ["wesupport-ai: API not answering"]
    assert sent[0]["priority"] == "5"
    assert sent[0]["url"] == f"https://ntfy.test/{TOPIC}"
    # two attempts per run: the retry is what keeps one lost packet quiet
    assert (env.fake / "requests.log").read_text().count(f"{API}/healthz") == 6
    env.ok()
    env.run("uptime")
    env.run("uptime")
    assert env.titles() == ["wesupport-ai: API not answering", "wesupport-ai: recovered: API not answering"]
    assert not (env.state / "groups" / "health").exists()


def test_one_failed_attempt_is_retried_not_alerted(env: Env) -> None:
    # healthz fails only on the first attempt: the fake curl reads routes per call
    hook = env.bin / "curl"
    real = hook.read_text()
    hook.write_text(real.replace(
        'r = json.load(open(os.path.join(fake, "routes.json"))).get(url)',
        'r = json.load(open(os.path.join(fake, "routes.json"))).get(url)\n'
        'flag = os.path.join(fake, "once")\n'
        'if url.endswith("/healthz") and not os.path.exists(flag):\n'
        '    open(flag, "w").close(); r = None'))
    env.run("uptime")
    assert env.sent() == []


def test_degraded_then_down_then_recovery(env: Env) -> None:
    env.route(f"{API}/healthz", health("DEGRADED", tiles_error="disk full"))
    env.run("uptime")
    env.run("uptime")
    assert env.titles() == ["wesupport-ai: health DEGRADED"]
    assert "disk full" in env.sent()[0]["body"]
    assert env.sent()[0]["priority"] == "4"
    env.drop(f"{API}/healthz")
    env.run("uptime")
    assert env.titles()[-1] == "wesupport-ai: API not answering (was: health DEGRADED)"
    env.ok()
    env.run("uptime")
    assert env.titles()[-1] == "wesupport-ai: recovered: API not answering"
    assert len(env.sent()) == 3


def test_unavailable_is_its_own_alert(env: Env) -> None:
    env.route(f"{API}/healthz", health("UNAVAILABLE", diverged=True), code=503)
    env.run("uptime")
    assert env.titles() == ["wesupport-ai: log UNAVAILABLE (diverged from its tiles)"]


def test_stale_checkpoint_once_cosigned_then_age_lost(env: Env) -> None:
    env.ok(cosig_ts=int(time.time()))
    env.run("uptime")
    assert env.sent() == []
    assert (env.state / "markers" / "checkpoint_age_seen").exists()
    env.ok(cosig_ts=int(time.time()) - 3600)
    env.run("uptime")
    env.run("uptime")
    assert env.titles() == ["wesupport-ai: checkpoint stale"]
    assert "old" in env.sent()[0]["body"]
    env.ok(cosig_ts=int(time.time()))
    env.run("uptime")
    assert env.titles()[-1] == "wesupport-ai: recovered: checkpoint stale"
    env.ok(cosig_ts=None)  # the cosignature disappears: now that is worth a message
    env.run("uptime")  # once is the gap between a new leaf and its cosignature: not yet
    assert len(env.sent()) == 2
    env.run("uptime")
    assert env.titles()[-1] == "wesupport-ai: checkpoint age unknown again (cosignature gone)"
    assert len(env.sent()) == 3


def test_stale_at_the_cards_max_checkpoint_age(env: Env) -> None:
    # The card says a cosignature older than 300 s is stale; the phone hears of it before that.
    env.ok(cosig_ts=int(time.time()) - 270)
    env.run("uptime")
    assert env.titles() == ["wesupport-ai: checkpoint stale"]
    assert "limit 240s" in env.sent()[0]["body"]


def pinned_witness(env: Env, name: str = "witness.test/w1") -> tuple[Path, bytes]:
    key = b"\x04" + bytes(range(32))
    key_id = hashlib.sha256(name.encode() + b"\n" + key).digest()[:4]
    path = env.tmp / "pinned-witness.vkey"
    path.write_text(f"{name}+{key_id.hex()}+{b64(key)}\n")
    return path, key_id


def test_only_the_pinned_witness_dates_the_checkpoint(env: Env) -> None:
    vkey, key_id = pinned_witness(env)
    now = int(time.time())
    fresh = note(7, cosig_ts=now, key_id=key_id)
    env.route(f"{API}/checkpoint", fresh)
    env.run("uptime", AICS_VANTAGE_WITNESS_VKEY_FILE=str(vkey))
    assert env.sent() == []
    assert "--witness-key witness.test/w1+" in (env.fake / "tlog.log").read_text()
    # A stale note made to look fresh by a line a signed-note parser ignores (another name, or the witness's
    # name with another key ID): it does not date the checkpoint, the pinned witness's stale line does.
    stale = note(7, cosig_ts=now - 3600, key_id=key_id)
    for forged in (f"— someone.else/w {b64(bytes(4) + now.to_bytes(8, 'big') + bytes(64))}\n",
                   f"— witness.test/w1 {b64(b'\x09' * 4 + now.to_bytes(8, 'big') + bytes(64))}\n"):
        env.route(f"{API}/checkpoint", stale + forged)
        p = subprocess.run(["bash", str(env.ops / "uptime-check.sh")], capture_output=True, text=True, env={
            "PATH": f"{env.bin}:{os.environ['PATH']}", "FAKE_DIR": str(env.fake), "AICS_API_BASE_URL": API,
            "AICS_DISK_CHECK": "0", "AICS_LIMITS_CHECK": "0", "HOME": str(env.tmp),
            "AICS_WITNESS_VKEY_FILE": str(vkey)})
        assert p.returncode == 3 and "old" in p.stderr, p.stdout + p.stderr
    # Without the pin the forged line would have passed: that is why the vantage passes the pin.
    p = subprocess.run(["bash", str(env.ops / "uptime-check.sh")], capture_output=True, text=True, env={
        "PATH": f"{env.bin}:{os.environ['PATH']}", "FAKE_DIR": str(env.fake), "AICS_API_BASE_URL": API,
        "AICS_DISK_CHECK": "0", "AICS_LIMITS_CHECK": "0", "HOME": str(env.tmp)})
    assert p.returncode == 0


def test_a_pinned_witness_line_that_does_not_verify_gives_no_age(env: Env) -> None:
    vkey, key_id = pinned_witness(env)
    base = {"PATH": f"{env.bin}:{os.environ['PATH']}", "FAKE_DIR": str(env.fake), "AICS_API_BASE_URL": API,
            "AICS_DISK_CHECK": "0", "AICS_LIMITS_CHECK": "0", "HOME": str(env.tmp),
            "AICS_WITNESS_VKEY_FILE": str(vkey), "AICS_LOG_VKEY_FILE": str(env.tmp / "log.vkey")}
    env.route(f"{API}/checkpoint", note(7, cosig_ts=int(time.time()), key_id=key_id, bad=True))
    p = subprocess.run(["bash", str(env.ops / "uptime-check.sh")], capture_output=True, text=True, env=base)
    assert p.returncode == 4 and "does not verify" in p.stderr, p.stdout + p.stderr
    env.route(f"{API}/checkpoint", note(7, cosig_ts=int(time.time()), key_id=key_id))
    p = subprocess.run(["bash", str(env.ops / "uptime-check.sh")], capture_output=True, text=True, env=base)
    assert p.returncode == 0 and "verified (aics-tlog)" in p.stdout, p.stdout + p.stderr
    (env.tmp / "pinned-witness.vkey").write_text("witness.test/w1+00000000+notakey\n")
    p = subprocess.run(["bash", str(env.ops / "uptime-check.sh")], capture_output=True, text=True, env=base)
    assert p.returncode == 11 and "holds no cosignature vkey" in p.stderr


def test_limits_still_checked_while_age_unknown(env: Env) -> None:
    env.route(f"{API}/v2/limits", limits(open_count=95))
    env.run("uptime")
    env.run("uptime")
    assert env.titles() == ["wesupport-ai: notice register near its cap"]
    env.route(f"{API}/v2/limits", limits(exhaustion={"stored_bytes": 9}))
    env.run("uptime")
    assert env.titles()[1:] == ["wesupport-ai: recovered: notice register near its cap",
                                "wesupport-ai: ciphertext resource exhaustion"]


def test_limits_unreachable_needs_two_runs(env: Env) -> None:
    env.drop(f"{API}/v2/limits")
    env.run("uptime")
    assert env.sent() == []
    env.run("uptime")
    assert env.titles() == ["wesupport-ai: /v2/limits not answering"]


def test_checks_not_judged_while_api_down(env: Env) -> None:
    env.ok(cosig_ts=int(time.time()) - 3600)
    env.run("uptime")
    assert env.titles() == ["wesupport-ai: checkpoint stale"]
    env.drop(f"{API}/healthz")
    env.run("uptime")
    # the stale alert neither recovers nor repeats while the API cannot be judged
    assert env.titles() == ["wesupport-ai: checkpoint stale", "wesupport-ai: API not answering"]
    assert (env.state / "groups" / "checkpoint").exists()


def test_failed_notification_is_retried(env: Env) -> None:
    env.drop(f"{API}/healthz")
    (env.fake / "ntfy.fail").touch()
    env.run("uptime")
    assert env.sent() == []
    (env.fake / "ntfy.fail").unlink()
    env.run("uptime")
    env.run("uptime")
    assert env.titles() == ["wesupport-ai: API not answering"]
    env.ok()
    (env.fake / "ntfy.fail").touch()
    env.run("uptime")  # recovery could not be sent: kept, retried
    (env.fake / "ntfy.fail").unlink()
    env.run("uptime")
    env.run("uptime")
    assert env.titles() == ["wesupport-ai: API not answering", "wesupport-ai: recovered: API not answering"]


def test_unconfirmed_failure_clears_silently(env: Env) -> None:
    env.drop(f"{API}/v2/limits")
    env.run("uptime")
    env.ok()
    env.run("uptime")
    assert env.sent() == []


def test_topic_is_required_and_never_printed(env: Env) -> None:
    e = dict(os.environ, NTFY_TOPIC="", AICS_VANTAGE_STATE=str(env.state))
    p = subprocess.run(["bash", str(PROBE), "uptime"], env=e, capture_output=True, text=True)
    assert p.returncode == 2 and "NTFY_TOPIC is required" in p.stderr
    env.drop(f"{API}/healthz")
    p = env.run("uptime")
    assert TOPIC not in p.stdout + p.stderr


def test_dry_run_prints_instead_of_sending(env: Env) -> None:
    env.drop(f"{API}/healthz")
    p = env.run("uptime", AICS_VANTAGE_DRY_RUN="1", NTFY_TOPIC="")
    assert "NOTIFY [p5 rotating_light] wesupport-ai: API not answering" in p.stdout
    assert env.sent() == []


# --- mirror and witness ------------------------------------------------------------

def test_mirror_ok_with_empty_witness_is_quiet(env: Env) -> None:
    env.witness("not found\n", code=404)
    env.run("mirror")
    env.run("mirror")
    assert env.sent() == []
    assert "nothing cosigned yet" in (env.state / "witness.info").read_text()
    runs = list((env.state / "mirror-evidence").glob("check-*"))
    assert len(runs) == 1, "only the newest successful run is kept"


def test_mirror_split_alerts_at_once(env: Env) -> None:
    env.witness("not found\n", code=404)
    (env.fake / "mirror.rc").write_text("5")
    env.run("mirror")
    env.run("mirror")
    assert env.titles() == ["wesupport-ai: SPLIT: api and tiles checkpoints disagree"]
    assert env.sent()[0]["priority"] == "5"
    assert "evidence kept" in env.sent()[0]["body"]
    assert len(list((env.state / "mirror-evidence").glob("check-*"))) == 2, "failed runs are kept"


def test_mirror_unproven_needs_three_runs(env: Env) -> None:
    env.witness("not found\n", code=404)
    (env.fake / "mirror.rc").write_text("6")
    env.run("mirror")
    env.run("mirror")
    assert env.sent() == []
    env.run("mirror")
    assert env.titles() == ["wesupport-ai: mirror consistency unproven"]
    (env.fake / "mirror.rc").write_text("5")
    env.run("mirror")
    assert env.titles()[-1] == "wesupport-ai: SPLIT: api and tiles checkpoints disagree (was: mirror consistency unproven)"


def test_mirror_fetch_failure_not_judged_while_api_down(env: Env) -> None:
    env.witness("not found\n", code=404)
    env.drop(f"{API}/healthz")
    env.run("uptime")
    (env.fake / "mirror.rc").write_text("3")
    env.run("mirror")
    env.run("mirror")
    assert env.titles() == ["wesupport-ai: API not answering"]


def test_mirror_setup_error(env: Env) -> None:
    env.witness("not found\n", code=404)
    (env.fake / "mirror.rc").write_text("2")
    env.run("mirror")
    assert env.titles() == ["wesupport-ai: mirror check cannot run"]


def test_witness_same_tree_then_split(env: Env) -> None:
    t = int(time.time())
    env.witness(note(7, cosig_ts=t))
    env.run("mirror")
    assert env.sent() == []
    assert "cosigned size 7 (api 7)" in (env.state / "witness.info").read_text()
    env.witness(note(7, root=b"\x02" * 32, cosig_ts=t))
    env.run("mirror")
    time.sleep(1.1)
    env.run("mirror")
    assert env.titles() == ["wesupport-ai: SPLIT: witness and api disagree"]
    assert len(list(env.state.glob("split-*.note"))) == 2, "one copy of each note however long the split lasts"


def test_witness_ahead_of_api_is_a_split(env: Env) -> None:
    env.witness(note(9, cosig_ts=int(time.time())))
    env.run("mirror")
    assert env.sent() == []  # twice in a row before it alerts
    env.run("mirror")
    assert env.titles() == ["wesupport-ai: SPLIT: witness and api disagree"]
    assert "rolled back" in env.sent()[0]["body"]


def test_the_api_checkpoint_is_fetched_after_the_witness_checkpoint(env: Env) -> None:
    # A leaf published and fed between the two fetches: the first api note is size 7, the witness already
    # cosigned 9, and the api serves 9 by the time it is fetched again. That is no rollback.
    hook = env.bin / "curl"
    hook.write_text(hook.read_text().replace(
        'r = json.load(open(os.path.join(fake, "routes.json"))).get(url)',
        'r = json.load(open(os.path.join(fake, "routes.json"))).get(url)\n'
        'flag = os.path.join(fake, "api-seen")\n'
        'if url.endswith("/tiles/checkpoint"):\n'
        '    if os.path.exists(flag): r = json.load(open(os.path.join(fake, "later.json")))\n'
        '    else: open(flag, "w").close()'))
    (env.fake / "later.json").write_text(json.dumps({"code": 200, "body": note(9, cosig_ts=int(time.time()))}))
    env.witness(note(9, cosig_ts=int(time.time())))
    env.run("mirror")
    env.run("mirror")
    assert env.sent() == []
    assert "cosigned size 9 (api 9)" in (env.state / "witness.info").read_text()
    requests = (env.fake / "requests.log").read_text().splitlines()
    witness = max(i for i, u in enumerate(requests) if u.startswith(WITNESS))
    assert any(u == f"{API}/tiles/checkpoint" for u in requests[witness + 1:])


def test_witness_behind_proved_or_unproven_or_stalled(env: Env) -> None:
    env.witness(note(5, cosig_ts=int(time.time())))
    env.run("mirror")
    assert env.sent() == []
    assert "verify-consistency" in (env.fake / "tlog.log").read_text()
    (env.fake / "consistency.fail").touch()
    for _ in range(3):
        env.run("mirror")
    assert env.titles() == ["wesupport-ai: witness consistency unproven"]
    (env.fake / "consistency.fail").unlink()
    env.witness(note(5, cosig_ts=int(time.time()) - 7200))
    env.run("mirror")
    assert env.titles()[-1] == "wesupport-ai: witness not cosigning new checkpoints (was: witness consistency unproven)"


def test_witness_bad_note_down_and_lost_state(env: Env) -> None:
    env.witness(note(7, cosig_ts=int(time.time()), bad=True))
    env.run("mirror")
    assert env.titles() == ["wesupport-ai: witness checkpoint fails verification"]
    env.witness(note(7, cosig_ts=int(time.time())))
    env.run("mirror")
    assert env.titles()[-1] == "wesupport-ai: recovered: witness checkpoint fails verification"
    env.witness(None)  # connection refused
    env.run("mirror")
    assert len(env.sent()) == 2
    env.run("mirror")
    assert env.titles()[-1] == "wesupport-ai: witness not answering"
    env.witness("not found\n", code=404)  # back, but empty: its database is gone
    env.run("mirror")
    assert env.titles()[-2:] == ["wesupport-ai: recovered: witness not answering",
                                 "wesupport-ai: witness lost its state (nothing cosigned any more)"]


def test_witness_key_is_passed_when_pinned(env: Env) -> None:
    (env.tmp / "w.vkey").write_text("witness.test/w1+a59e6bb3+BGzIS8zn9Oqt7RRCF2Yrp5bsV6HtcZuZUBJ/0cfeXwCy\n")
    env.witness(note(7, cosig_ts=int(time.time())))
    env.run("mirror", AICS_VANTAGE_WITNESS_VKEY_FILE=str(env.tmp / "w.vkey"))
    assert "--witness-key witness.test/w1+a59e6bb3+" in (env.fake / "tlog.log").read_text()
    assert "--quorum 1" in (env.fake / "tlog.log").read_text()


def test_witness_view_can_be_disabled(env: Env) -> None:
    env.run("mirror", AICS_VANTAGE_WITNESS_URL="")
    log = env.fake / "requests.log"
    assert not log.exists() or WITNESS not in log.read_text()


# --- daily status ----------------------------------------------------------------

def test_daily_status_all_clear_and_with_open_alerts(env: Env) -> None:
    env.witness("not found\n", code=404)
    env.run("uptime")
    env.run("mirror")
    env.run("status")
    first = env.sent()[-1]
    assert first["title"] == "wesupport-ai daily: all clear"
    assert first["priority"] == "2"
    assert "size=7" in first["body"] and "no cosignature yet" in first["body"]
    assert "nothing cosigned yet" in first["body"]
    env.drop(f"{API}/healthz")
    env.run("uptime")
    env.run("status")
    last = env.sent()[-1]
    assert last["title"] == "wesupport-ai daily: 1 open alert(s)"
    assert "- API not answering (since" in last["body"]
    (env.fake / "status.rc").write_text("2")
    env.run("status")
    assert env.sent()[-1]["title"] == "wesupport-ai daily: status.sh FAILED (exit 2)"
    assert env.sent()[-1]["priority"] == "4"


# --- uptime-check.sh keep-going mode ------------------------------------------------

def test_uptime_check_default_mode_unchanged(env: Env) -> None:
    e = {"PATH": f"{env.bin}:{os.environ['PATH']}", "FAKE_DIR": str(env.fake), "AICS_API_BASE_URL": API,
         "AICS_DISK_CHECK": "0", "HOME": str(env.tmp)}
    env.route(f"{API}/v2/limits", limits(open_count=95))
    p = subprocess.run(["bash", str(OPS / "uptime-check.sh")], env=e, capture_output=True, text=True)
    assert p.returncode == 4 and "notice register" not in p.stdout
    p = subprocess.run(["bash", str(OPS / "uptime-check.sh")], env=dict(e, AICS_UPTIME_KEEP_GOING="1"),
                       capture_output=True, text=True)
    assert p.returncode == 4
    assert "uptime-check: failed checks: 4,8" in p.stdout


# --- install.sh ----------------------------------------------------------------------

def test_install_is_idempotent_and_keeps_secrets_out(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    vkey = tmp_path / "log.vkey"
    vkey.write_text(LOG_VKEY + "\n")
    base = ["bash", str(INSTALL), "--destdir", str(dest), "--no-systemctl", "--skip-venv"]
    p = subprocess.run(base, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert "still needed" in p.stdout and "ntfy topic" in p.stdout and "log vkey" in p.stdout
    env_file = dest / "etc/default/aics-vantage"
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert "NTFY_TOPIC=\n" in env_file.read_text()
    env_file.chmod(0o644)
    p = subprocess.run(base + ["--log-vkey-file", str(vkey), "--generate-topic"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    topic = [l for l in env_file.read_text().splitlines() if l.startswith("NTFY_TOPIC=")][0].split("=", 1)[1]
    assert topic.startswith("aics-") and len(topic) == 37 and topic in p.stdout
    assert (dest / "etc/aics-vantage/log.vkey").read_text() == vkey.read_text()
    units = sorted(x.name for x in (dest / "etc/systemd/system").iterdir())
    assert units == [f"aics-vantage-{m}.{k}" for m in ("mirror", "status", "uptime") for k in ("service", "timer")]
    for m in ("mirror", "status", "uptime"):
        svc = (dest / f"etc/systemd/system/aics-vantage-{m}.service").read_text()
        assert f"vantage-probe.sh {m}" in svc and "EnvironmentFile=/etc/default/aics-vantage" in svc
        assert "StateDirectory=aics-vantage" in svc and TOPIC not in svc
    assert os.access(dest / "opt/wesupport-ai/ops/vantage/vantage-probe.sh", os.X_OK)
    # third run: nothing to do, the existing topic is never printed again
    p = subprocess.run(base, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert "installed" not in p.stdout and topic not in p.stdout and "still needed" not in p.stdout
    assert topic in env_file.read_text()
    bad = tmp_path / "bad.vkey"
    bad.write_text("https://example.org/vkey\n")
    p = subprocess.run(base + ["--log-vkey-file", str(bad)], capture_output=True, text=True)
    assert p.returncode == 2 and "does not hold a vkey" in p.stderr


def test_install_prefix_is_substituted(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    p = subprocess.run(["bash", str(INSTALL), "--destdir", str(dest), "--no-systemctl", "--skip-venv",
                        "--prefix", "/srv/aics"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    svc = (dest / "etc/systemd/system/aics-vantage-uptime.service").read_text()
    assert "/srv/aics/ops/vantage/vantage-probe.sh uptime" in svc and "/opt/wesupport-ai" not in svc
    assert (dest / "srv/aics/ops/uptime-check.sh").exists()


def test_a_pinned_witness_key_with_plus_signs_in_its_base64_parses(env: Env) -> None:
    # The production witness key (witness.wesupport-ai.com/w1+45a4adcd+BHew2Ur+QH2S…) carries "+" inside its
    # base64 part; the 2026-10-20 alert "too many values to unpack (expected 3)" came from splitting on every "+".
    name = "witness.test/w1"
    key = b"\x04" + b"\xfb" * 32
    assert "+" in b64(key) and "/" in b64(key)
    key_id = hashlib.sha256(name.encode() + b"\n" + key).digest()[:4]
    vkey = env.tmp / "pinned-witness.vkey"
    vkey.write_text(f"{name}+{key_id.hex()}+{b64(key)}\n")
    env.route(f"{API}/checkpoint", note(7, cosig_ts=int(time.time()), key_id=key_id))
    env.run("uptime", AICS_VANTAGE_WITNESS_VKEY_FILE=str(vkey))
    assert env.sent() == []
    assert f"--witness-key {name}+{key_id.hex()}+{b64(key)}" in (env.fake / "tlog.log").read_text()
