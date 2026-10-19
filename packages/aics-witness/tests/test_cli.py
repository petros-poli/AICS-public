"""aics-witness init | add-log | status | serve."""

from __future__ import annotations

import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog import cosignature_vkey, format_vkey, key_hash, parse_vkey, vkey_from_ed25519
from aics_witness.cli import main
from aics_witness.config import load_config
from aics_witness.feeder import merge_cosignatures, submit_checkpoint
from aics_witness.store import SEED_ENV, WitnessStore, seed_hex

from conftest import InProcessLog, threshold_policy_ok

NAME = "witness.example.test/cli"


@pytest.fixture(autouse=True)
def _no_seed_env(monkeypatch):
    monkeypatch.delenv(SEED_ENV, raising=False)
    monkeypatch.delenv("AICS_WITNESS_CONFIG", raising=False)


def run(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_init_creates_key_and_config_and_prints_vkey(tmp_path, capsys):
    cfg_path = tmp_path / "witness.json"
    code, out, err = run(capsys, "init", "--config", str(cfg_path), "--name", NAME)
    assert code == 0
    vkey_text = out.strip()
    assert out.count("\n") == 1
    vkey = parse_vkey(vkey_text)  # C2SP verifier key format, key ID checked
    assert vkey.name == NAME and vkey.key_type == 0x04 and len(vkey.public_key) == 32
    assert re.fullmatch(r"witness\.example\.test/cli\+[0-9a-f]{8}\+[A-Za-z0-9+/]+=*", vkey_text)

    key_path = tmp_path / "witness.key"
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    cfg = load_config(cfg_path)
    assert cfg.name == NAME and cfg.key_path == key_path.resolve() and cfg.logs == ()
    assert "created witness key" in err
    # The database exists from the start, bound to the printed vkey.
    assert "created witness database" in err
    with WitnessStore(cfg.db_path) as store:
        assert store.get_meta("witness_vkey") == vkey_text
        assert int(store.get_meta("created_at")) > 0

    # Idempotent: same vkey, key untouched.
    before = key_path.read_bytes()
    code, out2, err2 = run(capsys, "init", "--config", str(cfg_path))
    assert code == 0 and out2.strip() == vkey_text and key_path.read_bytes() == before
    assert "created" not in err2


def test_init_requires_name_for_new_config(tmp_path, capsys):
    code, _, err = run(capsys, "init", "--config", str(tmp_path / "w.json"))
    assert code == 1 and "--name" in err


def test_init_refuses_rename(tmp_path, capsys):
    cfg = tmp_path / "w.json"
    run(capsys, "init", "--config", str(cfg), "--name", NAME)
    code, _, err = run(capsys, "init", "--config", str(cfg), "--name", "other.example/w")
    assert code == 1 and "already names" in err


def test_init_with_seed_env_prints_matching_vkey(tmp_path, capsys, monkeypatch):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(SEED_ENV, seed_hex(key))
    code, out, _ = run(capsys, "init", "--config", str(tmp_path / "w.json"), "--name", NAME,
                       "--new-database")
    assert code == 0
    assert out.strip() == format_vkey(cosignature_vkey(NAME, key.public_key()))
    assert not (tmp_path / "witness.key").exists()
    with WitnessStore(tmp_path / "witness.db") as store:
        assert store.get_meta("witness_vkey") == out.strip()


def test_init_with_seed_env_and_missing_database_refuses(tmp_path, capsys, monkeypatch):
    """A seed from the environment is an existing identity: without its
    database the witness may have lost state, so init does not create one."""
    monkeypatch.setenv(SEED_ENV, seed_hex(Ed25519PrivateKey.generate()))
    code, out, err = run(capsys, "init", "--config", str(tmp_path / "w.json"), "--name", NAME)
    assert code == 1 and out == ""
    assert "database" in err and "is missing" in err and "--new-database" in err
    assert "retire" in err.lower()
    assert not (tmp_path / "witness.db").exists()


def test_init_refuses_when_the_database_of_an_existing_key_is_gone(tmp_path, capsys):
    cfg = tmp_path / "w.json"
    _, out, _ = run(capsys, "init", "--config", str(cfg), "--name", NAME)
    for p in tmp_path.glob("witness.db*"):
        p.unlink()
    code, _, err = run(capsys, "init", "--config", str(cfg))
    assert code == 1 and "is missing" in err
    assert not (tmp_path / "witness.db").exists()
    # The operator states that this key never cosigned anything.
    code, out2, _ = run(capsys, "init", "--config", str(cfg), "--new-database")
    assert code == 0 and out2 == out


def test_init_never_generates_a_key_for_a_bound_database(tmp_path, capsys):
    cfg = tmp_path / "w.json"
    _, out, _ = run(capsys, "init", "--config", str(cfg), "--name", NAME)
    (tmp_path / "witness.key").unlink()  # lost key file, database still there
    code, out2, err = run(capsys, "init", "--config", str(cfg))
    assert code == 1 and out2 == "" and out.strip() in err
    assert not (tmp_path / "witness.key").exists()  # no new key was generated
    # A deliberate new identity for the same state.
    code, out3, err3 = run(capsys, "init", "--config", str(cfg), "--new-key")
    assert code == 0 and out3 != out and "new key" in err3
    with WitnessStore(tmp_path / "witness.db") as store:
        assert store.get_meta("witness_vkey") == out3.strip()


def test_init_refuses_another_key_for_a_bound_database(tmp_path, capsys, monkeypatch):
    cfg = tmp_path / "w.json"
    _, out, _ = run(capsys, "init", "--config", str(cfg), "--name", NAME)
    other = Ed25519PrivateKey.generate()
    monkeypatch.setenv(SEED_ENV, seed_hex(other))
    code, _, err = run(capsys, "init", "--config", str(cfg))
    assert code == 1 and "belongs to witness key" in err and "--new-key" in err
    code, out2, _ = run(capsys, "init", "--config", str(cfg), "--new-key")
    assert code == 0 and out2.strip() == format_vkey(cosignature_vkey(NAME, other.public_key()))


def test_init_custom_paths(tmp_path, capsys):
    cfg = tmp_path / "etc" / "w.json"
    code, _, _ = run(capsys, "init", "--config", str(cfg), "--name", NAME, "--listen", "127.0.0.1:9999",
                     "--prefix", "/w", "--db", "state/w.db", "--key-file", "secret/w.key")
    assert code == 0
    c = load_config(cfg)
    assert (c.host, c.port, c.prefix) == ("127.0.0.1", 9999, "/w")
    assert c.db_path == (tmp_path / "etc" / "state" / "w.db").resolve()
    assert (tmp_path / "etc" / "secret" / "w.key").exists()


def test_add_log(tmp_path, capsys):
    cfg = tmp_path / "w.json"
    run(capsys, "init", "--config", str(cfg), "--name", NAME)
    log = InProcessLog()
    vkey = format_vkey(log.vkey)
    code, out, _ = run(capsys, "add-log", "--config", str(cfg), "--origin", log.origin, "--vkey", vkey)
    assert code == 0 and out.startswith("added log")
    code, out, _ = run(capsys, "add-log", "--config", str(cfg), "--origin", log.origin, "--vkey", vkey)
    assert code == 0 and out.startswith("unchanged")
    rotated = format_vkey(vkey_from_ed25519(log.origin, Ed25519PrivateKey.generate().public_key()))
    code, out, _ = run(capsys, "add-log", "--config", str(cfg), "--origin", log.origin, "--vkey", rotated)
    assert code == 0 and out.startswith("added vkey")
    [entry] = load_config(cfg).logs
    assert [format_vkey(k) for k in entry.vkeys] == [vkey, rotated]
    doc = json.loads(cfg.read_text())
    assert doc["logs"] == [{"origin": log.origin, "vkeys": [vkey, rotated]}]


def _vkey(name: str, key_type: int, key: bytes) -> str:
    import base64

    return f"{name}+{key_hash(name, key_type, key).hex()}+{base64.b64encode(bytes([key_type]) + key).decode()}"


@pytest.mark.parametrize(
    "vkey",
    [
        "not-a-vkey",
        "log.example+00000000+AQ==",  # key ID mismatch / too short
        "log.example+" + "0" * 8 + "+AQ" + "A" * 42,  # key ID does not match the key
        _vkey("log.example", 0x02, b"\x07" * 32),  # well-formed, but ECDSA type is unsupported
        _vkey("log.example", 0x06, b"\x07" * 32),  # ML-DSA-44 type: unsupported
        _vkey("log.example", 0x01, b"\x07" * 31),  # Ed25519 type with a 31-byte key
        _vkey("log.example", 0x01, bytes([1]) + bytes(31)),  # the identity point (small order)
        _vkey("log.example", 0x01, bytes.fromhex(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")),  # order 8
        _vkey("log.example", 0x01, b"\xed" + b"\xff" * 30 + b"\x7f"),  # y = p: non-canonical
    ],
)
def test_add_log_rejects_bad_vkeys(tmp_path, capsys, vkey):
    cfg = tmp_path / "w.json"
    run(capsys, "init", "--config", str(cfg), "--name", NAME)
    before = cfg.read_text()
    code, _, err = run(capsys, "add-log", "--config", str(cfg), "--origin", "log.example", "--vkey", vkey)
    assert code == 1 and "error" in err
    assert cfg.read_text() == before


def test_add_log_rejects_bad_origin(tmp_path, capsys):
    cfg = tmp_path / "w.json"
    run(capsys, "init", "--config", str(cfg), "--name", NAME)
    log = InProcessLog()
    code, _, err = run(capsys, "add-log", "--config", str(cfg), "--origin", "has space",
                       "--vkey", format_vkey(log.vkey))
    assert code == 1


def test_status(tmp_path, capsys):
    cfg = tmp_path / "w.json"
    _, out, _ = run(capsys, "init", "--config", str(cfg), "--name", NAME)
    vkey = out.strip()
    log = InProcessLog()
    run(capsys, "add-log", "--config", str(cfg), "--origin", log.origin, "--vkey", format_vkey(log.vkey))
    code, out, _ = run(capsys, "status", "--config", str(cfg))
    assert code == 0 and vkey in out and "nothing cosigned yet" in out
    code, out, _ = run(capsys, "status", "--config", str(cfg), "--json")
    doc = json.loads(out)
    assert doc["witness"]["vkey"] == vkey
    assert doc["logs"][0]["origin"] == log.origin and doc["logs"][0]["size"] is None


def test_status_warns_when_the_database_is_missing(tmp_path, capsys):
    cfg = tmp_path / "w.json"
    run(capsys, "init", "--config", str(cfg), "--name", NAME)
    (tmp_path / "witness.db").unlink()
    code, out, _ = run(capsys, "status", "--config", str(cfg))
    assert code == 0 and "the database is missing" in out
    code, out, _ = run(capsys, "status", "--config", str(cfg), "--json")
    assert json.loads(out)["witness"]["db_status"] == "missing"


def test_missing_config_is_an_error(tmp_path, capsys):
    code, _, err = run(capsys, "status", "--config", str(tmp_path / "nope.json"))
    assert code == 1 and "does not exist" in err


def test_config_rejects_unknown_fields(tmp_path, capsys):
    cfg = tmp_path / "w.json"
    run(capsys, "init", "--config", str(cfg), "--name", NAME)
    doc = json.loads(cfg.read_text())
    doc["witness"]["lisen"] = "0.0.0.0:1"
    cfg.write_text(json.dumps(doc))
    code, _, err = run(capsys, "status", "--config", str(cfg))
    assert code == 1 and "lisen" in err


# ---------------------------------------------------------------------------
# serve, as a real process
# ---------------------------------------------------------------------------


def _start_serve(cfg: Path, env: dict[str, str] | None = None, *extra: str) -> tuple[subprocess.Popen, str]:
    proc = subprocess.Popen(
        [sys.executable, "-m", "aics_witness", "serve", "--config", str(cfg),
         "--listen", "127.0.0.1:0", *extra],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, **(env or {})},
    )
    deadline = time.time() + 20
    lines = []
    while time.time() < deadline:
        line = proc.stderr.readline()
        if not line:
            break
        lines.append(line)
        m = re.search(r"listening on (http://127\.0\.0\.1:\d+)", line)
        if m:
            return proc, m.group(1)
    proc.kill()
    raise AssertionError("serve did not start:\n" + "".join(lines))


def _stop(proc: subprocess.Popen) -> str:
    proc.send_signal(signal.SIGTERM)
    try:
        _, err = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    return err


def test_serve_end_to_end_with_reload_and_restart(tmp_path, capsys):
    cfg = tmp_path / "w.json"
    _, out, _ = run(capsys, "init", "--config", str(cfg), "--name", NAME)
    witness_vkey = parse_vkey(out.strip())
    log = InProcessLog()
    run(capsys, "add-log", "--config", str(cfg), "--origin", log.origin, "--vkey", format_vkey(log.vkey))

    proc, url = _start_serve(cfg)
    try:
        log.append(17)
        line = submit_checkpoint(url, log.checkpoint(), log.proof, witness_vkey=witness_vkey)
        assert threshold_policy_ok(merge_cosignatures(log.checkpoint(), line), log.vkey, [witness_vkey], 1)

        # A second log added while running is picked up on SIGHUP.
        other = InProcessLog("second.example.test/log")
        other.append(3)
        run(capsys, "add-log", "--config", str(cfg), "--origin", other.origin,
            "--vkey", format_vkey(other.vkey))
        proc.send_signal(signal.SIGHUP)
        deadline = time.time() + 10
        while True:
            try:
                submit_checkpoint(url, other.checkpoint(), other.proof, witness_vkey=witness_vkey)
                break
            except Exception:
                if time.time() > deadline:
                    raise
                time.sleep(0.1)
    finally:
        err = _stop(proc)
    assert proc.returncode == 0
    assert "stopped" in err
    assert "127.0.0.1" not in err.replace(url, "")  # no client addresses logged

    # status reflects the persisted state
    code, out, _ = run(capsys, "status", "--config", str(cfg), "--json")
    sizes = {entry["origin"]: entry["size"] for entry in json.loads(out)["logs"]}
    assert sizes == {log.origin: 17, other.origin: 3}

    # restart: state survives
    proc, url = _start_serve(cfg)
    try:
        log.append(3)
        submit_checkpoint(url, log.checkpoint(), log.proof, witness_vkey=witness_vkey)
    finally:
        _stop(proc)
    code, out, _ = run(capsys, "status", "--config", str(cfg), "--json")
    assert {e["origin"]: e["size"] for e in json.loads(out)["logs"]}[log.origin] == 20


def test_serve_refuses_a_swapped_key(tmp_path, capsys):
    cfg = tmp_path / "w.json"
    run(capsys, "init", "--config", str(cfg), "--name", NAME)
    proc, _ = _start_serve(cfg)
    _stop(proc)
    other = Ed25519PrivateKey.generate()
    proc = subprocess.run(
        [sys.executable, "-m", "aics_witness", "serve", "--config", str(cfg), "--listen", "127.0.0.1:0"],
        capture_output=True, text=True, timeout=20, env={**os.environ, SEED_ENV: seed_hex(other)},
    )
    assert proc.returncode == 1
    assert "accept-new-key" in proc.stderr


def test_serve_without_key_fails(tmp_path, capsys):
    cfg = tmp_path / "w.json"
    run(capsys, "init", "--config", str(cfg), "--name", NAME)
    (tmp_path / "witness.key").unlink()
    code, _, err = run(capsys, "serve", "--config", str(cfg), "--listen", "127.0.0.1:0")
    assert code == 1 and "init" in err


def test_serve_refuses_to_start_after_the_database_is_lost(tmp_path, capsys):
    """Same key, no state: serve must not start with an empty database (it
    could then cosign a fork of what it cosigned before)."""
    cfg = tmp_path / "w.json"
    _, out, _ = run(capsys, "init", "--config", str(cfg), "--name", NAME)
    witness_vkey = parse_vkey(out.strip())
    log = InProcessLog()
    run(capsys, "add-log", "--config", str(cfg), "--origin", log.origin, "--vkey", format_vkey(log.vkey))
    proc, url = _start_serve(cfg)
    try:
        log.append(10)
        submit_checkpoint(url, log.checkpoint(), log.proof, witness_vkey=witness_vkey)
    finally:
        _stop(proc)
    for p in tmp_path.glob("witness.db*"):
        p.unlink()  # lost volume, wrong path, deleted files ...
    proc = subprocess.run(
        [sys.executable, "-m", "aics_witness", "serve", "--config", str(cfg), "--listen", "127.0.0.1:0"],
        capture_output=True, text=True, timeout=20,
    )
    assert proc.returncode == 1
    assert "missing" in proc.stderr and "retire the identity" in proc.stderr
    assert not (tmp_path / "witness.db").exists()


def test_serve_refuses_a_database_init_did_not_bind(tmp_path, capsys):
    cfg = tmp_path / "w.json"
    run(capsys, "init", "--config", str(cfg), "--name", NAME)
    for p in tmp_path.glob("witness.db*"):
        p.unlink()
    WitnessStore(tmp_path / "witness.db", create=True).close()  # created, never bound
    code, _, err = run(capsys, "serve", "--config", str(cfg), "--listen", "127.0.0.1:0")
    assert code == 1 and "not bound to a witness key" in err


def test_clear_timestamp_command(tmp_path, capsys):
    cfg = tmp_path / "w.json"
    run(capsys, "init", "--config", str(cfg), "--name", NAME)
    with WitnessStore(tmp_path / "witness.db") as store:
        with store.transaction() as tx:
            tx.put("log.example/a", 3, b"\x01" * 32, "n\n", 4_000_000_000, 0)
    code, _, err = run(capsys, "clear-timestamp", "--config", str(cfg))
    assert code == 1 and "--origin" in err
    code, out, _ = run(capsys, "clear-timestamp", "--config", str(cfg), "--origin", "log.example/a")
    assert code == 0 and "1 log(s)" in out
    with WitnessStore(tmp_path / "witness.db") as store:
        assert store.get("log.example/a").timestamp == 0
    code, out, _ = run(capsys, "clear-timestamp", "--config", str(cfg), "--all")
    assert code == 0 and "1 log(s)" in out
    code, out, _ = run(capsys, "status", "--config", str(cfg))
    assert "time cleared" in out


def test_evidence_command(tmp_path, capsys):
    from aics_witness.protocol import format_add_checkpoint_request
    from aics_witness.service import Witness, WitnessError
    from aics_witness.store import WitnessStore, load_or_create_key

    cfg = tmp_path / "w.json"
    run(capsys, "init", "--config", str(cfg), "--name", NAME)
    code, out, _ = run(capsys, "evidence", "--config", str(cfg))
    assert code == 0 and json.loads(out) == []

    log = InProcessLog()
    run(capsys, "add-log", "--config", str(cfg), "--origin", log.origin, "--vkey", format_vkey(log.vkey))
    c = load_config(cfg)
    key, _, _ = load_or_create_key(c.key_path, create=False)
    with WitnessStore(c.db_path) as store:
        witness = Witness(c.name, key, store, c.logs)
        log.append(6)
        witness.add_checkpoint(format_add_checkpoint_request(0, [], log.checkpoint()))
        fork = log.fork(keep=2)
        fork.append(4)  # same size 6, different root: a split view
        with pytest.raises(WitnessError):
            witness.add_checkpoint(format_add_checkpoint_request(6, [], fork.checkpoint()))

    code, out, _ = run(capsys, "evidence", "--config", str(cfg), "--origin", log.origin)
    [row] = json.loads(out)
    assert row["origin"] == log.origin and row["witness_size"] == 6
    assert "different root" in row["reason"]
    assert fork.checkpoint().decode() in row["request"]
    assert row["witness_latest_note"].startswith(log.checkpoint().decode().split("\n\n")[0])
    code, out, _ = run(capsys, "status", "--config", str(cfg))
    assert "EVIDENCE 1" in out


def test_serve_stops_with_status_1_when_a_database_write_fails(tmp_path, capsys, monkeypatch):
    """A failed COMMIT leaves the database state unknown: the add gets 503 and
    serve exits non-zero, so the container's restart policy takes over."""
    import socket
    import threading

    import aics_witness.cli as cli
    from aics_witness.protocol import format_add_checkpoint_request

    from conftest import FailingCommit, http_request

    cfg = tmp_path / "w.json"
    run(capsys, "init", "--config", str(cfg), "--name", NAME)
    log = InProcessLog()
    run(capsys, "add-log", "--config", str(cfg), "--origin", log.origin, "--vkey", format_vkey(log.vkey))

    class FullDisk(WitnessStore):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._conn = FailingCommit(self._conn)

    monkeypatch.setattr(cli, "WitnessStore", FullDisk)
    monkeypatch.setattr(cli.signal, "signal", lambda *args: None)  # keep pytest's handlers
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    seen: dict[str, int] = {}

    def feed() -> None:
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                seen["healthz"] = http_request(base + "/healthz", "GET").status
                break
            except OSError:
                time.sleep(0.05)
        log.append(3)
        seen["add"] = http_request(base + "/add-checkpoint", "POST",
                                   format_add_checkpoint_request(0, [], log.checkpoint())).status

    t = threading.Thread(target=feed, daemon=True)
    t.start()
    code = main(["serve", "--config", str(cfg), "--listen", f"127.0.0.1:{port}"])
    t.join(timeout=10)
    assert code == 1
    assert seen == {"healthz": 200, "add": 503}
    with WitnessStore(tmp_path / "witness.db") as store:
        assert store.get(log.origin) is None  # nothing was committed
