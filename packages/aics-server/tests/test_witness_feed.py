"""The witness feeder wired into the checkpoint publisher (aics_server.witness_feed, AICS-1 sections 6.2-6.3).

A real aics-witness (packages/aics-witness, run in-process on a loopback port) cosigns the
checkpoints the server publishes; fake witnesses on loopback refuse, hang, or answer with a
cosignature that does not verify.  What must hold: verified cosignatures are merged into the
note served at /checkpoint, /tiles/checkpoint and <tiles>/checkpoint; a witness that refuses or
times out never delays a write or a publication; a line that does not verify is never served;
/healthz reports each witness.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from aics_identity import keys
from aics_server.app import create_app
from aics_server.db import DEFAULT_ORIGIN, LOG_KEY_LABEL, SanctuaryDB
from aics_server.tlog_store import MMD_SECONDS
from aics_server.witness_feed import (
    MAX_BACKOFF_SECONDS,
    WitnessConfigError,
    WitnessEndpoint,
    WitnessFeeder,
    WitnessSettings,
    parse_witnesses,
)
from aics_tlog import (
    cosignature_vkey,
    format_vkey,
    parse_checkpoint,
    parse_note,
    sign_cosignature,
    verify_bundle,
    verify_checkpoint,
    vkey_from_ed25519,
)

aics_witness = pytest.importorskip("aics_witness")
from aics_witness.config import LogConfig  # noqa: E402
from aics_witness.protocol import format_signature_line, parse_add_checkpoint_request  # noqa: E402
from aics_witness.service import Witness, make_server  # noqa: E402
from aics_witness.store import WitnessStore  # noqa: E402

from conftest import TEST_LIMITS, Agent, Line, artifacts, entry_bundle  # noqa: E402

SEED_HEX = "11" * 32
WITNESS_NAME = "witness.example.test/w1"


def log_vkey():
    key = keys.derive_agent_key(bytes.fromhex(SEED_HEX), LOG_KEY_LABEL)
    return vkey_from_ed25519(DEFAULT_ORIGIN, key.public_key())


def wait_for(predicate, timeout: float = 10.0, interval: float = 0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError("condition not met in time")


# ----------------------------------------------------------------------
# witnesses on loopback
# ----------------------------------------------------------------------

class RealWitness:
    """aics-witness itself, trusting the test log's key."""

    def __init__(self, tmp_path: Path, name: str = WITNESS_NAME) -> None:
        self.key = Ed25519PrivateKey.generate()
        self.vkey = cosignature_vkey(name, self.key.public_key())
        self.store = WitnessStore(tmp_path / f"witness-{abs(hash(name))}.db", create=True)
        self.witness = Witness(name, self.key, self.store, [LogConfig(origin=DEFAULT_ORIGIN, vkeys=(log_vkey(),))])
        self.server = make_server(self.witness, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.requests = 0
        original = self.witness.add_checkpoint

        def counting(body: bytes) -> bytes:
            self.requests += 1
            return original(body)

        self.witness.add_checkpoint = counting  # type: ignore[method-assign]

    @property
    def url(self) -> str:
        return self.server.url

    @property
    def vkey_text(self) -> str:
        return format_vkey(self.vkey)

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.store.close()


class FakeWitness:
    """A witness that misbehaves: ``refuse`` (403), ``hang`` (answers after ``delay``), ``bad`` (a forged line)."""

    def __init__(self, mode: str, name: str = "witness.example.test/fake", delay: float = 3.0) -> None:
        self.mode = mode
        self.key = Ed25519PrivateKey.generate()
        self.vkey = cosignature_vkey(name, self.key.public_key())
        self.name = name
        self.delay = delay
        self.requests = 0
        self._release = threading.Event()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # noqa: D401 - quiet
                pass

            def do_POST(self):  # noqa: N802
                fake.requests += 1
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if fake.mode == "refuse":
                    self._answer(403, b"no\n")
                elif fake.mode == "hang":
                    fake._release.wait(fake.delay)
                    try:
                        self._answer(503, b"busy\n")
                    except OSError:
                        pass
                elif fake.mode == "bad":
                    req = parse_add_checkpoint_request(body)
                    cp = parse_checkpoint(parse_note(req.checkpoint).text)
                    # The right name and key ID, a signature over another root: does not verify.
                    _, line = sign_cosignature(fake.key, fake.name, int(time.time()), cp.origin, cp.size, b"\x07" * 32)
                    self._answer(200, format_signature_line(line).encode())

            def _answer(self, status: int, data: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def vkey_text(self) -> str:
        return format_vkey(self.vkey)

    def stop(self) -> None:
        self._release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@pytest.fixture()
def real_witness(tmp_path):
    w = RealWitness(tmp_path)
    yield w
    w.stop()


def settings(tmp_path: Path, *witnesses, refresh: float = 600.0, timeout: float = 2.0) -> WitnessSettings:
    return WitnessSettings(
        witnesses=tuple(WitnessEndpoint(name=f"w{i}", url=w.url, vkey=w.vkey) for i, w in enumerate(witnesses, 1)),
        state_dir=tmp_path / "witness-state",
        refresh_seconds=refresh,
        timeout_seconds=timeout,
        min_backoff_seconds=0.05,
        max_backoff_seconds=0.2,
    )


@pytest.fixture()
def open_db(tmp_path, monkeypatch):
    """``open_db(witness_settings)``: a fresh SanctuaryDB on a fixed seed, its feeder stopped after the test."""
    monkeypatch.setenv("AICS_SERVER_SEED_HEX", SEED_HEX)
    for var in ("AICS_TILES_DIR", "AICS_ORIGIN", "AICS_WITNESSES", "AICS_TILES_AUDIT"):
        monkeypatch.delenv(var, raising=False)
    opened: list[SanctuaryDB] = []

    def make(witnesses: WitnessSettings | None, name: str = "aics.db") -> SanctuaryDB:
        db = SanctuaryDB(db_path=tmp_path / name, witnesses=witnesses or WitnessSettings(witnesses=()))
        opened.append(db)
        return db

    yield make
    for db in opened:
        db.stop_witness_feeder()


@pytest.fixture()
def app_with(tmp_path, monkeypatch, owner):
    """``app_with(env)``: a TestClient on a fresh app whose environment names witnesses; feeder stopped after."""
    monkeypatch.setenv("AICS_SERVER_SEED_HEX", SEED_HEX)
    for var in ("AICS_TILES_DIR", "AICS_ORIGIN", "AICS_TILES_AUDIT", "AICS_CHARTER_FILE", "AICS_PUBKEYS_OUT"):
        monkeypatch.delenv(var, raising=False)
    clients: list[TestClient] = []

    def make(env: dict[str, str]) -> TestClient:
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        client = TestClient(
            create_app(
                db_path=tmp_path / "app.db", owner_public_key=owner.public_key_b64u,
                pubkeys_out=tmp_path / "keys.txt", announce=False, limits=TEST_LIMITS,
            )
        )
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.app.state.db.stop_witness_feeder()


def witnesses_env(**witnesses) -> str:
    """``AICS_WITNESSES``: ``label=url=vkey`` entries."""
    return ",".join(f"{label}={w.url}={w.vkey_text}" for label, w in witnesses.items())


def cosigned(note: bytes, witness) -> bool:
    result = verify_checkpoint(parse_note(note), log_vkey(), [witness.vkey], 1, max_age_seconds=300)
    return result.ok and witness.vkey.name in result.witnesses


def witness_lines(note: bytes) -> list:
    return [s for s in parse_note(note).signatures if len(s.signature) == 72]


# ----------------------------------------------------------------------
# configuration
# ----------------------------------------------------------------------

class TestConfiguration:
    def test_empty_means_no_witness(self):
        assert parse_witnesses("") == () and parse_witnesses("  ") == ()

    def test_name_url_vkey_entries(self):
        a = cosignature_vkey("a.example/w", Ed25519PrivateKey.generate().public_key())
        b = cosignature_vkey("b.example/w", Ed25519PrivateKey.generate().public_key())
        parsed = parse_witnesses("one=https://a.example=" + format_vkey(a) + f" , two=http://10.0.0.2:7380/p={format_vkey(b)}")
        assert [(e.name, e.url, e.vkey_text) for e in parsed] == [
            ("one", "https://a.example", format_vkey(a)),
            ("two", "http://10.0.0.2:7380/p", format_vkey(b)),
        ]

    def test_json_file(self, tmp_path):
        a = cosignature_vkey("a.example/w", Ed25519PrivateKey.generate().public_key())
        path = tmp_path / "witnesses.json"
        path.write_text(json.dumps({"witnesses": [{"name": "oracle", "url": "https://w.example", "vkey": format_vkey(a)}]}))
        (endpoint,) = parse_witnesses(str(path))
        assert endpoint.name == "oracle" and endpoint.vkey == a and endpoint.url == "https://w.example"
        assert endpoint.state_file_name == f"oracle-{a.key_id.hex()}.json"
        path.write_text(json.dumps([{"name": "oracle", "url": "https://w.example", "vkey": format_vkey(a), "x": 1}]))
        with pytest.raises(WitnessConfigError, match="exactly"):
            parse_witnesses(str(path))
        path.write_text('{"witnesses": [], "witnesses": []}')
        with pytest.raises(WitnessConfigError, match="duplicate"):
            parse_witnesses(str(path))
        with pytest.raises(WitnessConfigError, match="cannot read"):
            parse_witnesses(str(tmp_path / "missing.json"))

    def test_the_card_reads_the_same_setting(self):
        from aics_server import card

        if not hasattr(card, "witnesses_from_env"):
            pytest.skip("the card module does not read AICS_WITNESSES in this tree")
        a = cosignature_vkey("a.example/w", Ed25519PrivateKey.generate().public_key())
        value = f"oracle=https://w.example={format_vkey(a)}"
        (endpoint,) = parse_witnesses(value)
        config = card.witnesses_from_env({"AICS_WITNESSES": value})
        assert [w.vkey for w in config.witnesses] == [endpoint.vkey_text]

    @pytest.mark.parametrize("make", [
        lambda v: f"bad name=https://w.example={v}",
        lambda v: f"w=ftp://w.example={v}",
        lambda v: f"w=https://w.example/?x=1={v}",
        lambda v: "w=https://w.example=not-a-vkey",
        lambda v: f"w=https://w.example={v},w=https://x.example={v}",
        lambda v: "w=https://w.example",
        # A log (note signature, type 0x01) key is not a cosignature key.
        lambda v: f"w=https://w.example={format_vkey(vkey_from_ed25519('l.example/x', Ed25519PrivateKey.generate().public_key()))}",
    ])
    def test_malformed_settings_stop_the_start(self, make):
        v = format_vkey(cosignature_vkey("a.example/w", Ed25519PrivateKey.generate().public_key()))
        with pytest.raises(WitnessConfigError):
            parse_witnesses(make(v))

    def test_refresh_bounds(self, tmp_path):
        for bad in ("0", "101", "soon"):
            with pytest.raises(WitnessConfigError):
                WitnessSettings.from_env({"AICS_WITNESS_REFRESH_SECONDS": bad}, default_state_dir=tmp_path)
        s = WitnessSettings.from_env({}, default_state_dir=tmp_path)
        assert s.witnesses == () and s.refresh_seconds == 60 and s.state_dir == tmp_path
        # Fresh within the card's max_checkpoint_age (300 s) with room for a failed attempt.
        assert WitnessSettings.from_env({"AICS_WITNESS_REFRESH_SECONDS": "100"},
                                        default_state_dir=tmp_path).refresh_seconds == 100

    def test_a_malformed_environment_refuses_to_open_the_log(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AICS_WITNESSES", "w=https://w.example=nope")
        with pytest.raises(WitnessConfigError):
            SanctuaryDB(db_path=tmp_path / "x.db")
        assert not (tmp_path / "x.db").exists()

    def test_without_witnesses_nothing_changes(self, open_db):
        db = open_db(None)
        assert db.witness_feeder is None
        assert db.health()["witnesses"] == []
        assert len(parse_note(db.published_checkpoint()).signatures) == 1


class TestBackoff:
    """A witness that failed many times is tried again within half the MMD (AICS-1 section 10.1)."""

    def feeder(self, clock: list[float], **overrides) -> WitnessFeeder:
        key = Ed25519PrivateKey.generate()
        endpoint = WitnessEndpoint("w1", "http://127.0.0.1:1", cosignature_vkey("w.example/w1", key.public_key()))
        return WitnessFeeder(
            WitnessSettings(witnesses=(endpoint,), **overrides),
            proof=lambda old, new: [], deliver=lambda e, size, lines: (True, None),
            client_factory=lambda e: object(), monotonic=lambda: clock[0], clock=lambda: 1_800_000_000 + clock[0],
        )

    def test_the_default_cap_is_half_the_mmd(self):
        assert MAX_BACKOFF_SECONDS * 2 <= MMD_SECONDS
        assert WitnessSettings(witnesses=()).max_backoff_seconds == MAX_BACKOFF_SECONDS
        for bad in ({"max_backoff_seconds": 300.0}, {"min_backoff_seconds": 0.0}, {"min_backoff_seconds": 40.0}):
            with pytest.raises(WitnessConfigError):
                WitnessSettings(witnesses=(), **bad)

    def test_after_many_failures_a_recovered_witness_cosigns_a_new_checkpoint_within_the_mmd(self):
        clock = [0.0]
        feeder = self.feeder(clock)
        worker = feeder._workers[0]
        feeder.offer(5, b"note 5")
        for _ in range(25):  # a long outage: every retry fails, the backoff reaches its cap
            clock[0] += feeder._wait_for(worker, 5, clock[0])
            feeder._failed(worker, OSError("connection refused"))
            assert 0 < worker.retry_at - clock[0] <= MAX_BACKOFF_SECONDS
        assert worker.backoff == MAX_BACKOFF_SECONDS and worker.failures == 25
        # The witness is back, and a leaf is published just after the last failure.
        published = clock[0]
        feeder.offer(6, b"note 6")
        wait = feeder._wait_for(worker, 6, clock[0])
        assert wait <= MAX_BACKOFF_SECONDS
        clock[0] += wait
        feeder._succeeded(worker, 6)
        assert clock[0] - published < MMD_SECONDS
        (status,) = feeder.status()
        assert status["state"] == "ok" and status["last_cosigned_size"] == 6 and status["consecutive_failures"] == 0


# ----------------------------------------------------------------------
# merging
# ----------------------------------------------------------------------

class TestCosignaturesMerged:
    def test_a_real_witness_cosigns_and_the_served_note_carries_it(self, app_with, real_witness, tmp_path):
        client = app_with({"AICS_WITNESSES": witnesses_env(oracle=real_witness)})
        db = client.app.state.db
        wait_for(lambda: db.health()["witnesses"][0]["cosigned_current"])
        for path in ("/checkpoint", "/tiles/checkpoint"):
            assert cosigned(client.get(path).content, real_witness), path
        on_disk = (db.tiles_dir / "checkpoint").read_bytes()
        assert on_disk == client.get("/checkpoint").content
        assert cosigned(client.get("/v2/tlog/checkpoint").json()["signed_checkpoint"].encode(), real_witness)

        # A new leaf: a new checkpoint, fed again from the size the witness holds (consistency proof).
        origin = client.get("/v2/tlog/checkpoint").json()["origin"]
        before = parse_checkpoint(parse_note(client.get("/checkpoint").content).text).size
        assert Agent(client, origin).claim("alice").status_code in (200, 201, 202)
        after = wait_for(lambda: (lambda n: parse_checkpoint(parse_note(n).text).size > before and cosigned(n, real_witness)
                                  and n)(client.get("/checkpoint").content))
        assert len(witness_lines(after)) == 1

        status = client.get("/healthz").json()
        assert status["status"] == "OPERATIONAL"
        (w,) = status["witnesses"]
        assert w["name"] == "oracle" and w["vkey"] == real_witness.vkey_text and w["state"] == "ok"
        assert w["last_cosigned_size"] == status["published_size"] and w["last_error"] is None
        assert isinstance(w["last_success_at"], int) and w["cosigned_current"] is True
        assert 0 <= w["cosignature_age_seconds"] < 60 and w["consecutive_failures"] == 0
        assert real_witness.url not in json.dumps(status)

        # The client remembers what the witness cosigned across restarts (the state file, not secret).
        endpoint = db.witness_settings.witnesses[0]
        state = json.loads((db.db_path.parent / "witness-state" / endpoint.state_file_name).read_text())
        assert state["logs"][origin]["max_cosigned"] == status["published_size"]

    def test_the_probe_reads_an_age_from_the_cosignature(self, open_db, real_witness, tmp_path):
        db = open_db(settings(tmp_path, real_witness))
        wait_for(lambda: cosigned(db.published_checkpoint(), real_witness))
        # ops/uptime-check.sh: a 76-byte blob (key ID 4 + timestamp 8 + signature 64) yields the age.
        import base64
        blobs = [base64.b64decode(line.split()[-1]) for line in db.published_checkpoint().decode().splitlines()
                 if line.startswith("\N{EM DASH} ")]
        stamps = [int.from_bytes(b[4:12], "big") for b in blobs if len(b) == 76]
        assert stamps and abs(time.time() - max(stamps)) < 60

    def test_an_idle_log_refreshes_the_cosignature(self, open_db, real_witness, tmp_path):
        db = open_db(settings(tmp_path, real_witness, refresh=0.2))
        wait_for(lambda: cosigned(db.published_checkpoint(), real_witness))
        first = witness_lines(db.published_checkpoint())[0].signature[:8]
        wait_for(lambda: witness_lines(db.published_checkpoint())[0].signature[:8] > first, timeout=5)
        assert len(witness_lines(db.published_checkpoint())) == 1

    def test_cosignatures_survive_a_restart_when_they_still_verify(self, open_db, real_witness, tmp_path):
        configured = settings(tmp_path, real_witness)
        db = open_db(configured)
        note = wait_for(lambda: (lambda n: cosigned(n, real_witness) and n)(db.published_checkpoint()))
        db.stop_witness_feeder()
        real_witness.stop()
        reopened = open_db(configured)
        assert reopened.published_checkpoint() == note
        assert (reopened.tiles_dir / "checkpoint").read_bytes() == note
        # A server no longer configured with that witness serves the log signature alone.
        bare = open_db(None)
        assert len(parse_note(bare.published_checkpoint()).signatures) == 1


# ----------------------------------------------------------------------
# proofs are given against a cosigned checkpoint (AICS-1 sections 6.3, 14.3)
# ----------------------------------------------------------------------

class TestProofsAgainstCosignedCheckpoints:
    """A verifier pinning a card's positive quorum accepts a bundle only when its checkpoint carries that many
    cosignatures (AICS-1 section 14.3 step 1 under section 6.3; age does not matter offline).  The log publishes a
    checkpoint before a witness cosigns it, so a proof against the newest log-signed note never carries one: the
    pre-launch conformance run at quorum 1 failed G8 for exactly this (2026-10-20).  A proof is given against the
    newest checkpoint a witness cosigned that covers the leaf, and against the whole tree only for a leaf newer than
    that."""

    @staticmethod
    def setup(app_with):
        witness = FakeWitness("refuse")  # never cosigns by itself: its lines are delivered by hand below
        client = app_with({"AICS_WITNESSES": witnesses_env(w=witness), "AICS_WITNESS_TIMEOUT_SECONDS": "0.3"})
        db = client.app.state.db
        db.stop_witness_feeder()
        endpoint = db.witness_settings.witnesses[0]

        def cosign(size: int) -> None:
            cp = parse_checkpoint(parse_note(db._log.checkpoint_note(size)).text)
            _, line = sign_cosignature(witness.key, witness.name, int(time.time()), cp.origin, size, cp.root)
            assert db._deliver_cosignature(endpoint, size, format_signature_line(line)) == (True, None)

        return witness, client, db, cosign

    @staticmethod
    def proven(client, witness, index: int) -> tuple[int, bool]:
        """The size of bundle ``index``'s checkpoint, and whether the bundle verifies at quorum 1 (any age)."""
        bundle, _ = entry_bundle(client, index)
        assert verify_bundle(bundle, log_vkey(), expected_origin=DEFAULT_ORIGIN).ok  # quorum 0: always
        size = parse_checkpoint(parse_note(keys.b64u_decode(bundle["checkpoint_note"])).text).size
        return size, verify_bundle(bundle, log_vkey(), [witness.vkey], 1, expected_origin=DEFAULT_ORIGIN).ok

    def test_bundles_use_the_newest_cosigned_checkpoint_that_covers_the_leaf(self, app_with):
        witness, client, db, cosign = self.setup(app_with)
        try:
            origin = client.get("/v2/tlog/checkpoint").json()["origin"]
            first = db._log.tree.size
            assert self.proven(client, witness, 0) == (first, False)  # nothing cosigned yet: the whole tree
            cosign(first)
            assert self.proven(client, witness, first - 1) == (first, True)
            # A new leaf is published log-signed: earlier leaves stay proven against the cosigned checkpoint, the
            # new one (newer than every cosignature) against the whole tree.
            assert Agent(client, origin).claim("carol").status_code in (200, 201, 202)
            second = db._log.tree.size
            assert second > first and db._log.published.size == second
            assert self.proven(client, witness, 0) == (first, True)
            assert client.get(f"/v2/entries/{second - 1}").status_code == 503  # proved only against the served, cosigned note
            cosign(second)
            assert self.proven(client, witness, 0) == (second, True)
            assert self.proven(client, witness, second - 1) == (second, True)
            # The legacy proof endpoint and the gate's read state the same checkpoint and tree size.
            legacy = client.get(f"/v2/tlog/proof/{second - 1}").json()
            assert legacy["tree_size"] == second and cosigned(legacy["signed_checkpoint"].encode(), witness)
            line = Line(client)
            line.send()
            for index, size in ((0, second), (second - 1, second)):
                read = line.send(f"read {index}")
                assert read.startswith(f"ok read {index} "), read
                note = artifacts(read)["checkpoint"]
                assert parse_checkpoint(parse_note(note).text).size == size and cosigned(note, witness)
                assert note == keys.b64u_decode(entry_bundle(client, index)[0]["checkpoint_note"])
        finally:
            witness.stop()

    def test_the_cosigned_checkpoint_survives_a_restart(self, open_db, tmp_path):
        witness = FakeWitness("refuse")
        try:
            configured = settings(tmp_path, witness)
            db = open_db(configured)
            db.stop_witness_feeder()
            size = db._log.tree.size
            cp = parse_checkpoint(parse_note(db._log.checkpoint_note(size)).text)
            _, line = sign_cosignature(witness.key, witness.name, int(time.time()), cp.origin, size, cp.root)
            assert db._deliver_cosignature(db.witness_settings.witnesses[0], size, format_signature_line(line)) == (True, None)
            reopened = open_db(configured)
            reopened.stop_witness_feeder()
            assert reopened._log.cosigned is not None and reopened._log.cosigned.size == size
            proof = reopened.get_tlog_proof(0)
            assert proof["tree_size"] == size and cosigned(proof["signed_checkpoint"].encode(), witness)
        finally:
            witness.stop()

    def test_without_witnesses_proofs_are_against_the_whole_tree(self, open_db):
        db = open_db(None)
        size = db._log.tree.size
        proof = db.get_tlog_proof(0)
        assert db._log.cosigned is None
        assert proof["tree_size"] == size and proof["signed_checkpoint"].encode() == db._log.checkpoint_note(size)


# ----------------------------------------------------------------------
# failing witnesses never block, bad lines are never served
# ----------------------------------------------------------------------

class TestFailingWitnesses:
    @pytest.mark.parametrize("mode", ["refuse", "hang", "bad"])
    def test_a_failing_witness_does_not_block_writes_or_publication(self, app_with, mode):
        fake = FakeWitness(mode, delay=5.0)
        try:
            client = app_with({
                "AICS_WITNESSES": witnesses_env(flaky=fake),
                "AICS_WITNESS_TIMEOUT_SECONDS": "0.3",
            })
            db = client.app.state.db
            origin = client.get("/v2/tlog/checkpoint").json()["origin"]
            wait_for(lambda: fake.requests >= 1)
            started = time.monotonic()
            assert Agent(client, origin).claim("bob").status_code in (200, 201, 202)
            assert time.monotonic() - started < 2.0
            health = client.get("/healthz").json()
            assert health["status"] == "OPERATIONAL" and health["published_size"] == health["tree_size"]
            note = client.get("/checkpoint").content
            assert parse_checkpoint(parse_note(note).text).size == health["tree_size"]
            assert witness_lines(note) == []  # nothing unverified on the served note
            (w,) = wait_for(lambda: (lambda ws: ws[0]["last_error"] and ws)(db.health()["witnesses"]))
            assert w["state"] == "failing" and w["consecutive_failures"] >= 1 and w["cosigned_current"] is False
            assert w["last_success_at"] is None and isinstance(w["last_error_at"], int)
            assert fake.url not in w["last_error"] and "127.0.0.1" not in w["last_error"]
        finally:
            fake.stop()

    def test_one_witness_failing_leaves_the_other_cosigning(self, open_db, real_witness, tmp_path):
        fake = FakeWitness("refuse")
        try:
            db = open_db(settings(tmp_path, real_witness, fake))
            wait_for(lambda: cosigned(db.published_checkpoint(), real_witness))
            wait_for(lambda: db.health()["witnesses"][1]["consecutive_failures"] >= 2)  # retried with backoff
            ok, failing = db.health()["witnesses"]
            assert ok["state"] == "ok" and ok["cosigned_current"] is True
            assert failing["state"] == "failing" and "403" in failing["last_error"]
            assert len(witness_lines(db.published_checkpoint())) == 1
        finally:
            fake.stop()

    def test_a_witness_that_recovers_cosigns_after_backoff(self, open_db, tmp_path):
        witness = RealWitness(tmp_path)
        logs = witness.witness.logs
        witness.witness.set_logs([])  # the witness does not know the log yet: 404, retried
        try:
            db = open_db(settings(tmp_path, witness))
            wait_for(lambda: db.health()["witnesses"][0]["state"] == "failing")
            witness.witness.set_logs(logs.values())
            wait_for(lambda: cosigned(db.published_checkpoint(), witness))
            assert db.health()["witnesses"][0]["state"] == "ok"
        finally:
            witness.stop()

    def test_lines_that_do_not_verify_are_dropped(self, open_db, tmp_path):
        witness = FakeWitness("refuse")  # never cosigns by itself: the lines below are delivered by hand
        db = open_db(settings(tmp_path, witness))
        db.stop_witness_feeder()
        witness.stop()
        endpoint = db.witness_settings.witnesses[0]
        published = db._log.published
        cp = parse_checkpoint(parse_note(published.note).text)
        now = int(time.time())

        def line(*, key=witness.key, name=witness.name, ts=now, size=cp.size, root=cp.root):
            return format_signature_line(sign_cosignature(key, name, ts, cp.origin, size, root)[1])

        before = db.published_checkpoint()
        cases = {
            "wrong root": line(root=b"\x01" * 32),
            "wrong size": line(size=cp.size + 1),
            "dated ahead": line(ts=now + 120),
            "stale": line(ts=now - 3600),
            "another key under the witness name": line(key=Ed25519PrivateKey.generate()),
            "two lines": line() + line(ts=now - 1),
            "garbage": "not a signature line\n",
        }
        for label, lines in cases.items():
            served, reason = db._deliver_cosignature(endpoint, cp.size, lines)
            assert served is False and reason, label
            assert db.published_checkpoint() == before, label
            assert (db.tiles_dir / "checkpoint").read_bytes() == before, label
        assert db._log.cosignatures_dropped >= len(cases) - 1

        # A line for a size no longer published is superseded, not an error.
        assert db._deliver_cosignature(endpoint, cp.size - 1, line(size=cp.size - 1)) == (False, "superseded")
        # A key not configured is refused even when its line verifies.
        other = Ed25519PrivateKey.generate()
        stranger = WitnessEndpoint("x", "http://127.0.0.1:1", cosignature_vkey("x.example/w", other.public_key()))
        served, _ = db._deliver_cosignature(stranger, cp.size, line(key=other, name="x.example/w"))
        assert served is False and db.published_checkpoint() == before

        # The good line is served; an older one afterwards does not replace it.
        written_at = db._log.checkpoint_written_at
        assert written_at is not None and db._log.cosigned_at is None
        assert db._deliver_cosignature(endpoint, cp.size, line()) == (True, None)
        # A merged cosignature is not a publication: the checkpoint's age (owner stats) stays the publication's.
        assert db._log.checkpoint_written_at == written_at and db._log.cosigned_at is not None
        good = db.published_checkpoint()
        assert cosigned(good, witness) and good != before
        served, _ = db._deliver_cosignature(endpoint, cp.size, line(ts=now - 10))
        assert served is False and db.published_checkpoint() == good
        assert db.health()["witnesses"][0]["cosigned_current"] is True
