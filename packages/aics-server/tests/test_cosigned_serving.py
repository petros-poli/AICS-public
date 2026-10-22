"""Only cosigned checkpoints are served while a witness is configured (AICS-1 sections 6.3, 10.1 and 14.3).

With ``AICS_WITNESSES`` set the card states quorum 1, so a log-signed note no witness has cosigned yet is one a
verifier holding that card must reject.  The pre-launch walk-throughs of 2026-10-20 saw about 4 of 75 fetches of
``/checkpoint`` return such a note (the publisher served the new note first, the feeder cosigned it afterwards), and
``GET /v2/entries/{index}`` and the gate's ``read`` prove against the log-signed note of the whole tree even when
``/checkpoint`` at that size has the cosignature: under a quorum-1 card both fail from day one.

What must hold, with a witness that answers slowly, late, or not at all:

* every note served at ``/checkpoint``, ``/tiles/checkpoint``, ``<tiles>/checkpoint`` (the tile mirror),
  ``/v2/tlog/checkpoint`` and by the gate carries a verified cosignature, unless no witness has cosigned a served
  note yet or every witness has been failing for longer than the grace, and then ``/healthz`` says so
  (``serving_uncosigned``, ``uncosigned_reason``);
* the served size never decreases, and a newer publication is served once a witness cosigns it;
* an entry bundle is proved against exactly the note ``/checkpoint`` serves; a just-appended entry the served note
  does not cover yet waits for the next cosigned one, else gets an explicit 503 ``not_yet_cosigned`` with
  ``Retry-After`` (the gate: ``err busy``);
* without witnesses nothing changes (quorum 0: every publication is served at once).
"""

from __future__ import annotations

import asyncio
import base64
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aics_identity import keys
from aics_server.app import create_app
from aics_server.db import DEFAULT_ORIGIN
from aics_server.gate import TcpGate
from aics_server.tlog_store import TlogStore
from aics_server.witness_feed import (
    WitnessConfigError,
    WitnessEndpoint,
    WitnessFeeder,
    WitnessSettings,
    max_grace_seconds,
)
from aics_tlog import cosignature_vkey, parse_checkpoint, parse_note, sign_cosignature, verify_bundle, verify_checkpoint
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

aics_witness = pytest.importorskip("aics_witness")
from aics_witness.protocol import format_signature_line  # noqa: E402
from aics_witness.service import WitnessError  # noqa: E402

from conftest import TEST_LIMITS, Agent, KeyAgent, Line, artifacts, check_reply, ok_line, onboard  # noqa: E402
from test_witness_feed import SEED_HEX, WITNESS_NAME, FakeWitness, RealWitness, log_vkey, wait_for  # noqa: E402


# ----------------------------------------------------------------------
# a real witness that answers slowly, late, or not at all
# ----------------------------------------------------------------------

class ScriptedWitness(RealWitness):
    """aics-witness itself, answering request ``n`` after ``delay(n)`` seconds, and 503 while ``down``.

    A delay longer than the feeder's timeout makes the answer late: the feeder gives up on it (the witness still
    applies the checkpoint afterwards), backs off and tries again with the latest checkpoint.
    """

    def __init__(self, tmp_path: Path, delay=lambda n: 0.0, name: str = WITNESS_NAME) -> None:
        super().__init__(tmp_path, name)
        self.delay = delay
        self.down = False
        self.refused = 0
        self.pauses: list[float] = []
        counting = self.witness.add_checkpoint

        def scripted(body: bytes) -> bytes:
            if self.down:
                self.refused += 1
                raise WitnessError(503, "the witness is down for this test")
            pause = self.delay(len(self.pauses) + 1)
            self.pauses.append(pause)
            if pause:
                time.sleep(pause)
            return counting(body)

        self.witness.add_checkpoint = scripted  # type: ignore[method-assign]


def cosigned_by(note: bytes, witness, *, fresh: bool = True) -> bool:
    """Whether ``note`` is log-signed and carries a verified cosignature of ``witness`` (quorum 1)."""
    result = verify_checkpoint(parse_note(note), log_vkey(), [witness.vkey], 1, expected_origin=DEFAULT_ORIGIN,
                               max_age_seconds=300 if fresh else None)
    return result.ok and witness.vkey.name in result.witnesses


def size_of(note: bytes) -> int:
    return parse_checkpoint(parse_note(note).text).size


def bundle_note(bundle: dict) -> bytes:
    return keys.b64u_decode(bundle["checkpoint_note"])


@pytest.fixture()
def make_app(tmp_path, monkeypatch, owner):
    """``make_app(*witnesses, grace=, timeout=, refresh=, backoff=)``: a TestClient on the app of one database (a
    second call is a restart of the same log) whose feeder feeds ``witnesses`` with a fast backoff (``backoff``: its
    ``(min, max)``, 50-200 ms by default); feeders stopped after."""
    monkeypatch.setenv("AICS_SERVER_SEED_HEX", SEED_HEX)
    for var in ("AICS_TILES_DIR", "AICS_ORIGIN", "AICS_TILES_AUDIT", "AICS_CHARTER_FILE", "AICS_PUBKEYS_OUT",
                "AICS_WITNESSES"):
        monkeypatch.delenv(var, raising=False)
    clients: list[TestClient] = []

    def make(*witnesses, grace: float = 120.0, timeout: float = 2.0, refresh: float = 600.0,
             backoff: tuple[float, float] = (0.05, 0.2)) -> TestClient:
        configured = WitnessSettings(
            witnesses=tuple(WitnessEndpoint(f"w{i}", w.url, w.vkey) for i, w in enumerate(witnesses, 1)),
            state_dir=tmp_path / "witness-state", refresh_seconds=refresh, timeout_seconds=timeout,
            min_backoff_seconds=backoff[0], max_backoff_seconds=backoff[1], grace_seconds=grace,
        )
        monkeypatch.setattr(WitnessSettings, "from_env",
                            classmethod(lambda cls, environ=None, *, default_state_dir: configured))
        client = TestClient(create_app(
            db_path=tmp_path / "app.db", owner_public_key=owner.public_key_b64u, pubkeys_out=tmp_path / "keys.txt",
            announce=False, limits=TEST_LIMITS,
        ))
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.app.state.db.stop_witness_feeder()


def claim(client: TestClient, name: str) -> int:
    """Claim ``name`` with a new key (POST /v2/entries); its leaf index."""
    origin = client.get("/v2/tlog/checkpoint").json()["origin"]
    response = Agent(client, origin).claim(name)
    assert response.status_code == 202, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


def deliver(db, witness, size: int) -> tuple[bool, str | None]:
    """Hand the database a fresh cosignature line of ``witness`` for checkpoint ``size`` (as the feeder would)."""
    cp = parse_checkpoint(parse_note(db._log.checkpoint_note(size)).text)
    _, line = sign_cosignature(witness.key, witness.vkey.name, int(time.time()), cp.origin, size, cp.root)
    endpoint = next(w for w in db.witness_settings.witnesses if w.vkey == witness.vkey)
    return db._deliver_cosignature(endpoint, size, format_signature_line(line))


def served_notes(client: TestClient) -> dict[str, bytes]:
    """Every place the served note is read from: they must all be the same bytes."""
    db = client.app.state.db
    return {
        "/checkpoint": client.get("/checkpoint").content,
        "/tiles/checkpoint": client.get("/tiles/checkpoint").content,
        "<tiles>/checkpoint": (db.tiles_dir / "checkpoint").read_bytes(),
        "/v2/tlog/checkpoint": client.get("/v2/tlog/checkpoint").json()["signed_checkpoint"].encode(),
    }


def one_served_note(client: TestClient) -> bytes:
    notes = served_notes(client)
    assert len(set(notes.values())) == 1, {k: size_of(v) for k, v in notes.items()}
    return notes["/checkpoint"]


# ----------------------------------------------------------------------
# the rule, one delivered line at a time (the feeder stopped)
# ----------------------------------------------------------------------

class TestServedNote:
    """The cosignature lines are delivered by hand: every step is deterministic."""

    @staticmethod
    def setup(make_app):
        witness = FakeWitness("refuse")  # never cosigns by itself
        client = make_app(witness)
        db = client.app.state.db
        db.stop_witness_feeder()
        return witness, client, db

    def test_a_new_publication_is_served_once_cosigned_and_the_cosigned_note_stands_meanwhile(self, make_app):
        witness, client, db = self.setup(make_app)
        try:
            first = db._log.published.size
            assert deliver(db, witness, first) == (True, None)
            held = one_served_note(client)
            assert cosigned_by(held, witness) and size_of(held) == first

            index = claim(client, "carol")
            assert db._log.published.size == index + 1 > first
            # The new publication is not cosigned: every surface still serves the cosigned note, the mirror's too.
            assert one_served_note(client) == held
            health = client.get("/healthz").json()
            assert (health["published_size"], health["served_size"]) == (index + 1, first)
            assert health["serving_uncosigned"] is False and health["uncosigned_reason"] is None
            # Older entries are proved against exactly that note; the new one is not under it yet.
            bundle = client.get("/v2/entries/0").json()
            assert bundle_note(bundle) == held
            assert verify_bundle(bundle, log_vkey(), [witness.vkey], 1, expected_origin=DEFAULT_ORIGIN).ok
            pending = client.get(f"/v2/entries/{index}")
            assert pending.status_code == 503 and int(pending.headers["retry-after"]) >= 1
            detail = pending.json()["detail"]
            assert detail["error"] == "not_yet_cosigned" and detail["index"] == index
            assert (detail["checkpoint_size"], detail["tree_size"]) == (first, index + 1)
            assert client.get(f"/v2/tlog/proof/{index}").status_code == 503

            # Its cosignature arrives: from then on it is the served note, and the entry is proved against it.
            assert deliver(db, witness, index + 1) == (True, None)
            note = one_served_note(client)
            assert cosigned_by(note, witness) and size_of(note) == index + 1
            bundle = client.get(f"/v2/entries/{index}").json()
            assert bundle_note(bundle) == note
            assert verify_bundle(bundle, log_vkey(), [witness.vkey], 1, expected_origin=DEFAULT_ORIGIN).ok
            proof = client.get(f"/v2/tlog/proof/{index}").json()
            assert proof["tree_size"] == index + 1 and proof["signed_checkpoint"].encode() == note
            assert client.get("/healthz").json()["served_size"] == index + 1
        finally:
            witness.stop()

    def test_a_cosignature_of_an_intermediate_publication_moves_the_served_note_forward(self, make_app):
        """A log that publishes faster than its witness answers still advances: the feeder's line for a checkpoint
        that a later publication overtook while it was being cosigned is served (it is newer than the served one)."""
        witness, client, db = self.setup(make_app)
        try:
            assert deliver(db, witness, db._log.published.size) == (True, None)
            sizes = [claim(client, name) + 1 for name in ("dora", "emil", "fern")]
            assert db._log.published.size == sizes[-1]
            assert deliver(db, witness, sizes[1]) == (True, None)
            note = one_served_note(client)
            assert size_of(note) == sizes[1] and cosigned_by(note, witness)
            # Never back: a line for a checkpoint older than the served one is superseded.
            assert deliver(db, witness, sizes[0]) == (False, "superseded")
            assert one_served_note(client) == note
            assert client.get(f"/v2/entries/{sizes[1] - 1}").status_code == 200
            assert client.get(f"/v2/entries/{sizes[2] - 1}").status_code == 503
            assert deliver(db, witness, sizes[2]) == (True, None)
            assert size_of(one_served_note(client)) == sizes[2]
        finally:
            witness.stop()

    def test_before_any_cosignature_the_log_signed_note_is_served(self, make_app):
        """Nothing cosigned to hold on to (the first notes of a log whose witness never answered): the publications
        are served as they come, and /healthz says they carry no cosignature."""
        witness = FakeWitness("refuse")
        try:
            client = make_app(witness)
            db = client.app.state.db
            index = claim(client, "gail")
            note = one_served_note(client)
            assert size_of(note) == index + 1 and not cosigned_by(note, witness, fresh=False)
            health = client.get("/healthz").json()
            assert health["serving_uncosigned"] is True and "no witness has cosigned" in health["uncosigned_reason"]
            assert health["served_size"] == health["published_size"] == index + 1
            bundle = client.get(f"/v2/entries/{index}").json()
            assert bundle_note(bundle) == note
            assert verify_bundle(bundle, log_vkey(), expected_origin=DEFAULT_ORIGIN).ok  # quorum 0 only
            (w,) = health["witnesses"]
            assert w["state"] == "failing" and isinstance(w["failing_since"], int)
            # The first cosignature ends it.
            assert deliver(db, witness, index + 1) == (True, None)
            health = client.get("/healthz").json()
            assert health["serving_uncosigned"] is False and health["uncosigned_reason"] is None
            assert cosigned_by(one_served_note(client), witness)
        finally:
            witness.stop()


# ----------------------------------------------------------------------
# the store itself: held publications, and a model check of the rule
# ----------------------------------------------------------------------

MODEL_ORIGIN = "model.example.test/log"


class StoreModel:
    """A :class:`TlogStore` with witnesses, driven by random steps: commits of one to three entries (one publication
    each), cosignature lines for the sizes this store published (stale, held, current) and for sizes it never
    published (inside one commit, or from before a restart), witness outages, ``refresh_served`` calls and restarts
    on the same tiles directory.  :meth:`check` states the rule after every step."""

    def __init__(self, tiles: Path, seed: int, witnesses: int) -> None:
        self.rng = random.Random(seed)
        self.tiles = tiles
        self.log_key = Ed25519PrivateKey.generate()
        self.keys = [Ed25519PrivateKey.generate() for _ in range(witnesses)]
        self.vkeys = [cosignature_vkey(f"w{i}.model.test/w", k.public_key()) for i, k in enumerate(self.keys)]
        self.entries: list[bytes] = []
        self.published: list[int] = []  # the sizes the running store published, oldest first
        self.outage: float | None = None
        self.grace = 10.0
        self.steps: list[str] = []
        self.store = self.start()

    def start(self) -> TlogStore:
        store = TlogStore(origin=MODEL_ORIGIN, log_key=self.log_key, tiles_dir=self.tiles, fsync=False, audit="edge",
                          witness_keys=self.vkeys)
        store.grace_seconds = self.grace
        store.witness_outage = lambda: self.outage
        store.boot(len(self.entries), lambda start, end: self.entries[start:end])
        self.published = [store.published.size] if store.published is not None else []
        return store

    def line(self, witness: int, size: int) -> str:
        cp = parse_checkpoint(parse_note(self.store.checkpoint_note(size)).text)
        _, line = sign_cosignature(self.keys[witness], self.vkeys[witness].name, int(time.time()), cp.origin, size,
                                   cp.root)
        return format_signature_line(line)

    def cosigned(self, note: bytes) -> bool:
        result = verify_checkpoint(parse_note(note), self.store.vkey, self.vkeys, 1, expected_origin=MODEL_ORIGIN)
        return result.ok and result.cosignature_count >= 1

    def step(self) -> None:
        store = self.store
        before = store.served
        before_size = before.size if before is not None else 0
        before_cosigned = store.served_cosigned
        outage = self.outage
        r = self.rng.random()
        if r < 0.35:
            batch = [f"entry-{len(self.entries) + i}".encode() for i in range(self.rng.randint(1, 3))]
            self.entries.extend(batch)
            store.append_committed(batch)
            self.published.append(len(self.entries))
            what = f"commit {len(batch)} -> {len(self.entries)}"
        elif r < 0.65 and store.published is not None:
            witness = self.rng.randrange(len(self.keys))
            if self.rng.random() < 0.25:  # never published by this store
                sizes = [z for z in range(max(1, before_size - 3), store.published.size) if z not in self.published]
            else:
                sizes = [z for z in self.published if z >= max(1, before_size - 3)]
            if not sizes:
                return
            size = self.rng.choice(sizes)
            disk = (self.tiles / "checkpoint").read_bytes()
            result = store.add_cosignature(self.vkeys[witness], size, self.line(witness, size))
            what = f"cosign w{witness} size {size} -> {result}"
            if size == store.published.size or size == before_size or (size > before_size and size in self.published):
                assert result == (True, None) and store.served.size == size and store.served_cosigned, what
            else:
                assert result == (False, "superseded"), what
                assert (self.tiles / "checkpoint").read_bytes() == disk, what
        elif r < 0.8:
            self.outage = outage = self.rng.choice([None, None, 1.0, 5.0, 11.0, 50.0])
            store.refresh_served()
            what = f"outage {self.outage}"
        elif r < 0.9:
            store.refresh_served()
            what = "refresh"
        else:
            self.store = self.start()
            what = f"restart at {len(self.entries)}"
            if before is not None:
                assert self.store.served.size >= before_size, what
                assert self.store.served_cosigned or not before_cosigned, (what, "a restart lost the cosignature")
        self.steps.append(what)
        self.check(what, before_size, before_cosigned, outage)

    def check(self, what: str, before_size: int, before_cosigned: bool, outage: float | None) -> None:
        store = self.store
        served = store.served
        if served is None:
            return
        assert (self.tiles / "checkpoint").read_bytes() == served.note == store.read_resource("checkpoint"), what
        assert before_size <= served.size <= store.published.size, (what, "the served size went back")
        assert served.root == store.tree.root(served.size), what
        cosigned = self.cosigned(served.note)
        assert cosigned == store.served_cosigned and bool(store.uncosigned_reason) == (not cosigned), what
        if before_cosigned and not cosigned:
            assert outage is not None and outage > self.grace, (what, "uncosigned served inside the grace")
        if outage is None and before_size and served.size != before_size:
            assert cosigned, (what, "a newer uncosigned note served while a witness may still cosign")


class TestStore:
    def test_a_line_for_a_size_never_published_is_superseded_and_the_next_start_resumes(self, tmp_path):
        """A size inside one commit has no right-edge tiles of its own: served (written to ``<tiles>/checkpoint``),
        it would stop the next start (``cannot resume at size 2: tile/0/000.p/2 is missing``).  Only the held
        publications' sizes move the served note."""
        model = StoreModel(tmp_path / "tiles", seed=0, witnesses=1)
        store, w = model.store, model.vkeys[0]
        model.entries.append(b"first")
        store.append_committed([b"first"])
        assert store.add_cosignature(w, 1, model.line(0, 1)) == (True, None)
        batch = [b"second", b"third", b"fourth"]
        model.entries.extend(batch)
        store.append_committed(batch)  # one publication, of size 4
        model.entries.append(b"fifth")
        store.append_committed([b"fifth"])  # held as well, size 5
        assert (store.served.size, store.published.size) == (1, 5)
        held = (tmp_path / "tiles" / "checkpoint").read_bytes()
        assert not (tmp_path / "tiles" / "tile" / "0" / "000.p" / "2").exists()
        for size in (2, 3):
            assert store.add_cosignature(w, size, model.line(0, size)) == (False, "superseded")
            assert (tmp_path / "tiles" / "checkpoint").read_bytes() == held
        assert store.add_cosignature(w, 4, model.line(0, 4)) == (True, None)  # a held publication: served
        assert store.served.size == 4 and store.served_cosigned
        restarted = model.start()  # resumes the tiles at the served size 4, publishes 5 and holds it
        assert (restarted.served.size, restarted.published.size) == (4, 5) and restarted.served_cosigned

    @pytest.mark.parametrize("witnesses", [1, 2])
    @pytest.mark.parametrize("seed", range(16))
    def test_the_rule_holds_under_random_steps(self, tmp_path, seed, witnesses):
        model = StoreModel(tmp_path / "tiles", seed, witnesses)
        try:
            for _ in range(300):
                model.step()
        except AssertionError:
            print("\n".join(model.steps[-15:]))
            raise


# ----------------------------------------------------------------------
# a slow and late witness, N entries, readers everywhere
# ----------------------------------------------------------------------

class TestSlowWitness:
    def test_every_served_note_carries_the_cosignature_while_n_entries_are_published(self, make_app, tmp_path):
        """N writes, spread over a few seconds, while the witness takes 50-250 ms per answer and its third and
        every fourth answer after that come after the feeder's timeout (late: the feeder gives up, backs off and
        resubmits the latest).  Readers poll every surface throughout; every note they get is cosigned (no grace is
        reached: 120 s) and was the served one, the served size never decreases, and every bundle verifies at
        quorum 1."""
        rng = random.Random(20261020)
        witness = ScriptedWitness(tmp_path, delay=lambda n: 0.9 if n >= 3 and n % 4 == 3 else rng.uniform(0.05, 0.25))
        try:
            client = make_app(witness, timeout=0.6)
            db = client.app.state.db
            assert cosigned_by(one_served_note(client), witness)  # cosigned before the first request (start-up)
            # Every note the server ever made the served one, recorded as it happens (under the writer lock).
            history = [db._log.served.note]
            woken = db._log.on_served

            def record() -> None:
                history.append(db._log.served.note)
                woken()

            db._log.on_served = record
            seen: list[tuple[str, bytes]] = []
            problems: list[str] = []
            done = threading.Event()

            def read(seed: int) -> None:
                pick = random.Random(seed)
                reader = TestClient(client.app)
                line = Line(reader)
                line.send()
                sizes: list[int] = []
                while not done.is_set():
                    try:
                        note = reader.get("/checkpoint").content
                        seen.append(("/checkpoint", note))
                        sizes.append(size_of(note))
                        seen.append(("/tiles/checkpoint", reader.get("/tiles/checkpoint").content))
                        seen.append(("<tiles>/checkpoint", (db.tiles_dir / "checkpoint").read_bytes()))
                        index = pick.randrange(size_of(note))
                        response = reader.get(f"/v2/entries/{index}")
                        if response.status_code != 200:  # under the served size: never pending
                            problems.append(f"entry {index} under the served size: {response.status_code}")
                            continue
                        seen.append((f"/v2/entries/{index}", bundle_note(response.json())))
                        if not verify_bundle(response.json(), log_vkey(), [witness.vkey], 1,
                                             expected_origin=DEFAULT_ORIGIN).ok:
                            problems.append(f"bundle {index} does not verify at quorum 1")
                        text = line.send(f"read {index}")
                        seen.append((f"read {index}", artifacts(text)["checkpoint"]))
                    except Exception as exc:  # report it; a dying thread would pass unnoticed
                        problems.append(f"{type(exc).__name__}: {exc}")
                if sizes != sorted(sizes):
                    problems.append(f"the served size went back: {sizes}")

            readers = [threading.Thread(target=read, args=(seed,), daemon=True) for seed in (1, 2)]
            for thread in readers:
                thread.start()
            try:
                n = 24
                indices = []
                for i in range(n):
                    indices.append(claim(client, f"slow{i}"))
                    time.sleep(rng.uniform(0.0, 0.15))
                # A new entry's bundle waits for its cosigned checkpoint, or is answered 503, never given uncosigned.
                for index in indices[-3:]:
                    response = client.get(f"/v2/entries/{index}")
                    assert response.status_code in (200, 503), response.text
                    if response.status_code == 200:
                        assert cosigned_by(bundle_note(response.json()), witness)
                final = wait_for(lambda: (lambda n_: size_of(n_) == indices[-1] + 1 and n_)(client.get("/checkpoint").content),
                                 timeout=30)
            finally:  # a failed assertion above must not leave the readers polling: the run would never exit
                done.set()
                for thread in readers:
                    thread.join(timeout=30)
            assert not problems, problems[:5]
            assert len(seen) > 20, len(seen)
            # Every note anyone got was cosigned (the grace, 120 s, is never reached) and was the served one.
            uncosigned = [(where, size_of(note)) for where, note in seen if not cosigned_by(note, witness)]
            assert not uncosigned, uncosigned[:5]
            ever = set(history)
            assert all(note in ever for where, note in seen), [w for w, note in seen if note not in ever][:5]
            assert all(cosigned_by(note, witness) for note in history)
            assert [size_of(note) for note in history] == sorted(size_of(note) for note in history)
            assert cosigned_by(final, witness) and one_served_note(client) == final
            health = client.get("/healthz").json()
            assert health["serving_uncosigned"] is False and health["served_size"] == health["published_size"]
            # The scenario happened: several submissions, at least one answer too late, served notes in between.
            assert sum(1 for pause in witness.pauses if pause > 0.6) >= 1 and len(witness.pauses) >= 5
            assert len(history) >= 4
        finally:
            witness.stop()

    def test_aics_tlog_verify_checkpoint_at_quorum_1_accepts_every_fetch_around_writes(self, make_app, tmp_path, capsys):
        """The walk-through's measurement, repeated: 75 fetches of /checkpoint while entries are written to a log
        whose witness takes 50-200 ms; ``aics-tlog verify-checkpoint --quorum 1 --max-age 300`` (the CLI a verifier
        of the quorum-1 card runs) accepts every one."""
        from aics_tlog import format_vkey
        from aics_tlog.cli import main as aics_tlog

        rng = random.Random(75)
        witness = ScriptedWitness(tmp_path, delay=lambda n: rng.uniform(0.05, 0.2))
        try:
            client = make_app(witness, timeout=2.0)
            note_file = tmp_path / "fetched.note"
            sizes = set()
            for i in range(75):
                if i % 5 == 0:
                    claim(client, f"fetch{i}")
                note = client.get("/checkpoint").content
                sizes.add(size_of(note))
                note_file.write_bytes(note)
                code = aics_tlog(["verify-checkpoint", "--note", str(note_file), "--log-key", format_vkey(log_vkey()),
                                  "--witness-key", witness.vkey_text, "--quorum", "1", "--max-age", "300",
                                  "--origin", DEFAULT_ORIGIN])
                assert code == 0, (i, capsys.readouterr().out[-400:])
                capsys.readouterr()
            assert len(sizes) >= 3  # the fetches saw the log grow
        finally:
            witness.stop()

    def test_a_just_appended_entry_waits_for_its_cosigned_checkpoint(self, make_app, tmp_path):
        """The bundle of an entry written a moment ago is given once the witness has cosigned a checkpoint that
        covers it (the request waits, at most the per-witness timeout): never against the uncosigned note."""
        witness = ScriptedWitness(tmp_path, delay=lambda n: 0.4)
        try:
            client = make_app(witness, timeout=3.0)
            index = claim(client, "hana")
            started = time.monotonic()
            response = client.get(f"/v2/entries/{index}")
            waited = time.monotonic() - started
            assert response.status_code == 200, response.text
            note = bundle_note(response.json())
            assert size_of(note) > index and cosigned_by(note, witness)
            assert verify_bundle(response.json(), log_vkey(), [witness.vkey], 1, expected_origin=DEFAULT_ORIGIN).ok
            assert waited < 3.0
        finally:
            witness.stop()

    def test_a_request_waits_at_most_the_cap_whatever_the_submission_timeout(self, make_app, monkeypatch):
        """AICS_WITNESS_TIMEOUT_SECONDS bounds one submission to a witness (it may be set up to 120 s); a request
        thread, and the start-up, wait at most MAX_COSIGNATURE_WAIT_SECONDS (5 s; 0.5 s here) for a cosignature."""
        import aics_server.db as db_mod

        monkeypatch.setattr(db_mod, "MAX_COSIGNATURE_WAIT_SECONDS", 0.5)
        witness = FakeWitness("hang", delay=20.0)  # holds every submission for 20 s
        try:
            started = time.monotonic()
            client = make_app(witness, timeout=30.0)
            assert time.monotonic() - started < 5.0  # the start-up waited 0.5 + 1 s for the first answer, not 31 s
            db = client.app.state.db
            assert db.cosignature_wait_seconds == 0.5 and db.witness_settings.timeout_seconds == 30.0
            index = claim(client, "pia")
            started = time.monotonic()
            response = client.get(f"/v2/entries/{index}")
            assert response.status_code == 503 and response.json()["detail"]["error"] == "not_yet_cosigned"
            assert time.monotonic() - started < 3.0
        finally:
            witness.stop()


# ----------------------------------------------------------------------
# a failed submission is retried: requests wait for a retry due within their wait
# ----------------------------------------------------------------------

class TestFailedSubmission:
    def test_a_refused_submission_does_not_stop_the_waits_for_its_retry(self, make_app, tmp_path):
        """One refused submission, then the witness answers again at once.  The feeder tries again after its
        backoff (under a second after a first failure in production; 0.25-0.5 s here), so a read-after-write made
        meanwhile waits for that retry and gets the cosigned bundle.  The review of 2026-10-22 saw four
        read-after-writes in a row answered 503 at once over 1.3 s this way, and gate writes without a checkpoint
        line: the wait stopped as soon as every witness had failed its last attempt."""
        witness = ScriptedWitness(tmp_path)
        try:
            client = make_app(witness, timeout=3.0, backoff=(0.5, 1.0))
            db = client.app.state.db
            witness.down = True
            index = claim(client, "tove")
            wait_for(lambda: db.witness_feeder.outage() is not None)  # the submission of its checkpoint was refused
            assert witness.refused >= 1 and db._log.served_size <= index
            threading.Timer(0.05, lambda: setattr(witness, "down", False)).start()
            started = time.monotonic()
            response = client.get(f"/v2/entries/{index}")
            assert response.status_code == 200, response.text
            assert cosigned_by(bundle_note(response.json()), witness)
            assert time.monotonic() - started < 3.0
            # A gate write's evidence waits the same way (served_checkpoint_for): its checkpoint line comes, cosigned.
            witness.down = True
            second = claim(client, "ulla")
            wait_for(lambda: db.witness_feeder.outage() is not None)
            threading.Timer(0.05, lambda: setattr(witness, "down", False)).start()
            note, cosigned = db.served_checkpoint_for(second, wait=3.0)
            assert cosigned and size_of(note) > second and cosigned_by(note, witness)
        finally:
            witness.stop()

    def test_a_retry_due_after_the_wait_is_not_waited_for(self, make_app, tmp_path):
        """Every witness fails and the next retry is due after the wait: no cosignature can come in time, so the new
        entry's bundle, the view of a name claimed meanwhile and the gate's find are answered at once (503
        ``not_yet_cosigned``, ``err busy``), with a Retry-After that is the time to that retry."""
        witness = ScriptedWitness(tmp_path)
        try:
            client = make_app(witness, grace=600.0, timeout=3.0, backoff=(20.0, 20.0))
            db = client.app.state.db
            held = one_served_note(client)
            witness.down = True
            index = claim(client, "quin")
            wait_for(lambda: db.health()["witnesses"][0]["state"] == "failing")
            started = time.monotonic()
            view = client.get("/v2/names/quin")
            response = client.get(f"/v2/entries/{index}")
            line = Line(client)
            line.send()
            found = line.send("find quin")
            assert time.monotonic() - started < 1.5  # none waited the 3 s
            for answer in (view, response):
                assert answer.status_code == 503 and answer.json()["detail"]["error"] == "not_yet_cosigned"
                assert answer.json()["detail"]["index"] == index
                assert 9 <= int(answer.headers["retry-after"]) <= 20  # the retry, 10-20 s after the refusal
            assert found.startswith(f"err busy the claim of 'quin' (entry {index}) is committed but not yet under"), found
            assert one_served_note(client) == held
        finally:
            witness.stop()


# ----------------------------------------------------------------------
# a witness that stops answering: the grace
# ----------------------------------------------------------------------

class TestGrace:
    def test_the_cosigned_note_stands_for_the_grace_then_the_uncosigned_one_is_served_and_reported(
        self, make_app, tmp_path
    ):
        witness = ScriptedWitness(tmp_path)
        try:
            client = make_app(witness, grace=3.0, timeout=0.5)
            db = client.app.state.db
            held = one_served_note(client)
            assert cosigned_by(held, witness)
            witness.down = True
            index = claim(client, "ivan")
            outage = time.monotonic()
            wait_for(lambda: db.health()["witnesses"][0]["state"] == "failing")
            # Within the grace: the cosigned note stands, the new entry is not under it yet.
            assert one_served_note(client) == held
            health = client.get("/healthz").json()
            assert health["serving_uncosigned"] is False and health["served_size"] < health["published_size"]
            response = client.get(f"/v2/entries/{index}")
            assert response.status_code == 503 and response.json()["detail"]["error"] == "not_yet_cosigned"
            assert 1 <= int(response.headers["retry-after"]) <= 60
            line = Line(client)
            line.send()
            text = line.send(f"read {index}")
            assert text.startswith(f"err busy entry {index} is committed but not yet under a cosigned checkpoint")

            # Past the grace: the newest publication is served without a cosignature, and /healthz says why.
            note = wait_for(lambda: (lambda n: size_of(n) == index + 1 and n)(client.get("/checkpoint").content),
                            timeout=10)
            assert time.monotonic() - outage > 3.0
            assert not cosigned_by(note, witness, fresh=False) and one_served_note(client) == note
            health = client.get("/healthz").json()
            assert health["serving_uncosigned"] is True and "AICS_WITNESS_GRACE_SECONDS" in health["uncosigned_reason"]
            assert health["served_size"] == health["published_size"] == index + 1
            assert health["served_cosignature_age_seconds"] is None
            (w,) = health["witnesses"]
            assert w["state"] == "failing" and w["failing_since"] is not None and not w["cosigned_current"]
            bundle = client.get(f"/v2/entries/{index}").json()
            assert bundle_note(bundle) == note  # against the note served, which says what it is
            # While serving uncosigned, new publications are served as they come.
            later = claim(client, "jana")
            assert size_of(one_served_note(client)) == later + 1

            # The witness is back: the next cosignature is served again.
            witness.down = False
            note = wait_for(lambda: (lambda n: cosigned_by(n, witness) and n)(client.get("/checkpoint").content),
                            timeout=10)
            assert size_of(note) == later + 1 and one_served_note(client) == note
            health = client.get("/healthz").json()
            assert health["serving_uncosigned"] is False and health["uncosigned_reason"] is None
            assert health["witnesses"][0]["failing_since"] is None and health["witnesses"][0]["state"] == "ok"
        finally:
            witness.stop()

    def test_a_restart_keeps_the_cosigned_note_on_disk_served_until_a_newer_one_is_cosigned(self, make_app, tmp_path):
        witness = ScriptedWitness(tmp_path)
        try:
            client = make_app(witness, grace=600.0, timeout=0.5)
            db = client.app.state.db
            held = one_served_note(client)
            assert cosigned_by(held, witness)
            db.stop_witness_feeder()  # entries published now wait for a cosignature nobody asks for
            index = claim(client, "kurt")
            assert (db.tiles_dir / "checkpoint").read_bytes() == held

            witness.down = True
            restarted = make_app(witness, grace=600.0, timeout=0.5)
            again = restarted.app.state.db
            assert again._log.published.size == index + 1 and one_served_note(restarted) == held
            assert again.health()["serving_uncosigned"] is False
            assert restarted.get(f"/v2/entries/{index}").status_code == 503
            again.stop_witness_feeder()

            witness.down = False
            third = make_app(witness, grace=600.0, timeout=0.5)  # the start-up submission is cosigned at once
            note = one_served_note(third)
            assert size_of(note) == index + 1 and cosigned_by(note, witness)
        finally:
            witness.stop()


# ----------------------------------------------------------------------
# the gate
# ----------------------------------------------------------------------

class TestGate:
    def test_the_gate_serves_the_cosigned_checkpoint_in_reads_and_in_write_evidence(self, make_app, tmp_path):
        witness = ScriptedWitness(tmp_path, delay=lambda n: 0.1)
        try:
            client = make_app(witness, timeout=2.0)
            line = Line(client)
            agent = KeyAgent("lena")
            reply = onboard(line, agent)
            check_reply(reply)
            evidence = artifacts(reply)["checkpoint"]
            # The checkpoint a write answers with is the cosigned one that includes the new leaf.
            assert cosigned_by(evidence, witness) and size_of(evidence) > agent.claim_index
            assert "carries no witness cosignature" not in reply
            text = line.send(f"read {agent.claim_index}")
            check_reply(text)
            assert artifacts(text)["checkpoint"] == client.get("/checkpoint").content
            assert cosigned_by(artifacts(text)["checkpoint"], witness)
            found = line.send("find lena")
            assert cosigned_by(artifacts(found)["checkpoint"], witness)
        finally:
            witness.stop()

    def test_a_write_whose_cosignature_does_not_come_gets_no_checkpoint_line_but_when_to_read(self, make_app, tmp_path):
        """No cosigned checkpoint includes the leaf within the wait: the reply carries the entry and its receipt (what
        AICS-1 section 11.2 requires of a write), no checkpoint line (a note no witness cosigned, which /checkpoint
        does not serve, is never handed out: a quorum-1 verifier rejects it, and a client that kept it as its newest
        head could not relate the older served notes to it), and an ok line saying when read gives the checkpoint."""
        witness = ScriptedWitness(tmp_path)
        try:
            client = make_app(witness, grace=600.0, timeout=0.3)
            held = one_served_note(client)
            assert cosigned_by(held, witness)
            witness.down = True
            line = Line(client)
            agent = KeyAgent("mira")
            reply = onboard(line, agent)
            check_reply(reply)
            found = artifacts(reply)
            assert {"entry", "receipt"} <= set(found) and "checkpoint" not in found, sorted(found)
            pending = ok_line(reply, f"ok leaf {agent.claim_index} is not under a cosigned checkpoint yet")
            assert re.search(rf": read {agent.claim_index} in \d+ s for its checkpoint", pending), pending
            assert one_served_note(client) == held  # nothing newer was served meanwhile
            # The witness is back: read gives the cosigned checkpoint that includes the leaf.
            witness.down = False
            text = wait_for(lambda: (lambda t: t.startswith(f"ok read {agent.claim_index} ") and t)(
                line.send(f"read {agent.claim_index}")), timeout=10)
            assert cosigned_by(artifacts(text)["checkpoint"], witness)
            assert size_of(artifacts(text)["checkpoint"]) > agent.claim_index
        finally:
            witness.stop()

    def test_tcp_turns_run_on_the_gates_own_threads(self, client):
        """A turn that waits for a cosigned checkpoint holds its thread for up to 5 s.  TCP turns run on the gate's own
        pool (TCP_TURN_WORKERS), so a busy default executor (a few threads on a small host, shared with housekeeping)
        stalls no session: here its only thread is taken and a TCP session still gets every reply."""
        gate = client.app.state.gate

        async def turn(reader: asyncio.StreamReader) -> str:
            parts = []
            while True:
                raw = await reader.readline()
                parts.append(raw.decode())
                if raw in (b">\n", b""):
                    return "".join(parts)

        async def main() -> None:
            loop = asyncio.get_running_loop()
            loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
            release = threading.Event()
            busy = loop.run_in_executor(None, release.wait, 30)
            tcp = TcpGate(gate, host="127.0.0.1", plain_port=0, tls_port=None)
            await tcp.start()
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", tcp.ports["plain"])
                await asyncio.wait_for(turn(reader), 5)  # the banner
                for command in ("help", "read 0"):
                    writer.write(f"{command}\n".encode())
                    await writer.drain()
                    reply = await asyncio.wait_for(turn(reader), 5)
                    assert reply.startswith("ok "), reply[:200]
                writer.close()
            finally:
                release.set()
                await busy
                await tcp.close()

        asyncio.run(main())


# ----------------------------------------------------------------------
# read views stated at the served checkpoint, two witnesses
# ----------------------------------------------------------------------

class TestReadViews:
    def test_a_name_view_asked_right_after_the_claim_lists_the_claim(self, make_app, tmp_path):
        """The one-file client checks a name's key chain right after claiming it (store_sealed, a capsule, an
        upgrade): GET /v2/names/{name} is stated at the served (cosigned) checkpoint, so it waits for that to cover the
        name's newest key event instead of listing none under it ("lists no ordered key events under its
        checkpoint", which that client reports as evidence against the service)."""
        witness = ScriptedWitness(tmp_path, delay=lambda n: 1.0)  # longer than a claim takes, on a loaded machine too
        try:
            client = make_app(witness, timeout=3.0)
            index = claim(client, "pavo")
            assert client.app.state.db._log.served_size <= index  # the claim is not under the served note yet
            started = time.monotonic()
            view = client.get("/v2/names/pavo").json()
            assert time.monotonic() - started < 3.0
            note = keys.b64u_decode(view["checkpoint_note"])
            assert view["indices"] == [index] and view["size"] == size_of(note) > index
            assert cosigned_by(note, witness)
            # Its bundle is then given at once, against the same note; the gate's find shows the claim as well.
            assert bundle_note(client.get(f"/v2/entries/{index}").json()) == note
            line = Line(client)
            line.send()
            found = line.send("find pavo")
            assert f"claim {index} head {index}" in found and artifacts(found)["checkpoint"] == note
        finally:
            witness.stop()

    def test_a_key_event_not_under_the_served_note_yet_leaves_the_view_stated_there(self, make_app, tmp_path):
        """The name's claim is under the served note, a later key event is not (every witness fails, no retry in
        time): the view is stated at the served note all the same, its indices stop before that event and
        head_index names it.  Only a name whose claim itself is not under it is answered 503 (TestFailedSubmission:
        a view would list no key event of a name that exists)."""
        witness = ScriptedWitness(tmp_path)
        try:
            client = make_app(witness, grace=600.0, timeout=3.0, backoff=(20.0, 20.0))
            db = client.app.state.db
            agent = Agent(client, client.get("/v2/tlog/checkpoint").json()["origin"])
            assert agent.claim("vera").status_code == 202
            claimed = agent.head_index
            assert client.get(f"/v2/entries/{claimed}").status_code == 200  # waits for the cosigned note covering it
            held = one_served_note(client)
            witness.down = True
            assert agent.rotate_x25519().status_code == 202
            rotated = agent.head_index
            wait_for(lambda: db.health()["witnesses"][0]["state"] == "failing")
            started = time.monotonic()
            view = client.get("/v2/names/vera")
            assert time.monotonic() - started < 1.5 and view.status_code == 200, view.text
            body = view.json()
            assert body["indices"] == [claimed] and body["size"] == size_of(held) <= rotated
            assert body["head_index"] == rotated and body["x25519_leaf_index"] == rotated  # the committed state
            assert keys.b64u_decode(body["checkpoint_note"]) == held and cosigned_by(held, witness)
        finally:
            witness.stop()

    def test_the_json_checkpoint_states_the_size_of_its_note(self, make_app):
        """/v2/tlog/checkpoint: tree_size and root_hash_hex are the committed tree's, checkpoint_size is the size of
        signed_checkpoint (the served note), which trails tree_size while a publication waits for its cosignature."""
        witness, client, db = TestServedNote.setup(make_app)
        try:
            first = db._log.published.size
            assert deliver(db, witness, first) == (True, None)
            index = claim(client, "rhea")
            cp = client.get("/v2/tlog/checkpoint").json()
            assert (cp["tree_size"], cp["checkpoint_size"]) == (index + 1, first)
            assert size_of(cp["signed_checkpoint"].encode()) == first and cp["root_hash_hex"] == db._log.tree.root().hex()
            assert deliver(db, witness, index + 1) == (True, None)
            cp = client.get("/v2/tlog/checkpoint").json()
            assert cp["tree_size"] == cp["checkpoint_size"] == size_of(cp["signed_checkpoint"].encode()) == index + 1
        finally:
            witness.stop()


class TestTwoWitnesses:
    def test_one_witness_down_the_other_cosigns_every_served_note(self, make_app, tmp_path):
        """With two witnesses and one of them down there is no outage (the other answers): every served note and
        every bundle carries the cosignature of the one that answers, past the grace too."""
        up = ScriptedWitness(tmp_path, delay=lambda n: 0.05, name="witness.example.test/up")
        down = ScriptedWitness(tmp_path, name="witness.example.test/down")
        down.down = True
        try:
            client = make_app(up, down, grace=0.5, timeout=0.5)
            db = client.app.state.db
            for i in range(5):
                index = claim(client, f"duo{i}")
                response = client.get(f"/v2/entries/{index}")
                assert response.status_code == 200, response.text
                assert cosigned_by(bundle_note(response.json()), up)
                assert cosigned_by(one_served_note(client), up)
            time.sleep(0.8)  # longer than the grace: still no outage, one witness answers
            health = client.get("/healthz").json()
            assert health["serving_uncosigned"] is False and health["served_size"] == health["published_size"]
            assert {w["cosigner"]: w["state"] for w in health["witnesses"]} == {
                "witness.example.test/up": "ok", "witness.example.test/down": "failing"}
            assert db.witness_feeder.outage() is None and down.refused >= 1
        finally:
            up.stop()
            down.stop()


# ----------------------------------------------------------------------
# /healthz, the feeder, quorum 0
# ----------------------------------------------------------------------

class TestStatus:
    def test_healthz_names_the_label_and_the_cosigner(self, make_app, tmp_path):
        witness = ScriptedWitness(tmp_path)
        try:
            client = make_app(witness)
            health = client.get("/healthz").json()
            (w,) = health["witnesses"]
            assert w["name"] == "w1" and w["cosigner"] == witness.vkey.name == "witness.example.test/w1"
            assert w["vkey"].startswith(w["cosigner"] + "+") and w["failing_since"] is None
            # The served note's cosignature age at the top level, for a monitor: a quorum-1 verifier rejects the
            # note past the card's max_checkpoint_age (300 s) even while serving_uncosigned is false.
            assert health["serving_uncosigned"] is False
            assert 0 <= health["served_cosignature_age_seconds"] <= w["cosignature_age_seconds"] + 1 < 60
        finally:
            witness.stop()

    def test_without_witnesses_every_publication_is_served_at_once(self, client):
        db = client.app.state.db
        assert db.witness_feeder is None and db._log.served is db._log.published
        index = claim(client, "nora")
        note = one_served_note(client)
        assert size_of(note) == index + 1 and len(parse_note(note).signatures) == 1
        bundle = client.get(f"/v2/entries/{index}").json()
        assert bundle_note(bundle) == note
        health = client.get("/healthz").json()
        assert health["served_size"] == health["published_size"] == health["tree_size"] == index + 1
        assert health["serving_uncosigned"] is False and health["uncosigned_reason"] is None
        assert health["served_cosignature_age_seconds"] is None
        cp = client.get("/v2/tlog/checkpoint").json()
        assert cp["checkpoint_size"] == cp["tree_size"] == index + 1 and cp["signed_checkpoint"].encode() == note
        # A name view does not wait for anything either.
        assert client.get("/v2/names/nora").json()["indices"] == [index]
        # The write evidence of the gate is unchanged too: the log-signed note of the write, no extra line.
        line = Line(client)
        reply = onboard(line, KeyAgent("olga"))
        assert "cosignature" not in reply and len(parse_note(artifacts(reply)["checkpoint"]).signatures) == 1


class TestFeeder:
    def feeder(self, clock: list[float], n: int = 2) -> WitnessFeeder:
        endpoints = tuple(
            WitnessEndpoint(f"w{i}", "http://127.0.0.1:1",
                            cosignature_vkey(f"w{i}.example/w", Ed25519PrivateKey.generate().public_key()))
            for i in range(n)
        )
        feeder = WitnessFeeder(
            WitnessSettings(witnesses=endpoints), proof=lambda old, new: [], deliver=lambda e, s, lines: (True, None),
            client_factory=lambda e: object(), monotonic=lambda: clock[0], clock=lambda: 1_800_000_000 + clock[0],
        )
        feeder._started = True  # the threads are not needed: the attempts are reported by hand
        return feeder

    def test_an_outage_is_every_witness_failing_since_the_last_one_began(self):
        clock = [100.0]
        feeder = self.feeder(clock)
        one, two = feeder._workers
        assert feeder.outage() is None  # pending: an answer may still come
        feeder._failed(one, OSError("refused"))
        clock[0] += 5
        assert feeder.outage() is None  # the other one has not failed
        feeder._failed(two, OSError("refused"))
        clock[0] += 7
        assert feeder.outage() == 7
        feeder._failed(one, OSError("refused again"))  # a further failure does not move the start
        assert feeder.outage() == 7
        feeder._succeeded(two, 3)
        assert feeder.outage() is None
        (a, b) = feeder.status()
        assert a["failing_since"] == 1_800_000_100 and b["failing_since"] is None and b["state"] == "ok"
        feeder._stopping = True
        assert feeder.outage() is None  # a stopped feeder reports none: the served note is held

    def test_settings(self, tmp_path):
        s = WitnessSettings.from_env({}, default_state_dir=tmp_path)
        assert s.timeout_seconds == 5 and s.grace_seconds == 120
        s = WitnessSettings.from_env({"AICS_WITNESS_GRACE_SECONDS": "0", "AICS_WITNESS_TIMEOUT_SECONDS": "2.5"},
                                     default_state_dir=tmp_path)
        assert s.grace_seconds == 0 and s.timeout_seconds == 2.5
        for bad in ("-1", "3601", "soon"):
            with pytest.raises(WitnessConfigError):
                WitnessSettings.from_env({"AICS_WITNESS_GRACE_SECONDS": bad}, default_state_dir=tmp_path)

    def test_the_grace_ends_while_the_held_cosignature_is_still_fresh(self, tmp_path):
        """The cosigned note held while every witness fails was cosigned at most about a refresh interval before the
        outage began: a grace longer than max_checkpoint_age (300 s) - refresh - 30 s would hold a note every
        quorum-1 verifier rejects as stale, so such a setting stops the start (210 s with the default refresh)."""
        from aics_tlog import format_vkey

        assert max_grace_seconds(60.0) == 210 and max_grace_seconds(100.0) == 170
        vkey = format_vkey(cosignature_vkey("w1.example/w", Ed25519PrivateKey.generate().public_key()))
        witnessed = {"AICS_WITNESSES": f"w1=https://w1.example/={vkey}"}

        def grace(**env: str) -> float:
            return WitnessSettings.from_env({**witnessed, **env}, default_state_dir=tmp_path).grace_seconds

        assert grace(AICS_WITNESS_GRACE_SECONDS="210") == 210
        with pytest.raises(WitnessConfigError, match="at most 210 s with AICS_WITNESS_REFRESH_SECONDS 60"):
            grace(AICS_WITNESS_GRACE_SECONDS="211")
        assert grace(AICS_WITNESS_REFRESH_SECONDS="100") == 120  # the default fits any refresh
        with pytest.raises(WitnessConfigError, match="max_checkpoint_age"):
            grace(AICS_WITNESS_REFRESH_SECONDS="100", AICS_WITNESS_GRACE_SECONDS="171")
        # Without a witness the grace has no effect, and a quorum-0 server is not stopped by it.
        assert WitnessSettings.from_env({"AICS_WITNESS_GRACE_SECONDS": "600"}, default_state_dir=tmp_path).witnesses == ()
