"""The feeder: old-size discovery, 409 recovery, retries, verification."""

from __future__ import annotations

import base64
import datetime
import ipaddress
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog import (
    cosignature_vkey,
    parse_checkpoint,
    parse_note,
    sign_cosignature,
    vkey_from_ed25519,
)
from aics_witness.config import LogConfig
from aics_witness.feeder import (
    BadWitnessResponse,
    WitnessAhead,
    WitnessClient,
    WitnessConflict,
    WitnessRejected,
    WitnessRolledBack,
    WitnessUnavailable,
    merge_cosignatures,
    submit_checkpoint,
)
from aics_witness.protocol import (
    format_add_checkpoint_request,
    format_signature_line,
    parse_add_checkpoint_request,
)
from aics_witness.service import WitnessError

from conftest import WITNESS_NAME, InProcessLog, start_witness, threshold_policy_ok

# A well-formed witness vkey for tests whose fake witness never answers 200.
ANY_VKEY = cosignature_vkey(WITNESS_NAME, Ed25519PrivateKey.generate().public_key())


class Recorder:
    """Wraps a WitnessClient's transport to record the old sizes sent."""

    def __init__(self, client: WitnessClient) -> None:
        self.old_sizes: list[int] = []
        self.proof_lengths: list[int] = []
        original = client._request_once

        def spy(body: bytes):
            req = parse_add_checkpoint_request(body)
            self.old_sizes.append(req.old_size)
            self.proof_lengths.append(len(req.proof))
            return original(body)

        client._request_once = spy  # type: ignore[method-assign]


def test_first_contact_discovers_size_through_409(running, log: InProcessLog):
    log.append(25)
    running.witness.add_checkpoint(format_add_checkpoint_request(0, [], log.checkpoint()))
    log.append(6)
    with WitnessClient(running.url, running.witness.vkey_text) as client:
        rec = Recorder(client)
        line = client.submit(log.checkpoint(), log.proof)
    assert rec.old_sizes == [0, 25]
    assert rec.proof_lengths[0] == 0 and rec.proof_lengths[1] > 0
    assert threshold_policy_ok(merge_cosignatures(log.checkpoint(), line), log.vkey,
                               [cosignature_vkey(WITNESS_NAME, running.key.public_key())], 1)


def test_client_remembers_witness_size(running, log: InProcessLog):
    with WitnessClient(running.url, running.witness.vkey_text) as client:
        rec = Recorder(client)
        for _ in range(3):
            log.append(4)
            client.submit(log.checkpoint(), log.proof)
    assert rec.old_sizes == [0, 4, 8]


def test_fixed_proof_pair(running, log: InProcessLog):
    log.append(10)
    submit_checkpoint(running.url, log.checkpoint(), (0, []), witness_vkey=running.witness.vkey_text)
    log.append(10)
    line = submit_checkpoint(running.url, log.checkpoint(), (10, log.proof(10, 20)),
                             witness_vkey=running.witness.vkey_text)
    assert line
    assert running.store.get(log.origin).size == 20


def test_fixed_proof_pair_from_wrong_size_raises_conflict(running, log: InProcessLog):
    log.append(10)
    submit_checkpoint(running.url, log.checkpoint(), (0, []), witness_vkey=running.witness.vkey_text)
    log.append(10)
    with pytest.raises(WitnessConflict) as e:
        submit_checkpoint(running.url, log.checkpoint(), (5, log.proof(5, 20)),
                          witness_vkey=running.witness.vkey_text)
    assert e.value.known_size == 10
    assert running.store.get(log.origin).size == 10


def test_lost_response_is_recovered_without_a_proof(running, log: InProcessLog):
    """The witness applied the checkpoint but the answer never arrived; the
    retry from the old size gets a 409 naming the new size and resubmits
    with an equal old size and no proof."""
    log.append(8)
    running.witness.add_checkpoint(format_add_checkpoint_request(0, [], log.checkpoint()))
    log.append(8)
    running.witness.add_checkpoint(
        format_add_checkpoint_request(8, log.proof(8, 16), log.checkpoint()))  # "lost" answer
    with WitnessClient(running.url, running.witness.vkey_text) as client:
        rec = Recorder(client)
        line = client.submit(log.checkpoint(), (8, log.proof(8, 16)))
    assert rec.old_sizes == [8, 16]
    assert rec.proof_lengths == [len(log.proof(8, 16)), 0]
    assert line


def test_stale_checkpoint_raises_witness_ahead(running, log: InProcessLog):
    log.append(30)
    running.witness.add_checkpoint(format_add_checkpoint_request(0, [], log.checkpoint()))
    stale = log.checkpoint(20)
    with WitnessClient(running.url, running.witness.vkey_text) as client:
        with pytest.raises(WitnessAhead) as e:
            client.submit(stale, log.proof)
        assert isinstance(e.value, WitnessConflict)  # a WitnessConflict, as before
        assert e.value.known_size == 30
        assert log.origin not in client.known_sizes  # an answer from ahead is not remembered


def test_remembered_size_larger_than_the_checkpoint_is_ignored(running, log: InProcessLog):
    log.append(10)
    with WitnessClient(running.url, running.witness.vkey_text) as client:
        client.known_sizes[log.origin] = 50  # a stale or bogus hint
        rec = Recorder(client)
        assert client.submit(log.checkpoint(), log.proof)
    assert rec.old_sizes == [0]


def test_inconsistent_checkpoint_is_rejected_not_retried(running, log: InProcessLog):
    log.append(12)
    submit_checkpoint(running.url, log.checkpoint(), log.proof, witness_vkey=running.witness.vkey_text)
    fork = log.fork(keep=5)
    fork.append(10)
    with WitnessClient(running.url, running.witness.vkey_text) as client:
        client.known_sizes[log.origin] = 12
        rec = Recorder(client)
        with pytest.raises(WitnessRejected) as e:
            client.submit(fork.checkpoint(), fork.proof)
    assert e.value.status == 422
    assert rec.old_sizes == [12]


def test_unknown_origin_and_bad_signature_are_rejected(running, log: InProcessLog):
    vkey = running.witness.vkey_text
    other = InProcessLog("other.example.test/log")
    other.append(2)
    with pytest.raises(WitnessRejected) as e:
        submit_checkpoint(running.url, other.checkpoint(), other.proof, witness_vkey=vkey)
    assert e.value.status == 404
    impostor = InProcessLog(log.origin)
    impostor.append(2)
    with pytest.raises(WitnessRejected) as e:
        submit_checkpoint(running.url, impostor.checkpoint(), impostor.proof, witness_vkey=vkey)
    assert e.value.status == 403


def test_wrong_witness_vkey_is_detected(running, log: InProcessLog):
    log.append(3)
    wrong = cosignature_vkey(WITNESS_NAME, Ed25519PrivateKey.generate().public_key())
    with pytest.raises(BadWitnessResponse):
        submit_checkpoint(running.url, log.checkpoint(), log.proof, witness_vkey=wrong)


def test_witness_vkey_is_required(running, log: InProcessLog):
    with pytest.raises(ValueError, match="vkey is required"):
        WitnessClient(running.url)
    with pytest.raises(ValueError, match="vkey is required"):
        submit_checkpoint(running.url, b"unused\n", (0, []))
    log.append(2)
    # Diagnostics only: the line comes back unverified.
    line = submit_checkpoint(running.url, log.checkpoint(), log.proof, allow_unverified=True)
    assert line.startswith("— " + WITNESS_NAME + " ")


def test_witness_vkey_must_be_cosignature_type(running):
    plain = vkey_from_ed25519(WITNESS_NAME, Ed25519PrivateKey.generate().public_key())
    with pytest.raises(ValueError):
        WitnessClient(running.url, plain)


@pytest.mark.parametrize("public_key", [
    bytes([1]) + bytes(31),  # identity
    bytes(32),  # order 4
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),  # order 8
    b"\xee" + b"\xff" * 30 + b"\x7f",  # y = p + 1: non-canonical
])
def test_weak_witness_vkey_is_refused(public_key):
    with pytest.raises(ValueError, match="small-order|canonical"):
        WitnessClient("http://w.example", cosignature_vkey(WITNESS_NAME, public_key))


def test_url_forms():
    def url(u: str) -> str:
        return WitnessClient(u, ANY_VKEY).url

    assert url("http://w.example:8080") == "http://w.example:8080/add-checkpoint"
    assert url("https://w.example/p/") == "https://w.example/p/add-checkpoint"
    assert url("https://w.example/p/add-checkpoint") == "https://w.example/p/add-checkpoint"
    for bad in ("ftp://w.example", "w.example", "http://w.example/?q=1"):
        with pytest.raises(ValueError):
            WitnessClient(bad, ANY_VKEY)


def test_merge_replaces_older_cosignature_from_same_key(running, log: InProcessLog):
    log.append(5)
    signed = log.checkpoint()
    with WitnessClient(running.url, running.witness.vkey_text) as client:
        first = client.submit(signed, log.proof)
        second = client.submit(signed, log.proof)
    merged = merge_cosignatures(merge_cosignatures(signed, first), second)
    note = parse_note(merged)
    assert [s.name for s in note.signatures] == [log.origin, WITNESS_NAME]
    assert merged.endswith(second.encode())


# ---------------------------------------------------------------------------
# A witness that lost its state
# ---------------------------------------------------------------------------


def test_witness_restarted_on_a_fresh_database_is_detected(tmp_path, log: InProcessLog):
    key = Ed25519PrivateKey.generate()
    logs = [LogConfig(log.origin, (log.vkey,))]
    state_file = tmp_path / "witness1.state.json"
    w1 = start_witness(tmp_path / "a.db", key, logs)
    try:
        log.append(16)
        with WitnessClient(w1.url, w1.witness.vkey_text, state_path=state_file) as client:
            client.submit(log.checkpoint(), log.proof)
            assert client.max_cosigned(log.origin) == 16
    finally:
        w1.stop()
    assert json.loads(state_file.read_text())["logs"][log.origin]["max_cosigned"] == 16

    w2 = start_witness(tmp_path / "b.db", key, logs)  # same identity, state lost
    try:
        log.append(4)
        # A restarted log process: the state file remembers size 16.
        with WitnessClient(w2.url, w2.witness.vkey_text, state_path=state_file) as client:
            rec = Recorder(client)
            with pytest.raises(WitnessRolledBack) as e:
                client.submit(log.checkpoint(), log.proof)
            assert (e.value.origin, e.value.previous, e.value.named) == (log.origin, 16, 0)
            assert rec.old_sizes == [16]
            # Refused from now on, without asking the witness again.
            with pytest.raises(WitnessRolledBack):
                client.submit(log.checkpoint(), log.proof)
            assert rec.old_sizes == [16]
        assert w2.store.get(log.origin) is None  # it cosigned nothing
        with WitnessClient(w2.url, w2.witness.vkey_text, state_path=state_file) as client:
            assert client.rollback(log.origin)["previous"] == 16  # persisted
            with pytest.raises(WitnessRolledBack):
                client.submit(log.checkpoint(), log.proof)
            client.acknowledge_rollback(log.origin)  # the operator accepts it
            assert client.submit(log.checkpoint(), log.proof)
            assert client.max_cosigned(log.origin) == 20
    finally:
        w2.stop()


def test_cosignature_from_an_old_size_below_what_was_seen_is_a_rollback(tmp_path, log: InProcessLog):
    """A 200 means the witness held exactly the old size sent; below a size
    it cosigned before, that is a rollback, and the line is not returned."""
    key = Ed25519PrivateKey.generate()
    logs = [LogConfig(log.origin, (log.vkey,))]
    w1 = start_witness(tmp_path / "a.db", key, logs)
    w2 = start_witness(tmp_path / "b.db", key, logs)
    try:
        log.append(9)
        with WitnessClient(w1.url, w1.witness.vkey_text) as client:
            client.submit(log.checkpoint(), log.proof)
            client._host, client._port = "127.0.0.1", w2.server.server_address[1]
            client.close()
            log.append(3)
            with pytest.raises(WitnessRolledBack):
                client.submit(log.checkpoint(), log.proof, old_size=0)
    finally:
        w1.stop()
        w2.stop()


def test_state_file_belongs_to_one_witness_key(tmp_path, running):
    state_file = tmp_path / "s.json"
    WitnessClient(running.url, running.witness.vkey_text, state_path=state_file).acknowledge_rollback("x")
    with pytest.raises(ValueError, match="belongs to witness key"):
        WitnessClient(running.url, ANY_VKEY, state_path=state_file)


# ---------------------------------------------------------------------------
# Freshness of returned cosignatures
# ---------------------------------------------------------------------------


def _signing_fake(key: Ed25519PrivateKey, timestamp_of):
    def respond(req):
        cp = parse_checkpoint(parse_note(req.checkpoint).text)
        _, line = sign_cosignature(key, WITNESS_NAME, timestamp_of(), cp.origin, cp.size, cp.root)
        return 200, "text/plain", format_signature_line(line).encode()

    return FakeWitness(respond)


def test_stale_and_future_dated_cosignatures_are_bad_responses(log: InProcessLog):
    key = Ed25519PrivateKey.generate()
    vkey = cosignature_vkey(WITNESS_NAME, key.public_key())
    now = 1_900_000_000
    log.append(3)
    for ts, match in ((now - 61, "s old"), (now + 31, "in the future")):
        with _signing_fake(key, lambda ts=ts: ts) as fake:
            with pytest.raises(BadWitnessResponse, match=match):
                submit_checkpoint(fake.url, log.checkpoint(), log.proof, witness_vkey=vkey,
                                  clock=lambda: now)
    for ts in (now - 60, now + 30):  # the bounds themselves are accepted
        with _signing_fake(key, lambda ts=ts: ts) as fake:
            assert submit_checkpoint(fake.url, log.checkpoint(), log.proof, witness_vkey=vkey,
                                     clock=lambda: now)
    with _signing_fake(key, lambda: now - 3600) as fake:  # archival use can lift the age bound
        assert submit_checkpoint(fake.url, log.checkpoint(), log.proof, witness_vkey=vkey,
                                 clock=lambda: now, max_age_seconds=None)


# ---------------------------------------------------------------------------
# Retries against a flaky front end
# ---------------------------------------------------------------------------


class FlakyFront:
    """An HTTP front end that answers the first ``failures`` requests with
    ``status`` and passes the rest to a real Witness object."""

    def __init__(self, witness, failures: int, status: int = 503, retry_after: str | None = None):
        self.witness = witness
        self.failures = failures
        self.seen = 0
        front = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                front.seen += 1
                if front.seen <= front.failures:
                    self._send(status, b"busy\n", "text/plain",
                               {"Retry-After": retry_after} if retry_after else {})
                    return
                try:
                    out = front.witness.add_checkpoint(body)
                except WitnessError as e:
                    self._send(e.status, e.body, e.content_type, {})
                    return
                self._send(200, out, "text/plain; charset=utf-8", {})

            def _send(self, code, body, ctype, headers):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_transient_errors_are_retried(running, log: InProcessLog, status):
    front = FlakyFront(running.witness, failures=2, status=status, retry_after="1")
    sleeps: list[float] = []
    try:
        log.append(3)
        line = submit_checkpoint(front.url, log.checkpoint(), log.proof,
                                 witness_vkey=running.witness.vkey_text, sleep=sleeps.append)
    finally:
        front.close()
    assert line
    assert front.seen == 3
    assert sleeps == [1.0, 1.0]  # Retry-After honoured


def test_gives_up_after_max_attempts(running, log: InProcessLog):
    front = FlakyFront(running.witness, failures=100)
    sleeps: list[float] = []
    try:
        log.append(3)
        with pytest.raises(WitnessUnavailable):
            submit_checkpoint(front.url, log.checkpoint(), log.proof, max_attempts=3,
                              witness_vkey=running.witness.vkey_text,
                              sleep=sleeps.append, backoff=0.25, max_backoff=1.0)
    finally:
        front.close()
    assert front.seen == 3
    assert len(sleeps) == 2 and all(0 < s <= 1.0 for s in sleeps)
    assert running.store.get(log.origin) is None


def test_connection_refused_is_unavailable(log: InProcessLog):
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    log.append(1)
    sleeps: list[float] = []
    with pytest.raises(WitnessUnavailable):
        submit_checkpoint(f"http://127.0.0.1:{port}", log.checkpoint(), log.proof,
                          witness_vkey=ANY_VKEY, max_attempts=2, sleep=sleeps.append, timeout=2)
    assert len(sleeps) == 1


def test_keep_alive_connection_closed_by_the_witness_is_replaced_at_once(tmp_path, log: InProcessLog):
    """The witness closes idle keep-alive connections after a few seconds;
    the next submission reconnects without a backoff pause."""
    rw = start_witness(tmp_path / "w.db", Ed25519PrivateKey.generate(),
                       [LogConfig(log.origin, (log.vkey,))], idle_timeout=0.3)
    sleeps: list[float] = []
    try:
        with WitnessClient(rw.url, rw.witness.vkey_text, sleep=sleeps.append) as client:
            log.append(2)
            client.submit(log.checkpoint(), log.proof)
            first = client._conn.sock
            time.sleep(0.8)  # the witness drops the idle connection
            log.append(2)
            assert client.submit(log.checkpoint(), log.proof)
            assert client._conn.sock is not first
    finally:
        rw.stop()
    assert sleeps == []


class FakeWitness:
    """A scripted witness: ``respond(request) -> (status, content_type, body[, headers])``."""

    def __init__(self, respond, ssl_context: ssl.SSLContext | None = None):
        fake = self
        self.connections: set[tuple] = set()

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                fake.connections.add(self.client_address)
                req = parse_add_checkpoint_request(self.rfile.read(int(self.headers["Content-Length"])))
                status, ctype, body, *rest = respond(req)
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (rest[0] if rest else {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        scheme = "http"
        if ssl_context is not None:
            self.server.socket = ssl_context.wrap_socket(self.server.socket, server_side=True)
            scheme = "https"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()
        self.url = f"{scheme}://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def test_409_without_size_content_type_is_bad_response(log: InProcessLog):
    log.append(1)
    with FakeWitness(lambda req: (409, "text/html", b"<html>conflict</html>")) as fake:
        with pytest.raises(BadWitnessResponse):
            submit_checkpoint(fake.url, log.checkpoint(), log.proof, witness_vkey=ANY_VKEY)


def test_v1_0_0_root_mismatch_409_is_final(log: InProcessLog):
    """tlog-witness v1.0.0 reports a different root at an equal size with a
    409 naming that same size; the feeder treats it as a rejection."""
    calls = []

    def respond(req):
        calls.append(req.old_size)
        return 409, "text/x.tlog.size", f"{req.old_size}\n".encode()

    log.append(5)
    with FakeWitness(respond) as fake:
        with pytest.raises(WitnessRejected) as e:
            submit_checkpoint(fake.url, log.checkpoint(), (5, []), witness_vkey=ANY_VKEY)
    assert e.value.status == 409 and "different root" in e.value.message
    assert calls == [5]


def test_409_echoing_a_smaller_old_size_is_bad_response(log: InProcessLog):
    def respond(req):
        return 409, "text/x.tlog.size", f"{req.old_size}\n".encode()

    log.append(5)
    with FakeWitness(respond) as fake:
        with pytest.raises(BadWitnessResponse):
            submit_checkpoint(fake.url, log.checkpoint(), (3, log.proof(3, 5)), witness_vkey=ANY_VKEY)


def test_malformed_200_is_bad_response(log: InProcessLog):
    log.append(2)
    for body in (b"not a signature line\n", b"\xe2\x80\x94 w.example/w1 AQIDBAU=", b""):
        with FakeWitness(lambda req, b=body: (200, "text/plain", b)) as fake:
            with pytest.raises(BadWitnessResponse):
                submit_checkpoint(fake.url, log.checkpoint(), log.proof, witness_vkey=ANY_VKEY)


def test_oversized_response_is_bad_response(log: InProcessLog):
    log.append(2)
    big = b"x" * ((1 << 20) + 1)
    with FakeWitness(lambda req: (200, "text/plain", big)) as fake:
        with pytest.raises(BadWitnessResponse, match="too large"):
            submit_checkpoint(fake.url, log.checkpoint(), log.proof, witness_vkey=ANY_VKEY)


def test_conflict_loop_is_bounded(log: InProcessLog):
    """A witness that keeps moving its size cannot keep the client looping."""
    sizes = iter(range(1, 100))

    def respond(req):
        return 409, "text/x.tlog.size", f"{next(sizes)}\n".encode()

    log.append(200)
    with FakeWitness(respond) as fake:
        with pytest.raises(WitnessConflict):
            submit_checkpoint(fake.url, log.checkpoint(), log.proof, max_conflicts=3,
                              witness_vkey=ANY_VKEY)


def test_one_bogus_409_does_not_block_later_submissions(log: InProcessLog):
    """An unauthenticated 409 naming a huge size (a buggy witness, a proxy,
    anyone on a plain-HTTP path) is not remembered."""
    key = Ed25519PrivateKey.generate()
    vkey = cosignature_vkey(WITNESS_NAME, key.public_key())
    calls: list[int] = []

    def respond(req):
        calls.append(req.old_size)
        if len(calls) == 1:
            return 409, "text/x.tlog.size", b"9223372036854775807\n"
        cp = parse_checkpoint(parse_note(req.checkpoint).text)
        _, line = sign_cosignature(key, WITNESS_NAME, int(time.time()), cp.origin, cp.size, cp.root)
        return 200, "text/plain", format_signature_line(line).encode()

    log.append(10)
    with FakeWitness(respond) as fake, WitnessClient(fake.url, vkey) as client:
        with pytest.raises(WitnessAhead) as e:
            client.submit(log.checkpoint(), log.proof)
        assert e.value.known_size == 2**63 - 1
        assert log.origin not in client.known_sizes
        log.append(10)
        assert client.submit(log.checkpoint(), log.proof)
        assert client.known_sizes[log.origin] == 20
    assert calls == [0, 0]


def test_cosignature_for_another_checkpoint_is_bad_response(log: InProcessLog):
    """Right key name and ID, but the signature covers a different tree:
    the feeder must verify, not just match the key."""
    key = Ed25519PrivateKey.generate()
    vkey = cosignature_vkey(WITNESS_NAME, key.public_key())
    log.append(6)
    when = 1_792_281_600

    def respond(req):
        _, line = sign_cosignature(key, WITNESS_NAME, when, log.origin, 7, log.tree.root())
        return 200, "text/plain", format_signature_line(line).encode()

    with FakeWitness(respond) as fake:
        with pytest.raises(BadWitnessResponse, match="does not verify"):
            submit_checkpoint(fake.url, log.checkpoint(), log.proof, witness_vkey=vkey,
                              clock=lambda: when)
        # Without a vkey (diagnostics only) the line is returned unverified.
        assert submit_checkpoint(fake.url, log.checkpoint(), log.proof,
                                 allow_unverified=True).startswith("— " + WITNESS_NAME)

    def respond_good(req):
        _, line = sign_cosignature(key, WITNESS_NAME, when, log.origin, 6, log.tree.root())
        other = cosignature_vkey("other.example/w", Ed25519PrivateKey.generate().public_key())
        stranger = f"— other.example/w {base64.b64encode(other.key_id + bytes(72)).decode()}\n"
        return 200, "text/plain", (stranger + format_signature_line(line)).encode()

    with FakeWitness(respond_good) as fake:
        # Lines from unknown keys are ignored; only the witness's verified line is returned.
        got = submit_checkpoint(fake.url, log.checkpoint(), log.proof, witness_vkey=vkey,
                                clock=lambda: when)
    assert got.count("\n") == 1 and got.startswith("— " + WITNESS_NAME)


def test_connection_close_from_the_witness_is_honoured(log: InProcessLog):
    key = Ed25519PrivateKey.generate()
    vkey = cosignature_vkey(WITNESS_NAME, key.public_key())

    def respond(req):
        cp = parse_checkpoint(parse_note(req.checkpoint).text)
        _, line = sign_cosignature(key, WITNESS_NAME, int(time.time()), cp.origin, cp.size, cp.root)
        return 200, "text/plain", format_signature_line(line).encode(), {"Connection": "close"}

    with FakeWitness(respond) as fake, WitnessClient(fake.url, vkey) as client:
        log.append(2)
        client.submit(log.checkpoint(), log.proof)
        assert client._conn is None  # closed after the answer
        log.append(2)
        client.submit(log.checkpoint(), log.proof)
        assert len(fake.connections) == 2


def _self_signed_tls(tmp_path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aics-witness test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                       critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=True, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    client = ssl.create_default_context(cafile=str(cert_path))
    return server, client


def test_https_witness(tmp_path, log: InProcessLog):
    server_ctx, client_ctx = _self_signed_tls(tmp_path)
    key = Ed25519PrivateKey.generate()
    vkey = cosignature_vkey(WITNESS_NAME, key.public_key())
    log.append(3)
    with _signing_fake_tls(key, server_ctx) as fake:
        assert fake.url.startswith("https://")
        assert submit_checkpoint(fake.url, log.checkpoint(), log.proof, witness_vkey=vkey,
                                 ssl_context=client_ctx)
        # Without trusting the certificate the TLS handshake fails (retried, then unavailable).
        with pytest.raises(WitnessUnavailable, match="SSL|certificate"):
            submit_checkpoint(fake.url, log.checkpoint(), log.proof, witness_vkey=vkey,
                              max_attempts=1)


def _signing_fake_tls(key: Ed25519PrivateKey, server_ctx: ssl.SSLContext) -> FakeWitness:
    def respond(req):
        cp = parse_checkpoint(parse_note(req.checkpoint).text)
        _, line = sign_cosignature(key, WITNESS_NAME, int(time.time()), cp.origin, cp.size, cp.root)
        return 200, "text/plain", format_signature_line(line).encode()

    return FakeWitness(respond, ssl_context=server_ctx)
