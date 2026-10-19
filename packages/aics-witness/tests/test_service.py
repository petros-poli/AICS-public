"""The add-checkpoint rules of c2sp.org/tlog-witness, exercised over HTTP."""

from __future__ import annotations

import base64
import http.client
import logging
import random
import socket
import threading
import time
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog import (
    EMPTY_HASH,
    Checkpoint,
    MerkleTree,
    Note,
    SignatureLine,
    cosignature_vkey,
    parse_checkpoint,
    parse_note,
    sign_checkpoint,
    sign_cosignature,
    sign_note,
    verify_cosignature,
    vkey_from_ed25519,
)
from aics_witness.config import LogConfig
from aics_witness.protocol import (
    AddCheckpointRequest,
    format_add_checkpoint_request,
    origin_hash,
    parse_signature_lines,
)
from aics_witness.service import Witness, WitnessError, _check_consistency, _Inconsistent
from aics_witness.store import LogState, WitnessStore

from conftest import WITNESS_NAME, FailingCommit, FakeClock, InProcessLog, http_request, start_witness


def post(running, old: int, proof: list[bytes], note: bytes):
    return http_request(running.add_url, "POST", format_add_checkpoint_request(old, proof, note))


def cosign_to(running, log: InProcessLog, size: int | None = None):
    """Bring the witness to the log's current size from whatever it holds."""
    state = running.store.get(log.origin)
    old = 0 if state is None else state.size
    size = log.size if size is None else size
    res = post(running, old, log.proof(old, size) if old else [], log.checkpoint(size))
    assert res.status == 200, res.body
    return res


def cosignature_timestamp(line: str) -> int:
    blob = base64.b64decode(line.split()[-1])
    return int.from_bytes(blob[4:12], "big")


def raw_exchange(url: str, data: bytes, timeout: float = 5.0) -> bytes:
    """Send raw bytes, return everything the server sends until it closes."""
    parts = urlsplit(url)
    out = b""
    with socket.create_connection((parts.hostname, parts.port), timeout=timeout) as s:
        s.sendall(data)
        while True:
            try:
                chunk = s.recv(65536)
            except (TimeoutError, ConnectionError):
                break
            if not chunk:
                break
            out += chunk
    return out


# ---------------------------------------------------------------------------
# Success path and response format
# ---------------------------------------------------------------------------


def test_success_response_is_one_cosignature_line(running, log):
    log.append(4)
    res = post(running, 0, [], log.checkpoint())
    assert res.status == 200
    assert res.headers["content-type"].startswith("text/plain")
    text = res.body.decode()
    [sig] = parse_signature_lines(text)
    assert sig.name == WITNESS_NAME
    wkey = cosignature_vkey(WITNESS_NAME, running.key.public_key())
    assert sig.key_id == wkey.key_id
    assert len(sig.signature) == 72  # 8-byte timestamp || Ed25519 signature
    assert verify_cosignature(sig.signature, WITNESS_NAME, wkey.public_key, log.origin, 4,
                              log.tree.root())


def test_cosignature_covers_extension_lines(tmp_path, log, witness_key):
    rw = start_witness(tmp_path / "w.db", witness_key,
                       [LogConfig(log.origin, (log.vkey,), extension_lines=True)])
    try:
        log.append(2)
        res = post(rw, 0, [], log.checkpoint(extension_lines=("ext one", "ext two")))
        assert res.status == 200
        [sig] = parse_signature_lines(res.body.decode())
        key = witness_key.public_key()
        assert verify_cosignature(sig.signature, WITNESS_NAME, key, log.origin, 2, log.tree.root(),
                                  ("ext one", "ext two"))
        assert not verify_cosignature(sig.signature, WITNESS_NAME, key, log.origin, 2, log.tree.root())
    finally:
        rw.stop()


def test_extension_lines_are_refused_by_default(running, log):
    """AICS-1 §6.2 checkpoints have no extension lines; the witness does not
    sign opaque strings no AICS client accepts."""
    log.append(2)
    res = post(running, 0, [], log.checkpoint(extension_lines=("ext one",)))
    assert res.status == 400 and b"extension lines" in res.body
    assert running.store.get(log.origin) is None
    assert post(running, 0, [], log.checkpoint()).status == 200


def test_empty_tree_checkpoint(running, log):
    res = post(running, 0, [], log.checkpoint(0))
    assert res.status == 200
    state = running.store.get(log.origin)
    assert (state.size, state.root) == (0, EMPTY_HASH)
    log.append(3)
    assert post(running, 0, [], log.checkpoint()).status == 200


# ---------------------------------------------------------------------------
# Freshness and the clock
# ---------------------------------------------------------------------------


def test_cosignature_timestamp_is_current_time(running, log):
    log.append(6)
    before = int(time.time())
    res = post(running, 0, [], log.checkpoint())
    after = int(time.time())
    assert res.status == 200
    ts = cosignature_timestamp(res.body.decode())
    assert before <= ts <= after
    [sig] = parse_signature_lines(res.body.decode())
    assert verify_cosignature(sig.signature, WITNESS_NAME, running.key.public_key(), log.origin, 6,
                              log.tree.root(), max_future_seconds=5)


def test_cosignature_timestamp_follows_injected_clock(tmp_path, log, witness_key):
    now = [1_900_000_000.7]
    rw = start_witness(tmp_path / "w.db", witness_key, [LogConfig(log.origin, (log.vkey,))],
                       clock=lambda: now[0])
    try:
        log.append(3)
        res = post(rw, 0, [], log.checkpoint())
        assert cosignature_timestamp(res.body.decode()) == 1_900_000_000
        assert rw.store.get(log.origin).timestamp == 1_900_000_000
        # A cosignature dated in the future is detectable by verifiers.
        [sig] = parse_signature_lines(res.body.decode())
        assert not verify_cosignature(sig.signature, WITNESS_NAME, witness_key.public_key(),
                                      log.origin, 3, log.tree.root(), max_future_seconds=60)
    finally:
        rw.stop()


def test_small_backward_clock_step_is_503_with_retry_after(tmp_path, log, witness_key):
    clock = FakeClock(2_000_000_000.0)
    rw = start_witness(tmp_path / "w.db", witness_key, [LogConfig(log.origin, (log.vkey,))],
                       clock=clock)
    try:
        log.append(3)
        assert post(rw, 0, [], log.checkpoint()).status == 200
        clock.now -= 3  # the clock steps back a little
        log.append(2)
        res = post(rw, 3, log.proof(3, 5), log.checkpoint())
        assert res.status == 503 and res.headers["retry-after"] == "3"
        assert rw.store.get(log.origin).size == 3
        clock.now += 3
        res = post(rw, 3, log.proof(3, 5), log.checkpoint())
        assert res.status == 200
        assert cosignature_timestamp(res.body.decode()) == 2_000_000_000
    finally:
        rw.stop()


def test_forward_clock_glitch_never_dates_later_cosignatures_in_the_future(
    tmp_path, log, witness_key, caplog
):
    real = 1_900_000_000
    clock = FakeClock(real + 30 * 86400)  # NTP/RTC glitch: 30 days ahead
    rw = start_witness(tmp_path / "w.db", witness_key, [LogConfig(log.origin, (log.vkey,))],
                       clock=clock)
    try:
        log.append(3)
        assert post(rw, 0, [], log.checkpoint()).status == 200  # dated by the glitched clock
        clock.now = real + 60  # corrected
        produced: list[int] = []
        with caplog.at_level(logging.ERROR, logger="aics_witness"):
            for _ in range(3):
                log.append(1)
                res = post(rw, 3, log.proof(3, log.size), log.checkpoint())
                assert res.status == 503 and "retry-after" not in res.headers
                if res.status == 200:
                    produced.append(cosignature_timestamp(res.body.decode()))
        assert produced == []  # no cosignature at all, so none from the future
        assert "clock behind last cosignature by" in caplog.text
        assert rw.store.get(log.origin).size == 3
        # The operator fixed the clock and clears the stored time.
        assert rw.store.clear_last_timestamp(log.origin) == 1
        res = post(rw, 3, log.proof(3, log.size), log.checkpoint())
        assert res.status == 200
        assert cosignature_timestamp(res.body.decode()) == real + 60
    finally:
        rw.stop()


def test_startup_warns_about_cosignatures_dated_in_the_future(tmp_path, log, witness_key, caplog):
    store = WitnessStore(tmp_path / "w.db", create=True)
    try:
        with store.transaction() as tx:
            tx.put(log.origin, 0, EMPTY_HASH, "n\n", 2_000_000_100, 0)
        with caplog.at_level(logging.WARNING, logger="aics_witness"):
            Witness(WITNESS_NAME, witness_key, store, [LogConfig(log.origin, (log.vkey,))],
                    clock=lambda: 2_000_000_000)
        assert "dated 100 s after the current time" in caplog.text
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="aics_witness"):
            Witness(WITNESS_NAME, witness_key, store, [LogConfig(log.origin, (log.vkey,))],
                    clock=lambda: 2_000_000_096)  # 4 s: within the retry window
        assert "after the current time" not in caplog.text
    finally:
        store.close()


def test_same_second_replay_returns_the_stored_cosignature_without_a_write(tmp_path, log, witness_key):
    clock = FakeClock(1_900_000_000.0)
    rw = start_witness(tmp_path / "w.db", witness_key, [LogConfig(log.origin, (log.vkey,))],
                       clock=clock)
    try:
        log.append(5)
        first = post(rw, 0, [], log.checkpoint())
        assert first.status == 200
        changes = rw.store._conn.total_changes
        for _ in range(5):
            replay = post(rw, 5, [], log.checkpoint())
            assert (replay.status, replay.body) == (200, first.body)
        assert rw.store._conn.total_changes == changes  # nothing written
        clock.now += 1
        later = post(rw, 5, [], log.checkpoint())
        assert later.status == 200 and later.body != first.body
        assert cosignature_timestamp(later.body.decode()) == 1_900_000_001
        assert rw.store.get(log.origin).timestamp == 1_900_000_001
    finally:
        rw.stop()


# ---------------------------------------------------------------------------
# Old size handling (409 / 400)
# ---------------------------------------------------------------------------


def test_old_size_mismatch_is_409_with_latest_size(running, log):
    log.append(10)
    cosign_to(running, log)
    log.append(5)
    res = post(running, 0, [], log.checkpoint())  # the witness holds 10, not 0
    assert res.status == 409
    assert res.headers["content-type"] == "text/x.tlog.size"
    assert res.body == b"10\n"
    res = post(running, 7, log.proof(7, 15), log.checkpoint())
    assert (res.status, res.body) == (409, b"10\n")
    # The correct old size and proof succeed.
    res = post(running, 10, log.proof(10, 15), log.checkpoint())
    assert res.status == 200
    assert running.store.get(log.origin).size == 15
    assert running.store.evidence(log.origin) == []  # consistent views are not evidence


def test_unknown_log_state_is_409_zero(running, log):
    log.append(8)
    res = post(running, 3, log.proof(3, 8), log.checkpoint())
    assert (res.status, res.body) == (409, b"0\n")
    assert res.headers["content-type"] == "text/x.tlog.size"


def test_rollback_attempt_is_409(running, log):
    """A smaller (older) checkpoint can never be cosigned after a larger one."""
    log.append(20)
    old_cp = log.checkpoint(12)
    cosign_to(running, log)
    res = post(running, 12, [], old_cp)
    assert (res.status, res.body) == (409, b"20\n")
    res = post(running, 0, [], old_cp)
    assert (res.status, res.body) == (409, b"20\n")
    assert running.store.get(log.origin).size == 20


def test_old_size_larger_than_checkpoint_is_400(running, log):
    log.append(4)
    res = post(running, 5, [], log.checkpoint())
    assert res.status == 400


def test_tree_size_beyond_the_limit_is_400(running, log):
    huge = sign_checkpoint(Checkpoint(log.origin, 2**63, b"\x01" * 32), log.key, log.origin).to_bytes()
    res = post(running, 0, [], huge)
    assert res.status == 400 and b"too large" in res.body
    assert running.store.get(log.origin) is None


# ---------------------------------------------------------------------------
# Split view / inconsistency (422) and evidence
# ---------------------------------------------------------------------------


def test_split_view_fork_is_rejected_and_kept_as_evidence(running, log):
    log.append(16)
    cosign_to(running, log)
    fork = log.fork(keep=11)  # same key and origin, history diverges after leaf 11
    fork.append(10)  # fork size 21
    honest_root = log.tree.root()

    # The fork's own proof from 16 cannot connect to the root the witness holds.
    res = post(running, 16, fork.proof(16, 21), fork.checkpoint())
    assert res.status == 422
    state = running.store.get(log.origin)
    assert (state.size, state.root) == (16, honest_root)

    # Nor can an honest-looking proof taken from the real log.
    log.append(5)
    res = post(running, 16, log.proof(16, 21), fork.checkpoint())
    assert res.status == 422

    evidence = running.store.evidence(log.origin)
    assert len(evidence) == 2
    assert evidence[0].known_size == 16 and evidence[0].known_root == honest_root
    assert "does not verify" in evidence[0].reason
    assert fork.checkpoint() in evidence[0].request

    # The honest log continues normally.
    res = post(running, 16, log.proof(16, 21), log.checkpoint())
    assert res.status == 200


def test_same_size_different_root_is_rejected(running, log):
    log.append(9)
    cosign_to(running, log)
    fork = log.fork(keep=4)
    fork.append(5)  # also size 9, different root
    assert fork.tree.root() != log.tree.root()
    res = post(running, 9, [], fork.checkpoint())
    assert res.status == 422
    assert b"different root" in res.body
    [ev] = running.store.evidence(log.origin)
    assert ev.old_size == 9 and ev.known_size == 9
    # Two log-signed checkpoints, same size, different roots: proof of a split view.
    stored = parse_note(running.store.get(log.origin).note)
    assert stored.text != parse_note(fork.checkpoint()).text


def test_equal_size_fork_with_another_old_size_is_409_and_kept_as_evidence(running, log):
    """Same size, other root is proof of equivocation (AICS-1 §14.6) even when
    the request carries a wrong old size; the answer stays 409."""
    log.append(9)
    cosign_to(running, log)
    fork = log.fork(keep=4)
    fork.append(5)
    res = post(running, 0, [], fork.checkpoint())
    assert (res.status, res.body) == (409, b"9\n")
    [ev] = running.store.evidence(log.origin)
    assert ev.reason == "same size, different root (old size mismatch)"
    assert (ev.old_size, ev.known_size, ev.known_root) == (0, 9, log.tree.root())
    assert fork.checkpoint() in ev.request
    res = post(running, 4, fork.proof(4, 9), fork.checkpoint())
    assert res.status == 409 and len(running.store.evidence(log.origin)) == 2
    # A stale but consistent checkpoint with a wrong old size is not evidence.
    assert post(running, 0, [], log.checkpoint(5)).status == 409
    assert len(running.store.evidence(log.origin)) == 2


def test_nonempty_proof_with_old_size_zero_is_422(running, log):
    log.append(8)
    res = post(running, 0, log.proof(4, 8), log.checkpoint())
    assert res.status == 422
    assert running.store.get(log.origin) is None


def test_nonempty_proof_for_equal_sizes_is_422(running, log):
    log.append(8)
    cosign_to(running, log)
    res = post(running, 8, log.proof(4, 8), log.checkpoint())
    assert res.status == 422


def test_size_zero_with_wrong_root_is_422(running, log):
    bad = sign_checkpoint(Checkpoint(log.origin, 0, b"\x07" * 32), log.key, log.origin).to_bytes()
    res = post(running, 0, [], bad)
    assert res.status == 422
    assert running.store.get(log.origin) is None


def test_truncated_or_tampered_proof_is_422(running, log):
    log.append(100)
    cosign_to(running, log, 37)
    proof = log.proof(37, 100)
    assert len(proof) > 2
    assert post(running, 37, proof[:-1], log.checkpoint()).status == 422
    tampered = [proof[0][:-1] + bytes([proof[0][-1] ^ 1])] + proof[1:]
    assert post(running, 37, tampered, log.checkpoint()).status == 422
    assert post(running, 37, proof, log.checkpoint()).status == 200


def test_evidence_is_capped(tmp_path, log, witness_key):
    store = WitnessStore(tmp_path / "w.db", create=True, evidence_limit=2)
    witness = Witness(WITNESS_NAME, witness_key, store, [LogConfig(log.origin, (log.vkey,))])
    log.append(4)
    witness.add_checkpoint(format_add_checkpoint_request(0, [], log.checkpoint()))
    fork = log.fork(keep=1)
    fork.append(3)
    for _ in range(4):
        with pytest.raises(WitnessError) as e:
            witness.add_checkpoint(format_add_checkpoint_request(4, [], fork.checkpoint()))
        assert e.value.status == 422
    assert len(store.evidence(log.origin)) == 2
    store.close()


def test_consistency_check_is_exact_for_all_small_trees():
    """For every 0 < old < new <= 64 the honest proof is accepted, and a
    checkpoint whose history differs anywhere below the old size is refused,
    whether it comes with its own proof or with the honest one."""
    top = 64
    honest = MerkleTree([b"leaf %d" % i for i in range(top)])
    roots = {n: honest.root(n) for n in range(1, top + 1)}
    forks = {
        j: MerkleTree([b"forged %d" % i if i == j else b"leaf %d" % i for i in range(top)])
        for j in range(top - 1)
    }
    fork_roots = {j: {n: t.root(n) for n in range(j + 1, top + 1)} for j, t in forks.items()}
    checked = 0
    for old in range(1, top):
        state = LogState("o", old, roots[old], "", 0, 0)
        with pytest.raises(_Inconsistent):  # equal size, other root
            _check_consistency(AddCheckpointRequest(old, (), b""), Checkpoint("o", old, fork_roots[0][old]), state)
        for new in range(old + 1, top + 1):
            proof = tuple(honest.consistency_proof(old, new))
            _check_consistency(AddCheckpointRequest(old, proof, b""), Checkpoint("o", new, roots[new]), state)
            for j in range(old):
                fork_cp = Checkpoint("o", new, fork_roots[j][new])
                for candidate in (tuple(forks[j].consistency_proof(old, new)), proof):
                    with pytest.raises(_Inconsistent):
                        _check_consistency(AddCheckpointRequest(old, candidate, b""), fork_cp, state)
                    checked += 1
    assert checked == 2 * sum(old * (top - old) for old in range(1, top))


# ---------------------------------------------------------------------------
# The initial pin (no trust on first use)
# ---------------------------------------------------------------------------


def test_initial_pin_replaces_trust_on_first_use(tmp_path, log, witness_key):
    log.append(20)
    pin = (12, log.tree.root(12))
    rw = start_witness(tmp_path / "w.db", witness_key,
                       [LogConfig(log.origin, (log.vkey,), initial=pin)])
    try:
        res = post(rw, 0, [], log.checkpoint())
        assert (res.status, res.body) == (409, b"12\n")  # no starting point from old 0
        fork = log.fork(keep=5)
        fork.append(15)  # size 20, diverging below the pin
        res = post(rw, 12, fork.proof(12, 20), fork.checkpoint())
        assert res.status == 422
        [ev] = rw.store.evidence(log.origin)
        assert (ev.known_size, ev.known_root) == pin
        assert rw.store.get(log.origin) is None
        res = post(rw, 0, [], fork.checkpoint(12))  # fork at the pinned size: equivocation
        assert res.status == 409 and len(rw.store.evidence(log.origin)) == 2
        res = post(rw, 12, log.proof(12, 20), log.checkpoint())
        assert res.status == 200 and rw.store.get(log.origin).size == 20
        # Once the witness holds state, the pin no longer matters.
        log.append(1)
        assert post(rw, 20, log.proof(20, 21), log.checkpoint()).status == 200
    finally:
        rw.stop()


def test_initial_pin_accepts_the_pinned_checkpoint_itself(tmp_path, log, witness_key):
    log.append(7)
    rw = start_witness(tmp_path / "w.db", witness_key,
                       [LogConfig(log.origin, (log.vkey,), initial=(7, log.tree.root()))])
    try:
        assert post(rw, 7, [], log.checkpoint()).status == 200
        assert rw.store.get(log.origin).size == 7
    finally:
        rw.stop()


# ---------------------------------------------------------------------------
# Signatures and origins (403 / 404)
# ---------------------------------------------------------------------------


def test_unknown_origin_is_404(running):
    other = InProcessLog("other.example.test/log")
    other.append(3)
    res = post(running, 0, [], other.checkpoint())
    assert res.status == 404


def test_signature_from_wrong_key_with_same_name_is_403(running, log):
    """Same key name, different key: the key ID differs, so the signature is
    from an unknown key and no trusted signature remains."""
    log.append(5)
    impostor = InProcessLog(log.origin)  # fresh key, same origin/name
    impostor.tree = log.tree
    res = post(running, 0, [], impostor.checkpoint())
    assert res.status == 403
    assert running.store.get(log.origin) is None


def test_corrupted_trusted_signature_is_403(running, log):
    log.append(5)
    note = parse_note(log.checkpoint())
    sig = note.signatures[0]
    bad_sig = SignatureLine(sig.name, sig.key_id, sig.signature[:-1] + bytes([sig.signature[-1] ^ 1]))
    tampered = Note(note.text, (bad_sig,)).to_bytes()
    assert post(running, 0, [], tampered).status == 403


def test_bad_trusted_signature_next_to_good_one_is_403(running, log):
    """A known key's failing signature rejects the note even if another
    known key verifies (signed-note: such a note is malformed)."""
    second_key = Ed25519PrivateKey.generate()
    second_vkey = vkey_from_ed25519("log.example.test/second", second_key.public_key())
    running.witness.set_logs([LogConfig(log.origin, (log.vkey, second_vkey))])
    log.append(5)
    note = parse_note(log.checkpoint())
    other = sign_note(note.text, second_key, "log.example.test/second")
    broken = SignatureLine(other.name, other.key_id, bytes(64))
    assert post(running, 0, [], Note(note.text, note.signatures + (broken,)).to_bytes()).status == 403
    assert post(running, 0, [], Note(note.text, note.signatures + (other,)).to_bytes()).status == 200


def test_mixed_log_key_types_with_one_failing_is_403(tmp_path, log, witness_key):
    """A log trusted under an Ed25519 note key (0x01) and a cosignature key
    (0x04): either one failing rejects the note; both valid are kept."""
    cos_key = Ed25519PrivateKey.generate()
    cos_name = "log.example.test/cosigner"
    rw = start_witness(tmp_path / "w.db", witness_key,
                       [LogConfig(log.origin, (log.vkey, cosignature_vkey(cos_name, cos_key.public_key())))])
    try:
        log.append(4)
        note = parse_note(log.checkpoint())
        _, good = sign_cosignature(cos_key, cos_name, 1_700_000_000, log.origin, 4, log.tree.root())
        bad = SignatureLine(good.name, good.key_id, good.signature[:-1] + bytes([good.signature[-1] ^ 1]))
        log_sig = note.signatures[0]
        bad_log = SignatureLine(log_sig.name, log_sig.key_id, bytes(64))
        assert post(rw, 0, [], Note(note.text, (log_sig, bad)).to_bytes()).status == 403
        assert post(rw, 0, [], Note(note.text, (bad_log, good)).to_bytes()).status == 403
        assert post(rw, 0, [], Note(note.text, (log_sig, good)).to_bytes()).status == 200
        stored = parse_note(rw.store.get(log.origin).note)
        assert [s.name for s in stored.signatures] == [log.origin, cos_name, WITNESS_NAME]
    finally:
        rw.stop()


def test_checkpoint_text_altered_after_signing_is_403(running, log):
    log.append(5)
    note = parse_note(log.checkpoint())
    lines = note.text.split("\n")
    lines[1] = "6"  # claim a larger tree under the old signature
    altered = Note("\n".join(lines), note.signatures).to_bytes()
    assert post(running, 0, [], altered).status == 403


def test_only_unknown_signatures_is_403(running, log):
    log.append(5)
    note = parse_note(log.checkpoint())
    stranger = sign_note(note.text, Ed25519PrivateKey.generate(), "stranger.example/k")
    assert post(running, 0, [], Note(note.text, (stranger,)).to_bytes()).status == 403


def test_log_key_of_cosignature_type_is_accepted(tmp_path, log, witness_key):
    """A log may authenticate its checkpoints with an Ed25519 cosignature
    (type 0x04) instead of a plain note signature."""
    log_key = Ed25519PrivateKey.generate()
    vkey = cosignature_vkey(log.origin, log_key.public_key())
    rw = start_witness(tmp_path / "w.db", witness_key, [LogConfig(log.origin, (vkey,))])
    try:
        log.append(7)
        cp = Checkpoint(log.origin, 7, log.tree.root())
        _, line = sign_cosignature(log_key, log.origin, 1_700_000_000, log.origin, 7, log.tree.root())
        assert post(rw, 0, [], Note(cp.text(), (line,)).to_bytes()).status == 200
        bad = SignatureLine(line.name, line.key_id, line.signature[:-1] + b"\x00")
        log.append(1)
        cp2 = Checkpoint(log.origin, 8, log.tree.root())
        assert post(rw, 7, log.proof(7, 8), Note(cp2.text(), (bad,)).to_bytes()).status == 403
    finally:
        rw.stop()


def test_duplicate_trusted_signature_lines_are_403(running, log):
    log.append(5)
    note = parse_note(log.checkpoint())
    doubled = Note(note.text, note.signatures * 2).to_bytes()
    res = post(running, 0, [], doubled)
    assert res.status == 403 and b"two signature lines" in res.body


def test_duplicate_lines_from_unknown_keys_are_ignored(running, log):
    """tlog-witness: signatures from unknown keys MUST be ignored, repeated
    ones too (a log relaying another witness's cosignature twice)."""
    log.append(5)
    note = parse_note(log.checkpoint())
    other = sign_note(note.text, Ed25519PrivateKey.generate(), "other.example/w")
    res = post(running, 0, [], Note(note.text, note.signatures + (other, other)).to_bytes())
    assert res.status == 200
    stored = parse_note(running.store.get(log.origin).note)
    assert [s.name for s in stored.signatures] == [log.origin, WITNESS_NAME]


def test_witness_refuses_its_own_key_as_a_log_key(tmp_path, log, witness_key):
    """Its own earlier cosignatures must never authenticate a checkpoint."""
    store = WitnessStore(tmp_path / "w.db", create=True)
    try:
        own = cosignature_vkey("evil.example/log", witness_key.public_key())
        with pytest.raises(ValueError, match="own public key"):
            Witness(WITNESS_NAME, witness_key, store, [LogConfig("evil.example/log", (own,))])
        witness = Witness(WITNESS_NAME, witness_key, store, [LogConfig(log.origin, (log.vkey,))])
        same_key_other_type = vkey_from_ed25519("evil.example/log", witness_key.public_key())
        with pytest.raises(ValueError, match="own public key"):
            witness.set_logs([LogConfig(log.origin, (log.vkey,)),
                              LogConfig("evil.example/log", (same_key_other_type,))])
        assert list(witness.logs) == [log.origin]  # the previous list is kept
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Malformed requests and HTTP behaviour
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"old 0\n",
        b"old 0\n\n",
        b"old -1\n\n{cp}",
        b"old 01\n\n{cp}",
        b"old 0x1\n\n{cp}",
        b"new 0\n\n{cp}",
        b"old  0\n\n{cp}",
        b"old 0\r\n\r\n{cp}",
        b"old 99999999999999999999999\n\n{cp}",
        b"old 0\nnot base64!\n\n{cp}",
        b"old 0\nAAAA\n\n{cp}",  # decodes, but not 32 bytes
        b"old 0\n\n\n{cp}",
        b"old 0\n\n{cp_no_newline}",
        b"old 0\n\nnot a checkpoint\n\n\xe2\x80\x94 x AAAAAA==\n",
        b"old 0\n\n\xff\xfe\n\n",
    ],
)
def test_malformed_bodies_are_400(running, log, body):
    log.append(3)
    cp = log.checkpoint()
    body = body.replace(b"{cp}", cp).replace(b"{cp_no_newline}", cp.rstrip(b"\n"))
    res = http_request(running.add_url, "POST", body)
    assert res.status == 400, (body, res.body)


def test_more_than_63_proof_lines_is_400(running, log):
    log.append(3)
    proof_line = base64.b64encode(b"\x00" * 32)
    body = b"old 1\n" + (proof_line + b"\n") * 64 + b"\n" + log.checkpoint()
    assert http_request(running.add_url, "POST", body).status == 400
    body63 = b"old 1\n" + (proof_line + b"\n") * 63 + b"\n" + log.checkpoint()
    assert http_request(running.add_url, "POST", body63).status == 409  # parsed; state is 0


def test_non_canonical_base64_proof_line_is_400(running, log):
    log.append(3)
    good = base64.b64encode(b"\x01" * 32).decode()
    non_canonical = good[:-2] + "F="  # different unused bits
    assert base64.b64decode(non_canonical) == base64.b64decode(good)
    body = f"old 1\n{non_canonical}\n\n".encode() + log.checkpoint()
    assert http_request(running.add_url, "POST", body).status == 400


def _fuzz_witness(tmp_path, log, witness_key, **log_options):
    store = WitnessStore(tmp_path / "fuzz.db", create=True)
    witness = Witness(WITNESS_NAME, witness_key, store, [LogConfig(log.origin, (log.vkey,), **log_options)])
    return store, witness


def test_random_bodies_never_cause_a_500(tmp_path, log, witness_key):
    log.append(9)
    store, witness = _fuzz_witness(tmp_path, log, witness_key, extension_lines=True)
    witness.add_checkpoint(format_add_checkpoint_request(0, [], log.checkpoint(5)))
    seeds = [
        format_add_checkpoint_request(5, log.proof(5, 9), log.checkpoint()),
        format_add_checkpoint_request(5, log.proof(5, 9), log.checkpoint(extension_lines=("ext",))),
        format_add_checkpoint_request(5, [], log.checkpoint(5)),
    ]
    rng = random.Random(20261018)
    alphabet = b"\n \x00old0123456789=+/AQ\xe2\x80\x94-"

    def mutate(data: bytes) -> bytes:
        b = bytearray(data)
        for _ in range(rng.randint(1, 4)):
            op = rng.randrange(5)
            if op == 0 and b:
                b[rng.randrange(len(b))] = rng.randrange(256)
            elif op == 1 and b:
                del b[rng.randrange(len(b))]
            elif op == 2:
                b.insert(rng.randrange(len(b) + 1), rng.choice(alphabet))
            elif op == 3 and b:
                i = rng.randrange(len(b))
                b[i:i] = b[rng.randrange(len(b)):][: rng.randrange(1, 40)]
            elif b:
                del b[rng.randrange(len(b)):]
        return bytes(b)

    outcomes: dict[int, int] = {}
    try:
        for i in range(3000):
            if i % 4 == 0:
                body = bytes(rng.randrange(256) for _ in range(rng.randrange(300)))
            else:
                body = mutate(rng.choice(seeds))
            try:
                witness.add_checkpoint(body)
                status = 200
            except WitnessError as e:
                status = e.status
            assert status < 500, (body, status)
            outcomes[status] = outcomes.get(status, 0) + 1
    finally:
        store.close()
    assert outcomes.get(400, 0) > 1000  # most mutations are malformed ...
    assert len(outcomes) >= 4  # ... but the fuzzer reaches the later checks too


def test_http_methods_and_paths(running):
    res = http_request(running.add_url, "GET")
    assert res.status == 405 and res.headers["allow"] == "POST"
    assert http_request(running.url + "/nope", "POST", b"x").status == 404
    assert http_request(running.url + "/nope", "GET").status == 404
    res = http_request(running.url + "/healthz", "GET")
    assert (res.status, res.body) == (200, b"ok\n")


def test_body_too_large_is_413(tmp_path, log, witness_key):
    rw = start_witness(tmp_path / "w.db", witness_key, [LogConfig(log.origin, (log.vkey,))],
                       max_body_bytes=4096)
    try:
        res = http_request(rw.add_url, "POST", b"old 0\n\n" + b"x" * 5000)
        assert res.status == 413
    finally:
        rw.stop()


def test_missing_content_length_is_411(running):
    assert raw_exchange(running.add_url,
                        b"POST /add-checkpoint HTTP/1.1\r\nHost: x\r\n\r\n").startswith(b"HTTP/1.1 411")


def test_chunked_request_bodies_are_accepted(running, log):
    """HTTP/1.1 clients (and proxies relaying HTTP/2) may send chunked bodies."""
    log.append(6)
    body = format_add_checkpoint_request(0, [], log.checkpoint())
    parts = urlsplit(running.add_url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
    try:
        conn.request("POST", "/add-checkpoint", body=iter([body[:7], body[7:50], body[50:]]))
        resp = conn.getresponse()
        assert resp.status == 200, resp.read()
        resp.read()
    finally:
        conn.close()
    assert running.store.get(log.origin).size == 6
    # Chunk extensions and trailer fields are allowed and ignored.
    log.append(2)
    body = format_add_checkpoint_request(6, log.proof(6, 8), log.checkpoint())
    raw = (b"POST /add-checkpoint HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
           b"Connection: close\r\n\r\n"
           + f"{len(body):x};name=value\r\n".encode() + body + b"\r\n0\r\nX-Trailer: y\r\n\r\n")
    assert raw_exchange(running.add_url, raw).startswith(b"HTTP/1.1 200")
    assert running.store.get(log.origin).size == 8


@pytest.mark.parametrize(
    "head,body,status",
    [
        (b"Transfer-Encoding: chunked\r\n", b"zz\r\nabc\r\n0\r\n\r\n", b"400"),
        (b"Transfer-Encoding: chunked\r\n", b"3\r\nabcXY0\r\n\r\n", b"400"),
        (b"Transfer-Encoding: chunked\r\n", b"10001\r\n", b"413"),  # over max_body_bytes
        (b"Transfer-Encoding: chunked\r\n", b"8000\r\n" + b"a" * 0x8000 + b"\r\n" * 1
         + b"8000\r\n" + b"a" * 0x8000 + b"\r\n" + b"1\r\n", b"413"),
        (b"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n", b"0\r\n\r\n", b"400"),
        (b"Transfer-Encoding: gzip, chunked\r\n", b"0\r\n\r\n", b"501"),
        (b"Content-Length: 5\r\nContent-Length: 6\r\n", b"hello", b"400"),
    ],
)
def test_bad_request_framing(tmp_path, log, witness_key, head, body, status):
    rw = start_witness(tmp_path / "w.db", witness_key, [LogConfig(log.origin, (log.vkey,))],
                       max_body_bytes=0x10000)
    try:
        reply = raw_exchange(rw.add_url, b"POST /add-checkpoint HTTP/1.1\r\nHost: x\r\n" + head + b"\r\n" + body)
        assert reply.startswith(b"HTTP/1.1 " + status), reply[:80]
    finally:
        rw.stop()


def test_keep_alive_serves_several_requests_on_one_connection(running, log):
    parts = urlsplit(running.add_url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
    try:
        log.append(2)
        conn.request("POST", "/add-checkpoint", body=format_add_checkpoint_request(0, [], log.checkpoint()))
        r1 = conn.getresponse()
        assert r1.status == 200
        r1.read()
        sock = conn.sock
        log.append(2)
        conn.request("POST", "/add-checkpoint",
                     body=format_add_checkpoint_request(2, log.proof(2, 4), log.checkpoint()))
        r2 = conn.getresponse()
        assert r2.status == 200
        r2.read()
        assert conn.sock is sock  # same TCP connection
        conn.request("POST", "/add-checkpoint", body=format_add_checkpoint_request(0, [], log.checkpoint()))
        r3 = conn.getresponse()
        assert (r3.status, r3.read()) == (409, b"4\n")
        assert conn.sock is sock
    finally:
        conn.close()


def test_prefix(tmp_path, log, witness_key):
    rw = start_witness(tmp_path / "w.db", witness_key, [LogConfig(log.origin, (log.vkey,))],
                       prefix="/witness/v1/")
    try:
        assert rw.add_url.endswith("/witness/v1/add-checkpoint")
        log.append(2)
        assert http_request(rw.add_url, "POST",
                            format_add_checkpoint_request(0, [], log.checkpoint())).status == 200
        assert http_request(rw.add_url.replace("/witness/v1", ""), "POST", b"x").status == 404
    finally:
        rw.stop()


# ---------------------------------------------------------------------------
# Slow clients and connection slots
# ---------------------------------------------------------------------------


def test_trickling_clients_cannot_hold_every_slot(tmp_path, log, witness_key):
    rw = start_witness(tmp_path / "w.db", witness_key, [LogConfig(log.origin, (log.vkey,))],
                       max_connections=2, request_timeout=1.0, idle_timeout=0.5)
    host, port = rw.server.server_address[:2]
    slow = [socket.create_connection((host, port)) for _ in range(2)]
    stop = threading.Event()

    def trickle() -> None:
        while not stop.is_set():
            for s in slow:
                try:
                    s.sendall(b"s")  # one header byte at a time, forever
                except OSError:
                    pass
            time.sleep(0.2)

    for s in slow:
        s.sendall(b"POST /add-checkpoint HTTP/1.1\r\nHo")
    t = threading.Thread(target=trickle, daemon=True)
    t.start()
    try:
        time.sleep(0.3)  # both slots are taken by the tricklers now
        start = time.monotonic()
        res = http_request(rw.url + "/healthz", "GET")  # queued until a deadline expires
        assert (res.status, res.body) == (200, b"ok\n")
        assert time.monotonic() - start < 5
        for s in slow:  # the tricklers were cut off at their deadline
            s.settimeout(3)
            try:
                assert s.recv(100) == b""
            except ConnectionError:
                pass
    finally:
        stop.set()
        t.join(timeout=2)
        for s in slow:
            s.close()
        rw.stop()


def test_idle_keep_alive_connections_are_closed_to_free_a_slot(tmp_path, log, witness_key):
    rw = start_witness(tmp_path / "w.db", witness_key, [LogConfig(log.origin, (log.vkey,))],
                       max_connections=2, idle_timeout=30.0)
    host, port = rw.server.server_address[:2]
    idle = [socket.create_connection((host, port)) for _ in range(2)]
    try:
        time.sleep(0.3)  # accepted, waiting for a request line
        start = time.monotonic()
        res = http_request(rw.url + "/healthz", "GET")
        assert res.status == 200
        assert time.monotonic() - start < 3  # not the 30 s idle timeout
        for s in idle:
            s.settimeout(3)
            try:
                assert s.recv(10) == b""
            except ConnectionError:
                pass
    finally:
        for s in idle:
            s.close()
        rw.stop()


def test_slow_body_is_cut_off_at_the_request_deadline(tmp_path, log, witness_key):
    rw = start_witness(tmp_path / "w.db", witness_key, [LogConfig(log.origin, (log.vkey,))],
                       request_timeout=1.0)
    host, port = rw.server.server_address[:2]
    try:
        with socket.create_connection((host, port)) as s:
            s.sendall(b"POST /add-checkpoint HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n")
            start = time.monotonic()
            closed = False
            while time.monotonic() - start < 6 and not closed:
                try:
                    s.sendall(b"x")
                    s.settimeout(0.2)
                    closed = s.recv(100) == b""
                except TimeoutError:
                    pass
                except OSError:
                    closed = True
            assert closed
            assert time.monotonic() - start < 3
    finally:
        rw.stop()


def test_idle_connection_is_closed_after_the_idle_timeout(tmp_path, log, witness_key):
    rw = start_witness(tmp_path / "w.db", witness_key, [LogConfig(log.origin, (log.vkey,))],
                       idle_timeout=0.5)
    host, port = rw.server.server_address[:2]
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            start = time.monotonic()
            assert s.recv(10) == b""
            assert time.monotonic() - start < 3
    finally:
        rw.stop()


# ---------------------------------------------------------------------------
# Atomicity, persistence and storage failures
# ---------------------------------------------------------------------------


def test_concurrent_submissions_never_roll_back(running, log):
    """The race in the specification: concurrent requests from the same old
    size must not leave the witness at a smaller size than it cosigned."""
    log.append(10)
    cosign_to(running, log)
    sizes = [11, 13, 17, 19, 23, 29, 31, 37]
    log.append(max(sizes) - 10)
    results: dict[int, int] = {}

    def submit(size: int) -> None:
        res = post(running, 10, log.proof(10, size), log.checkpoint(size))
        results[size] = res.status

    threads = [threading.Thread(target=submit, args=(s,)) for s in sizes]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    winners = [s for s, status in results.items() if status == 200]
    assert len(winners) == 1
    assert all(status == 409 for s, status in results.items() if s not in winners)
    assert running.store.get(log.origin).size == winners[0]


def test_state_persists_across_restart(tmp_path, log, witness_key):
    logs = [LogConfig(log.origin, (log.vkey,))]
    rw = start_witness(tmp_path / "w.db", witness_key, logs)
    log.append(30)
    res = post(rw, 0, [], log.checkpoint())
    assert res.status == 200
    note_before = rw.store.get(log.origin).note
    rw.stop()

    rw2 = start_witness(tmp_path / "w.db", witness_key, logs)
    try:
        state = rw2.store.get(log.origin)
        assert (state.size, state.root, state.note) == (30, log.tree.root(), note_before)
        # The restarted witness still refuses to forget: old size 0 is a conflict.
        assert (post(rw2, 0, [], log.checkpoint()).body) == b"30\n"
        # And it still refuses a fork of what it cosigned before the restart.
        fork = log.fork(keep=20)
        fork.append(15)
        assert post(rw2, 30, fork.proof(30, 35), fork.checkpoint()).status == 422
        log.append(5)
        assert post(rw2, 30, log.proof(30, 35), log.checkpoint()).status == 200
    finally:
        rw2.stop()


def test_failed_commit_never_serves_or_keeps_uncommitted_state(tmp_path, log, witness_key):
    db = tmp_path / "w.db"
    logs = [LogConfig(log.origin, (log.vkey,))]
    monitor = None
    rw = start_witness(db, witness_key, logs)
    try:
        monitor = f"{rw.url}/{origin_hash(log.origin)}/checkpoint"
        log.append(4)
        assert post(rw, 0, [], log.checkpoint()).status == 200
        proxy = FailingCommit(rw.store._conn)
        rw.store._conn = proxy
        log.append(5)
        res = post(rw, 4, log.proof(4, 9), log.checkpoint())
        assert res.status == 503
        # The monitoring endpoint serves the committed size 4, not the
        # cosigned-but-uncommitted 9.
        mon = http_request(monitor, "GET")
        assert mon.status == 200
        assert parse_checkpoint(parse_note(mon.body).text).size == 4
        # Later submissions are refused (no "transaction within a transaction").
        log.append(3)
        assert post(rw, 4, log.proof(4, 12), log.checkpoint()).status == 503
        assert post(rw, 0, [], log.checkpoint()).status == 503
        # The health check turns red, so the operator (or the restart policy) acts.
        assert http_request(rw.url + "/healthz", "GET").status == 503
        rw.store._conn = proxy.conn
    finally:
        rw.stop()
    rw2 = start_witness(db, witness_key, logs)
    try:
        assert rw2.store.get(log.origin).size == 4
        assert http_request(rw2.url + "/healthz", "GET").status == 200
        assert post(rw2, 4, log.proof(4, 12), log.checkpoint()).status == 200
    finally:
        rw2.stop()


def test_unexpected_error_is_500_and_persists_nothing(running, log, monkeypatch):
    import aics_witness.service as service

    def broken(*args, **kwargs):
        raise RuntimeError("signing failed")

    monkeypatch.setattr(service, "sign_cosignature", broken)
    log.append(3)
    res = post(running, 0, [], log.checkpoint())
    assert res.status == 500 and res.body == b"internal error\n"
    assert running.store.get(log.origin) is None
    assert not running.store.failed
    monkeypatch.undo()
    assert post(running, 0, [], log.checkpoint()).status == 200


def test_removed_and_readded_log_keeps_its_state(running, log):
    log.append(12)
    cosign_to(running, log)
    running.witness.set_logs([])
    assert post(running, 12, [], log.checkpoint()).status == 404
    running.witness.set_logs([LogConfig(log.origin, (log.vkey,))])
    assert post(running, 0, [], log.checkpoint()).body == b"12\n"


def test_absurd_content_length_and_handler_errors_leak_no_address(running, caplog):
    parts = urlsplit(running.add_url)
    with socket.create_connection((parts.hostname, parts.port), timeout=5) as s:
        s.sendall(b"POST /add-checkpoint HTTP/1.1\r\nHost: x\r\nContent-Length: " + b"9" * 5000 + b"\r\n\r\n")
        data = s.recv(4096)
    assert data.startswith(b"HTTP/1.1 413")

    # An unexpected exception inside a handler is logged without the client address.
    def boom(self):
        raise RuntimeError("boom")

    import aics_witness.service as service

    original = service._Handler.do_GET
    service._Handler.do_GET = boom
    try:
        with caplog.at_level(logging.ERROR, logger="aics_witness"):
            with socket.create_connection((parts.hostname, parts.port), timeout=5) as s:
                s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
                s.recv(4096)
            deadline = time.time() + 5
            while not caplog.records and time.time() < deadline:
                time.sleep(0.05)
    finally:
        service._Handler.do_GET = original
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "unhandled error" in text
    assert "127.0.0.1" not in text
